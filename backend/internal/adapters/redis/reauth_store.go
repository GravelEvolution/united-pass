package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
)

// reauthChallengeKeySegment is the key segment for reauthentication challenge
// data. The full key is: {prefix}reauth:{sha256(reauthToken)}.
const reauthChallengeKeySegment = "reauth:"

// reauthChallengeAttemptsKeySegment is the key segment for the challenge
// attempt counter: {prefix}reauth:attempts:{sha256(reauthToken)}. The counter
// lives in a separate key so Redis INCR stays atomic.
const reauthChallengeAttemptsKeySegment = "reauth:attempts:"

// reauthChallengeClaimKeySegment is the key segment for the challenge claim
// lock: {prefix}reauth:claim:{sha256(reauthToken)}. The lock holds a random
// claim ID (SET NX PX) granting exclusive verification rights to one request.
const reauthChallengeClaimKeySegment = "reauth:claim:"

// reauthGrantKeySegment is the key segment for single-use reauthentication
// grants: {prefix}reauth:grant:{sha256(reauthToken)}.
const reauthGrantKeySegment = "reauth:grant:"

// reauthClaimTTL bounds how long a challenge claim lock may be held. If the
// verifying request dies or the provider call hangs, the lock expires and the
// user can retry. Mirrors the MFA claim TTL.
const reauthClaimTTL = 60 * time.Second

// ReauthStore persists reauthentication challenges and single-use grants in
// Redis (ADR-0004 §7). Challenges follow the same atomic claim/consume
// pattern as login MFA; grants are consumed atomically by the target
// operation before it executes. Redis loss only invalidates challenges and
// grants (fail closed) — it can never bypass the reauthentication gate.
type ReauthStore struct {
	client *Client
}

// NewReauthStore builds a ReauthStore backed by the given Client.
func NewReauthStore(client *Client) *ReauthStore {
	return &ReauthStore{client: client}
}

// CreateChallenge stores a reauthentication challenge under the given token
// hash with the specified TTL. The tokenHash must be the SHA-256 hex hash of
// the raw challenge token; the raw token must never reach Redis.
func (s *ReauthStore) CreateChallenge(
	ctx context.Context,
	tokenHash string,
	data auth.ReauthChallengeData,
	ttl time.Duration,
) error {
	if tokenHash == "" {
		return errors.New("redis: reauth challenge token hash must not be empty")
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis: encode reauth challenge: %w", err)
	}

	key := s.client.buildKey(reauthChallengeKeySegment, tokenHash)
	if err := s.client.rdb.Set(ctx, key, payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis: set reauth challenge: %w", err)
	}
	return nil
}

// ClaimChallenge atomically reserves a challenge for verification using a
// dedicated claim lock key with SET NX PX. It returns
// auth.ErrReauthChallengeClaimed when another request holds the lock and
// auth.ErrReauthChallengeNotFound when the challenge is gone. The challenge's
// own TTL is never modified.
func (s *ReauthStore) ClaimChallenge(ctx context.Context, tokenHash, claimID string) (auth.ReauthChallengeData, error) {
	if tokenHash == "" {
		return auth.ReauthChallengeData{}, errors.New("redis: reauth challenge token hash must not be empty")
	}
	if claimID == "" {
		return auth.ReauthChallengeData{}, errors.New("redis: reauth claim id must not be empty")
	}

	challengeKey := s.client.buildKey(reauthChallengeKeySegment, tokenHash)
	claimKey := s.client.buildKey(reauthChallengeClaimKeySegment, tokenHash)

	script := goredis.NewScript(`
local challengeKey = KEYS[1]
local claimKey = KEYS[2]
local claimID = ARGV[1]
local claimTTL = tonumber(ARGV[2])

local locked = redis.call('SET', claimKey, claimID, 'NX', 'PX', claimTTL)
if not locked then
	return redis.error_reply('CLAIMED')
end

local data = redis.call('GET', challengeKey)
if not data then
	redis.call('DEL', claimKey)
	return nil
end
return data
`)

	result, err := script.Run(ctx, s.client.rdb,
		[]string{challengeKey, claimKey},
		claimID, reauthClaimTTL.Milliseconds(),
	).Result()
	if err != nil {
		if isReauthClaimedError(err) {
			return auth.ReauthChallengeData{}, auth.ErrReauthChallengeClaimed
		}
		if errors.Is(err, goredis.Nil) {
			return auth.ReauthChallengeData{}, auth.ErrReauthChallengeNotFound
		}
		return auth.ReauthChallengeData{}, fmt.Errorf("redis: claim reauth challenge: %w", err)
	}

	var data auth.ReauthChallengeData
	if err := json.Unmarshal([]byte(result.(string)), &data); err != nil {
		return auth.ReauthChallengeData{}, fmt.Errorf("redis: decode claimed reauth challenge: %w", err)
	}
	return data, nil
}

// ReleaseChallenge removes the claim lock so the user can retry after a
// failed verification attempt. The lock is only removed when the given claimID
// still holds it. It returns auth.ErrReauthChallengeNotHeld when the claim ID
// no longer holds the lock.
func (s *ReauthStore) ReleaseChallenge(ctx context.Context, tokenHash, claimID string) error {
	if tokenHash == "" {
		return errors.New("redis: reauth challenge token hash must not be empty")
	}
	if claimID == "" {
		return errors.New("redis: reauth claim id must not be empty")
	}

	claimKey := s.client.buildKey(reauthChallengeClaimKeySegment, tokenHash)

	script := goredis.NewScript(`
local claimKey = KEYS[1]
local claimID = ARGV[1]

local current = redis.call('GET', claimKey)
if not current then
	return 0
end
if current ~= claimID then
	return 0
end

redis.call('DEL', claimKey)
return 1
`)

	result, err := script.Run(ctx, s.client.rdb, []string{claimKey}, claimID).Int()
	if err != nil {
		return fmt.Errorf("redis: release reauth challenge: %w", err)
	}
	if result == 0 {
		return auth.ErrReauthChallengeNotHeld
	}
	return nil
}

// ConsumeChallenge atomically deletes the challenge, its attempt counter and
// the claim lock, enforcing single-use semantics. The caller must hold the
// claim lock. It returns auth.ErrReauthChallengeNotHeld when the lock is no
// longer held and auth.ErrReauthChallengeNotFound when the challenge is
// already gone.
func (s *ReauthStore) ConsumeChallenge(ctx context.Context, tokenHash, claimID string) error {
	if tokenHash == "" {
		return errors.New("redis: reauth challenge token hash must not be empty")
	}
	if claimID == "" {
		return errors.New("redis: reauth claim id must not be empty")
	}

	challengeKey := s.client.buildKey(reauthChallengeKeySegment, tokenHash)
	attemptsKey := s.client.buildKey(reauthChallengeAttemptsKeySegment, tokenHash)
	claimKey := s.client.buildKey(reauthChallengeClaimKeySegment, tokenHash)

	script := goredis.NewScript(`
local challengeKey = KEYS[1]
local attemptsKey  = KEYS[2]
local claimKey     = KEYS[3]
local claimID = ARGV[1]

if redis.call('GET', claimKey) ~= claimID then
	return 0
end
if redis.call('EXISTS', challengeKey) == 0 then
	redis.call('DEL', claimKey)
	return -1
end

redis.call('DEL', challengeKey, attemptsKey, claimKey)
return 1
`)

	result, err := script.Run(ctx, s.client.rdb,
		[]string{challengeKey, attemptsKey, claimKey},
		claimID,
	).Int()
	if err != nil {
		return fmt.Errorf("redis: consume reauth challenge: %w", err)
	}

	switch result {
	case 1:
		return nil
	case -1:
		return auth.ErrReauthChallengeNotFound
	default:
		return auth.ErrReauthChallengeNotHeld
	}
}

// IncrementChallengeAttempts atomically increments the attempt counter for a
// challenge and returns the new count, copying the challenge's remaining TTL
// onto the counter so it never outlives the challenge. It returns
// auth.ErrReauthChallengeNotFound when the challenge is gone and
// auth.ErrReauthMaxAttemptsExceeded (with the count) when the budget is
// exhausted.
func (s *ReauthStore) IncrementChallengeAttempts(
	ctx context.Context,
	tokenHash string,
	maxAttempts int,
) (int, error) {
	if tokenHash == "" {
		return 0, errors.New("redis: reauth challenge token hash must not be empty")
	}

	challengeKey := s.client.buildKey(reauthChallengeKeySegment, tokenHash)
	attemptsKey := s.client.buildKey(reauthChallengeAttemptsKeySegment, tokenHash)

	script := goredis.NewScript(`
local challengeKey = KEYS[1]
local attemptsKey  = KEYS[2]

if redis.call('EXISTS', challengeKey) == 0 then
	return -1
end

local count = redis.call('INCR', attemptsKey)
local ttl = redis.call('PTTL', challengeKey)
if ttl > 0 then
	redis.call('PEXPIRE', attemptsKey, ttl)
end
return count
`)

	result, err := script.Run(ctx, s.client.rdb,
		[]string{challengeKey, attemptsKey},
	).Int()
	if err != nil {
		return 0, fmt.Errorf("redis: increment reauth attempts: %w", err)
	}

	if result < 0 {
		return 0, auth.ErrReauthChallengeNotFound
	}
	if result > maxAttempts {
		return result, auth.ErrReauthMaxAttemptsExceeded
	}
	return result, nil
}

// CreateGrant stores a single-use reauthentication grant under the given
// token hash with the specified TTL. The tokenHash must be the SHA-256 hex
// hash of the raw grant token; the raw token must never reach Redis.
func (s *ReauthStore) CreateGrant(
	ctx context.Context,
	tokenHash string,
	data auth.ReauthGrantData,
	ttl time.Duration,
) error {
	if tokenHash == "" {
		return errors.New("redis: reauth grant token hash must not be empty")
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis: encode reauth grant: %w", err)
	}

	key := s.client.buildKey(reauthGrantKeySegment, tokenHash)
	if err := s.client.rdb.Set(ctx, key, payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis: set reauth grant: %w", err)
	}
	return nil
}

// ConsumeGrant atomically reads and deletes a grant (single-winner,
// single-use). It returns the grant data or auth.ErrReauthGrantNotFound when
// the grant expired, was already consumed, or never existed. A consumed grant
// can never be reused, even if the token is intercepted.
func (s *ReauthStore) ConsumeGrant(ctx context.Context, tokenHash string) (auth.ReauthGrantData, error) {
	if tokenHash == "" {
		return auth.ReauthGrantData{}, errors.New("redis: reauth grant token hash must not be empty")
	}

	key := s.client.buildKey(reauthGrantKeySegment, tokenHash)

	// GETDEL is atomic: exactly one concurrent consumer receives the value.
	raw, err := s.client.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return auth.ReauthGrantData{}, auth.ErrReauthGrantNotFound
		}
		return auth.ReauthGrantData{}, fmt.Errorf("redis: consume reauth grant: %w", err)
	}

	var data auth.ReauthGrantData
	if err := json.Unmarshal(raw, &data); err != nil {
		return auth.ReauthGrantData{}, fmt.Errorf("redis: decode reauth grant: %w", err)
	}
	return data, nil
}

// isReauthClaimedError reports whether a Redis error is the Lua error_reply
// marker returned when a claim lock is already held.
func isReauthClaimedError(err error) bool {
	return strings.Contains(err.Error(), "CLAIMED")
}
