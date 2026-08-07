//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Redis store for MFA challenge state
//

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

// mfaKeySegment is the key segment for MFA challenge data. The full key is:
// {prefix}mfa:{sha256(mfaToken)}.
const mfaKeySegment = "mfa:"

// mfaAttemptsKeySegment is the key segment for the MFA attempt counter. The
// full key is: {prefix}mfa:attempts:{sha256(mfaToken)}. The counter is stored
// separately from the JSON challenge data so that Redis INCR can be used
// atomically.
const mfaAttemptsKeySegment = "mfa:attempts:"

// mfaClaimKeySegment is the key segment for the MFA claim lock. The full key
// is: {prefix}mfa:claim:{sha256(mfaToken)}. The lock holds a random claim ID
// (SET NX PX) that grants exclusive verification rights to one request. The
// challenge's own key and TTL are never modified by claim/release.
const mfaClaimKeySegment = "mfa:claim:"

// mfaClaimTTL bounds how long a claim lock may be held. If the verifying
// request dies or the provider call hangs, the lock expires and the user can
// start a fresh login. 60s is ample for a provider round-trip while short
// enough to unblock retries quickly.
const mfaClaimTTL = 60 * time.Second

// MFAStore implements MFA challenge persistence using Redis. Challenges are
// short-lived, single-use records keyed by the SHA-256 hash of the MFA token.
// An attempt counter is maintained in a separate key for atomic INCR, and a
// short-lived claim lock (separate key) provides single-winner verification
// semantics without touching the challenge's own TTL.
type MFAStore struct {
	client *Client
}

// NewMFAStore builds an MFAStore backed by the given Client.
func NewMFAStore(client *Client) *MFAStore {
	return &MFAStore{client: client}
}

// Create stores an MFA challenge under the given token hash with the specified
// TTL. The mfaTokenHash must be the SHA-256 hex hash of the raw MFA token
// (produced by session.HashToken); the raw token must never reach Redis.
func (m *MFAStore) Create(
	ctx context.Context,
	mfaTokenHash string,
	data auth.MFAChallengeData,
	ttl time.Duration,
) error {
	if mfaTokenHash == "" {
		return errors.New("redis: mfa token hash must not be empty")
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis: encode mfa challenge: %w", err)
	}

	key := m.client.buildKey(mfaKeySegment, mfaTokenHash)
	if err := m.client.rdb.Set(ctx, key, payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis: set mfa challenge: %w", err)
	}
	return nil
}

// Get retrieves the MFA challenge for the given token hash. It returns
// auth.ErrMFAChallengeNotFound when no record exists.
func (m *MFAStore) Get(ctx context.Context, mfaTokenHash string) (auth.MFAChallengeData, error) {
	if mfaTokenHash == "" {
		return auth.MFAChallengeData{}, errors.New("redis: mfa token hash must not be empty")
	}

	key := m.client.buildKey(mfaKeySegment, mfaTokenHash)
	raw, err := m.client.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return auth.MFAChallengeData{}, auth.ErrMFAChallengeNotFound
		}
		return auth.MFAChallengeData{}, fmt.Errorf("redis: get mfa challenge: %w", err)
	}

	var data auth.MFAChallengeData
	if err := json.Unmarshal(raw, &data); err != nil {
		return auth.MFAChallengeData{}, fmt.Errorf("redis: decode mfa challenge: %w", err)
	}
	return data, nil
}

// Delete removes the MFA challenge and its attempt counter for the given token
// hash. It is idempotent: deleting non-existent keys is not an error.
func (m *MFAStore) Delete(ctx context.Context, mfaTokenHash string) error {
	if mfaTokenHash == "" {
		return errors.New("redis: mfa token hash must not be empty")
	}

	challengeKey := m.client.buildKey(mfaKeySegment, mfaTokenHash)
	attemptsKey := m.client.buildKey(mfaAttemptsKeySegment, mfaTokenHash)

	// Delete both keys in a single pipeline to reduce round-trips.
	pipe := m.client.rdb.Pipeline()
	pipe.Del(ctx, challengeKey)
	pipe.Del(ctx, attemptsKey)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis: delete mfa challenge: %w", err)
	}
	return nil
}

// IncrementAttempts atomically increments the attempt counter for an MFA
// challenge and returns the new count. The counter TTL is copied from the
// challenge's remaining TTL so the counter can never outlive the challenge.
//
// If the challenge no longer exists (expired or consumed), the function
// returns auth.ErrMFAChallengeNotFound without creating a counter, so a
// stale counter can never linger after its challenge.
//
// If the count exceeds maxAttempts, the function returns
// auth.ErrMFAMaxAttemptsExceeded along with the count. The caller should then
// consume the challenge and redirect the user to re-authenticate.
//
// Atomicity is ensured via a Lua script: the existence check, INCR and
// conditional PEXPIRE execute as a single Redis command with no race window.
func (m *MFAStore) IncrementAttempts(
	ctx context.Context,
	mfaTokenHash string,
	maxAttempts int,
) (int, error) {
	if mfaTokenHash == "" {
		return 0, errors.New("redis: mfa token hash must not be empty")
	}

	challengeKey := m.client.buildKey(mfaKeySegment, mfaTokenHash)
	attemptsKey := m.client.buildKey(mfaAttemptsKeySegment, mfaTokenHash)

	// Lua script:
	// 1. Fail (-1) if the challenge no longer exists, so a counter is never
	//    created for a dead challenge.
	// 2. INCR the counter key (creates it with value 1 if absent).
	// 3. Copy the challenge's remaining TTL to the counter (PTTL is positive
	//    because the challenge was just confirmed to exist).
	// 4. Return the count.
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

	result, err := script.Run(ctx, m.client.rdb,
		[]string{challengeKey, attemptsKey},
	).Int()
	if err != nil {
		return 0, fmt.Errorf("redis: increment mfa attempts: %w", err)
	}

	if result < 0 {
		return 0, auth.ErrMFAChallengeNotFound
	}
	if result > maxAttempts {
		return result, auth.ErrMFAMaxAttemptsExceeded
	}
	return result, nil
}

// Claim atomically reserves an MFA challenge for verification using a
// dedicated claim lock key ({prefix}mfa:claim:{hash}) with SET NX PX:
//
//   - If the lock is already held by another request, it returns
//     auth.ErrMFAChallengeClaimed.
//   - If the challenge does not exist (expired or consumed), the lock is
//     removed again and auth.ErrMFAChallengeNotFound is returned.
//   - Otherwise the caller becomes the sole owner of the challenge for up to
//     mfaClaimTTL, and the challenge data is returned unchanged.
//
// The challenge's own key and TTL are never modified: an expiring challenge
// keeps its original TTL and cannot be extended by claiming. The claimID is
// caller-generated (a random value); Release and Consume must present the
// same claimID to act on this lock.
//
// The lock acquisition and challenge read run in a single Lua script, so
// there is no race window.
func (m *MFAStore) Claim(ctx context.Context, mfaTokenHash, claimID string) (auth.MFAChallengeData, error) {
	if mfaTokenHash == "" {
		return auth.MFAChallengeData{}, errors.New("redis: mfa token hash must not be empty")
	}
	if claimID == "" {
		return auth.MFAChallengeData{}, errors.New("redis: mfa claim id must not be empty")
	}

	challengeKey := m.client.buildKey(mfaKeySegment, mfaTokenHash)
	claimKey := m.client.buildKey(mfaClaimKeySegment, mfaTokenHash)

	// Lua script:
	// 1. SET NX PX on the claim lock. nil means the lock is already held.
	// 2. Read the challenge. If absent, drop the lock and return nil.
	// 3. Return the challenge data; its TTL is untouched.
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

	result, err := script.Run(ctx, m.client.rdb,
		[]string{challengeKey, claimKey},
		claimID, mfaClaimTTL.Milliseconds(),
	).Result()
	if err != nil {
		if isClaimedError(err) {
			return auth.MFAChallengeData{}, auth.ErrMFAChallengeClaimed
		}
		if errors.Is(err, goredis.Nil) {
			return auth.MFAChallengeData{}, auth.ErrMFAChallengeNotFound
		}
		return auth.MFAChallengeData{}, fmt.Errorf("redis: claim mfa challenge: %w", err)
	}

	var data auth.MFAChallengeData
	if err := json.Unmarshal([]byte(result.(string)), &data); err != nil {
		return auth.MFAChallengeData{}, fmt.Errorf("redis: decode claimed mfa challenge: %w", err)
	}
	return data, nil
}

// Release removes the claim lock so the user can retry after a failed
// verification attempt. The lock is only removed when the given claimID still
// holds it; a stale owner (after lock expiry or takeover) cannot delete a
// newer lock. It returns auth.ErrMFAChallengeNotHeld when the claim ID no
// longer holds the lock, and nil when the lock was held and removed.
func (m *MFAStore) Release(ctx context.Context, mfaTokenHash, claimID string) error {
	if mfaTokenHash == "" {
		return errors.New("redis: mfa token hash must not be empty")
	}
	if claimID == "" {
		return errors.New("redis: mfa claim id must not be empty")
	}

	claimKey := m.client.buildKey(mfaClaimKeySegment, mfaTokenHash)

	// Lua script: delete the lock only if this claimID still owns it. The
	// challenge key is left untouched (its TTL is authoritative).
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

	result, err := script.Run(ctx, m.client.rdb, []string{claimKey}, claimID).Int()
	if err != nil {
		return fmt.Errorf("redis: release mfa challenge: %w", err)
	}
	if result == 0 {
		return auth.ErrMFAChallengeNotHeld
	}
	return nil
}

// Consume atomically deletes the challenge, its attempt counter, and the
// claim lock, enforcing single-use semantics. After a successful MFA
// verification (or when the challenge has expired), the challenge must be
// consumed so the same token cannot be replayed. This is a security
// requirement: a consumed challenge cannot be reused even if the token is
// intercepted. See ADR-0002 section 7.
//
// The caller must hold the claim lock for this challenge (the claimID must
// match). It returns auth.ErrMFAChallengeNotHeld when the lock is no longer
// held (expired or taken over), and auth.ErrMFAChallengeNotFound when the
// challenge is already gone. Either way nothing is created.
func (m *MFAStore) Consume(ctx context.Context, mfaTokenHash, claimID string) error {
	if mfaTokenHash == "" {
		return errors.New("redis: mfa token hash must not be empty")
	}
	if claimID == "" {
		return errors.New("redis: mfa claim id must not be empty")
	}

	challengeKey := m.client.buildKey(mfaKeySegment, mfaTokenHash)
	attemptsKey := m.client.buildKey(mfaAttemptsKeySegment, mfaTokenHash)
	claimKey := m.client.buildKey(mfaClaimKeySegment, mfaTokenHash)

	// Lua script: consume atomically — only the lock owner can consume, and
	// the challenge must still exist.
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

	result, err := script.Run(ctx, m.client.rdb,
		[]string{challengeKey, attemptsKey, claimKey},
		claimID,
	).Int()
	if err != nil {
		return fmt.Errorf("redis: consume mfa challenge: %w", err)
	}

	switch result {
	case 1:
		return nil
	case -1:
		return auth.ErrMFAChallengeNotFound
	default:
		return auth.ErrMFAChallengeNotHeld
	}
}

// isClaimedError reports whether a Redis error is the Lua error_reply marker
// returned when a claim lock is already held. go-redis surfaces custom error
// replies as errors whose message contains the reply text.
func isClaimedError(err error) bool {
	return strings.Contains(err.Error(), "CLAIMED")
}
