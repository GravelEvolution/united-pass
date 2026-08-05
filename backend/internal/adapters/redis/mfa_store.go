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

// MFAStore implements MFA challenge persistence using Redis. Challenges are
// short-lived, single-use records keyed by the SHA-256 hash of the MFA token.
// An attempt counter is maintained in a separate key for atomic INCR.
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
// New challenges are created in the MFAStateAvailable state.
func (m *MFAStore) Create(
	ctx context.Context,
	mfaTokenHash string,
	data auth.MFAChallengeData,
	ttl time.Duration,
) error {
	if mfaTokenHash == "" {
		return errors.New("redis: mfa token hash must not be empty")
	}

	data.State = auth.MFAStateAvailable

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
// challenge and returns the new count. On the first increment (when the
// counter key does not exist), the TTL is set to match the challenge key's
// remaining TTL so the counter does not outlive the challenge.
//
// If the count exceeds maxAttempts, the function returns
// auth.ErrMFAMaxAttemptsExceeded along with the count. The caller should then
// consume (delete) the challenge and redirect the user to re-authenticate.
//
// Atomicity is ensured via a Lua script: INCR and conditional PEXPIRE execute
// as a single Redis command with no race window.
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
	// 1. INCR the counter key (creates it with value 1 if absent).
	// 2. If this is the first increment, copy the TTL from the challenge key
	//    so the counter expires when the challenge does.
	// 3. Return the count.
	script := goredis.NewScript(`
local challengeKey = KEYS[1]
local attemptsKey  = KEYS[2]

local count = redis.call('INCR', attemptsKey)
if count == 1 then
	local ttl = redis.call('PTTL', challengeKey)
	if ttl > 0 then
		redis.call('PEXPIRE', attemptsKey, ttl)
	end
end
return count
`)

	result, err := script.Run(ctx, m.client.rdb,
		[]string{challengeKey, attemptsKey},
	).Int()
	if err != nil {
		return 0, fmt.Errorf("redis: increment mfa attempts: %w", err)
	}

	if result > maxAttempts {
		return result, auth.ErrMFAMaxAttemptsExceeded
	}
	return result, nil
}

// mfaProcessingTTL is the short TTL applied when a challenge is claimed for
// verification. A claim that never completes (e.g. the provider call hangs)
// expires quickly so the user can start a fresh login instead of being blocked
// on a permanently processing challenge.
const mfaProcessingTTL = 60 * time.Second

// Claim atomically reserves an MFA challenge for verification. Only one
// concurrent request can claim a given challenge:
//
//   - If the challenge does not exist (expired or consumed), it returns
//     auth.ErrMFAChallengeNotFound.
//   - If another request already claimed it, it returns
//     auth.ErrMFAChallengeClaimed.
//   - Otherwise it transitions the challenge to MFAStateProcessing, shortens
//     its TTL to mfaProcessingTTL, and returns the challenge data.
//
// Claim is a single Lua script, so there is no race window between the
// existence check, the state transition, and the TTL update.
func (m *MFAStore) Claim(ctx context.Context, mfaTokenHash string) (auth.MFAChallengeData, error) {
	if mfaTokenHash == "" {
		return auth.MFAChallengeData{}, errors.New("redis: mfa token hash must not be empty")
	}

	key := m.client.buildKey(mfaKeySegment, mfaTokenHash)

	// Lua script: read the challenge, fail if absent or already claimed,
	// otherwise mark it processing and shorten its TTL.
	script := goredis.NewScript(`
local key = KEYS[1]
local processingTTL = tonumber(ARGV[1])

local data = redis.call('GET', key)
if not data then
	return nil
end

local obj = cjson.decode(data)
if obj.state == 'processing' then
	return redis.error_reply('CLAIMED')
end

obj.state = 'processing'
local encoded = cjson.encode(obj)
redis.call('SET', key, encoded)
redis.call('PEXPIRE', key, processingTTL)
return encoded
`)

	result, err := script.Run(ctx, m.client.rdb, []string{key}, mfaProcessingTTL.Milliseconds()).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return auth.MFAChallengeData{}, auth.ErrMFAChallengeNotFound
		}
		if isClaimedError(err) {
			return auth.MFAChallengeData{}, auth.ErrMFAChallengeClaimed
		}
		return auth.MFAChallengeData{}, fmt.Errorf("redis: claim mfa challenge: %w", err)
	}

	var data auth.MFAChallengeData
	if err := json.Unmarshal([]byte(result.(string)), &data); err != nil {
		return auth.MFAChallengeData{}, fmt.Errorf("redis: decode claimed mfa challenge: %w", err)
	}
	return data, nil
}

// Release returns a claimed challenge to the available state so the user can
// retry after a failed verification attempt. It returns
// auth.ErrMFAChallengeNotFound when the challenge no longer exists. Release
// is atomic: the state transition happens in a single Lua script.
func (m *MFAStore) Release(ctx context.Context, mfaTokenHash string) error {
	if mfaTokenHash == "" {
		return errors.New("redis: mfa token hash must not be empty")
	}

	key := m.client.buildKey(mfaKeySegment, mfaTokenHash)

	// Lua script: flip the state back to available without touching the
	// attempt counter (which lives in a separate key).
	script := goredis.NewScript(`
local key = KEYS[1]

local data = redis.call('GET', key)
if not data then
	return nil
end

local obj = cjson.decode(data)
obj.state = 'available'
local encoded = cjson.encode(obj)
redis.call('SET', key, encoded)
return encoded
`)

	_, err := script.Run(ctx, m.client.rdb, []string{key}).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return auth.ErrMFAChallengeNotFound
		}
		return fmt.Errorf("redis: release mfa challenge: %w", err)
	}
	return nil
}

// Consume deletes the MFA challenge and its attempt counter, enforcing
// single-use semantics. After a successful MFA verification (or when the
// challenge has expired), the challenge must be consumed so the same token
// cannot be replayed. This is a security requirement: a consumed challenge
// cannot be reused even if the token is intercepted. See ADR-0002 section 7.
//
// Consume is atomic: the existence check and the deletion run in a single
// Lua script. It returns auth.ErrMFAChallengeNotFound when the challenge is
// already gone (already consumed or expired).
func (m *MFAStore) Consume(ctx context.Context, mfaTokenHash string) error {
	if mfaTokenHash == "" {
		return errors.New("redis: mfa token hash must not be empty")
	}

	challengeKey := m.client.buildKey(mfaKeySegment, mfaTokenHash)
	attemptsKey := m.client.buildKey(mfaAttemptsKeySegment, mfaTokenHash)

	script := goredis.NewScript(`
local challengeKey = KEYS[1]
local attemptsKey  = KEYS[2]

if redis.call('EXISTS', challengeKey) == 0 then
	return 0
end

redis.call('DEL', challengeKey, attemptsKey)
return 1
`)

	result, err := script.Run(ctx, m.client.rdb, []string{challengeKey, attemptsKey}).Int()
	if err != nil {
		return fmt.Errorf("redis: consume mfa challenge: %w", err)
	}
	if result == 0 {
		return auth.ErrMFAChallengeNotFound
	}
	return nil
}

// isClaimedError reports whether a Redis error is the Lua error_reply marker
// returned when a challenge is already processing. go-redis surfaces custom
// error replies as errors whose message contains the reply text.
func isClaimedError(err error) bool {
	return strings.Contains(err.Error(), "CLAIMED")
}
