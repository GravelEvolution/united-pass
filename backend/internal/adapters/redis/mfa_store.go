package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// Consume deletes the MFA challenge and its attempt counter, enforcing
// single-use semantics. After a successful MFA verification, the challenge
// must be consumed so the same token cannot be replayed. This is a security
// requirement: a consumed challenge cannot be reused even if the token is
// intercepted. See ADR-0002 section 7.
func (m *MFAStore) Consume(ctx context.Context, mfaTokenHash string) error {
	return m.Delete(ctx, mfaTokenHash)
}
