//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Redis store for security factor enrollment challenges
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

// enrollmentKeySegment is the key segment for factor enrollment challenges:
// {prefix}enrollment:{sha256(enrollmentToken)}. Raw tokens never reach
// Redis; only their SHA-256 hashes are used as keys (ADR-0006 §7).
const enrollmentKeySegment = "enrollment:"

// enrollmentClaimKeySegment is the key segment for the enrollment claim
// lock: {prefix}enrollment:claim:{sha256(enrollmentToken)}. The lock holds a
// random claim ID (SET NX PX) granting exclusive confirmation rights to one
// request, exactly mirroring the frozen MFA/reauth claim/consume pattern
// (ADR-0006 §7). The challenge's own key and TTL are never modified by
// claim/release.
const enrollmentClaimKeySegment = "enrollment:claim:"

// Passkey cleanup records outlive the browser-facing challenge so an
// abandoned provider registration still has an eventual settlement path.
// The sorted-set member is only the token hash; the separate record contains
// the non-secret user/target binding required by the worker (ADR-0008 §7).
const (
	enrollmentCleanupKeySegment = "enrollment:cleanup:"
	enrollmentCleanupIndexKey   = "enrollment:cleanup-index"
)

// enrollmentClaimTTL bounds how long a claim lock may be held. If the
// confirming request dies or the provider call hangs, the lock expires and
// the enrollment becomes confirmable again. 60s is ample for a provider
// round-trip while short enough to unblock retries quickly.
const enrollmentClaimTTL = 60 * time.Second

// enrollmentCleanupLeaseTTL prevents two workers from settling the same
// registration concurrently. A crashed worker leaves the item eligible again
// after the lease; provider operations are bounded to a shorter deadline.
const enrollmentCleanupLeaseTTL = 45 * time.Second

// EnrollmentStore persists single-use factor enrollment challenges (TOTP and
// passkey) in Redis using the frozen claim/consume lifecycle: the confirm
// step claims the challenge (single-winner lock), performs the provider
// verification, then consumes confirmed/TOTP outcomes, preserves passkey
// cleanup work for abandoned/invalid ceremonies, or releases the claim on a
// transient provider failure. Redis loss only invalidates pending enrollments
// (fail closed); it can never bypass the reauth gate before begin.
type EnrollmentStore struct {
	client *Client
}

var createPasskeyEnrollmentScript = goredis.NewScript(`
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SET', KEYS[2], ARGV[3])
redis.call('ZADD', KEYS[3], ARGV[4], ARGV[5])
return 1
`)

// NewEnrollmentStore builds an EnrollmentStore backed by the given Client.
func NewEnrollmentStore(client *Client) *EnrollmentStore {
	return &EnrollmentStore{client: client}
}

// CreateEnrollment stores an enrollment challenge under the given token hash
// with the specified TTL. The tokenHash must be the SHA-256 hex hash of the
// raw enrollment token; the raw token must never reach Redis.
func (s *EnrollmentStore) CreateEnrollment(
	ctx context.Context,
	tokenHash string,
	data auth.EnrollmentData,
	ttl time.Duration,
) error {
	if tokenHash == "" {
		return errors.New("redis: enrollment token hash must not be empty")
	}
	if data.SecurityEpoch < 1 {
		return errors.New("redis: enrollment missing security epoch stamp")
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis: encode enrollment: %w", err)
	}

	key := s.client.buildKey(enrollmentKeySegment, tokenHash)
	if data.Kind == auth.EnrollmentPasskey {
		if data.Target == "" {
			return errors.New("redis: passkey enrollment missing cleanup target")
		}
		cleanup := auth.ExpiredPasskeyEnrollment{
			TokenHash: tokenHash,
			UserID:    data.UserID,
			Target:    data.Target,
			CreatedAt: time.Now().UTC(),
		}
		cleanupPayload, err := json.Marshal(cleanup)
		if err != nil {
			return fmt.Errorf("redis: encode passkey enrollment cleanup: %w", err)
		}
		cleanupKey := s.client.buildKey(enrollmentCleanupKeySegment, tokenHash)
		indexKey := s.client.buildKey(enrollmentCleanupIndexKey)
		expiresAt := time.Now().Add(ttl).UnixMilli()
		if _, err := createPasskeyEnrollmentScript.Run(ctx, s.client.rdb,
			[]string{key, cleanupKey, indexKey},
			payload, ttl.Milliseconds(), cleanupPayload, expiresAt, tokenHash,
		).Result(); err != nil {
			return fmt.Errorf("redis: create passkey enrollment: %w", err)
		}
		return nil
	}
	if err := s.client.rdb.Set(ctx, key, payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis: set enrollment: %w", err)
	}
	return nil
}

// ClaimEnrollment atomically reserves an enrollment challenge for
// confirmation using a dedicated claim lock key with SET NX PX:
//
//   - If the lock is already held by another request, it returns
//     auth.ErrEnrollmentClaimed (single-winner confirmation).
//   - If the challenge does not exist (expired, consumed or never minted),
//     the lock is dropped again and auth.ErrEnrollmentNotFound is returned.
//   - Otherwise the caller becomes the sole owner of the challenge for up to
//     enrollmentClaimTTL, and the challenge data is returned unchanged.
//
// The challenge's own key and TTL are never modified: an expiring challenge
// keeps its original TTL and cannot be extended by claiming. The claimID is
// caller-generated (a random value); ReleaseEnrollment and ConsumeEnrollment
// must present the same claimID to act on this lock. The lock acquisition
// and challenge read run in a single Lua script, so there is no race window.
func (s *EnrollmentStore) ClaimEnrollment(ctx context.Context, tokenHash, claimID string) (auth.EnrollmentData, error) {
	if tokenHash == "" {
		return auth.EnrollmentData{}, errors.New("redis: enrollment token hash must not be empty")
	}
	if claimID == "" {
		return auth.EnrollmentData{}, errors.New("redis: enrollment claim id must not be empty")
	}

	challengeKey := s.client.buildKey(enrollmentKeySegment, tokenHash)
	claimKey := s.client.buildKey(enrollmentClaimKeySegment, tokenHash)

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
		claimID, enrollmentClaimTTL.Milliseconds(),
	).Result()
	if err != nil {
		if isEnrollmentClaimedError(err) {
			return auth.EnrollmentData{}, auth.ErrEnrollmentClaimed
		}
		if errors.Is(err, goredis.Nil) {
			return auth.EnrollmentData{}, auth.ErrEnrollmentNotFound
		}
		return auth.EnrollmentData{}, fmt.Errorf("redis: claim enrollment: %w", err)
	}

	var data auth.EnrollmentData
	if err := json.Unmarshal([]byte(result.(string)), &data); err != nil {
		return auth.EnrollmentData{}, fmt.Errorf("redis: decode claimed enrollment: %w", err)
	}
	if data.SecurityEpoch < 1 {
		// Legacy pre-ADR-0007 decode normalization (F2): absent stamp
		// means generation 1.
		data.SecurityEpoch = 1
	}
	return data, nil
}

// ReleaseEnrollment removes the claim lock so the confirmation can be
// retried after a transient provider failure. The lock is only removed when
// the given claimID still holds it; a stale owner (after lock expiry or
// takeover) cannot delete a newer lock. The challenge itself is left
// untouched (its TTL is authoritative). It returns auth.ErrEnrollmentNotHeld
// when the claim ID no longer holds the lock.
func (s *EnrollmentStore) ReleaseEnrollment(ctx context.Context, tokenHash, claimID string) error {
	if tokenHash == "" {
		return errors.New("redis: enrollment token hash must not be empty")
	}
	if claimID == "" {
		return errors.New("redis: enrollment claim id must not be empty")
	}

	claimKey := s.client.buildKey(enrollmentClaimKeySegment, tokenHash)

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
		return fmt.Errorf("redis: release enrollment: %w", err)
	}
	if result == 0 {
		return auth.ErrEnrollmentNotHeld
	}
	return nil
}

// ConsumeEnrollment permanently deletes the enrollment challenge and its
// claim lock, enforcing single-use semantics. The caller must hold the claim
// lock (the claimID must match); exactly one confirmation of a given
// enrollment ever succeeds permanently. It returns auth.ErrEnrollmentNotHeld
// when the lock is no longer held. Consumption is mandatory for every
// confirmed registration or terminal TOTP outcome. Passkey abandonment uses
// AbandonEnrollment so provider cleanup remains scheduled.
func (s *EnrollmentStore) ConsumeEnrollment(ctx context.Context, tokenHash, claimID string) error {
	if tokenHash == "" {
		return errors.New("redis: enrollment token hash must not be empty")
	}
	if claimID == "" {
		return errors.New("redis: enrollment claim id must not be empty")
	}

	challengeKey := s.client.buildKey(enrollmentKeySegment, tokenHash)
	claimKey := s.client.buildKey(enrollmentClaimKeySegment, tokenHash)
	cleanupKey := s.client.buildKey(enrollmentCleanupKeySegment, tokenHash)
	indexKey := s.client.buildKey(enrollmentCleanupIndexKey)

	script := goredis.NewScript(`
local challengeKey = KEYS[1]
local claimKey = KEYS[2]
local cleanupKey = KEYS[3]
local indexKey = KEYS[4]
local claimID = ARGV[1]
local tokenHash = ARGV[2]

if redis.call('GET', claimKey) ~= claimID then
	return 0
end

redis.call('DEL', challengeKey, claimKey, cleanupKey)
redis.call('ZREM', indexKey, tokenHash)
return 1
`)

	result, err := script.Run(ctx, s.client.rdb,
		[]string{challengeKey, claimKey, cleanupKey, indexKey},
		claimID, tokenHash,
	).Int()
	if err != nil {
		return fmt.Errorf("redis: consume enrollment: %w", err)
	}
	if result == 0 {
		return auth.ErrEnrollmentNotHeld
	}
	return nil
}

// AbandonEnrollment consumes the browser capability while preserving and
// immediately scheduling the passkey cleanup work item. The caller must hold
// the enrollment claim. It is used for browser cancellation, invalid
// attestation and other terminal outcomes where provider pending state may
// remain (ADR-0008 §7).
func (s *EnrollmentStore) AbandonEnrollment(ctx context.Context, tokenHash, claimID string) error {
	if tokenHash == "" {
		return errors.New("redis: enrollment token hash must not be empty")
	}
	if claimID == "" {
		return errors.New("redis: enrollment claim id must not be empty")
	}

	challengeKey := s.client.buildKey(enrollmentKeySegment, tokenHash)
	claimKey := s.client.buildKey(enrollmentClaimKeySegment, tokenHash)
	cleanupKey := s.client.buildKey(enrollmentCleanupKeySegment, tokenHash)
	indexKey := s.client.buildKey(enrollmentCleanupIndexKey)

	script := goredis.NewScript(`
if redis.call('GET', KEYS[2]) ~= ARGV[1] then
	return 0
end
redis.call('DEL', KEYS[1], KEYS[2])
if redis.call('EXISTS', KEYS[3]) == 1 then
	redis.call('ZADD', KEYS[4], ARGV[2], ARGV[3])
end
return 1
`)
	result, err := script.Run(ctx, s.client.rdb,
		[]string{challengeKey, claimKey, cleanupKey, indexKey},
		claimID, time.Now().UnixMilli(), tokenHash,
	).Int()
	if err != nil {
		return fmt.Errorf("redis: abandon enrollment: %w", err)
	}
	if result == 0 {
		return auth.ErrEnrollmentNotHeld
	}
	return nil
}

// ClaimExpiredPasskeyEnrollments leases up to limit due cleanup work items.
// A live challenge or enrollment claim always wins and is skipped. Leased
// items stay indexed with a future score so a worker crash becomes retryable.
func (s *EnrollmentStore) ClaimExpiredPasskeyEnrollments(ctx context.Context, limit int) ([]auth.ExpiredPasskeyEnrollment, error) {
	if limit <= 0 {
		limit = 100
	}
	indexKey := s.client.buildKey(enrollmentCleanupIndexKey)
	challengePrefix := s.client.buildKey(enrollmentKeySegment)
	claimPrefix := s.client.buildKey(enrollmentClaimKeySegment)
	cleanupPrefix := s.client.buildKey(enrollmentCleanupKeySegment)
	now := time.Now()

	script := goredis.NewScript(`
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, ARGV[4])
local claimed = {}
for _, tokenHash in ipairs(members) do
	if #claimed >= tonumber(ARGV[3]) then
		break
	end
	local challengeKey = KEYS[2] .. tokenHash
	local claimKey = KEYS[3] .. tokenHash
	local cleanupKey = KEYS[4] .. tokenHash
	if redis.call('EXISTS', cleanupKey) == 0 then
		redis.call('ZREM', KEYS[1], tokenHash)
	elseif redis.call('EXISTS', challengeKey) == 0 and redis.call('EXISTS', claimKey) == 0 then
		local payload = redis.call('GET', cleanupKey)
		redis.call('ZADD', KEYS[1], ARGV[2], tokenHash)
		table.insert(claimed, tokenHash .. '\n' .. payload)
	end
end
return claimed
`)
	result, err := script.Run(ctx, s.client.rdb,
		[]string{indexKey, challengePrefix, claimPrefix, cleanupPrefix},
		now.UnixMilli(), now.Add(enrollmentCleanupLeaseTTL).UnixMilli(), limit, limit*10,
	).StringSlice()
	if err != nil {
		return nil, fmt.Errorf("redis: claim expired passkey enrollments: %w", err)
	}
	entries := make([]auth.ExpiredPasskeyEnrollment, 0, len(result))
	for _, member := range result {
		separator := strings.IndexByte(member, '\n')
		if separator < 1 {
			continue
		}
		var entry auth.ExpiredPasskeyEnrollment
		if err := json.Unmarshal([]byte(member[separator+1:]), &entry); err != nil {
			continue
		}
		entry.TokenHash = member[:separator]
		entries = append(entries, entry)
	}
	return entries, nil
}

// CompletePasskeyEnrollmentCleanup removes a successfully settled work item.
func (s *EnrollmentStore) CompletePasskeyEnrollmentCleanup(ctx context.Context, tokenHash string) error {
	if tokenHash == "" {
		return errors.New("redis: enrollment token hash must not be empty")
	}
	cleanupKey := s.client.buildKey(enrollmentCleanupKeySegment, tokenHash)
	indexKey := s.client.buildKey(enrollmentCleanupIndexKey)
	script := goredis.NewScript(`
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[1])
return 1
`)
	if _, err := script.Run(ctx, s.client.rdb, []string{cleanupKey, indexKey}, tokenHash).Result(); err != nil {
		return fmt.Errorf("redis: complete passkey enrollment cleanup: %w", err)
	}
	return nil
}

// RequeuePasskeyEnrollmentCleanup records the next capped-backoff attempt and
// moves the cleanup lease to its next due time atomically.
func (s *EnrollmentStore) RequeuePasskeyEnrollmentCleanup(ctx context.Context, entry auth.ExpiredPasskeyEnrollment, delay time.Duration) error {
	if entry.TokenHash == "" {
		return errors.New("redis: enrollment token hash must not be empty")
	}
	if delay < 0 {
		delay = 0
	}
	entry.Attempts++
	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("redis: encode passkey cleanup retry: %w", err)
	}
	cleanupKey := s.client.buildKey(enrollmentCleanupKeySegment, entry.TokenHash)
	indexKey := s.client.buildKey(enrollmentCleanupIndexKey)
	script := goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
	return 0
end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('ZADD', KEYS[2], ARGV[2], ARGV[3])
return 1
`)
	if _, err := script.Run(ctx, s.client.rdb, []string{cleanupKey, indexKey},
		payload, time.Now().Add(delay).UnixMilli(), entry.TokenHash,
	).Result(); err != nil {
		return fmt.Errorf("redis: requeue passkey enrollment cleanup: %w", err)
	}
	return nil
}

// isEnrollmentClaimedError reports whether a Redis error is the Lua
// error_reply marker returned when a claim lock is already held. go-redis
// surfaces custom error replies as errors whose message contains the reply
// text.
func isEnrollmentClaimedError(err error) bool {
	return strings.Contains(err.Error(), "CLAIMED")
}
