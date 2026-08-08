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

// enrollmentClaimTTL bounds how long a claim lock may be held. If the
// confirming request dies or the provider call hangs, the lock expires and
// the enrollment becomes confirmable again. 60s is ample for a provider
// round-trip while short enough to unblock retries quickly.
const enrollmentClaimTTL = 60 * time.Second

// EnrollmentStore persists single-use factor enrollment challenges (TOTP and
// passkey) in Redis using the frozen claim/consume lifecycle: the confirm
// step claims the challenge (single-winner lock), performs the provider
// verification, then either consumes the challenge (success, invalid
// code/attestation, binding mismatch) or releases the claim (transient
// provider failure). A provider outage therefore never permanently burns the
// user's enrollment. Redis loss only invalidates pending enrollments (fail
// closed); it can never bypass the reauth gate that precedes the begin step.
type EnrollmentStore struct {
	client *Client
}

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

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis: encode enrollment: %w", err)
	}

	key := s.client.buildKey(enrollmentKeySegment, tokenHash)
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
// terminal confirmation outcome (success, invalid code/attestation, binding
// mismatch); only transient provider failures release the claim instead.
func (s *EnrollmentStore) ConsumeEnrollment(ctx context.Context, tokenHash, claimID string) error {
	if tokenHash == "" {
		return errors.New("redis: enrollment token hash must not be empty")
	}
	if claimID == "" {
		return errors.New("redis: enrollment claim id must not be empty")
	}

	challengeKey := s.client.buildKey(enrollmentKeySegment, tokenHash)
	claimKey := s.client.buildKey(enrollmentClaimKeySegment, tokenHash)

	script := goredis.NewScript(`
local challengeKey = KEYS[1]
local claimKey = KEYS[2]
local claimID = ARGV[1]

if redis.call('GET', claimKey) ~= claimID then
	return 0
end

redis.call('DEL', challengeKey, claimKey)
return 1
`)

	result, err := script.Run(ctx, s.client.rdb,
		[]string{challengeKey, claimKey},
		claimID,
	).Int()
	if err != nil {
		return fmt.Errorf("redis: consume enrollment: %w", err)
	}
	if result == 0 {
		return auth.ErrEnrollmentNotHeld
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
