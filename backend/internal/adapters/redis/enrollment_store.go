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
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
)

// enrollmentKeySegment is the key segment for factor enrollment challenges:
// {prefix}enrollment:{sha256(enrollmentToken)}. Raw tokens never reach
// Redis; only their SHA-256 hashes are used as keys (ADR-0006 §7).
const enrollmentKeySegment = "enrollment:"

// EnrollmentStore persists single-use factor enrollment challenges (TOTP and
// passkey) in Redis. Enrollments follow the reauth grant pattern: created
// with a TTL at the begin step and consumed atomically (single-winner) at
// the confirm step, so the confirm needs no second reauthentication ceremony
// and a consumed token can never be replayed. Redis loss only invalidates
// pending enrollments (fail closed); it can never bypass the reauth gate
// that precedes the begin step.
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

// ConsumeEnrollment atomically reads and deletes an enrollment challenge
// (single-winner, single-use). It returns the enrollment data or
// auth.ErrEnrollmentNotFound when the challenge expired, was already
// consumed, or never existed. Exactly one concurrent consumer ever receives
// a given enrollment, so a double confirmation race has a single winner.
func (s *EnrollmentStore) ConsumeEnrollment(ctx context.Context, tokenHash string) (auth.EnrollmentData, error) {
	if tokenHash == "" {
		return auth.EnrollmentData{}, errors.New("redis: enrollment token hash must not be empty")
	}

	key := s.client.buildKey(enrollmentKeySegment, tokenHash)

	// GETDEL is atomic: exactly one concurrent consumer receives the value.
	raw, err := s.client.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return auth.EnrollmentData{}, auth.ErrEnrollmentNotFound
		}
		return auth.EnrollmentData{}, fmt.Errorf("redis: consume enrollment: %w", err)
	}

	var data auth.EnrollmentData
	if err := json.Unmarshal(raw, &data); err != nil {
		return auth.EnrollmentData{}, fmt.Errorf("redis: decode enrollment: %w", err)
	}
	return data, nil
}
