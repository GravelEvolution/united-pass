//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Redis session store (hashed tokens only)
//

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// sessionKeySegment is the key segment placed between the namespace prefix and
// the token hash. The full key is: {prefix}session:{sha256(token)}.
const sessionKeySegment = "session:"

// SessionStore implements session persistence using Redis. The raw session
// token is never stored — only its SHA-256 hash is used as the Redis key.
// SessionRecord values are JSON-encoded with a TTL. See ADR-0002 section 3.
type SessionStore struct {
	client *Client
}

// NewSessionStore builds a SessionStore backed by the given Client.
func NewSessionStore(client *Client) *SessionStore {
	return &SessionStore{client: client}
}

// Create stores a session record under the given token hash with the specified
// TTL. The tokenHash must be the SHA-256 hex hash of the raw session token
// (produced by session.HashToken); the raw token must never reach Redis. If a
// record already exists for the hash it is overwritten — callers must ensure
// token hashes are unique by generating tokens from crypto/rand.
func (s *SessionStore) Create(
	ctx context.Context,
	tokenHash string,
	record session.SessionRecord,
	ttl time.Duration,
) error {
	if tokenHash == "" {
		return errors.New("redis: session token hash must not be empty")
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("redis: encode session record: %w", err)
	}

	key := s.client.buildKey(sessionKeySegment, tokenHash)
	if err := s.client.rdb.Set(ctx, key, payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis: set session: %w", err)
	}
	return nil
}

// Get retrieves the session record for the given token hash. It returns
// session.ErrSessionNotFound when no record exists, including when Redis
// returns redis.Nil for a missing or expired key.
func (s *SessionStore) Get(ctx context.Context, tokenHash string) (session.SessionRecord, error) {
	if tokenHash == "" {
		return session.SessionRecord{}, errors.New("redis: session token hash must not be empty")
	}

	key := s.client.buildKey(sessionKeySegment, tokenHash)
	raw, err := s.client.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return session.SessionRecord{}, session.ErrSessionNotFound
		}
		return session.SessionRecord{}, fmt.Errorf("redis: get session: %w", err)
	}

	var record session.SessionRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return session.SessionRecord{}, fmt.Errorf("redis: decode session record: %w", err)
	}
	return record, nil
}

// Delete removes the session record for the given token hash. It is idempotent:
// deleting a non-existent key is not an error, so callers do not need to check
// existence before calling Delete.
func (s *SessionStore) Delete(ctx context.Context, tokenHash string) error {
	if tokenHash == "" {
		return errors.New("redis: session token hash must not be empty")
	}

	key := s.client.buildKey(sessionKeySegment, tokenHash)
	if err := s.client.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis: delete session: %w", err)
	}
	return nil
}

// Touch updates the LastSeenAt field of the session record and refreshes its
// TTL. It fetches, updates, and re-stores the record. If the session no longer
// exists, it returns session.ErrSessionNotFound so the caller can invalidate
// the browser cookie.
//
// This is a read-modify-write operation and is not atomic. Concurrent Touch
// calls on the same session could lose a LastSeenAt update, but this is
// acceptable because LastSeenAt is a best-effort idle-tracking field, not a
// security-critical value. See ADR-0002 section 9.
func (s *SessionStore) Touch(
	ctx context.Context,
	tokenHash string,
	lastSeenAt time.Time,
	ttl time.Duration,
) error {
	if tokenHash == "" {
		return errors.New("redis: session token hash must not be empty")
	}

	key := s.client.buildKey(sessionKeySegment, tokenHash)

	raw, err := s.client.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return session.ErrSessionNotFound
		}
		return fmt.Errorf("redis: touch session get: %w", err)
	}

	var record session.SessionRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("redis: touch session decode: %w", err)
	}

	record.LastSeenAt = lastSeenAt

	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("redis: touch session encode: %w", err)
	}

	if err := s.client.rdb.Set(ctx, key, payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis: touch session set: %w", err)
	}
	return nil
}

// Rotate replaces the session stored under oldTokenHash with a new record
// stored under newTokenHash. The new record is created before the old one is
// deleted, so a failure between the two operations leaves the user with a
// valid session (the old one) rather than none.
//
// This operation is NOT atomic — a brief window exists where both sessions are
// valid. This is acceptable for session rotation because the old session is
// revoked as soon as the delete succeeds, and the window is sub-millisecond
// under normal conditions. See ADR-0002 section 7.
func (s *SessionStore) Rotate(
	ctx context.Context,
	oldTokenHash string,
	newTokenHash string,
	newRecord session.SessionRecord,
	newTTL time.Duration,
) error {
	if oldTokenHash == "" {
		return errors.New("redis: old session token hash must not be empty")
	}
	if newTokenHash == "" {
		return errors.New("redis: new session token hash must not be empty")
	}

	// Create the new session first so a failure does not leave the user
	// without any session.
	if err := s.Create(ctx, newTokenHash, newRecord, newTTL); err != nil {
		return fmt.Errorf("redis: rotate create new: %w", err)
	}

	// Delete the old session. A failure here leaves a stale session that will
	// expire naturally via TTL; it does not compromise the new session.
	if err := s.Delete(ctx, oldTokenHash); err != nil {
		return fmt.Errorf("redis: rotate delete old: %w", err)
	}
	return nil
}
