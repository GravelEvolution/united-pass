//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Redis session store (hashed tokens, inventory index, locator)
//

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// Key segments. Full keys:
//
//	{prefix}session:{sha256(token)}          JSON SessionRecord (P1, unchanged)
//	{prefix}user_sessions:{userId}           ZSET member=SessionID score=effectiveExpiryUnixMilli (ADR-0006 §1)
//	{prefix}session_locator:{sessionId}      string: tokenHash (ADR-0006 §1)
//
// The delete script resolves the locator and index keys from the record
// contents at runtime, so it builds them from the prefix; the store targets
// a single Redis instance, never a cluster (ADR-0002 §8).
const (
	sessionKeySegment        = "session:"
	sessionIndexKeySegment   = "user_sessions:"
	sessionLocatorKeySegment = "session_locator:"
)

// SessionStore implements session persistence using Redis. The raw session
// token is never stored — only its SHA-256 hash is used as the Redis key.
// SessionRecord values are JSON-encoded with a TTL. See ADR-0002 section 3
// and ADR-0006 §1 for the session inventory layout.
//
// Multi-key invariants (record + index + locator) are maintained exclusively
// through Lua scripts, which Redis executes atomically. No bare pipelines are
// used for them (ADR-0006 §1 atomicity rule).
type SessionStore struct {
	client *Client
}

// NewSessionStore builds a SessionStore backed by the given Client.
func NewSessionStore(client *Client) *SessionStore {
	return &SessionStore{client: client}
}

// sessionCreateScript writes record + locator + index entry atomically and
// keeps the index key TTL aligned with the furthest effective expiry.
// KEYS: record, locator, index.
// ARGV: payload, ttlMs, tokenHash, sessionId, scoreMs, nowMs.
var sessionCreateScript = goredis.NewScript(`
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SET', KEYS[2], ARGV[3], 'PX', ARGV[2])
redis.call('ZADD', KEYS[3], ARGV[5], ARGV[4])
local pttl = redis.call('PTTL', KEYS[3])
if pttl == -1 or (tonumber(ARGV[5]) - tonumber(ARGV[6])) > pttl then
  redis.call('PEXPIREAT', KEYS[3], ARGV[5])
end
return 1
`)

// sessionDeleteScript removes record + locator + index entry atomically. The
// locator and index keys are derived from the record's sessionId/userId
// fields (known only at runtime). Returns 0 when the record is absent
// (idempotent). KEYS: record. ARGV: locatorKeyPrefix, indexKeyPrefix.
var sessionDeleteScript = goredis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 0
end
local rec = cjson.decode(raw)
redis.call('DEL', KEYS[1])
if rec.sessionId then
  redis.call('DEL', ARGV[1] .. rec.sessionId)
  if rec.userId then
    redis.call('ZREM', ARGV[2] .. rec.userId, rec.sessionId)
  end
end
return 1
`)

// sessionTouchScript persists the refreshed record, re-expires the locator
// and updates the index score atomically. Returns 0 when the record no
// longer exists (expired or revoked between Get and Touch).
// KEYS: record, locator, index.
// ARGV: payload, ttlMs, tokenHash, sessionId, scoreMs, nowMs.
var sessionTouchScript = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SET', KEYS[2], ARGV[3], 'PX', ARGV[2])
redis.call('ZADD', KEYS[3], ARGV[5], ARGV[4])
local pttl = redis.call('PTTL', KEYS[3])
if pttl == -1 or (tonumber(ARGV[5]) - tonumber(ARGV[6])) > pttl then
  redis.call('PEXPIREAT', KEYS[3], ARGV[5])
end
return 1
`)

// sessionRotateScript writes the new record, re-points the locator to the
// new token hash, deletes the old record and refreshes the index score, all
// atomically. The SessionID (index member) is unchanged.
// KEYS: oldRecord, newRecord, locator, index.
// ARGV: payload, ttlMs, newTokenHash, sessionId, scoreMs, nowMs.
var sessionRotateScript = goredis.NewScript(`
redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[2])
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[3], ARGV[3], 'PX', ARGV[2])
redis.call('ZADD', KEYS[4], ARGV[5], ARGV[4])
local pttl = redis.call('PTTL', KEYS[4])
if pttl == -1 or (tonumber(ARGV[5]) - tonumber(ARGV[6])) > pttl then
  redis.call('PEXPIREAT', KEYS[4], ARGV[5])
end
return 1
`)

// Create stores a session record, its user-index entry (score = the record's
// effective expiry, the single SessionRecord.EffectiveExpiry definition) and
// the SessionID locator atomically. The tokenHash must be the SHA-256 hex
// hash of the raw session token; the raw token must never reach Redis.
func (s *SessionStore) Create(
	ctx context.Context,
	tokenHash string,
	record session.SessionRecord,
	ttl, idleTTL time.Duration,
) error {
	if tokenHash == "" {
		return errors.New("redis: session token hash must not be empty")
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("redis: encode session record: %w", err)
	}

	now := time.Now()
	_, err = sessionCreateScript.Run(ctx, s.client.rdb,
		[]string{
			s.recordKey(tokenHash),
			s.locatorKey(record.SessionID),
			s.indexKey(record.UserID),
		},
		string(payload),
		ttl.Milliseconds(),
		tokenHash,
		string(record.SessionID),
		record.EffectiveExpiry(idleTTL).UnixMilli(),
		now.UnixMilli(),
	).Result()
	if err != nil {
		return fmt.Errorf("redis: create session: %w", err)
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

	key := s.recordKey(tokenHash)
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

// Delete removes the session record, its index entry and its locator
// atomically. It is idempotent: deleting a non-existent session is not an
// error, so callers do not need to check existence before calling Delete.
func (s *SessionStore) Delete(ctx context.Context, tokenHash string) error {
	if tokenHash == "" {
		return errors.New("redis: session token hash must not be empty")
	}
	return s.deleteByTokenHash(ctx, tokenHash)
}

// deleteByTokenHash runs the atomic delete script for one session.
func (s *SessionStore) deleteByTokenHash(ctx context.Context, tokenHash string) error {
	_, err := sessionDeleteScript.Run(ctx, s.client.rdb,
		[]string{s.recordKey(tokenHash)},
		s.client.buildKey(sessionLocatorKeySegment),
		s.client.buildKey(sessionIndexKeySegment),
	).Result()
	if err != nil {
		return fmt.Errorf("redis: delete session: %w", err)
	}
	return nil
}

// Touch persists the updated record (new LastSeenAt), re-expires the locator
// and refreshes the index member score atomically. The score is recomputed
// from SessionRecord.EffectiveExpiry — the single frozen definition. It
// returns session.ErrSessionNotFound when the record vanished between the
// caller's Get and Touch (expired or revoked).
func (s *SessionStore) Touch(
	ctx context.Context,
	tokenHash string,
	record session.SessionRecord,
	ttl, idleTTL time.Duration,
) error {
	if tokenHash == "" {
		return errors.New("redis: session token hash must not be empty")
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("redis: encode session record: %w", err)
	}

	now := time.Now()
	res, err := sessionTouchScript.Run(ctx, s.client.rdb,
		[]string{
			s.recordKey(tokenHash),
			s.locatorKey(record.SessionID),
			s.indexKey(record.UserID),
		},
		string(payload),
		ttl.Milliseconds(),
		tokenHash,
		string(record.SessionID),
		record.EffectiveExpiry(idleTTL).UnixMilli(),
		now.UnixMilli(),
	).Int()
	if err != nil {
		return fmt.Errorf("redis: touch session: %w", err)
	}
	if res == 0 {
		return session.ErrSessionNotFound
	}
	return nil
}

// Rotate replaces the record under oldTokenHash with newRecord under
// newTokenHash, re-points the locator and refreshes the index score, all in
// one atomic Lua script. The SessionID stays stable across rotation.
func (s *SessionStore) Rotate(
	ctx context.Context,
	oldTokenHash string,
	newTokenHash string,
	newRecord session.SessionRecord,
	newTTL, idleTTL time.Duration,
) error {
	if oldTokenHash == "" {
		return errors.New("redis: old session token hash must not be empty")
	}
	if newTokenHash == "" {
		return errors.New("redis: new session token hash must not be empty")
	}

	payload, err := json.Marshal(newRecord)
	if err != nil {
		return fmt.Errorf("redis: encode session record: %w", err)
	}

	now := time.Now()
	_, err = sessionRotateScript.Run(ctx, s.client.rdb,
		[]string{
			s.recordKey(oldTokenHash),
			s.recordKey(newTokenHash),
			s.locatorKey(newRecord.SessionID),
			s.indexKey(newRecord.UserID),
		},
		string(payload),
		newTTL.Milliseconds(),
		newTokenHash,
		string(newRecord.SessionID),
		newRecord.EffectiveExpiry(idleTTL).UnixMilli(),
		now.UnixMilli(),
	).Result()
	if err != nil {
		return fmt.Errorf("redis: rotate session: %w", err)
	}
	return nil
}

// GetBySessionID resolves a browser-supplied SessionID through the locator
// and returns the record only when it belongs to userID and is still live.
// Unknown, foreign, idle/absolute-expired or vanished sessions all yield
// session.ErrSessionNotFound — the responses never distinguish these cases
// (non-enumeration, ADR-0006 §1.4/§2). Expired records are cleaned up
// best-effort.
func (s *SessionStore) GetBySessionID(
	ctx context.Context,
	userID identity.UserID,
	sessionID session.SessionID,
	now time.Time,
	idleTTL time.Duration,
) (session.SessionRecord, error) {
	tokenHash, record, err := s.resolve(ctx, userID, sessionID)
	if err != nil {
		return session.SessionRecord{}, err
	}

	if record.IsExpired(now, idleTTL) {
		// Authoritative expiry replay (ADR-0006 §1): the index score is only
		// an inventory clock. Clean up and report not found.
		_ = s.deleteByTokenHash(ctx, tokenHash)
		return session.SessionRecord{}, session.ErrSessionNotFound
	}
	return record, nil
}

// DeleteBySessionID resolves like GetBySessionID and removes the session
// atomically (record + locator + index entry). Same non-enumerating error
// contract: unknown, foreign or already-expired sessions yield
// session.ErrSessionNotFound.
func (s *SessionStore) DeleteBySessionID(
	ctx context.Context,
	userID identity.UserID,
	sessionID session.SessionID,
) error {
	tokenHash, record, err := s.resolve(ctx, userID, sessionID)
	if err != nil {
		return err
	}
	// An expired target is indistinguishable from an unknown one; clean it up
	// and report not found rather than revoking a dead session.
	if record.IsExpired(time.Now(), 0) {
		_ = s.deleteByTokenHash(ctx, tokenHash)
		return session.ErrSessionNotFound
	}
	return s.deleteByTokenHash(ctx, tokenHash)
}

// resolve maps a SessionID through the locator to the record and enforces the
// ownership check. Every miss (no locator, no record, corrupt record, foreign
// owner) yields session.ErrSessionNotFound.
func (s *SessionStore) resolve(
	ctx context.Context,
	userID identity.UserID,
	sessionID session.SessionID,
) (string, session.SessionRecord, error) {
	if sessionID == "" {
		return "", session.SessionRecord{}, session.ErrSessionNotFound
	}

	tokenHash, err := s.client.rdb.Get(ctx, s.locatorKey(sessionID)).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return "", session.SessionRecord{}, session.ErrSessionNotFound
		}
		return "", session.SessionRecord{}, fmt.Errorf("redis: get session locator: %w", err)
	}

	record, err := s.Get(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			// Locator points at a vanished record: heal the stale locator.
			_ = s.client.rdb.Del(ctx, s.locatorKey(sessionID)).Err()
			_ = s.client.rdb.ZRem(ctx, s.indexKey(userID), string(sessionID)).Err()
		}
		return "", session.SessionRecord{}, session.ErrSessionNotFound
	}

	// Ownership is fail-closed and non-enumerating: foreign sessions look
	// identical to unknown ones.
	if record.UserID != userID || record.SessionID != sessionID {
		return "", session.SessionRecord{}, session.ErrSessionNotFound
	}
	return tokenHash, record, nil
}

// ListUserSessions returns the caller's live sessions with stale index
// entries self-healed (ADR-0006 §1 rule 7). Members whose effective expiry
// score has passed are dropped in bulk; survivors are replayed against the
// authoritative SessionRecord.IsExpired, and any record that is missing or
// expired is removed from the index. Results are ordered by creation time.
func (s *SessionStore) ListUserSessions(
	ctx context.Context,
	userID identity.UserID,
	now time.Time,
	idleTTL time.Duration,
) ([]session.SessionRecord, error) {
	indexKey := s.indexKey(userID)

	// Bulk-drop members whose effective expiry has passed. Redis deletes the
	// ZSET key automatically once it becomes empty.
	if err := s.client.rdb.ZRemRangeByScore(ctx, indexKey, "-inf", fmt.Sprint(now.UnixMilli())).Err(); err != nil {
		return nil, fmt.Errorf("redis: prune session index: %w", err)
	}

	members, err := s.client.rdb.ZRange(ctx, indexKey, 0, -1).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis: range session index: %w", err)
	}
	if len(members) == 0 {
		return nil, nil
	}

	locatorKeys := make([]string, len(members))
	for i, m := range members {
		locatorKeys[i] = s.locatorKey(session.SessionID(m))
	}
	tokenHashes, err := s.client.rdb.MGet(ctx, locatorKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: get session locators: %w", err)
	}

	recordKeys := make([]string, len(members))
	for i, v := range tokenHashes {
		if h, ok := v.(string); ok && h != "" {
			recordKeys[i] = s.recordKey(h)
		}
	}
	payloads, err := s.client.rdb.MGet(ctx, recordKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: get session records: %w", err)
	}

	records := make([]session.SessionRecord, 0, len(members))
	for i := range members {
		record, ok := decodePayload(payloads[i])
		if !ok || record.UserID != userID {
			// Stale or orphaned member: heal the index.
			_ = s.client.rdb.ZRem(ctx, indexKey, members[i]).Err()
			continue
		}
		if record.IsExpired(now, idleTTL) {
			// Authoritative expiry replay: drop the member and its keys.
			_ = s.client.rdb.ZRem(ctx, indexKey, members[i]).Err()
			if h, ok := tokenHashes[i].(string); ok && h != "" {
				_ = s.deleteByTokenHash(ctx, h)
			}
			continue
		}
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].SessionID < records[j].SessionID
		}
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
	return records, nil
}

// RevokeAllOtherSessions removes every session of userID except
// currentSessionID. It walks only the caller's own ZSET (never KEYS/SCAN)
// and never touches the current session's keys. It returns the removed
// records (for best-effort provider revocation) and the revoked count.
func (s *SessionStore) RevokeAllOtherSessions(
	ctx context.Context,
	userID identity.UserID,
	currentSessionID session.SessionID,
) ([]session.SessionRecord, int, error) {
	indexKey := s.indexKey(userID)

	members, err := s.client.rdb.ZRange(ctx, indexKey, 0, -1).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("redis: range session index: %w", err)
	}

	victims := make([]session.SessionRecord, 0, len(members))
	for _, m := range members {
		sessionID := session.SessionID(m)
		// Never revoke the caller's current session.
		if sessionID == currentSessionID {
			continue
		}

		tokenHash, record, err := s.resolve(ctx, userID, sessionID)
		if err != nil {
			if errors.Is(err, session.ErrSessionNotFound) {
				// Already gone or foreign-corrupted: heal the index entry.
				_ = s.client.rdb.ZRem(ctx, indexKey, m).Err()
			}
			continue
		}
		if record.IsExpired(time.Now(), 0) {
			// Past its absolute deadline: cleanup only, not a revocation.
			_ = s.deleteByTokenHash(ctx, tokenHash)
			continue
		}
		if err := s.deleteByTokenHash(ctx, tokenHash); err != nil {
			return victims, len(victims), err
		}
		victims = append(victims, record)
	}
	return victims, len(victims), nil
}

// decodePayload decodes one MGET slot into a SessionRecord. Missing (nil)
// or corrupt payloads report ok=false.
func decodePayload(v any) (session.SessionRecord, bool) {
	raw, ok := v.(string)
	if !ok || raw == "" {
		return session.SessionRecord{}, false
	}
	var record session.SessionRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return session.SessionRecord{}, false
	}
	return record, true
}

// recordKey builds the session record key: {prefix}session:{tokenHash}.
func (s *SessionStore) recordKey(tokenHash string) string {
	return s.client.buildKey(sessionKeySegment, tokenHash)
}

// locatorKey builds the SessionID locator key: {prefix}session_locator:{sessionId}.
func (s *SessionStore) locatorKey(sessionID session.SessionID) string {
	return s.client.buildKey(sessionLocatorKeySegment, string(sessionID))
}

// indexKey builds the per-user inventory ZSET key: {prefix}user_sessions:{userId}.
func (s *SessionStore) indexKey(userID identity.UserID) string {
	return s.client.buildKey(sessionIndexKeySegment, string(userID))
}
