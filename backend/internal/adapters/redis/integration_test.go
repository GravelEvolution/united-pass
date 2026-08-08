//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Redis integration test setup and store coverage
//

//go:build integration

// Redis integration tests verify session store, MFA store, and rate limiter
// behavior against a real Redis instance. These tests require UP_TEST_REDIS_URL
// and UP_TEST_REDIS_KEY_PREFIX to be set; they skip when the variables are
// absent. They never run FLUSHALL or FLUSHDB, and only delete keys under the
// configured test prefix.
//
// Run locally (through the SSH tunnel managed by scripts/tunnel.sh):
//
//	UP_TEST_REDIS_URL=redis://:password@127.0.0.1:16379/1 \
//	UP_TEST_REDIS_KEY_PREFIX=up:test: \
//	go test -tags integration ./internal/adapters/redis/...
//
// Never point these tests at a public network endpoint with plaintext. The
// tunnel keeps plaintext traffic on the loopback interface only.
package redis

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

func mustLoadTestRedisConfig(t *testing.T) config.RedisConfig {
	t.Helper()
	url := os.Getenv("UP_TEST_REDIS_URL")
	prefix := os.Getenv("UP_TEST_REDIS_KEY_PREFIX")
	if prefix == "" {
		prefix = "up:test:"
	}
	if url == "" {
		t.Skip("UP_TEST_REDIS_URL not set; skipping Redis integration tests")
	}
	return config.RedisConfig{
		URL:       url,
		KeyPrefix: prefix,
		PoolSize:  5,
	}
}

func setupTestRedis(t *testing.T) *Client {
	t.Helper()
	cfg := mustLoadTestRedisConfig(t)
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("create redis client: %v", err)
	}

	// Verify connectivity.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("ping redis: %v", err)
	}

	// Clean up: delete only keys under the test prefix. Never FLUSHALL or
	// FLUSHDB.
	t.Cleanup(func() {
		cleanupTestKeys(t, client, cfg.KeyPrefix)
		_ = client.Close()
	})

	return client
}

// cleanupTestKeys deletes all keys matching the test prefix pattern. It uses
// SCAN to find keys (never KEYS, which blocks) and deletes them in batches.
// This is the only destructive operation in the integration tests, and it is
// scoped to the test prefix.
func cleanupTestKeys(t *testing.T, client *Client, prefix string) {
	t.Helper()
	ctx := context.Background()
	rdb := client.RDB()

	var cursor uint64
	for {
		keys, nextCursor, err := rdb.Scan(ctx, cursor, prefix+"*", 100).Result()
		if err != nil {
			t.Logf("cleanup scan error: %v", err)
			return
		}
		if len(keys) > 0 {
			if err := rdb.Del(ctx, keys...).Err(); err != nil {
				t.Logf("cleanup delete error: %v", err)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}

// --- Session Store Tests ---

func TestIntegration_SessionStoreCreateAndGet(t *testing.T) {
	client := setupTestRedis(t)
	store := NewSessionStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("integration-test-token-1")
	record := session.SessionRecord{
		Version:            1,
		SessionID:          session.SessionID("sess_test_001"),
		UserID:             identity.UserID("user_test_001"),
		Provider:           "fake",
		CreatedAt:          time.Now().UTC(),
		LastSeenAt:         time.Now().UTC(),
		ExpiresAt:          time.Now().Add(1 * time.Hour).UTC(),
		AuthenticationTime: time.Now().UTC(),
		CSRFTokenHash:      session.HashToken("csrf-token-1"),
	}

	if err := store.Create(ctx, tokenHash, record, 1*time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("create session: %v", err)
	}

	loaded, err := store.Get(ctx, tokenHash)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if loaded.UserID != record.UserID {
		t.Errorf("UserID: got %q, want %q", loaded.UserID, record.UserID)
	}
	if loaded.SessionID != record.SessionID {
		t.Errorf("SessionID: got %q, want %q", loaded.SessionID, record.SessionID)
	}

	// The locator written atomically with the record resolves the same
	// session for its owner.
	byID, err := store.GetBySessionID(ctx, record.UserID, record.SessionID, time.Now(), 30*time.Minute)
	if err != nil {
		t.Fatalf("get by session id: %v", err)
	}
	if byID.SessionID != record.SessionID {
		t.Errorf("GetBySessionID returned %q, want %q", byID.SessionID, record.SessionID)
	}
}

func TestIntegration_SessionStoreDelete(t *testing.T) {
	client := setupTestRedis(t)
	store := NewSessionStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("integration-test-token-delete")
	record := session.SessionRecord{
		Version:            1,
		SessionID:          session.SessionID("sess_test_delete"),
		UserID:             identity.UserID("user_test_delete"),
		Provider:           "fake",
		CreatedAt:          time.Now().UTC(),
		LastSeenAt:         time.Now().UTC(),
		ExpiresAt:          time.Now().Add(1 * time.Hour).UTC(),
		AuthenticationTime: time.Now().UTC(),
		CSRFTokenHash:      session.HashToken("csrf-delete"),
	}

	if err := store.Create(ctx, tokenHash, record, 1*time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.Delete(ctx, tokenHash); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := store.Get(ctx, tokenHash)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}

	// The atomic delete also removed locator and index entry.
	if _, err := store.GetBySessionID(ctx, record.UserID, record.SessionID, time.Now(), 30*time.Minute); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("locator should be gone after delete, got %v", err)
	}

	// Delete is idempotent.
	if err := store.Delete(ctx, tokenHash); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestIntegration_SessionStoreRotate(t *testing.T) {
	client := setupTestRedis(t)
	store := NewSessionStore(client)
	ctx := context.Background()

	oldHash := session.HashToken("old-rotation-token")
	newHash := session.HashToken("new-rotation-token")
	record := session.SessionRecord{
		Version:            2,
		SessionID:          session.SessionID("sess_rotate"),
		UserID:             identity.UserID("user_rotate"),
		Provider:           "fake",
		CreatedAt:          time.Now().UTC(),
		LastSeenAt:         time.Now().UTC(),
		ExpiresAt:          time.Now().Add(1 * time.Hour).UTC(),
		AuthenticationTime: time.Now().UTC(),
		CSRFTokenHash:      session.HashToken("csrf-rotated"),
	}

	if err := store.Create(ctx, oldHash, record, 1*time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("create old: %v", err)
	}

	if err := store.Rotate(ctx, oldHash, newHash, record, 1*time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Old session should be gone.
	_, err := store.Get(ctx, oldHash)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("old session should be deleted, got %v", err)
	}

	// New session should exist.
	loaded, err := store.Get(ctx, newHash)
	if err != nil {
		t.Fatalf("get new: %v", err)
	}
	if loaded.UserID != record.UserID {
		t.Errorf("new session UserID: got %q, want %q", loaded.UserID, record.UserID)
	}

	// The locator re-points to the new token hash: the same SessionID still
	// resolves after rotation.
	byID, err := store.GetBySessionID(ctx, record.UserID, record.SessionID, time.Now(), 30*time.Minute)
	if err != nil {
		t.Fatalf("get by session id after rotate: %v", err)
	}
	if byID.SessionID != record.SessionID {
		t.Errorf("rotated locator returned %q, want %q", byID.SessionID, record.SessionID)
	}

	// Rotating a vanished old record must fail closed: no fresh session may
	// be re-written under the rotated token (a revoked session must never be
	// resurrected by an in-flight rotation).
	vanishedOld := session.HashToken("vanished-rotation-token")
	vanishedNew := session.HashToken("vanished-rotation-new-token")
	if err := store.Rotate(ctx, vanishedOld, vanishedNew, record, 1*time.Hour, 30*time.Minute); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("rotate of vanished session must yield ErrSessionNotFound, got %v", err)
	}
	if _, err := store.Get(ctx, vanishedNew); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("no new record may be written for a vanished rotation, got %v", err)
	}
}

func TestIntegration_SessionStoreTouch(t *testing.T) {
	client := setupTestRedis(t)
	store := NewSessionStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("touch-test-token")
	oldTime := time.Now().Add(-10 * time.Minute).UTC()
	record := session.SessionRecord{
		Version:            1,
		SessionID:          session.SessionID("sess_touch"),
		UserID:             identity.UserID("user_touch"),
		Provider:           "fake",
		CreatedAt:          oldTime,
		LastSeenAt:         oldTime,
		ExpiresAt:          time.Now().Add(1 * time.Hour).UTC(),
		AuthenticationTime: oldTime,
		CSRFTokenHash:      session.HashToken("csrf-touch"),
	}

	if err := store.Create(ctx, tokenHash, record, 1*time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	newTime := time.Now().UTC()
	record.LastSeenAt = newTime
	if err := store.Touch(ctx, tokenHash, record, 1*time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("touch: %v", err)
	}

	loaded, err := store.Get(ctx, tokenHash)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !loaded.LastSeenAt.After(oldTime) {
		t.Errorf("LastSeenAt not updated: got %v, want after %v", loaded.LastSeenAt, oldTime)
	}
}

// sessionInventoryRecord builds a live record for inventory tests.
func sessionInventoryRecord(sessionID, userID string, createdAt time.Time, ttl time.Duration) session.SessionRecord {
	return session.SessionRecord{
		Version:            1,
		SessionID:          session.SessionID(sessionID),
		UserID:             identity.UserID(userID),
		Provider:           "fake",
		CreatedAt:          createdAt,
		LastSeenAt:         createdAt,
		ExpiresAt:          createdAt.Add(ttl),
		AuthenticationTime: createdAt,
		CSRFTokenHash:      session.HashToken("csrf-" + sessionID),
	}
}

func TestIntegration_SessionStoreGetBySessionIDNonEnumeration(t *testing.T) {
	client := setupTestRedis(t)
	store := NewSessionStore(client)
	ctx := context.Background()

	now := time.Now().UTC()
	idleTTL := 30 * time.Minute
	record := sessionInventoryRecord("sess_inv_own", "user_inv_a", now, time.Hour)
	if err := store.Create(ctx, session.HashToken("inv-own-token"), record, time.Hour, idleTTL); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Foreign lookups are indistinguishable from unknown ones.
	if _, err := store.GetBySessionID(ctx, "user_inv_b", record.SessionID, now, idleTTL); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("foreign lookup must yield ErrSessionNotFound, got %v", err)
	}
	if _, err := store.GetBySessionID(ctx, record.UserID, "sess_does_not_exist", now, idleTTL); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("unknown lookup must yield ErrSessionNotFound, got %v", err)
	}

	// An idle-expired record is also reported not found.
	if _, err := store.GetBySessionID(ctx, record.UserID, record.SessionID, now.Add(2*idleTTL), idleTTL); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("idle-expired lookup must yield ErrSessionNotFound, got %v", err)
	}
}

func TestIntegration_SessionStoreDeleteBySessionID(t *testing.T) {
	client := setupTestRedis(t)
	store := NewSessionStore(client)
	ctx := context.Background()

	now := time.Now().UTC()
	idleTTL := 30 * time.Minute
	record := sessionInventoryRecord("sess_inv_del", "user_inv_del", now, time.Hour)
	tokenHash := session.HashToken("inv-del-token")
	if err := store.Create(ctx, tokenHash, record, time.Hour, idleTTL); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Foreign deletes are refused without side effects.
	if err := store.DeleteBySessionID(ctx, "user_inv_other", record.SessionID, now, idleTTL); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("foreign delete must yield ErrSessionNotFound, got %v", err)
	}
	if _, err := store.Get(ctx, tokenHash); err != nil {
		t.Fatalf("record must survive a foreign delete attempt: %v", err)
	}

	if err := store.DeleteBySessionID(ctx, record.UserID, record.SessionID, now, idleTTL); err != nil {
		t.Fatalf("delete by session id: %v", err)
	}
	if _, err := store.Get(ctx, tokenHash); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("record must be gone after delete, got %v", err)
	}
	if _, err := store.GetBySessionID(ctx, record.UserID, record.SessionID, now, idleTTL); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("locator must be gone after delete, got %v", err)
	}

	// An idle-expired session must not be revokable as a live one: the
	// expiry replay honours the frozen idle semantics (R2).
	idle := sessionInventoryRecord("sess_inv_del_idle", "user_inv_del", now.Add(-2*time.Hour), time.Hour)
	idleHash := session.HashToken("inv-del-idle-token")
	if err := store.Create(ctx, idleHash, idle, time.Hour, idleTTL); err != nil {
		t.Fatalf("create idle record: %v", err)
	}
	if err := store.DeleteBySessionID(ctx, idle.UserID, idle.SessionID, now, idleTTL); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("idle-expired delete must yield ErrSessionNotFound, got %v", err)
	}
	if _, err := store.Get(ctx, idleHash); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("idle-expired record must be cleaned up, got %v", err)
	}
}

func TestIntegration_SessionStoreListUserSessions(t *testing.T) {
	client := setupTestRedis(t)
	store := NewSessionStore(client)
	ctx := context.Background()

	now := time.Now().UTC()
	idleTTL := 30 * time.Minute

	// Two live sessions for the user, one idle-expired, one belonging to
	// another user.
	live1 := sessionInventoryRecord("sess_list_1", "user_list", now, time.Hour)
	live2 := sessionInventoryRecord("sess_list_2", "user_list", now.Add(time.Minute), time.Hour)
	idleExpired := sessionInventoryRecord("sess_list_idle", "user_list", now.Add(-2*time.Hour), time.Hour)
	foreign := sessionInventoryRecord("sess_list_foreign", "user_list_other", now, time.Hour)
	for token, rec := range map[string]session.SessionRecord{
		"list-token-1": live1,
		"list-token-2": live2,
		"list-token-3": idleExpired,
		"list-token-4": foreign,
	} {
		if err := store.Create(ctx, session.HashToken(token), rec, time.Hour, idleTTL); err != nil {
			t.Fatalf("create %q: %v", rec.SessionID, err)
		}
	}

	records, err := store.ListUserSessions(ctx, "user_list", now.Add(5*time.Minute), idleTTL)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("list returned %d records, want 2", len(records))
	}
	// Ordered by creation time.
	if records[0].SessionID != "sess_list_1" || records[1].SessionID != "sess_list_2" {
		t.Errorf("unexpected order: %q, %q", records[0].SessionID, records[1].SessionID)
	}

	// The idle-expired member was self-healed out of the index.
	indexKey := store.indexKey("user_list")
	members, err := client.RDB().ZRange(ctx, indexKey, 0, -1).Result()
	if err != nil {
		t.Fatalf("zrange: %v", err)
	}
	for _, m := range members {
		if m == "sess_list_idle" {
			t.Fatal("idle-expired member not removed from the index")
		}
	}

	// Listing a user with no sessions yields an empty slice, not an error.
	empty, err := store.ListUserSessions(ctx, "user_list_nobody", now, idleTTL)
	if err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty list returned %d records", len(empty))
	}
}

func TestIntegration_SessionStoreRevokeAllOtherSessions(t *testing.T) {
	client := setupTestRedis(t)
	store := NewSessionStore(client)
	ctx := context.Background()

	now := time.Now().UTC()
	idleTTL := 30 * time.Minute
	current := sessionInventoryRecord("sess_revoke_current", "user_revoke", now, time.Hour)
	other1 := sessionInventoryRecord("sess_revoke_a", "user_revoke", now, time.Hour)
	other2 := sessionInventoryRecord("sess_revoke_b", "user_revoke", now, time.Hour)
	idleOther := sessionInventoryRecord("sess_revoke_idle", "user_revoke", now.Add(-2*time.Hour), time.Hour)
	foreign := sessionInventoryRecord("sess_revoke_foreign", "user_revoke_other", now, time.Hour)
	for token, rec := range map[string]session.SessionRecord{
		"revoke-token-current": current,
		"revoke-token-a":       other1,
		"revoke-token-b":       other2,
		"revoke-token-idle":    idleOther,
		"revoke-token-foreign": foreign,
	} {
		if err := store.Create(ctx, session.HashToken(token), rec, time.Hour, idleTTL); err != nil {
			t.Fatalf("create %q: %v", rec.SessionID, err)
		}
	}

	victims, count, err := store.RevokeAllOtherSessions(ctx, "user_revoke", current.SessionID, now, idleTTL)
	if err != nil {
		t.Fatalf("revoke all others: %v", err)
	}
	if count != 2 || len(victims) != 2 {
		t.Fatalf("revoked %d (victims %d), want 2", count, len(victims))
	}
	for _, v := range victims {
		if v.SessionID == current.SessionID {
			t.Fatal("current session was revoked")
		}
		if v.SessionID == idleOther.SessionID {
			t.Fatal("idle-expired session must not be counted as a victim (R2)")
		}
		if v.UserID != "user_revoke" {
			t.Fatalf("foreign session %q was revoked", v.SessionID)
		}
	}

	// The current session survives with its locator intact.
	if _, err := store.GetBySessionID(ctx, "user_revoke", current.SessionID, now, idleTTL); err != nil {
		t.Fatalf("current session must survive: %v", err)
	}
	// The foreign user's session is untouched.
	if _, err := store.GetBySessionID(ctx, "user_revoke_other", foreign.SessionID, now, idleTTL); err != nil {
		t.Fatalf("foreign user's session must survive: %v", err)
	}
	// Revoking again finds nothing.
	_, count, err = store.RevokeAllOtherSessions(ctx, "user_revoke", current.SessionID, now, idleTTL)
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if count != 0 {
		t.Fatalf("second revoke removed %d sessions, want 0", count)
	}
}

// --- MFA Store Tests ---

func TestIntegration_MFAStoreCreateGetDelete(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-test-token")
	data := auth.MFAChallengeData{
		UserID:                   identity.UserID("user_mfa_001"),
		Provider:                 "fake",
		ProviderSessionReference: "provider-ref-001",
		AvailableMethods:         []auth.MFAMethod{auth.MFAMethodTOTP},
		CreatedAt:                time.Now().UTC(),
	}

	if err := store.Create(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	loaded, err := store.Get(ctx, tokenHash)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if loaded.UserID != data.UserID {
		t.Errorf("UserID: got %q, want %q", loaded.UserID, data.UserID)
	}

	if err := store.Delete(ctx, tokenHash); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err = store.Get(ctx, tokenHash)
	if !errors.Is(err, auth.ErrMFAChallengeNotFound) {
		t.Fatalf("expected ErrMFAChallengeNotFound, got %v", err)
	}
}

func TestIntegration_MFAStoreConsumeIsOneTime(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-consume-token")
	data := auth.MFAChallengeData{
		UserID:           identity.UserID("user_mfa_consume"),
		Provider:         "fake",
		AvailableMethods: []auth.MFAMethod{auth.MFAMethodTOTP},
		CreatedAt:        time.Now().UTC(),
	}

	if err := store.Create(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Claim, then consume the challenge.
	if _, err := store.Claim(ctx, tokenHash, "consume-claim"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := store.Consume(ctx, tokenHash, "consume-claim"); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// Second consume should report the claim not held.
	err := store.Consume(ctx, tokenHash, "consume-claim")
	if !errors.Is(err, auth.ErrMFAChallengeNotHeld) {
		t.Fatalf("expected ErrMFAChallengeNotHeld on second consume, got %v", err)
	}

	// The challenge is gone.
	_, err = store.Get(ctx, tokenHash)
	if !errors.Is(err, auth.ErrMFAChallengeNotFound) {
		t.Fatalf("expected ErrMFAChallengeNotFound after consume, got %v", err)
	}
}

func TestIntegration_MFAStoreAttemptIncrement(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-attempts-token")
	data := auth.MFAChallengeData{
		UserID:    identity.UserID("user_mfa_attempts"),
		Provider:  "fake",
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Create(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Increment attempts up to maxAttempts.
	maxAttempts := 3
	for i := 1; i <= maxAttempts; i++ {
		count, err := store.IncrementAttempts(ctx, tokenHash, maxAttempts)
		if err != nil {
			t.Fatalf("increment %d: %v", i, err)
		}
		if count != i {
			t.Errorf("attempt %d: got count %d, want %d", i, count, i)
		}
	}

	// Next increment should exceed maxAttempts.
	_, err := store.IncrementAttempts(ctx, tokenHash, maxAttempts)
	if !errors.Is(err, auth.ErrMFAMaxAttemptsExceeded) {
		t.Fatalf("expected ErrMFAMaxAttemptsExceeded, got %v", err)
	}
}

func TestIntegration_MFAStoreConcurrentReplay(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-concurrent-token")
	data := auth.MFAChallengeData{
		UserID:    identity.UserID("user_mfa_concurrent"),
		Provider:  "fake",
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Create(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Launch multiple goroutines, each with its own claimID. Exactly one can
	// claim (and therefore consume) the challenge.
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	consumers := 10

	for i := 0; i < consumers; i++ {
		wg.Add(1)
		go func(seq int) {
			defer wg.Done()
			claimID := fmt.Sprintf("claim-%d", seq)
			if _, err := store.Claim(ctx, tokenHash, claimID); err != nil {
				return
			}
			if err := store.Consume(ctx, tokenHash, claimID); err != nil {
				return
			}
			mu.Lock()
			winners++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if winners != 1 {
		t.Fatalf("consumers succeeded = %d, want exactly 1", winners)
	}

	// The challenge must be consumed (gone) regardless of how many goroutines
	// succeeded.
	_, err := store.Get(ctx, tokenHash)
	if !errors.Is(err, auth.ErrMFAChallengeNotFound) {
		t.Fatalf("challenge should be consumed, got err: %v", err)
	}
}

func TestIntegration_MFAStoreClaimIsAtomic(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-claim-atomic")
	data := auth.MFAChallengeData{
		UserID:    identity.UserID("user_mfa_claim_atomic"),
		Provider:  "fake",
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Create(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Launch many concurrent claims with distinct claimIDs: exactly one must
	// win, every other request must observe the claim as already held.
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	claimants := 10

	for i := 0; i < claimants; i++ {
		wg.Add(1)
		go func(seq int) {
			defer wg.Done()
			if _, err := store.Claim(ctx, tokenHash, fmt.Sprintf("claim-%d", seq)); err != nil {
				return
			}
			mu.Lock()
			winners++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if winners != 1 {
		t.Fatalf("claims won = %d, want exactly 1", winners)
	}
}

func TestIntegration_MFAStoreClaimReleaseAndReclaim(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-claim-release")
	data := auth.MFAChallengeData{
		UserID:    identity.UserID("user_mfa_claim_release"),
		Provider:  "fake",
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Create(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	// First claim wins with claim-A.
	if _, err := store.Claim(ctx, tokenHash, "claim-A"); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	// A second claim with a different claimID must be rejected.
	_, err := store.Claim(ctx, tokenHash, "claim-B")
	if !errors.Is(err, auth.ErrMFAChallengeClaimed) {
		t.Fatalf("second claim error = %v, want ErrMFAChallengeClaimed", err)
	}

	// A stale owner (claim-B) cannot release the lock held by claim-A.
	if err := store.Release(ctx, tokenHash, "claim-B"); !errors.Is(err, auth.ErrMFAChallengeNotHeld) {
		t.Fatalf("stale release error = %v, want ErrMFAChallengeNotHeld", err)
	}

	// The lock owner (claim-A) releases it.
	if err := store.Release(ctx, tokenHash, "claim-A"); err != nil {
		t.Fatalf("release: %v", err)
	}

	// The challenge can now be claimed again by a new owner.
	if _, err := store.Claim(ctx, tokenHash, "claim-C"); err != nil {
		t.Fatalf("reclaim after release: %v", err)
	}

	// Consume the claimed challenge (owner claim-C only).
	if err := store.Consume(ctx, tokenHash, "claim-C"); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// Consuming again must report the claim not held (lock gone).
	err = store.Consume(ctx, tokenHash, "claim-C")
	if !errors.Is(err, auth.ErrMFAChallengeNotHeld) {
		t.Fatalf("second consume error = %v, want ErrMFAChallengeNotHeld", err)
	}
}

func TestIntegration_MFAStoreReleaseAfterConsume(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-release-after-consume")
	data := auth.MFAChallengeData{
		UserID:    identity.UserID("user_mfa_release_after_consume"),
		Provider:  "fake",
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Create(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := store.Claim(ctx, tokenHash, "claim-A"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := store.Consume(ctx, tokenHash, "claim-A"); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// Releasing after consume must report the claim not held.
	err := store.Release(ctx, tokenHash, "claim-A")
	if !errors.Is(err, auth.ErrMFAChallengeNotHeld) {
		t.Fatalf("release after consume error = %v, want ErrMFAChallengeNotHeld", err)
	}
}

// TestIntegration_MFAStoreClaimPreservesChallengeTTL is a regression test for
// the TTL leak: claiming must never extend (or clear) the challenge's own
// TTL, because the claim lock lives in a separate key.
func TestIntegration_MFAStoreClaimPreservesChallengeTTL(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-ttl-preserve")
	data := auth.MFAChallengeData{
		UserID:    identity.UserID("user_mfa_ttl_preserve"),
		Provider:  "fake",
		CreatedAt: time.Now().UTC(),
	}

	// Short TTL so any TTL extension by Claim would be obvious.
	challengeTTL := 30 * time.Second
	if err := store.Create(ctx, tokenHash, data, challengeTTL); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := store.Claim(ctx, tokenHash, "claim-A"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	ttl := client.rdb.TTL(ctx, client.buildKey(mfaKeySegment, tokenHash)).Val()
	if ttl <= 0 || ttl > challengeTTL {
		t.Fatalf("challenge TTL after claim = %v, want in (0, %v]", ttl, challengeTTL)
	}
	if ttl < challengeTTL-5*time.Second {
		t.Fatalf("challenge TTL after claim = %v, unexpectedly shorter than %v", ttl, challengeTTL)
	}

	// Release must not clear the challenge TTL either.
	if err := store.Release(ctx, tokenHash, "claim-A"); err != nil {
		t.Fatalf("release: %v", err)
	}

	ttlAfter := client.rdb.TTL(ctx, client.buildKey(mfaKeySegment, tokenHash)).Val()
	if ttlAfter <= 0 {
		t.Fatalf("challenge TTL after release = %v, want still set (not cleared)", ttlAfter)
	}
}

// TestIntegration_MFAStoreClaimMissingChallengeCleansLock verifies that
// claiming an expired/consumed challenge removes the claim lock instead of
// leaking it.
func TestIntegration_MFAStoreClaimMissingChallengeCleansLock(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-claim-missing")
	data := auth.MFAChallengeData{
		UserID:    identity.UserID("user_mfa_claim_missing"),
		Provider:  "fake",
		CreatedAt: time.Now().UTC(),
	}

	// Create with a 1s TTL and wait for it to expire.
	if err := store.Create(ctx, tokenHash, data, time.Second); err != nil {
		t.Fatalf("create: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)

	_, err := store.Claim(ctx, tokenHash, "claim-A")
	if !errors.Is(err, auth.ErrMFAChallengeNotFound) {
		t.Fatalf("claim on expired challenge error = %v, want ErrMFAChallengeNotFound", err)
	}

	// The claim lock must not linger.
	claimKey := client.buildKey(mfaClaimKeySegment, tokenHash)
	if n := client.rdb.Exists(ctx, claimKey).Val(); n != 0 {
		t.Fatalf("claim lock leaked after failed claim on missing challenge (exists=%d)", n)
	}
}

// TestIntegration_MFAStoreIncrementAttemptsNoStaleCounter verifies that
// incrementing attempts on a missing challenge neither creates nor leaves a
// stale counter.
func TestIntegration_MFAStoreIncrementAttemptsNoStaleCounter(t *testing.T) {
	client := setupTestRedis(t)
	store := NewMFAStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("mfa-attempts-missing")
	// No challenge created.

	_, err := store.IncrementAttempts(ctx, tokenHash, 5)
	if !errors.Is(err, auth.ErrMFAChallengeNotFound) {
		t.Fatalf("increment on missing challenge error = %v, want ErrMFAChallengeNotFound", err)
	}

	attemptsKey := client.buildKey(mfaAttemptsKeySegment, tokenHash)
	if n := client.rdb.Exists(ctx, attemptsKey).Val(); n != 0 {
		t.Fatalf("attempt counter leaked for missing challenge (exists=%d)", n)
	}
}

// --- Rate Limiter Tests ---

func TestIntegration_RateLimiterLogin(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()

	ip := "10.0.0.1"
	identifierHash := session.HashToken("rate-test-identifier")
	limit := 3
	window := 10 * time.Second

	for i := 1; i <= limit; i++ {
		allowed, _, err := limiter.CheckLogin(ctx, ip, identifierHash, limit, window)
		if err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("check %d should be allowed", i)
		}
	}

	// Next request should be rate limited.
	allowed, retryAfter, err := limiter.CheckLogin(ctx, ip, identifierHash, limit, window)
	if err != nil {
		t.Fatalf("check over limit: %v", err)
	}
	if allowed {
		t.Fatal("should be rate limited")
	}
	if retryAfter <= 0 {
		t.Error("retryAfter should be positive")
	}
}

func TestIntegration_RateLimiterDifferentIPs(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()

	identifierHash := session.HashToken("rate-multi-ip")
	limit := 2
	window := 10 * time.Second

	// IP 1 uses up the limit.
	for i := 0; i < limit; i++ {
		allowed, _, err := limiter.CheckLogin(ctx, "10.0.0.1", identifierHash, limit, window)
		if err != nil || !allowed {
			t.Fatalf("ip1 check %d: allowed=%v err=%v", i, allowed, err)
		}
	}

	// IP 2 should still be allowed.
	allowed, _, err := limiter.CheckLogin(ctx, "10.0.0.2", identifierHash, limit, window)
	if err != nil || !allowed {
		t.Fatalf("ip2 should be allowed: allowed=%v err=%v", allowed, err)
	}
}

// --- Prefix Isolation Test ---

func TestIntegration_PrefixIsolation(t *testing.T) {
	cfg := mustLoadTestRedisConfig(t)

	// Create a client with a different prefix.
	otherCfg := cfg
	otherCfg.KeyPrefix = "up:other_test:"
	otherClient, err := NewClient(otherCfg)
	if err != nil {
		t.Fatalf("create other client: %v", err)
	}
	defer func() {
		cleanupTestKeys(t, otherClient, otherCfg.KeyPrefix)
		_ = otherClient.Close()
	}()

	testClient := setupTestRedis(t)

	// Store a session with the test prefix.
	testStore := NewSessionStore(testClient)
	tokenHash := session.HashToken("prefix-isolation-token")
	record := session.SessionRecord{
		Version:            1,
		SessionID:          session.SessionID("sess_prefix"),
		UserID:             identity.UserID("user_prefix"),
		Provider:           "fake",
		CreatedAt:          time.Now().UTC(),
		LastSeenAt:         time.Now().UTC(),
		ExpiresAt:          time.Now().Add(1 * time.Hour).UTC(),
		AuthenticationTime: time.Now().UTC(),
		CSRFTokenHash:      session.HashToken("csrf-prefix"),
	}

	ctx := context.Background()
	if err := testStore.Create(ctx, tokenHash, record, 1*time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	// The other client should not find it.
	otherStore := NewSessionStore(otherClient)
	_, err = otherStore.Get(ctx, tokenHash)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("other prefix should not find session, got err: %v", err)
	}

	// Verify the key contains the test prefix, not the other prefix.
	// This is implicitly verified by the Get success/failure above.
}

// --- Key Content Safety Test ---

func TestIntegration_KeysDoNotContainRawTokens(t *testing.T) {
	cfg := mustLoadTestRedisConfig(t)
	client := setupTestRedis(t)
	ctx := context.Background()

	rawToken := "super-secret-raw-token-value"
	tokenHash := session.HashToken(rawToken)
	store := NewSessionStore(client)
	record := session.SessionRecord{
		Version:            1,
		SessionID:          session.SessionID("sess_key_safety"),
		UserID:             identity.UserID("user_key_safety"),
		Provider:           "fake",
		CreatedAt:          time.Now().UTC(),
		LastSeenAt:         time.Now().UTC(),
		ExpiresAt:          time.Now().Add(1 * time.Hour).UTC(),
		AuthenticationTime: time.Now().UTC(),
		CSRFTokenHash:      session.HashToken("csrf-safety"),
	}

	if err := store.Create(ctx, tokenHash, record, 1*time.Hour, 30*time.Minute); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Scan all keys with the test prefix and verify none contain the raw token.
	var cursor uint64
	for {
		keys, nextCursor, err := client.RDB().Scan(ctx, cursor, cfg.KeyPrefix+"*", 100).Result()
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		for _, key := range keys {
			if strings.Contains(key, rawToken) {
				t.Errorf("Redis key %q contains the raw session token", key)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	// Verify the hash IS present in a key (the correct behavior).
	expectedKey := fmt.Sprintf("%ssession:%s", cfg.KeyPrefix, tokenHash)
	exists, err := client.RDB().Exists(ctx, expectedKey).Result()
	if err != nil {
		t.Fatalf("exists check: %v", err)
	}
	if exists != 1 {
		t.Errorf("expected key %q to exist", expectedKey)
	}
}

// --- Reauth Store Tests (ADR-0004 §7) ---

func reauthChallengeData(action string) auth.ReauthChallengeData {
	return auth.ReauthChallengeData{
		UserID:        identity.UserID("user_reauth_1"),
		SessionID:     "sess_reauth_1",
		Action:        action,
		ApplicationID: "app_reauth_1",
		ClientID:      "clt_reauth_1",
	}
}

func TestIntegration_ReauthStoreChallengeLifecycle(t *testing.T) {
	client := setupTestRedis(t)
	store := NewReauthStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("reauth-challenge-token")

	if err := store.CreateChallenge(ctx, tokenHash, reauthChallengeData("client.secret.rotate"), 5*time.Minute); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	// The first claim wins and returns the stored binding.
	data, err := store.ClaimChallenge(ctx, tokenHash, "claim-1")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if data.Action != "client.secret.rotate" || data.SessionID != "sess_reauth_1" || data.ClientID != "clt_reauth_1" {
		t.Errorf("claimed data = %+v, want stored binding", data)
	}

	// A concurrent claim is rejected while the lock is held.
	if _, err := store.ClaimChallenge(ctx, tokenHash, "claim-2"); !errors.Is(err, auth.ErrReauthChallengeClaimed) {
		t.Fatalf("second claim err = %v, want ErrReauthChallengeClaimed", err)
	}

	// Release only succeeds for the holder; the lock can then be reclaimed.
	if err := store.ReleaseChallenge(ctx, tokenHash, "claim-other"); !errors.Is(err, auth.ErrReauthChallengeNotHeld) {
		t.Fatalf("foreign release err = %v, want ErrReauthChallengeNotHeld", err)
	}
	if err := store.ReleaseChallenge(ctx, tokenHash, "claim-1"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := store.ClaimChallenge(ctx, tokenHash, "claim-3"); err != nil {
		t.Fatalf("reclaim after release: %v", err)
	}

	// Consuming without holding the lock fails closed.
	if err := store.ConsumeChallenge(ctx, tokenHash, "claim-1"); !errors.Is(err, auth.ErrReauthChallengeNotHeld) {
		t.Fatalf("consume without lock err = %v, want ErrReauthChallengeNotHeld", err)
	}
	if err := store.ConsumeChallenge(ctx, tokenHash, "claim-3"); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// The challenge is gone: claims report not found and the lock was cleaned.
	if _, err := store.ClaimChallenge(ctx, tokenHash, "claim-4"); !errors.Is(err, auth.ErrReauthChallengeNotFound) {
		t.Fatalf("claim after consume err = %v, want ErrReauthChallengeNotFound", err)
	}
}

func TestIntegration_ReauthStoreChallengeAttemptBudget(t *testing.T) {
	client := setupTestRedis(t)
	store := NewReauthStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("reauth-attempts-token")

	if err := store.CreateChallenge(ctx, tokenHash, reauthChallengeData("client.delete"), 5*time.Minute); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	for i := 1; i <= 3; i++ {
		count, err := store.IncrementChallengeAttempts(ctx, tokenHash, 3)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if count != i {
			t.Errorf("attempt count = %d, want %d", count, i)
		}
	}
	// The budget is exhausted: the store rejects further attempts.
	if _, err := store.IncrementChallengeAttempts(ctx, tokenHash, 3); !errors.Is(err, auth.ErrReauthMaxAttemptsExceeded) {
		t.Fatalf("over-budget err = %v, want ErrReauthMaxAttemptsExceeded", err)
	}

	// Unknown challenges report not found instead of silently counting.
	if _, err := store.IncrementChallengeAttempts(ctx, session.HashToken("missing"), 3); !errors.Is(err, auth.ErrReauthChallengeNotFound) {
		t.Fatalf("missing challenge err = %v, want ErrReauthChallengeNotFound", err)
	}
}

func TestIntegration_ReauthStoreGrantSingleUse(t *testing.T) {
	client := setupTestRedis(t)
	store := NewReauthStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("reauth-grant-token")
	data := auth.ReauthGrantData{
		UserID:        identity.UserID("user_reauth_1"),
		SessionID:     "sess_reauth_1",
		Action:        "client.secret.rotate",
		ApplicationID: "app_reauth_1",
		ClientID:      "clt_reauth_1",
	}

	if err := store.CreateGrant(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create grant: %v", err)
	}

	got, err := store.ConsumeGrant(ctx, tokenHash)
	if err != nil {
		t.Fatalf("consume grant: %v", err)
	}
	if got.UserID != data.UserID || got.SessionID != data.SessionID || got.Action != data.Action ||
		got.ApplicationID != data.ApplicationID || got.ClientID != data.ClientID {
		t.Errorf("grant data = %+v, want %+v", got, data)
	}

	// A consumed grant can never be reused.
	if _, err := store.ConsumeGrant(ctx, tokenHash); !errors.Is(err, auth.ErrReauthGrantNotFound) {
		t.Fatalf("reuse err = %v, want ErrReauthGrantNotFound", err)
	}
}

func TestIntegration_ReauthStoreGrantConcurrentConsume(t *testing.T) {
	client := setupTestRedis(t)
	store := NewReauthStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("reauth-grant-race-token")
	data := auth.ReauthGrantData{
		UserID:        identity.UserID("user_reauth_1"),
		SessionID:     "sess_reauth_1",
		Action:        "application.delete",
		ApplicationID: "app_reauth_1",
	}
	if err := store.CreateGrant(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create grant: %v", err)
	}

	const workers = 8
	var wg sync.WaitGroup
	winners := make(chan struct{}, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.ConsumeGrant(ctx, tokenHash); err == nil {
				winners <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(winners)
	if count := len(winners); count != 1 {
		t.Fatalf("concurrent winners = %d, want exactly 1", count)
	}
}

// TestIntegration_ReauthStoreCreateIndexesBothKeys verifies the atomic
// create invariant: right after CreateChallenge returns, the challenge
// record and its cleanup-index entry both exist. The Lua script leaves no
// window where a stored challenge is missing from the abandoned-challenge
// index (which would leak its provider session on abandonment).
func TestIntegration_ReauthStoreCreateIndexesBothKeys(t *testing.T) {
	client := setupTestRedis(t)
	store := NewReauthStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("reauth-atomic-index-token")
	data := reauthChallengeData("client.secret.rotate")
	data.ProviderSessionID = "ps_atomic"

	if err := store.CreateChallenge(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	key := client.buildKey(reauthChallengeKeySegment, tokenHash)
	exists, err := client.rdb.Exists(ctx, key).Result()
	if err != nil {
		t.Fatalf("exists challenge: %v", err)
	}
	if exists != 1 {
		t.Fatalf("challenge key exists = %d, want 1", exists)
	}

	members, err := client.rdb.ZRange(ctx, client.buildKey(reauthCleanupIndexKey), 0, -1).Result()
	if err != nil {
		t.Fatalf("zrange cleanup index: %v", err)
	}
	indexed := false
	for _, m := range members {
		if strings.Contains(m, tokenHash) {
			indexed = true
			break
		}
	}
	if !indexed {
		t.Fatalf("cleanup index members = %v, want an entry for the created challenge", members)
	}
}

func TestIntegration_ReauthStoreCleanupPopsExpiredChallenge(t *testing.T) {
	client := setupTestRedis(t)
	store := NewReauthStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("reauth-cleanup-expired-token")
	data := reauthChallengeData("client.secret.rotate")
	data.ProviderSessionID = "ps_cleanup_1"

	if err := store.CreateChallenge(ctx, tokenHash, data, 2*time.Second); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	// While the challenge record still exists, nothing is popped.
	entries, err := store.PopExpiredChallenges(ctx, 10)
	if err != nil {
		t.Fatalf("pop: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("pop while live = %d entries, want 0", len(entries))
	}

	// Abandon the challenge: let its TTL lapse, then the sweep must surface
	// the cleanup entry with the provider session to revoke.
	time.Sleep(2500 * time.Millisecond)
	entries, err = store.PopExpiredChallenges(ctx, 10)
	if err != nil {
		t.Fatalf("pop after expiry: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("pop after expiry = %d entries, want 1", len(entries))
	}
	entry := entries[0]
	if entry.TokenHash != tokenHash || entry.ProviderSessionID != "ps_cleanup_1" ||
		entry.UserID != data.UserID || entry.ApplicationID != data.ApplicationID ||
		entry.ClientID != data.ClientID || entry.Action != data.Action {
		t.Errorf("cleanup entry = %+v, want challenge binding", entry)
	}

	// Popping is idempotent: the entry was removed atomically.
	entries, err = store.PopExpiredChallenges(ctx, 10)
	if err != nil {
		t.Fatalf("second pop: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("second pop = %d entries, want 0", len(entries))
	}
}

// --- Enrollment Store Tests (ADR-0006 §7/§8) ---

func enrollmentData(kind auth.EnrollmentKind, target string) auth.EnrollmentData {
	return auth.EnrollmentData{
		UserID:    identity.UserID("user_enroll_1"),
		SessionID: "sess_enroll_1",
		Kind:      kind,
		Target:    target,
	}
}

func TestIntegration_EnrollmentStoreCreateAndConsume(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("enrollment-totp-token")
	if err := store.CreateEnrollment(ctx, tokenHash, enrollmentData(auth.EnrollmentTOTP, ""), 5*time.Minute); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	data, err := store.ConsumeEnrollment(ctx, tokenHash)
	if err != nil {
		t.Fatalf("consume enrollment: %v", err)
	}
	if data.UserID != "user_enroll_1" || data.SessionID != "sess_enroll_1" || data.Kind != auth.EnrollmentTOTP || data.Target != "" {
		t.Errorf("enrollment data = %+v, want stored binding", data)
	}

	// Single-use: the record is gone after consumption.
	if _, err := store.ConsumeEnrollment(ctx, tokenHash); !errors.Is(err, auth.ErrEnrollmentNotFound) {
		t.Fatalf("reuse err = %v, want ErrEnrollmentNotFound", err)
	}

	// Passkey enrollments round-trip the target binding.
	pkHash := session.HashToken("enrollment-passkey-token")
	if err := store.CreateEnrollment(ctx, pkHash, enrollmentData(auth.EnrollmentPasskey, "pk-42"), 5*time.Minute); err != nil {
		t.Fatalf("create passkey enrollment: %v", err)
	}
	pkData, err := store.ConsumeEnrollment(ctx, pkHash)
	if err != nil {
		t.Fatalf("consume passkey enrollment: %v", err)
	}
	if pkData.Kind != auth.EnrollmentPasskey || pkData.Target != "pk-42" {
		t.Errorf("passkey enrollment = %+v, want (passkey, pk-42)", pkData)
	}
}

func TestIntegration_EnrollmentStoreUnknownToken(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)

	if _, err := store.ConsumeEnrollment(context.Background(), session.HashToken("never-issued")); !errors.Is(err, auth.ErrEnrollmentNotFound) {
		t.Fatalf("unknown token err = %v, want ErrEnrollmentNotFound", err)
	}
}

func TestIntegration_EnrollmentStoreExpiry(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("enrollment-expiring-token")
	if err := store.CreateEnrollment(ctx, tokenHash, enrollmentData(auth.EnrollmentTOTP, ""), 1*time.Second); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	// Once the TTL lapses the challenge fails closed.
	time.Sleep(1500 * time.Millisecond)
	if _, err := store.ConsumeEnrollment(ctx, tokenHash); !errors.Is(err, auth.ErrEnrollmentNotFound) {
		t.Fatalf("expired consume err = %v, want ErrEnrollmentNotFound", err)
	}
}

func TestIntegration_EnrollmentStoreConcurrentReplay(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("enrollment-race-token")
	if err := store.CreateEnrollment(ctx, tokenHash, enrollmentData(auth.EnrollmentPasskey, "pk-race"), 5*time.Minute); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	// GETDEL guarantees a single winner across concurrent confirmations.
	const workers = 8
	var mu sync.Mutex
	winners := 0
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.ConsumeEnrollment(ctx, tokenHash); err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("concurrent winners = %d, want exactly 1", winners)
	}
}

func TestIntegration_ReauthStoreCleanupSkipsLiveChallenge(t *testing.T) {
	client := setupTestRedis(t)
	store := NewReauthStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("reauth-cleanup-live-token")
	data := reauthChallengeData("client.delete")
	data.ProviderSessionID = "ps_cleanup_2"

	if err := store.CreateChallenge(ctx, tokenHash, data, 5*time.Minute); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	// A live challenge must never be surfaced to the cleanup worker.
	entries, err := store.PopExpiredChallenges(ctx, 10)
	if err != nil {
		t.Fatalf("pop: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("pop = %d entries, want 0 for a live challenge", len(entries))
	}
}

func TestIntegration_ReauthStoreCleanupAfterConsume(t *testing.T) {
	client := setupTestRedis(t)
	store := NewReauthStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("reauth-cleanup-consumed-token")
	data := reauthChallengeData("application.delete")
	data.ProviderSessionID = "ps_cleanup_3"

	if err := store.CreateChallenge(ctx, tokenHash, data, 2*time.Second); err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	if _, err := store.ClaimChallenge(ctx, tokenHash, "claim-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := store.ConsumeChallenge(ctx, tokenHash, "claim-1"); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// The record is gone at a terminal state; once the scheduled expiry
	// passes, the entry surfaces so the worker revokes again (idempotent
	// double revocation is safe), and it surfaces exactly once.
	time.Sleep(2500 * time.Millisecond)
	entries, err := store.PopExpiredChallenges(ctx, 10)
	if err != nil {
		t.Fatalf("pop after consume: %v", err)
	}
	if len(entries) != 1 || entries[0].ProviderSessionID != "ps_cleanup_3" {
		t.Fatalf("pop after consume = %+v, want the consumed challenge entry", entries)
	}
	entries, err = store.PopExpiredChallenges(ctx, 10)
	if err != nil {
		t.Fatalf("second pop: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("second pop = %d entries, want 0", len(entries))
	}
}
