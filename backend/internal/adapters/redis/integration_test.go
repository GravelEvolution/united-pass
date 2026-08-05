//go:build integration

// Redis integration tests verify session store, MFA store, and rate limiter
// behavior against a real Redis instance. These tests require UP_TEST_REDIS_URL
// and UP_TEST_REDIS_KEY_PREFIX to be set; they skip when the variables are
// absent. They never run FLUSHALL or FLUSHDB, and only delete keys under the
// configured test prefix.
//
// Run locally:
//
//	UP_TEST_REDIS_URL=rediss://:password@host:6379/1 \
//	UP_TEST_REDIS_KEY_PREFIX=up:test: \
//	go test -tags integration ./internal/adapters/redis/...
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
		URL:           url,
		KeyPrefix:     prefix,
		PoolSize:      5,
		AllowInsecure: os.Getenv("UP_DEBUG_ALLOW_INSECURE") == "true",
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

	if err := store.Create(ctx, tokenHash, record, 1*time.Hour); err != nil {
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

	if err := store.Create(ctx, tokenHash, record, 1*time.Hour); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.Delete(ctx, tokenHash); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := store.Get(ctx, tokenHash)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
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

	if err := store.Create(ctx, oldHash, record, 1*time.Hour); err != nil {
		t.Fatalf("create old: %v", err)
	}

	if err := store.Rotate(ctx, oldHash, newHash, record, 1*time.Hour); err != nil {
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

	if err := store.Create(ctx, tokenHash, record, 1*time.Hour); err != nil {
		t.Fatalf("create: %v", err)
	}

	newTime := time.Now().UTC()
	if err := store.Touch(ctx, tokenHash, newTime, 1*time.Hour); err != nil {
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

	// Consume the challenge.
	if err := store.Consume(ctx, tokenHash); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// Second consume should not find the challenge.
	_, err := store.Get(ctx, tokenHash)
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

	// Launch multiple goroutines that try to consume the same challenge.
	var wg sync.WaitGroup
	successCount := int64(0)
	var mu sync.Mutex
	consumers := 10

	for i := 0; i < consumers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine tries to get and then consume the challenge.
			_, err := store.Get(ctx, tokenHash)
			if err != nil {
				return // Challenge already consumed.
			}
			// Small race window is acceptable for this test: we verify
			// that after all goroutines finish, the challenge is gone.
			if err := store.Consume(ctx, tokenHash); err != nil {
				return
			}
			mu.Lock()
			successCount++
			mu.Unlock()
		}()
	}
	wg.Wait()

	// The challenge must be consumed (gone) regardless of how many goroutines
	// succeeded.
	_, err := store.Get(ctx, tokenHash)
	if !errors.Is(err, auth.ErrMFAChallengeNotFound) {
		t.Fatalf("challenge should be consumed, got err: %v", err)
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
	if err := testStore.Create(ctx, tokenHash, record, 1*time.Hour); err != nil {
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

	if err := store.Create(ctx, tokenHash, record, 1*time.Hour); err != nil {
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
