//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Redis integration test setup and store coverage
//

//go:build integration

// Redis integration tests verify session store, MFA store, and rate limiter
// behavior against the disposable instance created by the local integration
// matrix. A per-run ownership token, exact loopback port/database and exact
// namespace are mandatory; missing or shared configuration fails before any
// connection is opened. Cleanup never runs FLUSHALL or FLUSHDB.
package redis

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/integrationboundary"
	"github.com/GravelEvolution/united-pass/backend/internal/qrauth"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	testRedisRunTokenBytes = 16
	maxTestRedisPrefixLen  = 128
)

var (
	testRedisRunTokenOnce  sync.Once
	testRedisRunTokenValue string
	testRedisRunTokenErr   error
)

func TestMain(m *testing.M) {
	if err := integrationboundary.ValidateRedis(
		os.Getenv("UP_TEST_REDIS_URL"),
		os.Getenv("UP_TEST_REDIS_KEY_PREFIX"),
		os.Getenv(integrationboundary.RunTokenEnvironment),
	); err != nil {
		fmt.Fprintln(os.Stderr, "Redis integration boundary rejected:", err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func TestIntegration_AdminChallengeRateLimiter(t *testing.T) {
	client := setupTestRedis(t)
	keyring, err := adminstepup.NewKeyring("rate-1", map[string][]byte{"rate-1": bytes.Repeat([]byte{0x71}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := NewAdminChallengeRateLimiter(client, keyring, 2, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := limiter.Check(ctx, "user_1", "ip-a|ua-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Check(ctx, "user_1", "ip-b|ua-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Check(ctx, "user_1", "ip-c|ua-c"); !errors.Is(err, adminstepup.ErrRateLimited) {
		t.Fatalf("changed client reset immutable user counter: %v", err)
	}

	// A shared client has its own budget across distinct users.
	limiter2, err := NewAdminChallengeRateLimiter(client, keyring, 2, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter2.Check(ctx, "user_10", "shared-client"); err != nil {
		t.Fatal(err)
	}
	if _, err := limiter2.Check(ctx, "user_11", "shared-client"); err != nil {
		t.Fatal(err)
	}
	if _, err := limiter2.Check(ctx, "user_12", "shared-client"); !errors.Is(err, adminstepup.ErrRateLimited) {
		t.Fatalf("many users bypassed client counter: %v", err)
	}

	keys, _, err := client.RDB().Scan(ctx, 0, client.KeyPrefix()+adminChallengeRateSegment+"*", 100).Result()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(keys, " ")
	for _, raw := range []string{"user_1", "shared-client", "ip-a", "ua-a"} {
		if strings.Contains(joined, raw) {
			t.Fatalf("raw identifier leaked into redis key: %q", raw)
		}
	}
}

func mustLoadTestRedisConfig(t *testing.T) config.RedisConfig {
	t.Helper()
	url := os.Getenv("UP_TEST_REDIS_URL")
	prefix := os.Getenv("UP_TEST_REDIS_KEY_PREFIX")
	if err := integrationboundary.ValidateRedis(url, prefix, os.Getenv(integrationboundary.RunTokenEnvironment)); err != nil {
		t.Fatalf("Redis integration boundary rejected: %v", err)
	}
	if err := validateTestRedisPrefix(prefix, os.Getenv("UP_REDIS_KEY_PREFIX")); err != nil {
		t.Fatal(err)
	}
	prefix, err := isolatedTestRedisPrefix(prefix)
	if err != nil {
		t.Fatalf("create isolated Redis test namespace: %v", err)
	}
	return config.RedisConfig{
		URL:       url,
		KeyPrefix: prefix,
		PoolSize:  5,
	}
}

func isolatedTestRedisPrefix(basePrefix string) (string, error) {
	if err := validateTestRedisPrefix(basePrefix, ""); err != nil {
		return "", err
	}
	runToken, err := testRedisRunToken()
	if err != nil {
		return "", err
	}
	namespace := basePrefix + "run:" + runToken + ":"
	if len(namespace) > maxTestRedisPrefixLen {
		return "", errors.New("random Redis integration namespace exceeds the maximum prefix length")
	}
	return namespace, nil
}

func testRedisRunToken() (string, error) {
	testRedisRunTokenOnce.Do(func() {
		value := make([]byte, testRedisRunTokenBytes)
		if _, err := cryptorand.Read(value); err != nil {
			testRedisRunTokenErr = fmt.Errorf("read cryptographic randomness: %w", err)
			return
		}
		testRedisRunTokenValue = hex.EncodeToString(value)
	})
	return testRedisRunTokenValue, testRedisRunTokenErr
}

func validateCleanupTestRedisPrefix(prefix, runToken string) error {
	if len(prefix) > maxTestRedisPrefixLen {
		return errors.New("Redis integration cleanup namespace is too long")
	}
	decoded, err := hex.DecodeString(runToken)
	if err != nil || len(decoded) != testRedisRunTokenBytes || runToken != strings.ToLower(runToken) {
		return errors.New("Redis integration cleanup token is invalid")
	}
	suffix := "run:" + runToken + ":"
	if !strings.HasSuffix(prefix, suffix) {
		return errors.New("Redis integration cleanup requires the exact random run namespace")
	}
	basePrefix := strings.TrimSuffix(prefix, suffix)
	if err := validateTestRedisPrefix(basePrefix, ""); err != nil {
		return fmt.Errorf("Redis integration cleanup namespace is invalid: %w", err)
	}
	return nil
}

func exactCleanupTestRedisPrefix(clientPrefix, basePrefix, runToken string) (string, error) {
	if err := validateTestRedisPrefix(basePrefix, ""); err != nil {
		return "", err
	}
	expected := basePrefix + "run:" + runToken + ":"
	if err := validateCleanupTestRedisPrefix(expected, runToken); err != nil {
		return "", err
	}
	if clientPrefix != expected {
		return "", fmt.Errorf("Redis client namespace %q does not match exact cleanup namespace %q", clientPrefix, expected)
	}
	return expected, nil
}

func exactTestCleanupKeys(keys []string, namespace string) ([]string, error) {
	for _, key := range keys {
		if !strings.HasPrefix(key, namespace) {
			return nil, fmt.Errorf("Redis cleanup key escaped exact test namespace: %q", key)
		}
	}
	return keys, nil
}

func validateTestRedisPrefix(prefix, productionPrefix string) error {
	// Backslash is a Redis glob escape and is therefore just as unsafe as a
	// wildcard in the SCAN pattern used by cleanupTestKeys.
	if prefix != strings.TrimSpace(prefix) || len(prefix) < 8 || len(prefix) > maxTestRedisPrefixLen || !strings.HasSuffix(prefix, ":") || strings.ContainsAny(prefix, "*?[]\\ \t\r\n") {
		return errors.New("UP_TEST_REDIS_KEY_PREFIX must be an explicit, glob-free, colon-terminated dedicated namespace")
	}
	if productionPrefix != "" && (strings.HasPrefix(prefix, productionPrefix) || strings.HasPrefix(productionPrefix, prefix)) {
		return errors.New("UP_TEST_REDIS_KEY_PREFIX must not overlap UP_REDIS_KEY_PREFIX")
	}
	return nil
}

func TestIntegration_RedisPrefixRejectsGlobEscape(t *testing.T) {
	if err := validateTestRedisPrefix("up:test\\foo:", ""); err == nil {
		t.Fatal("Redis glob escape accepted in destructive-cleanup prefix")
	}
	if err := validateTestRedisPrefix("up:test:qr:", "up:production:"); err != nil {
		t.Fatalf("dedicated literal prefix rejected: %v", err)
	}
	for name, prefixes := range map[string][2]string{
		"test ancestor": {"up:test:", "up:test:production:"},
		"test child":    {"up:test:integration:", "up:test:"},
		"equal":         {"up:test:", "up:test:"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateTestRedisPrefix(prefixes[0], prefixes[1]); err == nil {
				t.Fatalf("overlapping test=%q production=%q prefixes accepted", prefixes[0], prefixes[1])
			}
		})
	}
}

func TestIntegration_RedisCleanupRequiresExactRandomNamespace(t *testing.T) {
	runToken := strings.Repeat("a", testRedisRunTokenBytes*2)
	exactNamespace := "up:test:run:" + runToken + ":"
	if err := validateCleanupTestRedisPrefix(exactNamespace, runToken); err != nil {
		t.Fatalf("exact random namespace rejected: %v", err)
	}
	for name, prefix := range map[string]string{
		"ancestor base":   "up:test:",
		"ancestor run":    "up:test:run:",
		"child namespace": exactNamespace + "child:",
		"wrong token":     "up:test:run:" + strings.Repeat("b", testRedisRunTokenBytes*2) + ":",
		"glob namespace":  "up:*:run:" + runToken + ":",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCleanupTestRedisPrefix(prefix, runToken); err == nil {
				t.Fatalf("unsafe cleanup prefix %q accepted", prefix)
			}
		})
	}
	for name, token := range map[string]string{
		"short":   strings.Repeat("a", testRedisRunTokenBytes*2-2),
		"non-hex": strings.Repeat("z", testRedisRunTokenBytes*2),
		"upper":   strings.Repeat("A", testRedisRunTokenBytes*2),
	} {
		t.Run("token "+name, func(t *testing.T) {
			if err := validateCleanupTestRedisPrefix(exactNamespace, token); err == nil {
				t.Fatalf("invalid cleanup token %q accepted", token)
			}
		})
	}

	keys := []string{exactNamespace + "session:one", exactNamespace + "rate:two"}
	if _, err := exactTestCleanupKeys(keys, exactNamespace); err != nil {
		t.Fatalf("in-namespace cleanup keys rejected: %v", err)
	}
	if _, err := exactTestCleanupKeys(
		append(keys, "up:test:production:session:do-not-delete"),
		exactNamespace,
	); err == nil {
		t.Fatal("out-of-namespace cleanup key was accepted")
	}
	if _, err := exactCleanupTestRedisPrefix(exactNamespace, "up:test:", runToken); err != nil {
		t.Fatalf("exact client/base cleanup binding rejected: %v", err)
	}
	if _, err := exactCleanupTestRedisPrefix(
		"up:production:run:"+runToken+":",
		"up:test:",
		runToken,
	); err == nil {
		t.Fatal("foreign client namespace was accepted for cleanup")
	}
}

func TestIntegration_RedisPrefixDerivesProcessRandomNamespace(t *testing.T) {
	const basePrefix = "up:test:"
	runToken, err := testRedisRunToken()
	if err != nil {
		t.Fatalf("create random run token: %v", err)
	}
	if len(runToken) != testRedisRunTokenBytes*2 {
		t.Fatalf("run token length=%d, want %d hex characters", len(runToken), testRedisRunTokenBytes*2)
	}
	prefix, err := isolatedTestRedisPrefix(basePrefix)
	if err != nil {
		t.Fatalf("derive random test namespace: %v", err)
	}
	want := basePrefix + "run:" + runToken + ":"
	if prefix != want {
		t.Fatalf("derived namespace=%q, want exact process namespace %q", prefix, want)
	}
	if err := validateCleanupTestRedisPrefix(prefix, runToken); err != nil {
		t.Fatalf("derived namespace is not cleanup-safe: %v", err)
	}
	tooLongBase := strings.Repeat("x", maxTestRedisPrefixLen-len("run:"+runToken+":")) + ":"
	if _, err := isolatedTestRedisPrefix(tooLongBase); err == nil {
		t.Fatal("oversized derived namespace was accepted")
	}
}

func TestIntegration_QRAuthCreateApproveWrongReceiverAndDuplicateTransitions(t *testing.T) {
	client := setupTestRedis(t)
	store := NewQRAuthStore(client)
	ctx := context.Background()
	challengeHash := strings.Repeat("a", 64)
	receiverHash := strings.Repeat("b", 64)
	const challengeTTL = 4 * time.Second
	if err := store.Create(ctx, challengeHash, receiverHash, challengeTTL); err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	key := client.buildKey(qrAuthChallengeSegment, challengeHash)
	if !strings.HasPrefix(key, client.KeyPrefix()) {
		t.Fatalf("QR key escaped dedicated prefix: %q", key)
	}
	createdTTL, err := client.rdb.PTTL(ctx, key).Result()
	if err != nil || createdTTL < 3*time.Second || createdTTL > challengeTTL {
		t.Fatalf("challenge TTL=%v err=%v, want [3s,%v]", createdTTL, err, challengeTTL)
	}
	if _, err := store.Consume(ctx, challengeHash, receiverHash); !errors.Is(err, qrauth.ErrPending) {
		t.Fatalf("pre-approval consume error=%v", err)
	}
	if err := store.Approve(ctx, challengeHash, identity.UserID("user_qr_1")); err != nil {
		t.Fatalf("approve challenge: %v", err)
	}
	approvedTTL, err := client.rdb.PTTL(ctx, key).Result()
	if err != nil || approvedTTL <= 0 || approvedTTL > createdTTL {
		t.Fatalf("approved TTL=%v err=%v, want positive and no greater than pre-approval %v", approvedTTL, err, createdTTL)
	}
	if err := store.Approve(ctx, challengeHash, identity.UserID("user_qr_2")); !errors.Is(err, qrauth.ErrConsumed) {
		t.Fatalf("duplicate approval error=%v", err)
	}
	if _, err := store.Consume(ctx, challengeHash, strings.Repeat("c", 64)); !errors.Is(err, qrauth.ErrDenied) {
		t.Fatalf("wrong receiver error=%v", err)
	}
	// The wrong receiver must not consume or rewrite the approved terminal
	// value; the original receiver remains the sole successful consumer.
	userID, err := store.Consume(ctx, challengeHash, receiverHash)
	if err != nil || userID != "user_qr_1" {
		t.Fatalf("correct receiver user=%q err=%v", userID, err)
	}
	if _, err := store.Consume(ctx, challengeHash, receiverHash); !errors.Is(err, qrauth.ErrNotFound) {
		t.Fatalf("duplicate consume error=%v", err)
	}
}

func TestIntegration_QRAuthConcurrentApproveHasExactlyOneWinner(t *testing.T) {
	client := setupTestRedis(t)
	store := NewQRAuthStore(client)
	ctx := context.Background()
	challengeHash := strings.Repeat("1", 64)
	receiverHash := strings.Repeat("2", 64)
	if err := store.Create(ctx, challengeHash, receiverHash, 4*time.Second); err != nil {
		t.Fatal(err)
	}

	const approvers = 16
	type approvalResult struct {
		userID identity.UserID
		err    error
	}
	results := make(chan approvalResult, approvers)
	var wait sync.WaitGroup
	wait.Add(approvers)
	for index := range approvers {
		go func() {
			defer wait.Done()
			userID := identity.UserID(fmt.Sprintf("user_qr_approver_%d", index))
			results <- approvalResult{userID: userID, err: store.Approve(ctx, challengeHash, userID)}
		}()
	}
	wait.Wait()
	close(results)

	winners, consumed := make([]identity.UserID, 0, 1), 0
	for result := range results {
		switch {
		case result.err == nil:
			winners = append(winners, result.userID)
		case errors.Is(result.err, qrauth.ErrConsumed):
			consumed++
		default:
			t.Fatalf("unexpected concurrent approval error: %v", result.err)
		}
	}
	if len(winners) != 1 || consumed != approvers-1 {
		t.Fatalf("approval winners=%d consumed=%d, want 1/%d", len(winners), consumed, approvers-1)
	}
	userID, err := store.Consume(ctx, challengeHash, receiverHash)
	if err != nil || userID != winners[0] {
		t.Fatalf("approved winner user=%q want=%q err=%v", userID, winners[0], err)
	}
}

func TestIntegration_QRAuthConcurrentConsumeHasExactlyOneWinner(t *testing.T) {
	client := setupTestRedis(t)
	store := NewQRAuthStore(client)
	ctx := context.Background()
	challengeHash := strings.Repeat("d", 64)
	receiverHash := strings.Repeat("e", 64)
	if err := store.Create(ctx, challengeHash, receiverHash, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(ctx, challengeHash, identity.UserID("user_qr_winner")); err != nil {
		t.Fatal(err)
	}
	const consumers = 16
	results := make(chan error, consumers)
	var wait sync.WaitGroup
	wait.Add(consumers)
	for range consumers {
		go func() {
			defer wait.Done()
			userID, err := store.Consume(ctx, challengeHash, receiverHash)
			if err == nil && userID != "user_qr_winner" {
				err = fmt.Errorf("unexpected winner user %q", userID)
			}
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	winners, missing := 0, 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, qrauth.ErrNotFound):
			missing++
		default:
			t.Fatalf("unexpected concurrent consume error: %v", err)
		}
	}
	if winners != 1 || missing != consumers-1 {
		t.Fatalf("winners=%d missing=%d, want 1/%d", winners, missing, consumers-1)
	}
}

func TestIntegration_QRAuthChallengeTTLExpiresWithoutApprovalOrConsumption(t *testing.T) {
	client := setupTestRedis(t)
	store := NewQRAuthStore(client)
	ctx := context.Background()
	challengeHash := strings.Repeat("f", 64)
	receiverHash := strings.Repeat("0", 64)
	const challengeTTL = 2 * time.Second
	if err := store.Create(ctx, challengeHash, receiverHash, challengeTTL); err != nil {
		t.Fatal(err)
	}
	key := client.buildKey(qrAuthChallengeSegment, challengeHash)
	createdTTL, err := client.rdb.PTTL(ctx, key).Result()
	if err != nil || createdTTL < time.Second || createdTTL > challengeTTL {
		t.Fatalf("challenge TTL=%v err=%v, want [1s,%v]", createdTTL, err, challengeTTL)
	}
	deadline := time.Now().Add(challengeTTL + time.Second)
	for {
		exists, err := client.rdb.Exists(ctx, key).Result()
		if err != nil {
			t.Fatal(err)
		}
		if exists == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("QR challenge did not expire within the bounded deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := store.Approve(ctx, challengeHash, identity.UserID("user_qr_expired")); !errors.Is(err, qrauth.ErrNotFound) {
		t.Fatalf("expired approval error=%v", err)
	}
	if _, err := store.Consume(ctx, challengeHash, receiverHash); !errors.Is(err, qrauth.ErrNotFound) {
		t.Fatalf("expired consume error=%v", err)
	}
}

func TestIntegration_QRAuthApprovedChallengeKeepsOriginalDeadline(t *testing.T) {
	client := setupTestRedis(t)
	store := NewQRAuthStore(client)
	ctx := context.Background()
	challengeHash := strings.Repeat("3", 64)
	receiverHash := strings.Repeat("4", 64)
	const challengeTTL = 2 * time.Second
	createdAt := time.Now()
	if err := store.Create(ctx, challengeHash, receiverHash, challengeTTL); err != nil {
		t.Fatal(err)
	}
	key := client.buildKey(qrAuthChallengeSegment, challengeHash)
	beforeApproval, err := client.rdb.PTTL(ctx, key).Result()
	if err != nil || beforeApproval < time.Second || beforeApproval > challengeTTL {
		t.Fatalf("pre-approval TTL=%v err=%v, want [1s,%v]", beforeApproval, err, challengeTTL)
	}
	if err := store.Approve(ctx, challengeHash, identity.UserID("user_qr_ttl")); err != nil {
		t.Fatal(err)
	}
	afterApproval, err := client.rdb.PTTL(ctx, key).Result()
	if err != nil || afterApproval <= 0 || afterApproval > beforeApproval {
		t.Fatalf("post-approval TTL=%v err=%v, want positive and no greater than %v", afterApproval, err, beforeApproval)
	}

	deadline := createdAt.Add(challengeTTL + time.Second)
	for {
		exists, err := client.rdb.Exists(ctx, key).Result()
		if err != nil {
			t.Fatal(err)
		}
		if exists == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("approved QR challenge outlived its original TTL deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := store.Approve(ctx, challengeHash, identity.UserID("user_qr_ttl_retry")); !errors.Is(err, qrauth.ErrNotFound) {
		t.Fatalf("expired approved challenge approval error=%v", err)
	}
	if _, err := store.Consume(ctx, challengeHash, receiverHash); !errors.Is(err, qrauth.ErrNotFound) {
		t.Fatalf("expired approved challenge consume error=%v", err)
	}
}

func setupTestRedis(t *testing.T) *Client {
	t.Helper()
	basePrefix := os.Getenv("UP_TEST_REDIS_KEY_PREFIX")
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

	// A failed test can leave keys for a later test in this process. Clear only
	// this process's exact random namespace before each test; never sweep an
	// ancestor prefix to recover artifacts from an earlier process.
	cleanupTestKeys(t, client, basePrefix)

	// Clean up: delete only keys under the test prefix. Never FLUSHALL or
	// FLUSHDB.
	t.Cleanup(func() {
		cleanupTestKeys(t, client, basePrefix)
		_ = client.Close()
	})

	return client
}

// cleanupTestKeys derives and verifies this process's exact random namespace,
// then uses SCAN to find its keys (never KEYS, which blocks) and deletes them
// in batches. This is the only destructive operation in the integration tests;
// an ancestor, child, sibling, globbed, or foreign-run namespace is rejected
// before Redis is queried.
func cleanupTestKeys(t *testing.T, client *Client, basePrefix string) {
	t.Helper()
	runToken, err := testRedisRunToken()
	if err != nil {
		t.Fatalf("load Redis integration cleanup token: %v", err)
	}
	prefix, err := exactCleanupTestRedisPrefix(client.KeyPrefix(), basePrefix, runToken)
	if err != nil {
		t.Fatalf("refusing unsafe Redis integration cleanup: %v", err)
	}
	ctx := context.Background()
	rdb := client.RDB()

	var cursor uint64
	for {
		keys, nextCursor, err := rdb.Scan(ctx, cursor, prefix+"*", 100).Result()
		if err != nil {
			t.Fatalf("cleanup scan error: %v", err)
		}
		keys, err = exactTestCleanupKeys(keys, prefix)
		if err != nil {
			t.Fatalf("refusing out-of-namespace Redis cleanup: %v", err)
		}
		if len(keys) > 0 {
			if err := rdb.Del(ctx, keys...).Err(); err != nil {
				t.Fatalf("cleanup delete error: %v", err)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}

// --- Session Store Tests ---

func TestIntegration_RegistrationStoreHashesTokenAndSeparatesRateBudgets(t *testing.T) {
	client := setupTestRedis(t)
	store := NewRegistrationStore(client)
	ctx := context.Background()
	const rawToken = "raw-registration-secret"
	want := registration.TokenRecord{UserID: "user_0123456789abcdef0123456789abcdef", RequestID: "request-1"}
	if err := store.Create(ctx, rawToken, want, time.Minute); err != nil {
		t.Fatalf("create registration token: %v", err)
	}
	keys, _, err := client.RDB().Scan(ctx, 0, client.KeyPrefix()+registrationTokenSegment+"*", 10).Result()
	if err != nil || len(keys) != 1 {
		t.Fatalf("registration keys=%v err=%v", keys, err)
	}
	if strings.Contains(keys[0], rawToken) || !strings.HasSuffix(keys[0], session.HashToken(rawToken)) {
		t.Fatalf("raw token leaked or hash missing from key: %q", keys[0])
	}
	payload, err := client.RDB().Get(ctx, keys[0]).Result()
	if err != nil || strings.Contains(payload, rawToken) {
		t.Fatalf("registration payload leaked raw token: payload=%q err=%v", payload, err)
	}
	got, err := store.Get(ctx, rawToken)
	if err != nil || got != want {
		t.Fatalf("get registration token=%#v err=%v", got, err)
	}

	limiter := NewRateLimiter(client)
	createPolicy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 1, Window: time.Minute}, ClientNet: registration.Limit{Max: 1, Window: time.Minute},
		Email: registration.Limit{Max: 1, Window: time.Minute}, ClientEmail: registration.Limit{Max: 1, Window: time.Minute},
		IPv4NetBits: 24, IPv6NetBits: 56,
	}
	checks := []func() (bool, time.Duration, error){
		func() (bool, time.Duration, error) {
			return limiter.CheckRegistrationCreate(ctx, "127.0.0.1", "127.0.0.0/24", "same", createPolicy)
		},
		func() (bool, time.Duration, error) {
			return limiter.CheckRegistrationVerify(ctx, "127.0.0.1", registration.HashAbuseValue("same"), registration.Limit{Max: 1, Window: time.Minute})
		},
		func() (bool, time.Duration, error) {
			return limiter.CheckRegistrationResend(ctx, "127.0.0.1", registration.HashAbuseValue("same"), registration.Limit{Max: 1, Window: time.Minute})
		},
	}
	for index, check := range checks {
		allowed, _, err := check()
		if err != nil || !allowed {
			t.Fatalf("independent rate budget %d allowed=%v err=%v", index, allowed, err)
		}
	}
}

func TestIntegration_RegistrationLifecycleTargetBudgetSurvivesIPRotation(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	limit := registration.Limit{Max: 3, Window: time.Minute}
	for _, check := range []struct {
		name string
		call func(context.Context, string, string, registration.Limit) (bool, time.Duration, error)
	}{
		{name: "verify", call: limiter.CheckRegistrationVerify},
		{name: "resend", call: limiter.CheckRegistrationResend},
	} {
		t.Run(check.name, func(t *testing.T) {
			target := registration.HashAbuseValue("one-stable-target-" + check.name)
			for attempt := 0; attempt < limit.Max; attempt++ {
				allowed, _, err := check.call(t.Context(), fmt.Sprintf("198.51.100.%d", attempt+1), target, limit)
				if err != nil || !allowed {
					t.Fatalf("attempt %d allowed=%v err=%v", attempt, allowed, err)
				}
			}
			allowed, retry, err := check.call(t.Context(), "203.0.113.250", target, limit)
			if err != nil || allowed || retry <= 0 {
				t.Fatalf("rotated IP bypass: allowed=%v retry=%v err=%v", allowed, retry, err)
			}
		})
	}
}

func TestIntegration_RegistrationVerificationGlobalBudgetSurvivesTargetAndIPRotation(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	global := registration.AggregateRatePolicy{
		Burst: registration.Limit{Max: 4, Window: time.Minute}, Sustained: registration.Limit{Max: 100, Window: time.Hour},
	}
	allowedCount := 0
	for attempt := 0; attempt < 16; attempt++ {
		allowed, retry, err := limiter.CheckRegistrationVerifyWithGlobal(
			t.Context(), fmt.Sprintf("198.51.100.%d", attempt+1),
			registration.HashAbuseValue(fmt.Sprintf("rotating-user-%d", attempt)),
			registration.Limit{Max: 100, Window: time.Minute}, global,
		)
		if err != nil {
			t.Fatal(err)
		}
		if allowed {
			allowedCount++
		} else if retry <= 0 {
			t.Fatalf("attempt %d denied without retry", attempt)
		}
	}
	if allowedCount != global.Burst.Max {
		t.Fatalf("fully rotated verification calls allowed=%d, want %d", allowedCount, global.Burst.Max)
	}
}

func TestIntegration_RegistrationCreateClientBudgetSurvivesEmailRotation(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	policy := registration.CreateRatePolicy{
		ClientIP:    registration.Limit{Max: 2, Window: time.Minute},
		ClientNet:   registration.Limit{Max: 20, Window: time.Minute},
		Email:       registration.Limit{Max: 5, Window: time.Minute},
		ClientEmail: registration.Limit{Max: 2, Window: time.Minute},
		IPv4NetBits: 24, IPv6NetBits: 56,
	}
	ctx := context.Background()
	for _, emailHash := range []string{"email-a", "email-b"} {
		allowed, _, err := limiter.CheckRegistrationCreate(ctx, "203.0.113.7", "203.0.113.0/24", emailHash, policy)
		if err != nil || !allowed {
			t.Fatalf("initial email %q allowed=%v err=%v", emailHash, allowed, err)
		}
	}
	allowed, retry, err := limiter.CheckRegistrationCreate(ctx, "203.0.113.7", "203.0.113.0/24", "email-c", policy)
	if err != nil || allowed || retry <= 0 {
		t.Fatalf("rotated email bypassed client budget: allowed=%v retry=%v err=%v", allowed, retry, err)
	}
	buckets := limiter.registrationCreateBuckets("203.0.113.7", "203.0.113.0/24", "email-c", policy)
	if ipCount, err := client.RDB().Get(ctx, buckets[0].key).Int(); err != nil || ipCount != 2 {
		t.Fatalf("denied request changed saturated client budget: count=%d err=%v", ipCount, err)
	}
	for _, bucket := range buckets[2:] {
		if _, err := client.RDB().Get(ctx, bucket.key).Result(); !errors.Is(err, goredis.Nil) {
			t.Fatalf("denied request poisoned rotated-email bucket %q: err=%v", bucket.key, err)
		}
	}
}

func TestIntegration_RegistrationMailboxFamilyBudgetSurvivesAliasAndFullRotation(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	policy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
		Email: registration.Limit{Max: 100, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
		MailboxFamily: registration.Limit{Max: 3, Window: 24 * time.Hour},
		Global:        registration.AggregateRatePolicy{Burst: registration.Limit{Max: 100, Window: time.Minute}, Sustained: registration.Limit{Max: 100, Window: time.Hour}},
	}
	familyHash := registration.HashAbuseValue(registration.MailboxFamilyRateIdentity("victim.name@gmail.com"))
	for attempt := 0; attempt < 4; attempt++ {
		subject := registration.CreateRateSubject{
			ClientIP: fmt.Sprintf("198.51.100.%d", attempt+1), ClientNetwork: fmt.Sprintf("198.51.%d.0/24", attempt+1),
			EmailHash:         registration.HashAbuseValue(fmt.Sprintf("victim.name+campaign-%d@gmail.com", attempt)),
			MailboxFamilyHash: familyHash, FormIntentHash: registration.HashAbuseValue(fmt.Sprintf("mailbox-family-intent-%d", attempt)),
		}
		outcome, retry, err := limiter.CheckRegistrationCreateChainWithCohorts(t.Context(), subject, policy, 20*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if attempt < policy.MailboxFamily.Max && outcome != registration.CreateChainRateFirstAllowed {
			t.Fatalf("alias %d outcome=%v retry=%v, want allowed", attempt, outcome, retry)
		}
		if attempt == policy.MailboxFamily.Max && (outcome != registration.CreateChainRateLimited || retry <= 0) {
			t.Fatalf("rotated alias outcome=%v retry=%v, want family denial", outcome, retry)
		}
	}
}

func TestIntegration_RegistrationFormIntentBudgetIsAtomicAndIndependent(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()
	intentLimit := registration.Limit{Max: 2, Window: time.Minute}
	networkHash := registration.HashAbuseValue("203.0.113.0/24")
	for attempt := 1; attempt <= 2; attempt++ {
		allowed, retry, err := limiter.CheckRegistrationFormIntent(ctx, networkHash, intentLimit)
		if err != nil || !allowed || retry != 0 {
			t.Fatalf("form-intent attempt %d allowed=%v retry=%v err=%v", attempt, allowed, retry, err)
		}
	}
	allowed, retry, err := limiter.CheckRegistrationFormIntent(ctx, networkHash, intentLimit)
	if err != nil || allowed || retry <= 0 {
		t.Fatalf("exhausted form-intent budget allowed=%v retry=%v err=%v", allowed, retry, err)
	}

	createPolicy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 1, Window: time.Minute}, ClientNet: registration.Limit{Max: 1, Window: time.Minute},
		Email: registration.Limit{Max: 1, Window: time.Minute}, ClientEmail: registration.Limit{Max: 1, Window: time.Minute},
		IPv4NetBits: 24, IPv6NetBits: 56,
	}
	allowed, retry, err = limiter.CheckRegistrationCreate(ctx, "203.0.113.7", "203.0.113.0/24", registration.HashAbuseValue("person@example.com"), createPolicy)
	if err != nil || !allowed || retry != 0 {
		t.Fatalf("form-intent budget consumed create budget: allowed=%v retry=%v err=%v", allowed, retry, err)
	}
}

func TestIntegration_RegistrationFormIntentGlobalBudgetSurvivesFullRotation(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	policy := registration.AggregateRatePolicy{
		Burst:     registration.Limit{Max: 5, Window: time.Minute},
		Sustained: registration.Limit{Max: 100, Window: time.Hour},
	}
	allowedCount := 0
	for attempt := 0; attempt < 20; attempt++ {
		allowed, retry, err := limiter.CheckRegistrationFormIntentGlobal(
			t.Context(), registration.HashAbuseValue(fmt.Sprintf("rotating-network-%d", attempt)),
			registration.Limit{Max: 100, Window: time.Minute}, policy,
		)
		if err != nil {
			t.Fatal(err)
		}
		if allowed {
			allowedCount++
		} else if retry <= 0 {
			t.Fatalf("attempt %d denied without retry", attempt)
		}
	}
	if allowedCount != policy.Burst.Max {
		t.Fatalf("fully rotated form intents allowed=%d, want %d", allowedCount, policy.Burst.Max)
	}
}

func TestIntegration_RiskRegistrationIssueGlobalBudgetSurvivesFullRotation(t *testing.T) {
	client := setupTestRedis(t)
	store := NewRiskStore(client)
	policy := riskdefense.RegistrationIssueRatePolicy{
		Device:          riskdefense.RateLimit{Max: 100, Window: time.Minute},
		Network:         riskdefense.RateLimit{Max: 100, Window: time.Minute},
		GlobalBurst:     riskdefense.RateLimit{Max: 4, Window: time.Minute},
		GlobalSustained: riskdefense.RateLimit{Max: 100, Window: time.Hour},
	}
	allowedCount := 0
	for attempt := 0; attempt < 16; attempt++ {
		allowed, retry, err := store.CheckRegistrationIssueRate(
			t.Context(), session.HashToken(fmt.Sprintf("rotating-device-%d", attempt)),
			session.HashToken(fmt.Sprintf("rotating-risk-network-%d", attempt)), policy,
		)
		if err != nil {
			t.Fatal(err)
		}
		if allowed {
			allowedCount++
		} else if retry <= 0 {
			t.Fatalf("attempt %d denied without retry", attempt)
		}
	}
	if allowedCount != policy.GlobalBurst.Max {
		t.Fatalf("fully rotated CAPTCHA issues allowed=%d, want %d", allowedCount, policy.GlobalBurst.Max)
	}
}

func TestIntegration_RegistrationCreateChainIsAtomicBoundAndSingleReplay(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()
	markerTTL := 20 * time.Minute
	policy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
		Email: registration.Limit{Max: 100, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
		IPv4NetBits: 24, IPv6NetBits: 56,
	}
	ip, network := "203.0.113.7", "203.0.113.0/24"
	emailHash := registration.HashAbuseValue("chain@example.com")
	intentHash := registration.HashAbuseValue("opaque-form-intent")

	type result struct {
		outcome registration.CreateChainRateOutcome
		err     error
	}
	results := make(chan result, 16)
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			outcome, _, err := limiter.CheckRegistrationCreateChain(ctx, ip, network, emailHash, intentHash, policy, markerTTL)
			results <- result{outcome: outcome, err: err}
		}()
	}
	wait.Wait()
	close(results)
	counts := map[registration.CreateChainRateOutcome]int{}
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent create-chain check: %v", result.err)
		}
		counts[result.outcome]++
	}
	if counts[registration.CreateChainRateFirstAllowed] != 1 || counts[registration.CreateChainRateReplayAllowed] != 1 || counts[registration.CreateChainRateReplayExhausted] != 14 {
		t.Fatalf("concurrent outcomes=%#v", counts)
	}
	for _, bucket := range limiter.registrationCreateBuckets(ip, network, emailHash, policy) {
		value, err := client.RDB().Get(ctx, bucket.key).Int()
		if err != nil || value != 1 {
			t.Fatalf("bucket %q count=%d err=%v, want exactly one charge", bucket.key, value, err)
		}
	}
	markerKey := limiter.registrationCreateChainKey(intentHash)
	marker, err := client.RDB().HGetAll(ctx, markerKey).Result()
	if err != nil || marker["uses"] != "2" || marker["binding"] != registrationCreateChainBinding(network, emailHash) {
		t.Fatalf("marker=%#v err=%v", marker, err)
	}
	markerText := markerKey + fmt.Sprint(marker)
	if strings.Contains(markerText, "opaque-form-intent") || strings.Contains(markerText, "chain@example.com") || strings.Contains(markerText, network) {
		t.Fatalf("create-chain marker leaked raw binding material: %q", markerText)
	}
	ttl, err := client.RDB().PTTL(ctx, markerKey).Result()
	if err != nil || ttl <= 0 || ttl > markerTTL {
		t.Fatalf("marker ttl=%v err=%v", ttl, err)
	}
}

func TestIntegration_RegistrationConflictRefundIsBoundIdempotentAndEmailOnly(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()
	policy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
		Email: registration.Limit{Max: 100, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
		IPv4NetBits: 24, IPv6NetBits: 56,
	}
	ip, network := "203.0.113.31", "203.0.113.0/24"
	emailHash := registration.HashAbuseValue("existing@example.com")
	intentHash := registration.HashAbuseValue("conflict-form-intent")
	legacyEmailHash := registration.HashAbuseValue("legacy-marker@example.com")
	legacyIntentHash := registration.HashAbuseValue("legacy-marker-intent")
	legacyMarkerKey := client.buildKey("rl:registration:create-chain:", "intent:", legacyIntentHash)
	legacyBinding := registrationCreateChainBinding(network, legacyEmailHash)
	if err := client.RDB().HSet(ctx, legacyMarkerKey, "binding", legacyBinding, "uses", "1").Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.RDB().Expire(ctx, legacyMarkerKey, 20*time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	legacyMarkerEmailKey := limiter.registrationCreateEmailKey(legacyEmailHash)
	if err := client.RDB().Set(ctx, legacyMarkerEmailKey, 1, 24*time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	if refunded, err := limiter.RefundRegistrationCreateEmail(ctx, network, legacyEmailHash, legacyIntentHash); err != nil || refunded {
		t.Fatalf("legacy marker crossed v2 refund boundary: refunded=%v err=%v", refunded, err)
	}
	if value, err := client.RDB().Get(ctx, legacyMarkerEmailKey).Int(); err != nil || value != 1 {
		t.Fatalf("legacy marker changed v2 email budget: value=%d err=%v", value, err)
	}

	oldEmailKey := client.buildKey(rateLimitRegistrationCreateSegment, "email:", emailHash)
	if err := client.RDB().Set(ctx, oldEmailKey, 4, 12*time.Hour).Err(); err != nil {
		t.Fatal(err)
	}

	outcome, _, err := limiter.CheckRegistrationCreateChain(ctx, ip, network, emailHash, intentHash, policy, 20*time.Minute)
	if err != nil || outcome != registration.CreateChainRateFirstAllowed {
		t.Fatalf("v2 chain was blocked by legacy email key: outcome=%v err=%v", outcome, err)
	}
	buckets := limiter.registrationCreateBuckets(ip, network, emailHash, policy)
	emailKey := limiter.registrationCreateEmailKey(emailHash)
	if emailKey == oldEmailKey {
		t.Fatalf("v2 email key reused legacy namespace: %q", emailKey)
	}
	if value, err := client.RDB().Incr(ctx, emailKey).Result(); err != nil || value != 2 {
		t.Fatalf("prepare shared email count: value=%d err=%v", value, err)
	}

	if refunded, err := limiter.RefundRegistrationCreateEmail(ctx, "198.51.100.0/24", emailHash, intentHash); err != nil || refunded {
		t.Fatalf("mismatched binding refunded=%v err=%v", refunded, err)
	}
	missingIntent := registration.HashAbuseValue("missing-form-intent")
	if refunded, err := limiter.RefundRegistrationCreateEmail(ctx, network, emailHash, missingIntent); err != nil || refunded {
		t.Fatalf("missing marker refunded=%v err=%v", refunded, err)
	}

	type refundResult struct {
		refunded bool
		err      error
	}
	results := make(chan refundResult, 16)
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			refunded, refundErr := limiter.RefundRegistrationCreateEmail(ctx, network, emailHash, intentHash)
			results <- refundResult{refunded: refunded, err: refundErr}
		}()
	}
	wait.Wait()
	close(results)
	refunds := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent refund: %v", result.err)
		}
		if result.refunded {
			refunds++
		}
	}
	if refunds != 1 {
		t.Fatalf("successful refunds=%d, want exactly one", refunds)
	}
	if value, err := client.RDB().Get(ctx, emailKey).Int(); err != nil || value != 1 {
		t.Fatalf("email count=%d err=%v, want one remaining charge", value, err)
	}
	for index, bucket := range buckets {
		if index == 2 {
			continue
		}
		if value, err := client.RDB().Get(ctx, bucket.key).Int(); err != nil || value != 1 {
			t.Fatalf("non-email bucket %q count=%d err=%v", bucket.key, value, err)
		}
	}
	if value, err := client.RDB().Get(ctx, oldEmailKey).Int(); err != nil || value != 4 {
		t.Fatalf("legacy email key changed: value=%d err=%v", value, err)
	}
	marker, err := client.RDB().HGetAll(ctx, limiter.registrationCreateChainKey(intentHash)).Result()
	if err != nil || marker["email_refunded"] != "1" {
		t.Fatalf("refund marker=%#v err=%v", marker, err)
	}

	deleteEmailHash := registration.HashAbuseValue("single-charge@example.com")
	deleteIntentHash := registration.HashAbuseValue("single-charge-intent")
	outcome, _, err = limiter.CheckRegistrationCreateChain(ctx, ip, network, deleteEmailHash, deleteIntentHash, policy, 20*time.Minute)
	if err != nil || outcome != registration.CreateChainRateFirstAllowed {
		t.Fatalf("single-charge chain outcome=%v err=%v", outcome, err)
	}
	refunded, err := limiter.RefundRegistrationCreateEmail(ctx, network, deleteEmailHash, deleteIntentHash)
	if err != nil || !refunded {
		t.Fatalf("single-charge refund=%v err=%v", refunded, err)
	}
	if _, err := client.RDB().Get(ctx, limiter.registrationCreateEmailKey(deleteEmailHash)).Result(); !errors.Is(err, goredis.Nil) {
		t.Fatalf("single-charge email key survived refund: err=%v", err)
	}
}

func TestIntegration_RegistrationCohortRefundIsAtomicAcrossMultipleMXOperators(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()
	policy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
		Email: registration.Limit{Max: 100, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
		MailboxFamily:    registration.Limit{Max: 100, Window: 24 * time.Hour},
		Global:           registration.AggregateRatePolicy{Burst: registration.Limit{Max: 100, Window: time.Minute}, Sustained: registration.Limit{Max: 100, Window: time.Hour}},
		UnfamiliarDomain: registration.AggregateRatePolicy{Burst: registration.Limit{Max: 100, Window: time.Minute}, Sustained: registration.Limit{Max: 100, Window: time.Hour}},
		UnfamiliarMX:     registration.AggregateRatePolicy{Burst: registration.Limit{Max: 100, Window: time.Minute}, Sustained: registration.Limit{Max: 100, Window: time.Hour}},
	}
	subject := registration.CreateRateSubject{
		ClientIP: "203.0.113.61", ClientNetwork: "203.0.113.0/24",
		EmailHash: registration.HashAbuseValue("existing@rare.example"), DomainHash: registration.HashAbuseValue("rare.example"),
		MailboxFamilyHash: registration.HashAbuseValue("existing-family@example.com"),
		MXHashes:          []string{registration.HashAbuseValue("primary-operator.example"), registration.HashAbuseValue("backup-operator.example")},
		FormIntentHash:    registration.HashAbuseValue("multi-mx-refund-intent"),
	}
	var err error
	subject, err = normalizeRegistrationCreateMXCohorts(subject)
	if err != nil {
		t.Fatal(err)
	}
	outcome, _, err := limiter.CheckRegistrationCreateChainWithCohorts(ctx, subject, policy, 20*time.Minute)
	if err != nil || outcome != registration.CreateChainRateFirstAllowed {
		t.Fatalf("create outcome=%v err=%v", outcome, err)
	}
	refundableKeys := []string{limiter.registrationCreateEmailKey(subject.EmailHash)}
	refundableKeys = append(refundableKeys, limiter.registrationCreateMailboxFamilyKey(subject.MailboxFamilyHash))
	refundableKeys = append(refundableKeys, limiter.registrationDomainKeys(subject.DomainHash, policy.UnfamiliarDomain)...)
	for _, mxHash := range subject.MXHashes {
		refundableKeys = append(refundableKeys, limiter.registrationMXKeys(mxHash, policy.UnfamiliarMX)...)
	}
	for _, key := range refundableKeys {
		if value, err := client.RDB().Get(ctx, key).Int(); err != nil || value != 1 {
			t.Fatalf("initial refundable key %q count=%d err=%v", key, value, err)
		}
		if value, err := client.RDB().Incr(ctx, key).Result(); err != nil || value != 2 {
			t.Fatalf("prepare refundable key %q count=%d err=%v", key, value, err)
		}
	}

	type refundResult struct {
		refunded bool
		err      error
	}
	results := make(chan refundResult, 16)
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			refunded, refundErr := limiter.RefundRegistrationCreateCohorts(ctx, subject, policy)
			results <- refundResult{refunded: refunded, err: refundErr}
		}()
	}
	wait.Wait()
	close(results)
	refunds := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent multi-cohort refund: %v", result.err)
		}
		if result.refunded {
			refunds++
		}
	}
	if refunds != 1 {
		t.Fatalf("successful refunds=%d, want exactly one", refunds)
	}
	for _, key := range refundableKeys {
		if value, err := client.RDB().Get(ctx, key).Int(); err != nil || value != 1 {
			t.Fatalf("refunded key %q count=%d err=%v, want one remaining charge", key, value, err)
		}
	}
	marker, err := client.RDB().HGetAll(ctx, limiter.registrationCreateChainKey(subject.FormIntentHash)).Result()
	if err != nil || marker["email_refunded"] != "1" {
		t.Fatalf("refund marker=%#v err=%v", marker, err)
	}
}

func TestIntegration_RegistrationCreateMultiMXDoesNotChargePastSaturatedOperator(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()
	policy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
		Email: registration.Limit{Max: 100, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
		UnfamiliarMX: registration.AggregateRatePolicy{Burst: registration.Limit{Max: 1, Window: time.Minute}, Sustained: registration.Limit{Max: 1, Window: time.Hour}},
	}
	sharedMX := registration.HashAbuseValue("shared-operator.example")
	first := registration.CreateRateSubject{
		ClientIP: "203.0.113.70", ClientNetwork: "203.0.113.0/24", EmailHash: registration.HashAbuseValue("first@rare.example"),
		MXHashes: []string{sharedMX, registration.HashAbuseValue("first-backup.example")}, FormIntentHash: registration.HashAbuseValue("first-multi-mx-intent"),
	}
	if outcome, _, err := limiter.CheckRegistrationCreateChainWithCohorts(ctx, first, policy, 20*time.Minute); err != nil || outcome != registration.CreateChainRateFirstAllowed {
		t.Fatalf("first create outcome=%v err=%v", outcome, err)
	}
	freshMX := registration.HashAbuseValue("fresh-backup.example")
	second := registration.CreateRateSubject{
		ClientIP: "198.51.100.70", ClientNetwork: "198.51.100.0/24", EmailHash: registration.HashAbuseValue("second@other.example"),
		MXHashes: []string{freshMX, sharedMX}, FormIntentHash: registration.HashAbuseValue("second-multi-mx-intent"),
	}
	if outcome, retry, err := limiter.CheckRegistrationCreateChainWithCohorts(ctx, second, policy, 20*time.Minute); err != nil || outcome != registration.CreateChainRateLimited || retry <= 0 {
		t.Fatalf("second create outcome=%v retry=%v err=%v", outcome, retry, err)
	}
	for _, key := range limiter.registrationMXKeys(freshMX, policy.UnfamiliarMX) {
		if exists, err := client.RDB().Exists(ctx, key).Result(); err != nil || exists != 0 {
			t.Fatalf("denied request charged fresh MX key %q: exists=%d err=%v", key, exists, err)
		}
	}
	if exists, err := client.RDB().Exists(ctx, limiter.registrationCreateChainKey(second.FormIntentHash)).Result(); err != nil || exists != 0 {
		t.Fatalf("denied request created marker: exists=%d err=%v", exists, err)
	}
}

func TestIntegration_RegistrationCreateScriptsValidateCountersBeforeAnyWrite(t *testing.T) {
	t.Run("ordinary create", func(t *testing.T) {
		client := setupTestRedis(t)
		limiter := NewRateLimiter(client)
		ctx := context.Background()
		policy := registration.CreateRatePolicy{
			ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
			Email: registration.Limit{Max: 100, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
		}
		buckets := limiter.registrationCreateBuckets("203.0.113.80", "203.0.113.0/24", "email-scope", policy)
		corruptKey := buckets[len(buckets)-1].key
		if err := client.RDB().Set(ctx, corruptKey, "1e0", time.Hour).Err(); err != nil {
			t.Fatal(err)
		}
		if allowed, _, err := limiter.CheckRegistrationCreate(ctx, "203.0.113.80", "203.0.113.0/24", "email-scope", policy); err == nil || allowed {
			t.Fatalf("non-canonical counter create allowed=%v err=%v", allowed, err)
		}
		for _, bucket := range buckets[:len(buckets)-1] {
			if exists, err := client.RDB().Exists(ctx, bucket.key).Result(); err != nil || exists != 0 {
				t.Fatalf("earlier bucket %q changed: exists=%d err=%v", bucket.key, exists, err)
			}
		}
		if value, err := client.RDB().Get(ctx, corruptKey).Result(); err != nil || value != "1e0" {
			t.Fatalf("corrupt counter changed: value=%q err=%v", value, err)
		}
	})

	t.Run("browser chain with MX", func(t *testing.T) {
		client := setupTestRedis(t)
		limiter := NewRateLimiter(client)
		ctx := context.Background()
		policy := registration.CreateRatePolicy{
			ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
			Email: registration.Limit{Max: 100, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
			UnfamiliarMX: registration.AggregateRatePolicy{Burst: registration.Limit{Max: 100, Window: time.Minute}, Sustained: registration.Limit{Max: 100, Window: time.Hour}},
		}
		subject := registration.CreateRateSubject{
			ClientIP: "203.0.113.81", ClientNetwork: "203.0.113.0/24", EmailHash: registration.HashAbuseValue("person@rare.example"),
			MXHashes: []string{registration.HashAbuseValue("operator.example")}, FormIntentHash: registration.HashAbuseValue("non-canonical-chain-intent"),
		}
		buckets, err := limiter.registrationCreateBucketsWithCohorts(subject, policy)
		if err != nil {
			t.Fatal(err)
		}
		corruptKey := buckets[len(buckets)-1].key
		if err := client.RDB().Set(ctx, corruptKey, "1e0", time.Hour).Err(); err != nil {
			t.Fatal(err)
		}
		if outcome, _, err := limiter.CheckRegistrationCreateChainWithCohorts(ctx, subject, policy, 20*time.Minute); err == nil || outcome != registration.CreateChainRateUnknown {
			t.Fatalf("non-canonical chain outcome=%v err=%v", outcome, err)
		}
		for _, bucket := range buckets[:len(buckets)-1] {
			if exists, err := client.RDB().Exists(ctx, bucket.key).Result(); err != nil || exists != 0 {
				t.Fatalf("earlier bucket %q changed: exists=%d err=%v", bucket.key, exists, err)
			}
		}
		if exists, err := client.RDB().Exists(ctx, limiter.registrationCreateChainKey(subject.FormIntentHash)).Result(); err != nil || exists != 0 {
			t.Fatalf("failed chain created marker: exists=%d err=%v", exists, err)
		}
		if value, err := client.RDB().Get(ctx, corruptKey).Result(); err != nil || value != "1e0" {
			t.Fatalf("corrupt counter changed: value=%q err=%v", value, err)
		}
	})
}

func TestIntegration_RegistrationCohortRefundValidatesAllKeysBeforeMutation(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()
	policy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
		Email: registration.Limit{Max: 100, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
		UnfamiliarDomain: registration.AggregateRatePolicy{Burst: registration.Limit{Max: 100, Window: time.Minute}, Sustained: registration.Limit{Max: 100, Window: time.Hour}},
		UnfamiliarMX:     registration.AggregateRatePolicy{Burst: registration.Limit{Max: 100, Window: time.Minute}, Sustained: registration.Limit{Max: 100, Window: time.Hour}},
	}
	subject := registration.CreateRateSubject{
		ClientIP: "203.0.113.62", ClientNetwork: "203.0.113.0/24",
		EmailHash: registration.HashAbuseValue("existing@rare.example"), DomainHash: registration.HashAbuseValue("rare.example"),
		MXHashes:       []string{registration.HashAbuseValue("primary-operator.example"), registration.HashAbuseValue("backup-operator.example")},
		FormIntentHash: registration.HashAbuseValue("corrupt-multi-mx-refund-intent"),
	}
	var err error
	subject, err = normalizeRegistrationCreateMXCohorts(subject)
	if err != nil {
		t.Fatal(err)
	}
	outcome, _, err := limiter.CheckRegistrationCreateChainWithCohorts(ctx, subject, policy, 20*time.Minute)
	if err != nil || outcome != registration.CreateChainRateFirstAllowed {
		t.Fatalf("create outcome=%v err=%v", outcome, err)
	}
	earlierKeys := []string{limiter.registrationCreateEmailKey(subject.EmailHash)}
	earlierKeys = append(earlierKeys, limiter.registrationDomainKeys(subject.DomainHash, policy.UnfamiliarDomain)...)
	for _, mxHash := range subject.MXHashes[:len(subject.MXHashes)-1] {
		earlierKeys = append(earlierKeys, limiter.registrationMXKeys(mxHash, policy.UnfamiliarMX)...)
	}
	lastMXKeys := limiter.registrationMXKeys(subject.MXHashes[len(subject.MXHashes)-1], policy.UnfamiliarMX)
	corruptKey := lastMXKeys[len(lastMXKeys)-1]
	earlierKeys = append(earlierKeys, lastMXKeys[:len(lastMXKeys)-1]...)
	if err := client.RDB().Set(ctx, corruptKey, "broken", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	if refunded, err := limiter.RefundRegistrationCreateCohorts(ctx, subject, policy); err == nil || refunded {
		t.Fatalf("corrupt cohort refund=%v err=%v, want atomic failure", refunded, err)
	}
	for _, key := range earlierKeys {
		if value, err := client.RDB().Get(ctx, key).Int(); err != nil || value != 1 {
			t.Fatalf("earlier key %q changed after failed refund: count=%d err=%v", key, value, err)
		}
	}
	if value, err := client.RDB().Get(ctx, corruptKey).Result(); err != nil || value != "broken" {
		t.Fatalf("corrupt key changed: value=%q err=%v", value, err)
	}
	marker, err := client.RDB().HGetAll(ctx, limiter.registrationCreateChainKey(subject.FormIntentHash)).Result()
	if err != nil || marker["email_refunded"] != "" {
		t.Fatalf("failed refund marked completion: marker=%#v err=%v", marker, err)
	}

	if err := client.RDB().Set(ctx, corruptKey, 1, 0).Err(); err != nil {
		t.Fatal(err)
	}
	if refunded, err := limiter.RefundRegistrationCreateCohorts(ctx, subject, policy); err == nil || refunded {
		t.Fatalf("missing-TTL cohort refund=%v err=%v, want atomic failure", refunded, err)
	}
	for _, key := range earlierKeys {
		if value, err := client.RDB().Get(ctx, key).Int(); err != nil || value != 1 {
			t.Fatalf("earlier key %q changed after missing-TTL refund: count=%d err=%v", key, value, err)
		}
	}
	marker, err = client.RDB().HGetAll(ctx, limiter.registrationCreateChainKey(subject.FormIntentHash)).Result()
	if err != nil || marker["email_refunded"] != "" {
		t.Fatalf("missing-TTL refund marked completion: marker=%#v err=%v", marker, err)
	}
}

func TestIntegration_RegistrationCreateChainConcurrentLimitNeverPoisonsDeniedBuckets(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()
	const attempts = 16
	const clientLimit = 3
	policy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: clientLimit, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
		Email: registration.Limit{Max: 10, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 10, Window: time.Hour},
		IPv4NetBits: 24, IPv6NetBits: 56,
	}
	ip, network := "203.0.113.41", "203.0.113.0/24"
	type attemptResult struct {
		index   int
		outcome registration.CreateChainRateOutcome
		err     error
	}
	results := make(chan attemptResult, attempts)
	var wait sync.WaitGroup
	for index := range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			emailHash := registration.HashAbuseValue(fmt.Sprintf("concurrent-%d@example.com", index))
			intentHash := registration.HashAbuseValue(fmt.Sprintf("concurrent-intent-%d", index))
			outcome, _, err := limiter.CheckRegistrationCreateChain(ctx, ip, network, emailHash, intentHash, policy, 20*time.Minute)
			results <- attemptResult{index: index, outcome: outcome, err: err}
		}()
	}
	wait.Wait()
	close(results)
	allowedIndexes := make(map[int]struct{}, clientLimit)
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent attempt %d: %v", result.index, result.err)
		}
		switch result.outcome {
		case registration.CreateChainRateFirstAllowed:
			allowedIndexes[result.index] = struct{}{}
		case registration.CreateChainRateLimited:
		default:
			t.Fatalf("concurrent attempt %d unexpected outcome=%v", result.index, result.outcome)
		}
	}
	if len(allowedIndexes) != clientLimit {
		t.Fatalf("allowed attempts=%d, want %d", len(allowedIndexes), clientLimit)
	}
	ipKey := limiter.registrationCreateBuckets(ip, network, registration.HashAbuseValue("unused@example.com"), policy)[0].key
	if value, err := client.RDB().Get(ctx, ipKey).Int(); err != nil || value != clientLimit {
		t.Fatalf("client bucket count=%d err=%v, want %d", value, err, clientLimit)
	}
	for index := range attempts {
		emailHash := registration.HashAbuseValue(fmt.Sprintf("concurrent-%d@example.com", index))
		intentHash := registration.HashAbuseValue(fmt.Sprintf("concurrent-intent-%d", index))
		_, wasAllowed := allowedIndexes[index]
		expected := int64(0)
		if wasAllowed {
			expected = 2
		}
		keys := []string{
			limiter.registrationCreateEmailKey(emailHash),
			limiter.registrationCreateBuckets(ip, network, emailHash, policy)[3].key,
		}
		if count, err := client.RDB().Exists(ctx, keys...).Result(); err != nil || count != expected {
			t.Fatalf("attempt %d allowed=%v charged keys=%d err=%v, want %d", index, wasAllowed, count, err, expected)
		}
		markerExists, err := client.RDB().Exists(ctx, limiter.registrationCreateChainKey(intentHash)).Result()
		expectedMarker := int64(0)
		if wasAllowed {
			expectedMarker = 1
		}
		if err != nil || markerExists != expectedMarker {
			t.Fatalf("attempt %d allowed=%v marker=%d err=%v", index, wasAllowed, markerExists, err)
		}
	}
}

func TestIntegration_RegistrationCreateChainRejectsBindingChangesAndDoesNotMarkDeniedTokens(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()
	markerTTL := 20 * time.Minute
	policy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 1, Window: time.Hour}, ClientNet: registration.Limit{Max: 10, Window: time.Hour},
		Email: registration.Limit{Max: 10, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 10, Window: time.Hour},
		IPv4NetBits: 24, IPv6NetBits: 56,
	}
	ip, network := "203.0.113.8", "203.0.113.0/24"
	firstEmail := registration.HashAbuseValue("first@example.com")
	firstIntent := registration.HashAbuseValue("first-form-intent")
	outcome, _, err := limiter.CheckRegistrationCreateChain(ctx, ip, network, firstEmail, firstIntent, policy, markerTTL)
	if err != nil || outcome != registration.CreateChainRateFirstAllowed {
		t.Fatalf("first outcome=%v err=%v", outcome, err)
	}
	outcome, _, err = limiter.CheckRegistrationCreateChain(ctx, ip, network, registration.HashAbuseValue("changed@example.com"), firstIntent, policy, markerTTL)
	if err != nil || outcome != registration.CreateChainRateBindingMismatch {
		t.Fatalf("email-binding outcome=%v err=%v", outcome, err)
	}
	outcome, _, err = limiter.CheckRegistrationCreateChain(ctx, ip, "198.51.100.0/24", firstEmail, firstIntent, policy, markerTTL)
	if err != nil || outcome != registration.CreateChainRateBindingMismatch {
		t.Fatalf("network-binding outcome=%v err=%v", outcome, err)
	}

	deniedIntent := registration.HashAbuseValue("denied-form-intent")
	deniedEmail := registration.HashAbuseValue("second@example.com")
	outcome, retry, err := limiter.CheckRegistrationCreateChain(ctx, ip, network, deniedEmail, deniedIntent, policy, markerTTL)
	if err != nil || outcome != registration.CreateChainRateLimited || retry <= 0 {
		t.Fatalf("denied outcome=%v retry=%v err=%v", outcome, retry, err)
	}
	exists, err := client.RDB().Exists(ctx, limiter.registrationCreateChainKey(deniedIntent)).Result()
	if err != nil || exists != 0 {
		t.Fatalf("rate-denied arbitrary token created marker: exists=%d err=%v", exists, err)
	}
	for index, bucket := range limiter.registrationCreateBuckets(ip, network, deniedEmail, policy) {
		value, getErr := client.RDB().Get(ctx, bucket.key).Int()
		if index == 0 || index == 1 {
			if getErr != nil || value != 1 {
				t.Fatalf("existing shared bucket %q count=%d err=%v, want unchanged", bucket.key, value, getErr)
			}
			continue
		}
		if !errors.Is(getErr, goredis.Nil) {
			t.Fatalf("denied request poisoned bucket %q: count=%d err=%v", bucket.key, value, getErr)
		}
	}
}

func TestIntegration_RegistrationCohortBudgetsStopFullProxyAndMailboxRotation(t *testing.T) {
	tests := []struct {
		name        string
		attempts    int
		wantAllowed int
		subject     func(int) registration.CreateRateSubject
		policy      registration.CreateRatePolicy
	}{
		{
			name: "global survives complete rotation", attempts: 48, wantAllowed: 5,
			policy: registration.CreateRatePolicy{
				ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
				Email: registration.Limit{Max: 100, Window: time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
				Global: registration.AggregateRatePolicy{Burst: registration.Limit{Max: 5, Window: time.Minute}, Sustained: registration.Limit{Max: 100, Window: time.Hour}},
			},
			subject: func(index int) registration.CreateRateSubject {
				return registration.CreateRateSubject{
					ClientIP: fmt.Sprintf("198.51.%d.%d", index/250, index%250+1), ClientNetwork: fmt.Sprintf("198.51.%d.0/24", index),
					EmailHash:      registration.HashAbuseValue(fmt.Sprintf("person-%d@domain-%d.example", index, index)),
					FormIntentHash: registration.HashAbuseValue(fmt.Sprintf("intent-%d", index)),
				}
			},
		},
		{
			name: "one unfamiliar domain survives proxy rotation", attempts: 32, wantAllowed: 3,
			policy: registration.CreateRatePolicy{
				ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
				Email: registration.Limit{Max: 100, Window: time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
				UnfamiliarDomain: registration.AggregateRatePolicy{Burst: registration.Limit{Max: 3, Window: time.Minute}, Sustained: registration.Limit{Max: 10, Window: time.Hour}},
			},
			subject: func(index int) registration.CreateRateSubject {
				return registration.CreateRateSubject{
					ClientIP: fmt.Sprintf("203.0.%d.%d", index/250, index%250+1), ClientNetwork: fmt.Sprintf("203.0.%d.0/24", index),
					EmailHash: registration.HashAbuseValue(fmt.Sprintf("person-%d@rare.example", index)), DomainHash: registration.HashAbuseValue("rare.example"),
					FormIntentHash: registration.HashAbuseValue(fmt.Sprintf("domain-intent-%d", index)),
				}
			},
		},
		{
			name: "rotating domains on one unfamiliar MX", attempts: 32, wantAllowed: 4,
			policy: registration.CreateRatePolicy{
				ClientIP: registration.Limit{Max: 100, Window: time.Hour}, ClientNet: registration.Limit{Max: 100, Window: time.Hour},
				Email: registration.Limit{Max: 100, Window: time.Hour}, ClientEmail: registration.Limit{Max: 100, Window: time.Hour},
				UnfamiliarMX: registration.AggregateRatePolicy{Burst: registration.Limit{Max: 4, Window: time.Minute}, Sustained: registration.Limit{Max: 20, Window: time.Hour}},
			},
			subject: func(index int) registration.CreateRateSubject {
				return registration.CreateRateSubject{
					ClientIP: fmt.Sprintf("192.0.%d.%d", index/250, index%250+1), ClientNetwork: fmt.Sprintf("192.0.%d.0/24", index),
					EmailHash: registration.HashAbuseValue(fmt.Sprintf("person@rare-%d.example", index)), MXHashes: []string{registration.HashAbuseValue("one-mail-operator.example")},
					FormIntentHash: registration.HashAbuseValue(fmt.Sprintf("mx-intent-%d", index)),
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := setupTestRedis(t)
			limiter := NewRateLimiter(client)
			results := make(chan registration.CreateChainRateOutcome, test.attempts)
			var wait sync.WaitGroup
			for index := range test.attempts {
				wait.Add(1)
				go func() {
					defer wait.Done()
					outcome, _, err := limiter.CheckRegistrationCreateChainWithCohorts(t.Context(), test.subject(index), test.policy, 20*time.Minute)
					if err != nil {
						t.Errorf("attempt %d: %v", index, err)
						return
					}
					results <- outcome
				}()
			}
			wait.Wait()
			close(results)
			allowed := 0
			for outcome := range results {
				if outcome == registration.CreateChainRateFirstAllowed {
					allowed++
				} else if outcome != registration.CreateChainRateLimited {
					t.Fatalf("unexpected outcome = %v", outcome)
				}
			}
			if allowed != test.wantAllowed {
				t.Fatalf("allowed = %d, want %d", allowed, test.wantAllowed)
			}
		})
	}
}

func TestIntegration_WeChatRegistrationProofClaimIsAtomicGlobalAndIPBounded(t *testing.T) {
	client := setupTestRedis(t)
	limiter := NewRateLimiter(client)
	ctx := context.Background()
	window := time.Minute
	claim := func(ip, loginCode, phoneCode string, limit int) (bool, time.Duration, error) {
		return limiter.ClaimWeChatRegistrationProofs(
			ctx, ip, registration.HashAbuseValue(loginCode), registration.HashAbuseValue(phoneCode), limit, window,
		)
	}

	for _, pair := range [][2]string{{"login-one", "phone-one"}, {"login-two", "phone-two"}} {
		allowed, retry, err := claim("203.0.113.20", pair[0], pair[1], 2)
		if err != nil || !allowed || retry != 0 {
			t.Fatalf("initial proof pair=%v allowed=%v retry=%v err=%v", pair, allowed, retry, err)
		}
	}
	thirdLogin := registration.HashAbuseValue("login-three")
	thirdPhone := registration.HashAbuseValue("phone-three")
	allowed, retry, err := limiter.ClaimWeChatRegistrationProofs(ctx, "203.0.113.20", thirdLogin, thirdPhone, 2, window)
	if err != nil || allowed || retry <= 0 {
		t.Fatalf("IP overflow allowed=%v retry=%v err=%v", allowed, retry, err)
	}
	thirdKeys := limiter.wechatRegistrationProofKeys("203.0.113.20", thirdLogin, thirdPhone)
	exists, err := client.RDB().Exists(ctx, thirdKeys[1:]...).Result()
	if err != nil || exists != 0 {
		t.Fatalf("IP-denied arbitrary codes created proof keys: exists=%d err=%v", exists, err)
	}
	ipCount, err := client.RDB().Get(ctx, thirdKeys[0]).Int()
	if err != nil || ipCount != 3 {
		t.Fatalf("proof IP counter=%d err=%v, want 3", ipCount, err)
	}

	allowed, retry, err = claim("198.51.100.30", "login-one", "phone-one", 2)
	if err != nil || allowed || retry <= 0 {
		t.Fatalf("global cross-IP replay allowed=%v retry=%v err=%v", allowed, retry, err)
	}

	const attempts = 24
	type claimResult struct {
		allowed bool
		err     error
	}
	results := make(chan claimResult, attempts)
	var wait sync.WaitGroup
	for index := 0; index < attempts; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			allowed, _, err := claim(fmt.Sprintf("192.0.2.%d", index+1), "concurrent-login", "concurrent-phone", 2)
			results <- claimResult{allowed: allowed, err: err}
		}(index)
	}
	wait.Wait()
	close(results)
	allowedCount := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent proof claim: %v", result.err)
		}
		if result.allowed {
			allowedCount++
		}
	}
	if allowedCount != 1 {
		t.Fatalf("concurrent proof claim allowed=%d, want 1", allowedCount)
	}

	keys, _, err := client.RDB().Scan(ctx, 0, client.KeyPrefix()+"rl:wechat:*", 200).Result()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(keys, " ")
	for _, rawCode := range []string{"login-one", "phone-one", "login-three", "phone-three", "concurrent-login", "concurrent-phone"} {
		if strings.Contains(joined, rawCode) {
			t.Fatalf("raw WeChat code leaked into Redis key: %q", rawCode)
		}
	}
}

func TestIntegration_RiskStoreRegistrationChallengeReservationIsAtomic(t *testing.T) {
	client := setupTestRedis(t)
	store := NewRiskStore(client)
	ctx := context.Background()
	scopeHash := session.HashToken("registration-scope-concurrent")

	const workers = 8
	type outcome struct {
		challengeHash string
		acquired      bool
		retry         time.Duration
		err           error
	}
	outcomes := make(chan outcome, workers)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		challengeHash := session.HashToken(fmt.Sprintf("registration-challenge-concurrent-%d", worker))
		go func() {
			defer wg.Done()
			acquired, retry, err := store.ReserveRegistrationChallenge(ctx, scopeHash, challengeHash, 5*time.Second)
			outcomes <- outcome{challengeHash: challengeHash, acquired: acquired, retry: retry, err: err}
		}()
	}
	wg.Wait()
	close(outcomes)

	var winner string
	for result := range outcomes {
		if result.err != nil {
			t.Fatalf("reserve %s: %v", result.challengeHash, result.err)
		}
		if result.acquired {
			if winner != "" {
				t.Fatalf("multiple reservation winners: %s and %s", winner, result.challengeHash)
			}
			if result.retry != 0 {
				t.Errorf("winner retry=%v, want 0", result.retry)
			}
			winner = result.challengeHash
			continue
		}
		if result.retry <= 0 {
			t.Errorf("loser retry=%v, want positive active-lease TTL", result.retry)
		}
	}
	if winner == "" {
		t.Fatal("no registration reservation winner")
	}

	record := riskdefense.ChallengeRecord{
		Operation:      riskdefense.OperationRegistration,
		Level:          riskdefense.LevelHigh,
		Method:         riskdefense.MethodInteractiveCAPTCHA,
		DeviceIDHash:   session.HashToken("registration-device-concurrent"),
		UserAgentHash:  session.HashToken("registration-ua-concurrent"),
		IdentifierHash: session.HashToken("registration-identifier-concurrent"),
		CreatedAt:      time.Now().UTC(),
	}
	if err := store.FinalizeRegistrationChallenge(ctx, scopeHash, winner, record, 5*time.Second); err != nil {
		t.Fatalf("finalize reservation winner: %v", err)
	}
	got, err := store.ClaimChallenge(ctx, winner, "registration-claim-concurrent")
	if err != nil {
		t.Fatalf("claim finalized challenge: %v", err)
	}
	if got.Operation != record.Operation || got.DeviceIDHash != record.DeviceIDHash || got.IdentifierHash != record.IdentifierHash {
		t.Fatalf("claimed challenge=%+v, want finalized binding=%+v", got, record)
	}
	if err := store.ConsumeRegistrationChallenge(ctx, winner, "registration-claim-concurrent", scopeHash); err != nil {
		t.Fatalf("consume finalized registration challenge: %v", err)
	}
	if exists, err := client.RDB().Exists(ctx, client.buildKey(riskRegistrationActiveChallengeSegment, scopeHash)).Result(); err != nil || exists != 0 {
		t.Fatalf("active scope after consume exists=%d err=%v, want absent", exists, err)
	}
	if acquired, retry, err := store.ReserveRegistrationChallenge(ctx, scopeHash, session.HashToken("registration-challenge-after-consume"), time.Second); err != nil || !acquired || retry != 0 {
		t.Fatalf("reserve after consume acquired=%v retry=%v err=%v", acquired, retry, err)
	}
}

func TestIntegration_RiskStoreRegistrationChallengeOwnerIsolation(t *testing.T) {
	client := setupTestRedis(t)
	store := NewRiskStore(client)
	ctx := context.Background()
	scopeHash := session.HashToken("registration-scope-owner")
	ownerHash := session.HashToken("registration-challenge-owner")
	foreignHash := session.HashToken("registration-challenge-foreign")

	if acquired, _, err := store.ReserveRegistrationChallenge(ctx, scopeHash, ownerHash, 5*time.Second); err != nil || !acquired {
		t.Fatalf("reserve owner acquired=%v err=%v", acquired, err)
	}
	record := riskdefense.ChallengeRecord{
		Operation:      riskdefense.OperationRegistration,
		Level:          riskdefense.LevelHigh,
		Method:         riskdefense.MethodInteractiveCAPTCHA,
		DeviceIDHash:   session.HashToken("registration-device-owner"),
		UserAgentHash:  session.HashToken("registration-ua-owner"),
		IdentifierHash: session.HashToken("registration-identifier-owner"),
		CreatedAt:      time.Now().UTC(),
	}
	if err := store.FinalizeRegistrationChallenge(ctx, scopeHash, foreignHash, record, 5*time.Second); !errors.Is(err, riskdefense.ErrChallengeNotHeld) {
		t.Fatalf("foreign finalize err=%v, want ErrChallengeNotHeld", err)
	}
	if err := store.ReleaseRegistrationChallenge(ctx, scopeHash, foreignHash); !errors.Is(err, riskdefense.ErrChallengeNotHeld) {
		t.Fatalf("foreign release err=%v, want ErrChallengeNotHeld", err)
	}
	activeKey := client.buildKey(riskRegistrationActiveChallengeSegment, scopeHash)
	if active, err := client.RDB().Get(ctx, activeKey).Result(); err != nil || active != ownerHash {
		t.Fatalf("active owner after foreign operations=%q err=%v, want %q", active, err, ownerHash)
	}
	if err := store.FinalizeRegistrationChallenge(ctx, scopeHash, ownerHash, record, 5*time.Second); err != nil {
		t.Fatalf("owner finalize: %v", err)
	}
	if _, err := store.ClaimChallenge(ctx, ownerHash, "registration-claim-owner"); err != nil {
		t.Fatalf("claim owner challenge: %v", err)
	}
	if err := client.RDB().Set(ctx, activeKey, foreignHash, 5*time.Second).Err(); err != nil {
		t.Fatalf("install newer active owner: %v", err)
	}
	if err := store.ConsumeRegistrationChallenge(ctx, ownerHash, "registration-claim-owner", scopeHash); err != nil {
		t.Fatalf("consume stale challenge: %v", err)
	}
	if active, err := client.RDB().Get(ctx, activeKey).Result(); err != nil || active != foreignHash {
		t.Fatalf("stale consume changed newer owner=%q err=%v, want %q", active, err, foreignHash)
	}
}

func TestIntegration_RiskStoreRegistrationChallengeExpiryAllowsSafeReissue(t *testing.T) {
	client := setupTestRedis(t)
	store := NewRiskStore(client)
	ctx := context.Background()
	scopeHash := session.HashToken("registration-scope-expiry")
	firstHash := session.HashToken("registration-challenge-expiry-first")
	secondHash := session.HashToken("registration-challenge-expiry-second")

	if acquired, _, err := store.ReserveRegistrationChallenge(ctx, scopeHash, firstHash, 3*time.Second); err != nil || !acquired {
		t.Fatalf("reserve first acquired=%v err=%v", acquired, err)
	}
	record := riskdefense.ChallengeRecord{
		Operation:      riskdefense.OperationRegistration,
		Level:          riskdefense.LevelHigh,
		Method:         riskdefense.MethodInteractiveCAPTCHA,
		DeviceIDHash:   session.HashToken("registration-device-expiry"),
		UserAgentHash:  session.HashToken("registration-ua-expiry"),
		IdentifierHash: session.HashToken("registration-identifier-expiry"),
		CreatedAt:      time.Now().UTC(),
	}
	if err := store.FinalizeRegistrationChallenge(ctx, scopeHash, firstHash, record, time.Second); err != nil {
		t.Fatalf("finalize first: %v", err)
	}
	if acquired, retry, err := store.ReserveRegistrationChallenge(ctx, scopeHash, secondHash, 3*time.Second); err != nil || acquired || retry <= 0 {
		t.Fatalf("reserve while first live acquired=%v retry=%v err=%v", acquired, retry, err)
	}

	time.Sleep(1200 * time.Millisecond)
	if exists, err := client.RDB().Exists(ctx, client.buildKey(riskChallengeSegment, firstHash)).Result(); err != nil || exists != 0 {
		t.Fatalf("expired first challenge exists=%d err=%v, want absent", exists, err)
	}
	if acquired, retry, err := store.ReserveRegistrationChallenge(ctx, scopeHash, secondHash, 3*time.Second); err != nil || !acquired || retry != 0 {
		t.Fatalf("reserve after expiry acquired=%v retry=%v err=%v", acquired, retry, err)
	}
}

func TestIntegration_RiskStoreRegistrationAggregateRateBudgets(t *testing.T) {
	client := setupTestRedis(t)
	store := NewRiskStore(client)
	ctx := context.Background()

	checks := []struct {
		name  string
		check func(context.Context, string, string, int, int, time.Duration) (bool, time.Duration, error)
	}{
		{name: "issue", check: func(ctx context.Context, deviceHash, networkHash string, deviceLimit, networkLimit int, window time.Duration) (bool, time.Duration, error) {
			return store.CheckRegistrationIssueRate(ctx, deviceHash, networkHash, riskdefense.RegistrationIssueRatePolicy{
				Device: riskdefense.RateLimit{Max: deviceLimit, Window: window}, Network: riskdefense.RateLimit{Max: networkLimit, Window: window},
				GlobalBurst: riskdefense.RateLimit{Max: 100, Window: window}, GlobalSustained: riskdefense.RateLimit{Max: 100, Window: window},
			})
		}},
		{name: "completion", check: store.CheckRegistrationCompletionRate},
	}
	for _, check := range checks {
		check := check
		t.Run(check.name+" device budget", func(t *testing.T) {
			deviceHash := session.HashToken(check.name + "-shared-device")
			for attempt := 1; attempt <= 3; attempt++ {
				networkHash := session.HashToken(fmt.Sprintf("%s-device-budget-network-%d", check.name, attempt))
				allowed, retry, err := check.check(ctx, deviceHash, networkHash, 2, 10, time.Minute)
				if err != nil {
					t.Fatalf("attempt %d: %v", attempt, err)
				}
				if attempt <= 2 && (!allowed || retry != 0) {
					t.Fatalf("attempt %d allowed=%v retry=%v, want allowed", attempt, allowed, retry)
				}
				if attempt == 3 && (allowed || retry <= 0) {
					t.Fatalf("attempt %d allowed=%v retry=%v, want device denial", attempt, allowed, retry)
				}
			}
		})
		t.Run(check.name+" network budget", func(t *testing.T) {
			networkHash := session.HashToken(check.name + "-shared-network")
			for attempt := 1; attempt <= 3; attempt++ {
				deviceHash := session.HashToken(fmt.Sprintf("%s-network-budget-device-%d", check.name, attempt))
				allowed, retry, err := check.check(ctx, deviceHash, networkHash, 10, 2, time.Minute)
				if err != nil {
					t.Fatalf("attempt %d: %v", attempt, err)
				}
				if attempt <= 2 && (!allowed || retry != 0) {
					t.Fatalf("attempt %d allowed=%v retry=%v, want allowed", attempt, allowed, retry)
				}
				if attempt == 3 && (allowed || retry <= 0) {
					t.Fatalf("attempt %d allowed=%v retry=%v, want network denial", attempt, allowed, retry)
				}
			}
		})
		t.Run(check.name+" denied device does not burn shared network", func(t *testing.T) {
			networkHash := session.HashToken(check.name + "-non-burning-network")
			firstDevice := session.HashToken(check.name + "-non-burning-device-1")
			secondDevice := session.HashToken(check.name + "-non-burning-device-2")
			thirdDevice := session.HashToken(check.name + "-non-burning-device-3")
			if allowed, _, err := check.check(ctx, firstDevice, networkHash, 1, 2, time.Minute); err != nil || !allowed {
				t.Fatalf("first device allowed=%v err=%v", allowed, err)
			}
			if allowed, _, err := check.check(ctx, firstDevice, networkHash, 1, 2, time.Minute); err != nil || allowed {
				t.Fatalf("exhausted first device allowed=%v err=%v, want denied", allowed, err)
			}
			if allowed, _, err := check.check(ctx, secondDevice, networkHash, 1, 2, time.Minute); err != nil || !allowed {
				t.Fatalf("second device allowed=%v err=%v; denied peer burned shared network", allowed, err)
			}
			if allowed, _, err := check.check(ctx, thirdDevice, networkHash, 1, 2, time.Minute); err != nil || allowed {
				t.Fatalf("third device allowed=%v err=%v, want shared-network denial", allowed, err)
			}
		})
	}

	// Issuance and completion are separate fixed windows. Exhausting one must
	// not accidentally consume the other, or successful users could be locked
	// out before submitting their first proof.
	separationDevice := session.HashToken("registration-rate-separation-device")
	separationNetwork := session.HashToken("registration-rate-separation-network")
	separationIssuePolicy := riskdefense.RegistrationIssueRatePolicy{
		Device: riskdefense.RateLimit{Max: 1, Window: time.Minute}, Network: riskdefense.RateLimit{Max: 1, Window: time.Minute},
		GlobalBurst: riskdefense.RateLimit{Max: 10, Window: time.Minute}, GlobalSustained: riskdefense.RateLimit{Max: 10, Window: time.Minute},
	}
	if allowed, _, err := store.CheckRegistrationIssueRate(ctx, separationDevice, separationNetwork, separationIssuePolicy); err != nil || !allowed {
		t.Fatalf("first issue allowed=%v err=%v", allowed, err)
	}
	if allowed, _, err := store.CheckRegistrationIssueRate(ctx, separationDevice, separationNetwork, separationIssuePolicy); err != nil || allowed {
		t.Fatalf("second issue allowed=%v err=%v, want denied", allowed, err)
	}
	if allowed, retry, err := store.CheckRegistrationCompletionRate(ctx, separationDevice, separationNetwork, 1, 1, time.Minute); err != nil || !allowed || retry != 0 {
		t.Fatalf("independent first completion allowed=%v retry=%v err=%v", allowed, retry, err)
	}
}

func TestIntegration_RegistrationFormDefenseRequiresExactDeviceOriginAndBlocksOnlySource(t *testing.T) {
	client := setupTestRedis(t)
	store := NewRegistrationFormDefenseStore(client)
	ctx := context.Background()
	now := time.Now().UTC()
	uaHash := registration.HashAbuseValue("browser")
	networkHash := registration.HashAbuseValue("203.0.113.0/24")
	originHash := registration.HashAbuseValue("https://auth.moonstone.org.cn")

	withoutDevice := registration.FormIntentRecord{
		UserAgentHash: uaHash, ClientNetworkHash: networkHash, OriginHash: originHash,
		NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
	}
	if err := store.CreateFormIntent(ctx, "intent-before-device", withoutDevice, time.Minute); !errors.Is(err, registration.ErrUnavailable) {
		t.Fatalf("intent without a server device was accepted: %v", err)
	}

	withDevice := withoutDevice
	withDevice.DeviceIDHash = registration.HashAbuseValue("original-device")
	if err := store.CreateFormIntent(ctx, "intent-bound-device", withDevice, time.Minute); err != nil {
		t.Fatal(err)
	}
	emailHash := registration.HashAbuseValue("person@example.com")
	originalBinding := registration.FormIntentBinding{
		UserAgentHash: uaHash, ClientNetworkHash: networkHash, DeviceIDHash: withDevice.DeviceIDHash, OriginHash: originHash, EmailHash: emailHash,
	}
	baseBinding := originalBinding
	baseBinding.EmailHash = ""
	if err := store.ValidateFormIntent(ctx, "intent-bound-device", baseBinding, now); err != nil {
		t.Fatalf("validate unbound intent: %v", err)
	}
	if err := store.BindFormIntentEmail(ctx, "intent-bound-device", originalBinding, now); err != nil {
		t.Fatalf("bind email: %v", err)
	}
	if err := store.ValidateFormIntent(ctx, "intent-bound-device", originalBinding, now); err != nil {
		t.Fatalf("validate bound intent: %v", err)
	}
	changedEmail := originalBinding
	changedEmail.EmailHash = registration.HashAbuseValue("other@example.com")
	if err := store.ValidateFormIntent(ctx, "intent-bound-device", changedEmail, now); !errors.Is(err, registration.ErrFormIntentInvalid) {
		t.Fatalf("validate accepted replacement email: %v", err)
	}
	if err := store.BindFormIntentEmail(ctx, "intent-bound-device", changedEmail, now); !errors.Is(err, registration.ErrFormIntentInvalid) {
		t.Fatalf("replacement email accepted: %v", err)
	}
	replacementDevice := originalBinding
	replacementDevice.DeviceIDHash = registration.HashAbuseValue("replacement-device")
	if err := store.ConsumeFormIntent(ctx, "intent-bound-device", replacementDevice, now); !errors.Is(err, registration.ErrFormIntentInvalid) {
		t.Fatalf("replacement device accepted: %v", err)
	}
	withDevice.DeviceIDHash = registration.HashAbuseValue("original-device-2")
	if err := store.CreateFormIntent(ctx, "intent-bound-origin", withDevice, time.Minute); err != nil {
		t.Fatal(err)
	}
	originBinding := registration.FormIntentBinding{
		UserAgentHash: uaHash, ClientNetworkHash: networkHash, DeviceIDHash: withDevice.DeviceIDHash, OriginHash: originHash,
		EmailHash: registration.HashAbuseValue("origin@example.com"),
	}
	if err := store.BindFormIntentEmail(ctx, "intent-bound-origin", originBinding, now); err != nil {
		t.Fatalf("bind origin intent: %v", err)
	}
	wrongOrigin := originBinding
	wrongOrigin.OriginHash = registration.HashAbuseValue("https://evil.example")
	if err := store.ConsumeFormIntent(ctx, "intent-bound-origin", wrongOrigin, now); !errors.Is(err, registration.ErrFormIntentInvalid) {
		t.Fatalf("replacement origin accepted: %v", err)
	}

	withDevice.DeviceIDHash = registration.HashAbuseValue("concurrent-device")
	if err := store.CreateFormIntent(ctx, "intent-one-use", withDevice, time.Minute); err != nil {
		t.Fatal(err)
	}
	oneUseBinding := registration.FormIntentBinding{
		UserAgentHash: uaHash, ClientNetworkHash: networkHash, DeviceIDHash: withDevice.DeviceIDHash, OriginHash: originHash,
		EmailHash: registration.HashAbuseValue("one-use@example.com"),
	}
	if err := store.BindFormIntentEmail(ctx, "intent-one-use", oneUseBinding, now); err != nil {
		t.Fatalf("bind one-use intent: %v", err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- store.ConsumeFormIntent(ctx, "intent-one-use", oneUseBinding, now) }()
	}
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, registration.ErrFormIntentInvalid) {
			t.Fatalf("concurrent consume: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent consume successes=%d, want 1", successes)
	}

	policy := registration.AbusePolicy{
		DeviceBlockTTL: time.Hour, IPStrikeWindow: time.Hour,
		IPBlockAfter: 3, IPBlockTTL: time.Hour, IPLongBlockAfter: 6, IPLongBlockTTL: 24 * time.Hour,
	}
	attackSource := registration.AbuseFingerprint{
		ClientIPHash: registration.HashAbuseValue("203.0.113.8"), ClientIPBlockEligible: true,
		DeviceIDHash: registration.HashAbuseValue("attack-device"), UserAgentHash: uaHash,
	}
	if _, err := store.RecordRegistrationHoneypot(ctx, attackSource, policy); err != nil {
		t.Fatal(err)
	}
	blocked, err := store.IsRegistrationBlocked(ctx, attackSource)
	if err != nil || !blocked {
		t.Fatalf("attack source blocked=%v err=%v", blocked, err)
	}
	cleanSource := registration.AbuseFingerprint{
		ClientIPHash: registration.HashAbuseValue("198.51.100.44"), ClientIPBlockEligible: true,
		DeviceIDHash: registration.HashAbuseValue("clean-device"), UserAgentHash: uaHash,
	}
	blocked, err = store.IsRegistrationBlocked(ctx, cleanSource)
	if err != nil || blocked {
		t.Fatalf("clean source blocked=%v err=%v", blocked, err)
	}
}

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
		SecurityEpoch:      1,
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
		SecurityEpoch:      1,
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
		SecurityEpoch:      1,
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
		SecurityEpoch:      1,
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
		SecurityEpoch:      1,
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

	// The final configured attempt is rejected as exhausted.
	maxAttempts := 3
	for i := 1; i < maxAttempts; i++ {
		count, err := store.IncrementAttempts(ctx, tokenHash, maxAttempts)
		if err != nil {
			t.Fatalf("increment %d: %v", i, err)
		}
		if count != i {
			t.Errorf("attempt %d: got count %d, want %d", i, count, i)
		}
	}

	// Reaching maxAttempts exhausts the budget.
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

func TestIntegration_RateLimiterAccountBudgetSurvivesIPRotation(t *testing.T) {
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

	// Rotating to IP 2 must not reset the immutable account budget.
	allowed, retryAfter, err := limiter.CheckLogin(ctx, "10.0.0.2", identifierHash, limit, window)
	if err != nil || allowed || retryAfter <= 0 {
		t.Fatalf("IP rotation bypassed account budget: allowed=%v retry=%v err=%v", allowed, retryAfter, err)
	}

	// A denied atomic check must not consume IP 2's independent budget.
	otherIdentifierHash := session.HashToken("rate-multi-ip-independent-account")
	allowed, _, err = limiter.CheckLogin(ctx, "10.0.0.2", otherIdentifierHash, limit, window)
	if err != nil || !allowed {
		t.Fatalf("denied account check consumed unrelated IP budget: allowed=%v err=%v", allowed, err)
	}
}

// --- Prefix Isolation Test ---

func TestIntegration_PrefixIsolation(t *testing.T) {
	basePrefix := os.Getenv("UP_TEST_REDIS_KEY_PREFIX")
	cfg := mustLoadTestRedisConfig(t)

	// Create a client with a different prefix.
	otherCfg := cfg
	otherBasePrefix := basePrefix + "other:"
	otherPrefix, err := isolatedTestRedisPrefix(otherBasePrefix)
	if err != nil {
		t.Fatalf("create sibling test namespace: %v", err)
	}
	otherCfg.KeyPrefix = otherPrefix
	otherClient, err := NewClient(otherCfg)
	if err != nil {
		t.Fatalf("create other client: %v", err)
	}
	defer func() {
		cleanupTestKeys(t, otherClient, otherBasePrefix)
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
		SecurityEpoch:      1,
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
		SecurityEpoch:      1,
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
		SecurityEpoch: 1,
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

	for i := 1; i < 3; i++ {
		count, err := store.IncrementChallengeAttempts(ctx, tokenHash, 3)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if count != i {
			t.Errorf("attempt count = %d, want %d", count, i)
		}
	}
	// The configured final attempt exhausts the budget.
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
		SecurityEpoch: 1,
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
		SecurityEpoch: 1,
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
		UserID:        identity.UserID("user_enroll_1"),
		SessionID:     "sess_enroll_1",
		Kind:          kind,
		Target:        target,
		SecurityEpoch: 1,
	}
}

func TestIntegration_EnrollmentStoreClaimAndConsume(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("enrollment-totp-token")
	if err := store.CreateEnrollment(ctx, tokenHash, enrollmentData(auth.EnrollmentTOTP, ""), 5*time.Minute); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	data, err := store.ClaimEnrollment(ctx, tokenHash, "claim-a")
	if err != nil {
		t.Fatalf("claim enrollment: %v", err)
	}
	if data.UserID != "user_enroll_1" || data.SessionID != "sess_enroll_1" || data.Kind != auth.EnrollmentTOTP || data.Target != "" {
		t.Errorf("enrollment data = %+v, want stored binding", data)
	}
	if err := store.ConsumeEnrollment(ctx, tokenHash, "claim-a"); err != nil {
		t.Fatalf("consume enrollment: %v", err)
	}

	// Single-use: the record is gone after consumption.
	if _, err := store.ClaimEnrollment(ctx, tokenHash, "claim-b"); !errors.Is(err, auth.ErrEnrollmentNotFound) {
		t.Fatalf("reuse err = %v, want ErrEnrollmentNotFound", err)
	}

	// Passkey enrollments round-trip the target binding.
	pkHash := session.HashToken("enrollment-passkey-token")
	if err := store.CreateEnrollment(ctx, pkHash, enrollmentData(auth.EnrollmentPasskey, "pk-42"), 5*time.Minute); err != nil {
		t.Fatalf("create passkey enrollment: %v", err)
	}
	pkData, err := store.ClaimEnrollment(ctx, pkHash, "claim-c")
	if err != nil {
		t.Fatalf("claim passkey enrollment: %v", err)
	}
	if pkData.Kind != auth.EnrollmentPasskey || pkData.Target != "pk-42" {
		t.Errorf("passkey enrollment = %+v, want (passkey, pk-42)", pkData)
	}
	cleanupKey := client.buildKey(enrollmentCleanupKeySegment, pkHash)
	indexKey := client.buildKey(enrollmentCleanupIndexKey)
	if exists, err := client.rdb.Exists(ctx, cleanupKey).Result(); err != nil || exists != 1 {
		t.Fatalf("passkey cleanup record before consume = %d, %v; want present", exists, err)
	}
	if _, err := client.rdb.ZScore(ctx, indexKey, pkHash).Result(); err != nil {
		t.Fatalf("passkey cleanup index before consume: %v", err)
	}
	if err := store.ConsumeEnrollment(ctx, pkHash, "claim-c"); err != nil {
		t.Fatalf("consume passkey enrollment: %v", err)
	}
	if exists, err := client.rdb.Exists(ctx, cleanupKey).Result(); err != nil || exists != 0 {
		t.Fatalf("passkey cleanup record after consume = %d, %v; want absent", exists, err)
	}
	if _, err := client.rdb.ZScore(ctx, indexKey, pkHash).Result(); !errors.Is(err, goredis.Nil) {
		t.Fatalf("passkey cleanup index after consume err = %v, want redis.Nil", err)
	}
}

func TestIntegration_EnrollmentStoreUnknownToken(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)

	if _, err := store.ClaimEnrollment(context.Background(), session.HashToken("never-issued"), "claim-1"); !errors.Is(err, auth.ErrEnrollmentNotFound) {
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
	if _, err := store.ClaimEnrollment(ctx, tokenHash, "claim-1"); !errors.Is(err, auth.ErrEnrollmentNotFound) {
		t.Fatalf("expired claim err = %v, want ErrEnrollmentNotFound", err)
	}
}

func TestIntegration_EnrollmentStoreReleaseAllowsRetry(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("enrollment-release-token")
	if err := store.CreateEnrollment(ctx, tokenHash, enrollmentData(auth.EnrollmentTOTP, ""), 5*time.Minute); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	if _, err := store.ClaimEnrollment(ctx, tokenHash, "claim-1"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	// A concurrent claimer while the lock is held loses (single winner).
	if _, err := store.ClaimEnrollment(ctx, tokenHash, "claim-2"); !errors.Is(err, auth.ErrEnrollmentClaimed) {
		t.Fatalf("second claim err = %v, want ErrEnrollmentClaimed", err)
	}

	// A transient provider failure releases the claim; the challenge itself
	// survives untouched and stays confirmable.
	if err := store.ReleaseEnrollment(ctx, tokenHash, "claim-1"); err != nil {
		t.Fatalf("release: %v", err)
	}
	// A stale owner can no longer act on the released lock.
	if err := store.ReleaseEnrollment(ctx, tokenHash, "claim-1"); !errors.Is(err, auth.ErrEnrollmentNotHeld) {
		t.Fatalf("stale release err = %v, want ErrEnrollmentNotHeld", err)
	}

	// The retry claims the same enrollment and consumes it.
	if _, err := store.ClaimEnrollment(ctx, tokenHash, "claim-3"); err != nil {
		t.Fatalf("retry claim: %v", err)
	}
	// A foreign claim ID can never consume someone else's lock.
	if err := store.ConsumeEnrollment(ctx, tokenHash, "claim-2"); !errors.Is(err, auth.ErrEnrollmentNotHeld) {
		t.Fatalf("foreign consume err = %v, want ErrEnrollmentNotHeld", err)
	}
	if err := store.ConsumeEnrollment(ctx, tokenHash, "claim-3"); err != nil {
		t.Fatalf("retry consume: %v", err)
	}
}

func TestIntegration_PasskeyEnrollmentCleanupAbandonAndLease(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("passkey-cleanup-abandon")

	if err := store.CreateEnrollment(ctx, tokenHash, enrollmentData(auth.EnrollmentPasskey, "pk-abandoned"), 5*time.Minute); err != nil {
		t.Fatalf("create passkey enrollment: %v", err)
	}
	if _, err := store.ClaimEnrollment(ctx, tokenHash, "claim-abandon"); err != nil {
		t.Fatalf("claim passkey enrollment: %v", err)
	}
	if err := store.AbandonEnrollment(ctx, tokenHash, "claim-abandon"); err != nil {
		t.Fatalf("abandon passkey enrollment: %v", err)
	}

	entries, err := store.ClaimExpiredPasskeyEnrollments(ctx, 10)
	if err != nil {
		t.Fatalf("claim cleanup: %v", err)
	}
	if len(entries) != 1 || entries[0].TokenHash != tokenHash || entries[0].Target != "pk-abandoned" || entries[0].UserID != "user_enroll_1" {
		t.Fatalf("cleanup entries = %+v, want abandoned binding", entries)
	}
	// The first worker holds a lease; a second worker cannot receive it.
	if again, err := store.ClaimExpiredPasskeyEnrollments(ctx, 10); err != nil || len(again) != 0 {
		t.Fatalf("cleanup lease second claim = %+v, %v; want empty", again, err)
	}

	if err := store.RequeuePasskeyEnrollmentCleanup(ctx, entries[0], 0); err != nil {
		t.Fatalf("requeue cleanup: %v", err)
	}
	retried, err := store.ClaimExpiredPasskeyEnrollments(ctx, 10)
	if err != nil {
		t.Fatalf("claim requeued cleanup: %v", err)
	}
	if len(retried) != 1 || retried[0].Attempts != 1 {
		t.Fatalf("retried entries = %+v, want attempts=1", retried)
	}
	if err := store.CompletePasskeyEnrollmentCleanup(ctx, tokenHash); err != nil {
		t.Fatalf("complete cleanup: %v", err)
	}
	if final, err := store.ClaimExpiredPasskeyEnrollments(ctx, 10); err != nil || len(final) != 0 {
		t.Fatalf("completed cleanup claim = %+v, %v; want empty", final, err)
	}
}

func TestIntegration_PasskeyCleanupSkipsLiveClaimAfterChallengeExpiry(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)
	ctx := context.Background()
	tokenHash := session.HashToken("passkey-cleanup-live-claim")

	// Keep the pre-claim window comfortably above one remote Redis round trip
	// under the race detector. This TTL is test-only; the assertion begins
	// after the challenge has expired while its claim lease remains live.
	if err := store.CreateEnrollment(ctx, tokenHash, enrollmentData(auth.EnrollmentPasskey, "pk-racing"), 2*time.Second); err != nil {
		t.Fatalf("create passkey enrollment: %v", err)
	}
	if _, err := store.ClaimEnrollment(ctx, tokenHash, "claim-racing"); err != nil {
		t.Fatalf("claim enrollment: %v", err)
	}
	time.Sleep(2200 * time.Millisecond)
	if entries, err := store.ClaimExpiredPasskeyEnrollments(ctx, 10); err != nil || len(entries) != 0 {
		t.Fatalf("cleanup while claim live = %+v, %v; want empty", entries, err)
	}
	if err := store.ReleaseEnrollment(ctx, tokenHash, "claim-racing"); err != nil {
		t.Fatalf("release expired challenge claim: %v", err)
	}
	entries, err := store.ClaimExpiredPasskeyEnrollments(ctx, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("cleanup after claim release = %+v, %v; want one", entries, err)
	}
}

func TestIntegration_EnrollmentStoreConcurrentClaim(t *testing.T) {
	client := setupTestRedis(t)
	store := NewEnrollmentStore(client)
	ctx := context.Background()

	tokenHash := session.HashToken("enrollment-race-token")
	if err := store.CreateEnrollment(ctx, tokenHash, enrollmentData(auth.EnrollmentPasskey, "pk-race"), 5*time.Minute); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	// The SET NX PX claim lock guarantees a single confirmation winner
	// across concurrent requests; losers receive ErrEnrollmentClaimed.
	const workers = 8
	var mu sync.Mutex
	winners := 0
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		claimID := fmt.Sprintf("claim-%d", i)
		go func() {
			defer wg.Done()
			if _, err := store.ClaimEnrollment(ctx, tokenHash, claimID); err == nil {
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
