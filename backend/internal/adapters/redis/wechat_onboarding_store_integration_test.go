//go:build integration

package redis

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
)

func integrationWeChatOnboardingStore(t *testing.T) (*Client, *WeChatOnboardingStore) {
	t.Helper()
	client := setupTestRedis(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	encryptor, err := session.NewAESGCMEncryptor(base64.StdEncoding.EncodeToString(key), "integration-v1")
	if err != nil {
		t.Fatal(err)
	}
	return client, NewWeChatOnboardingStore(client, encryptor)
}

func integrationMFAChallenge(providerSessionID string) wechatonboarding.ChallengeData {
	return wechatonboarding.ChallengeData{
		Purpose: wechatonboarding.MFAChallengePurpose, Kind: wechatonboarding.ChallengeKindMFA,
		TenantID: "wx-app", Subject: "private-subject", Phone: "+8613800138000",
		TargetUserID: identity.UserID("user_existing"), NormalizedEmail: "owner@example.com",
		ExpectedVersion: 7, ExpectedSecurityEpoch: 4, Provider: "zitadel", ProviderSessionID: providerSessionID,
		AvailableMethods: []auth.MFAMethod{auth.MFAMethodTOTP}, CreatedAt: time.Now().UTC(),
	}
}

func TestIntegration_WeChatOnboardingMFAAtomicCreateAndPromotion(t *testing.T) {
	client, store := integrationWeChatOnboardingStore(t)
	ctx := context.Background()
	rawToken := "integration-mfa-token"
	hash := session.HashToken(rawToken)
	data := integrationMFAChallenge("private-provider-session")

	if err := store.Create(ctx, rawToken, data, time.Minute); err != nil {
		t.Fatal(err)
	}
	challengeCiphertext, err := client.rdb.Get(ctx, store.challengeKey(hash)).Result()
	if err != nil {
		t.Fatal(err)
	}
	cleanupCiphertext, err := client.rdb.Get(ctx, store.cleanupKey(hash)).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttl, err := client.rdb.PTTL(ctx, store.cleanupKey(hash)).Result(); err != nil || ttl != -1 {
		t.Fatalf("cleanup obligation TTL = %v, err=%v; want no natural TTL", ttl, err)
	}
	if _, err := client.rdb.ZScore(ctx, store.cleanupDueKey(), hash).Result(); err != nil {
		t.Fatalf("cleanup due index missing: %v", err)
	}
	for _, private := range []string{rawToken, data.Subject, data.Phone, data.NormalizedEmail, data.ProviderSessionID} {
		if strings.Contains(challengeCiphertext, private) || strings.Contains(cleanupCiphertext, private) {
			t.Fatalf("Redis ciphertext leaked %q", private)
		}
	}

	if _, err := store.Claim(ctx, rawToken, "integration-claim"); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(ctx, rawToken, "integration-claim"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.rdb.Get(ctx, store.challengeKey(hash)).Result(); !errors.Is(err, goredis.Nil) {
		t.Fatalf("consumed challenge err=%v, want redis.Nil", err)
	}
	if _, err := client.rdb.Get(ctx, store.cleanupKey(hash)).Result(); err != nil {
		t.Fatalf("promotion dropped cleanup payload: %v", err)
	}
	if _, err := client.rdb.Get(ctx, store.promotionKey(hash)).Result(); err != nil {
		t.Fatalf("promotion lease missing: %v", err)
	}

	if err := store.CompleteProviderSessionPromotion(ctx, rawToken); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteProviderSessionPromotion(ctx, rawToken); err != nil {
		t.Fatalf("idempotent promotion completion: %v", err)
	}
	for _, key := range []string{store.cleanupKey(hash), store.promotionKey(hash)} {
		if _, err := client.rdb.Get(ctx, key).Result(); !errors.Is(err, goredis.Nil) {
			t.Fatalf("promotion terminal key %q err=%v, want redis.Nil", key, err)
		}
	}
	if _, err := client.rdb.ZScore(ctx, store.cleanupDueKey(), hash).Result(); !errors.Is(err, goredis.Nil) {
		t.Fatalf("promotion left due member: %v", err)
	}
	if _, err := client.rdb.Get(ctx, store.promotionDoneKey(hash)).Result(); err != nil {
		t.Fatalf("promotion completion tombstone missing: %v", err)
	}
}

func TestIntegration_WeChatOnboardingPromotionFailsAfterWorkerCompletion(t *testing.T) {
	client, store := integrationWeChatOnboardingStore(t)
	ctx := context.Background()
	rawToken := "integration-mfa-promotion-race-token"
	hash := session.HashToken(rawToken)

	if err := store.Create(ctx, rawToken, integrationMFAChallenge("provider-session-race"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, rawToken, "integration-race-claim"); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(ctx, rawToken, "integration-race-claim"); err != nil {
		t.Fatal(err)
	}

	// Model a slow local-session creation whose promotion lease expires. The
	// cleanup worker claims and completes revocation before the handler resumes.
	if err := client.rdb.Del(ctx, store.promotionKey(hash)).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.rdb.ZAdd(ctx, store.cleanupDueKey(), goredis.Z{
		Score:  float64(time.Now().Add(-time.Second).UnixMilli()),
		Member: hash,
	}).Err(); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := store.claimCleanup(ctx, hash, "promotion-race-worker", time.Second); err != nil || !claimed {
		t.Fatalf("worker cleanup claimed=%v err=%v", claimed, err)
	}
	if err := store.completeCleanup(ctx, hash, "promotion-race-worker"); err != nil {
		t.Fatal(err)
	}

	if err := store.CompleteProviderSessionPromotion(ctx, rawToken); err == nil {
		t.Fatal("promotion succeeded after worker completed revocation")
	}
}

func TestIntegration_WeChatOnboardingCleanupClaimIsHAAndRetryable(t *testing.T) {
	client, store := integrationWeChatOnboardingStore(t)
	ctx := context.Background()
	rawToken := "integration-mfa-ha-token"
	hash := session.HashToken(rawToken)
	if err := store.Create(ctx, rawToken, integrationMFAChallenge("provider-session-ha"), time.Minute); err != nil {
		t.Fatal(err)
	}
	// Make the index due while the challenge remains live: no worker may
	// claim or revoke it.
	if err := client.rdb.ZAdd(ctx, store.cleanupDueKey(), goredis.Z{Score: float64(time.Now().Add(-time.Second).UnixMilli()), Member: hash}).Err(); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := store.claimCleanup(ctx, hash, "live-challenge-claim", time.Second); err != nil || claimed {
		t.Fatalf("live challenge cleanup claimed=%v err=%v", claimed, err)
	}

	if err := client.rdb.Del(ctx, store.challengeKey(hash)).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.rdb.ZAdd(ctx, store.cleanupDueKey(), goredis.Z{Score: float64(time.Now().Add(-time.Second).UnixMilli()), Member: hash}).Err(); err != nil {
		t.Fatal(err)
	}
	var claimed atomic.Int32
	var winnerMu sync.Mutex
	winnerID := ""
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			claimID := "ha-claim-" + string(rune('a'+index))
			payload, ok, err := store.claimCleanup(ctx, hash, claimID, time.Second)
			if err != nil {
				t.Errorf("claim cleanup: %v", err)
				return
			}
			if ok {
				if payload.ProviderSessionID != "provider-session-ha" {
					t.Errorf("provider session = %q", payload.ProviderSessionID)
				}
				claimed.Add(1)
				winnerMu.Lock()
				winnerID = claimID
				winnerMu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if claimed.Load() != 1 {
		t.Fatalf("HA cleanup claim winners = %d, want 1", claimed.Load())
	}
	winnerMu.Lock()
	claimID := winnerID
	winnerMu.Unlock()
	if err := store.retryCleanup(ctx, hash, claimID, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok, err := store.claimCleanup(ctx, hash, "retry-claim", time.Second); err != nil || !ok {
		t.Fatalf("retried cleanup claimed=%v err=%v", ok, err)
	}
	if err := store.completeCleanup(ctx, hash, "retry-claim"); err != nil {
		t.Fatal(err)
	}
}
