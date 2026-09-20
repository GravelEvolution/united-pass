package redis

import (
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
)

func TestRegistrationCreateBucketsIncludeCrossAccountScopes(t *testing.T) {
	client := &Client{keyPrefix: "up:test:"}
	limiter := NewRateLimiter(client)
	policy := registration.CreateRatePolicy{
		ClientIP:    registration.Limit{Max: 3, Window: time.Hour},
		ClientNet:   registration.Limit{Max: 10, Window: time.Hour},
		Email:       registration.Limit{Max: 3, Window: 24 * time.Hour},
		ClientEmail: registration.Limit{Max: 2, Window: time.Hour},
	}
	buckets := limiter.registrationCreateBuckets("203.0.113.7", "203.0.113.0/24", "email-hash", policy)
	if len(buckets) != 4 {
		t.Fatalf("bucket count = %d, want 4", len(buckets))
	}
	wants := []string{"ip:203.0.113.7", "net:203.0.113.0/24", "email:email-hash", "pair:203.0.113.7:email-hash"}
	for index, want := range wants {
		if !strings.Contains(buckets[index].key, want) {
			t.Errorf("bucket %d key = %q, want component %q", index, buckets[index].key, want)
		}
	}
	if buckets[0].limit != policy.ClientIP || buckets[1].limit != policy.ClientNet || buckets[2].limit != policy.Email || buckets[3].limit != policy.ClientEmail {
		t.Fatalf("bucket policies drifted: %#v", buckets)
	}
}

func TestRegistrationBucketValidationFailsClosed(t *testing.T) {
	limiter := &RateLimiter{client: &Client{keyPrefix: "up:test:"}}
	allowed, _, err := limiter.checkBuckets(t.Context(), []rateBucket{{
		key: "up:test:registration", limit: registration.Limit{Max: 0, Window: time.Hour},
	}})
	if err == nil || allowed {
		t.Fatalf("invalid bucket allowed=%v err=%v", allowed, err)
	}
}

func TestAccountContactChangeBucketsIncludeUserIPAndPairScopes(t *testing.T) {
	client := &Client{keyPrefix: "up:test:"}
	limiter := NewRateLimiter(client)
	buckets := limiter.accountContactChangeBuckets(rateLimitAccountEmailVerifySegment, "203.0.113.7", strings.Repeat("a", 64), 5, time.Hour)
	if len(buckets) != 3 {
		t.Fatalf("bucket count = %d, want 3", len(buckets))
	}
	for index, want := range []string{"user:" + strings.Repeat("a", 64), "ip:203.0.113.7", "pair:203.0.113.7:" + strings.Repeat("a", 64)} {
		if !strings.Contains(buckets[index].key, want) {
			t.Errorf("bucket %d key = %q, want component %q", index, buckets[index].key, want)
		}
	}
}

func TestDreamUPMobileAssertionRateLimitFailsClosedWithoutBoundScope(t *testing.T) {
	limiter := NewRateLimiter(&Client{keyPrefix: "up:test:"})
	allowed, retry, err := limiter.CheckDreamUPMobileAssertion(t.Context(), "user_1", "", "203.0.113.7", 60, 2000, time.Minute)
	if err == nil || allowed || retry != time.Minute {
		t.Fatalf("allowed=%v retry=%s err=%v", allowed, retry, err)
	}
}

func TestRegistrationFormIntentBudgetUsesSeparateHashedNetworkKey(t *testing.T) {
	limiter := &RateLimiter{client: &Client{keyPrefix: "up:test:"}}
	networkHash := registration.HashAbuseValue("203.0.113.0/24")
	key := limiter.registrationFormIntentKey(networkHash)
	if !strings.Contains(key, rateLimitRegistrationFormIntentSegment+"net:"+networkHash) {
		t.Fatalf("form-intent key = %q", key)
	}
	if strings.Contains(key, "203.0.113.0/24") || strings.Contains(key, rateLimitRegistrationCreateSegment) {
		t.Fatalf("form-intent key leaked raw network or shared create budget: %q", key)
	}
}

func TestRegistrationBlockRevokeBudgetUsesHashedAdministratorKey(t *testing.T) {
	limiter := &RateLimiter{client: &Client{keyPrefix: "up:test:"}}
	actorHash := registration.HashAbuseValue("user_operator")
	key := limiter.registrationBlockRevokeKey(actorHash)
	if !strings.Contains(key, rateLimitRegistrationUnblockSegment+"actor:"+actorHash) {
		t.Fatalf("registration unblock key = %q", key)
	}
	if strings.Contains(key, "user_operator") || strings.Contains(key, rateLimitReauthSegment) {
		t.Fatalf("registration unblock key leaked the actor or shared another budget: %q", key)
	}
}

func TestRegistrationBlockRevokeBudgetRejectsUntypedActorKey(t *testing.T) {
	limiter := &RateLimiter{client: &Client{keyPrefix: "up:test:"}}
	for _, actorHash := range []string{"", "user_operator", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		allowed, _, err := limiter.CheckRegistrationBlockRevoke(t.Context(), actorHash, 10, time.Minute)
		if err == nil || allowed {
			t.Fatalf("actorHash=%q allowed=%v err=%v", actorHash, allowed, err)
		}
	}
}
