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
	wants := []string{"ip:203.0.113.7", "net:203.0.113.0/24", rateLimitRegistrationCreateEmailSegment + "email-hash", "pair:203.0.113.7:email-hash"}
	for index, want := range wants {
		if !strings.Contains(buckets[index].key, want) {
			t.Errorf("bucket %d key = %q, want component %q", index, buckets[index].key, want)
		}
	}
	if buckets[0].limit != policy.ClientIP || buckets[1].limit != policy.ClientNet || buckets[2].limit != policy.Email || buckets[3].limit != policy.ClientEmail {
		t.Fatalf("bucket policies drifted: %#v", buckets)
	}
	legacyEmailKey := client.buildKey(rateLimitRegistrationCreateSegment, "email:", "email-hash")
	if buckets[2].key == legacyEmailKey {
		t.Fatalf("email bucket reused the legacy 24-hour namespace: %q", buckets[2].key)
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

func TestRegistrationFormIntentDeviceAndGlobalKeysDoNotLeakRawScope(t *testing.T) {
	client := &Client{keyPrefix: "up:test:"}
	deviceHash := registration.HashAbuseValue("raw-device-token")
	deviceKey := client.buildKey(rateLimitRegistrationFormIntentDeviceSegment, deviceHash)
	globalBurst := client.buildKey(rateLimitRegistrationFormIntentGlobalSegment, "burst")
	globalSustained := client.buildKey(rateLimitRegistrationFormIntentGlobalSegment, "sustained")
	if !strings.Contains(deviceKey, deviceHash) || strings.Contains(deviceKey, "raw-device-token") {
		t.Fatalf("device key leaked raw scope: %q", deviceKey)
	}
	if globalBurst == globalSustained || !strings.Contains(globalBurst, ":burst") || !strings.Contains(globalSustained, ":sustained") {
		t.Fatalf("global form-intent keys drifted: %q %q", globalBurst, globalSustained)
	}
}

func TestRegistrationCreateChainMarkerUsesOnlyHashedBindingMaterial(t *testing.T) {
	limiter := &RateLimiter{client: &Client{keyPrefix: "up:test:"}}
	rawIntent := "opaque-form-intent"
	intentHash := registration.HashAbuseValue(rawIntent)
	rawNetwork := "203.0.113.0/24"
	rawEmail := "person@example.com"
	emailHash := registration.HashAbuseValue(rawEmail)
	key := limiter.registrationCreateChainKey(intentHash)
	binding := registrationCreateChainBinding(rawNetwork, emailHash)
	if !strings.Contains(key, rateLimitRegistrationCreateChainSegment+"intent:"+intentHash) || len(binding) != 64 {
		t.Fatalf("key=%q binding=%q", key, binding)
	}
	if strings.Contains(key+binding, rawIntent) || strings.Contains(key+binding, rawEmail) || strings.Contains(key+binding, rawNetwork) {
		t.Fatalf("marker material leaked a raw binding value: %q %q", key, binding)
	}
}

func TestRegistrationCohortBucketsContainOnlyHashedDomainAndMXMaterial(t *testing.T) {
	limiter := &RateLimiter{client: &Client{keyPrefix: "up:test:"}}
	policy := registration.CreateRatePolicy{
		ClientIP: registration.Limit{Max: 3, Window: time.Hour}, ClientNet: registration.Limit{Max: 10, Window: time.Hour},
		Email: registration.Limit{Max: 3, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 2, Window: time.Hour},
		MailboxFamily:    registration.Limit{Max: 3, Window: 24 * time.Hour},
		Global:           registration.AggregateRatePolicy{Burst: registration.Limit{Max: 20, Window: 10 * time.Second}, Sustained: registration.Limit{Max: 60, Window: time.Minute}},
		UnfamiliarDomain: registration.AggregateRatePolicy{Burst: registration.Limit{Max: 3, Window: 10 * time.Minute}, Sustained: registration.Limit{Max: 10, Window: 24 * time.Hour}},
		UnfamiliarMX:     registration.AggregateRatePolicy{Burst: registration.Limit{Max: 20, Window: 10 * time.Minute}, Sustained: registration.Limit{Max: 100, Window: 24 * time.Hour}},
	}
	rawDomain := "rare.example"
	rawMX := []string{"mail-operator.example", "backup-operator.example"}
	subject := registration.CreateRateSubject{
		ClientIP: "203.0.113.9", ClientNetwork: "203.0.113.0/24",
		EmailHash:         registration.HashAbuseValue("person@rare.example"),
		MailboxFamilyHash: registration.HashAbuseValue("canonical-inbox@example.com"),
		DomainHash:        registration.HashAbuseValue(rawDomain), MXHashes: []string{
			registration.HashAbuseValue(rawMX[0]), registration.HashAbuseValue(rawMX[1]),
		},
		FormIntentHash: registration.HashAbuseValue("intent"),
	}
	buckets, err := limiter.registrationCreateBucketsWithCohorts(subject, policy)
	if err != nil || len(buckets) != 13 {
		t.Fatalf("buckets=%d err=%v, want 13", len(buckets), err)
	}
	joined := ""
	for _, bucket := range buckets {
		joined += bucket.key + " "
	}
	if strings.Contains(joined, rawDomain) || strings.Contains(joined, rawMX[0]) || strings.Contains(joined, rawMX[1]) ||
		!strings.Contains(joined, rateLimitRegistrationCreateDomainSegment+"burst:"+subject.DomainHash) ||
		!strings.Contains(joined, rateLimitRegistrationCreateMailboxSegment+subject.MailboxFamilyHash) ||
		!strings.Contains(joined, rateLimitRegistrationCreateMXSegment+"burst:"+subject.MXHashes[0]) ||
		!strings.Contains(joined, rateLimitRegistrationCreateMXSegment+"burst:"+subject.MXHashes[1]) {
		t.Fatalf("cohort bucket material = %q", joined)
	}
}

func TestRegistrationMXCohortsAreCanonicalAndBounded(t *testing.T) {
	limiter := &RateLimiter{client: &Client{keyPrefix: "up:test:"}}
	first := registration.HashAbuseValue("first-operator.example")
	second := registration.HashAbuseValue("second-operator.example")
	forward := registration.CreateRateSubject{ClientNetwork: "203.0.113.0/24", EmailHash: registration.HashAbuseValue("person@example.com"), MXHashes: []string{first, second}}
	reverse := forward
	reverse.MXHashes = []string{second, first}
	if registrationCreateChainCohortBinding(forward) != registrationCreateChainCohortBinding(reverse) {
		t.Fatal("MX cohort order changed the registration binding")
	}
	policy := registration.CreateRatePolicy{UnfamiliarMX: registration.AggregateRatePolicy{
		Burst: registration.Limit{Max: 2, Window: time.Minute}, Sustained: registration.Limit{Max: 4, Window: time.Hour},
	}}
	if buckets, err := limiter.registrationCreateBucketsWithCohorts(reverse, policy); err != nil || len(buckets) != 8 {
		t.Fatalf("canonical buckets=%d err=%v, want 8", len(buckets), err)
	}

	invalid := []registration.CreateRateSubject{
		{MXHashes: []string{first, first}},
		{MXHashes: []string{"not-a-hash"}},
		{MXHashes: make([]string, registration.MaxCreateRateMXCohorts+1)},
	}
	for index := range invalid[2].MXHashes {
		invalid[2].MXHashes[index] = registration.HashAbuseValue(string(rune(index + 1)))
	}
	for index, subject := range invalid {
		if _, err := limiter.registrationCreateBucketsWithCohorts(subject, policy); err == nil {
			t.Errorf("invalid MX cohort set %d was accepted", index)
		}
	}
}

func TestWeChatRegistrationProofClaimUsesDedicatedIPAndHashedProofKeys(t *testing.T) {
	limiter := &RateLimiter{client: &Client{keyPrefix: "up:test:"}}
	rawLoginCode := "fresh-login-code"
	rawPhoneCode := "fresh-phone-code"
	loginHash := registration.HashAbuseValue(rawLoginCode)
	phoneHash := registration.HashAbuseValue(rawPhoneCode)
	keys := limiter.wechatRegistrationProofKeys("203.0.113.7", loginHash, phoneHash)
	if len(keys) != 3 || !strings.Contains(keys[0], rateLimitWeChatRegistrationProofSegment+"ip:203.0.113.7") ||
		!strings.Contains(keys[1], rateLimitWeChatLoginSegment+"proof:"+loginHash) ||
		!strings.Contains(keys[2], rateLimitWeChatPhoneSegment+"proof:"+phoneHash) {
		t.Fatalf("proof claim keys=%#v", keys)
	}
	joined := strings.Join(keys, " ")
	if strings.Contains(joined, rawLoginCode) || strings.Contains(joined, rawPhoneCode) {
		t.Fatalf("proof claim keys leaked raw codes: %q", joined)
	}
}

func TestWeChatRegistrationProofClaimRejectsInvalidScopeBeforeRedis(t *testing.T) {
	limiter := &RateLimiter{client: &Client{keyPrefix: "up:test:"}}
	validHash := registration.HashAbuseValue("code")
	for _, test := range []struct {
		name      string
		ip        string
		loginHash string
		phoneHash string
		limit     int
		window    time.Duration
	}{
		{name: "missing ip", loginHash: validHash, phoneHash: validHash, limit: 1, window: time.Minute},
		{name: "raw login code", ip: "203.0.113.7", loginHash: "code", phoneHash: validHash, limit: 1, window: time.Minute},
		{name: "raw phone code", ip: "203.0.113.7", loginHash: validHash, phoneHash: "code", limit: 1, window: time.Minute},
		{name: "zero limit", ip: "203.0.113.7", loginHash: validHash, phoneHash: validHash, window: time.Minute},
		{name: "sub-millisecond window", ip: "203.0.113.7", loginHash: validHash, phoneHash: validHash, limit: 1, window: time.Nanosecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			allowed, _, err := limiter.ClaimWeChatRegistrationProofs(t.Context(), test.ip, test.loginHash, test.phoneHash, test.limit, test.window)
			if err == nil || allowed {
				t.Fatalf("allowed=%v err=%v", allowed, err)
			}
		})
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
