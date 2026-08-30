package redis

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
)

func onboardingTestStore(t *testing.T) *WeChatOnboardingStore {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	encryptor, err := session.NewAESGCMEncryptor(base64.StdEncoding.EncodeToString(key), "test-v1")
	if err != nil {
		t.Fatal(err)
	}
	return NewWeChatOnboardingStore(&Client{keyPrefix: "up:test:"}, encryptor)
}

func TestWeChatOnboardingPayloadIsEncryptedAndBoundToTokenHash(t *testing.T) {
	store := onboardingTestStore(t)
	rawToken := "raw-onboarding-token"
	hash := session.HashToken(rawToken)
	data := wechatonboarding.ChallengeData{
		Purpose: wechatonboarding.ChallengePurpose, Kind: wechatonboarding.ChallengeKindOnboarding,
		TenantID: "wx-app", Subject: "private-open-id", Phone: "+8613800138000", TargetUserID: identity.UserID("user_pending"), CreatedAt: time.Now().UTC(),
	}
	ciphertext, err := store.seal(hash, data)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{rawToken, data.Subject, data.Phone, data.TenantID, wechatonboarding.ChallengePurpose} {
		if strings.Contains(ciphertext, secret) {
			t.Fatalf("ciphertext leaked %q", secret)
		}
	}
	opened, err := store.open(hash, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if opened.TokenHash != hash || opened.Subject != data.Subject || opened.Phone != data.Phone || opened.TargetUserID != data.TargetUserID {
		t.Fatalf("opened = %#v", opened)
	}
	if _, err := store.open(session.HashToken("different-token"), ciphertext); !errors.Is(err, wechatonboarding.ErrChallengeInvalid) {
		t.Fatalf("swapped ciphertext error = %v", err)
	}
	key := store.challengeKey(hash)
	if strings.Contains(key, rawToken) || !strings.Contains(key, hash) {
		t.Fatalf("unsafe Redis key = %q", key)
	}
}

func TestWeChatOnboardingStoreRejectsWrongPurposeOrIncompleteMFA(t *testing.T) {
	store := onboardingTestStore(t)
	hash := session.HashToken("token")
	wrongPurpose := wechatonboarding.ChallengeData{
		Purpose: "other-purpose", Kind: wechatonboarding.ChallengeKindOnboarding,
		TenantID: "wx-app", Subject: "open-id", CreatedAt: time.Now().UTC(),
	}
	if _, err := store.seal(hash, wrongPurpose); !errors.Is(err, wechatonboarding.ErrChallengeInvalid) {
		t.Fatalf("wrong purpose error = %v", err)
	}
	incompleteMFA := wechatonboarding.ChallengeData{
		Purpose: wechatonboarding.MFAChallengePurpose, Kind: wechatonboarding.ChallengeKindMFA,
		TenantID: "wx-app", Subject: "open-id", TargetUserID: identity.UserID("user_1"), ProviderSessionID: "provider-session",
		AvailableMethods: []auth.MFAMethod{auth.MFAMethodTOTP}, CreatedAt: time.Now().UTC(),
	}
	if _, err := store.seal(hash, incompleteMFA); !errors.Is(err, wechatonboarding.ErrChallengeInvalid) {
		t.Fatalf("incomplete MFA error = %v", err)
	}
	completeMFA := incompleteMFA
	completeMFA.NormalizedEmail = "owner@example.com"
	completeMFA.ExpectedVersion = 7
	completeMFA.ExpectedSecurityEpoch = 4
	if _, err := store.seal(hash, completeMFA); err != nil {
		t.Fatalf("complete MFA authority snapshot rejected: %v", err)
	}
}

func TestWeChatOnboardingMFACleanupPayloadIsEncryptedAndTokenBound(t *testing.T) {
	store := onboardingTestStore(t)
	hash := session.HashToken("mfa-token")
	data := wechatonboarding.ChallengeData{
		Purpose: wechatonboarding.MFAChallengePurpose, Kind: wechatonboarding.ChallengeKindMFA,
		TenantID: "wx-app", Subject: "private-open-id", TargetUserID: identity.UserID("user_1"),
		NormalizedEmail: "owner@example.com", ExpectedVersion: 7, ExpectedSecurityEpoch: 4,
		ProviderSessionID: "private-provider-session", AvailableMethods: []auth.MFAMethod{auth.MFAMethodTOTP}, CreatedAt: time.Now().UTC(),
	}
	ciphertext, err := store.sealCleanup(hash, data)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{data.ProviderSessionID, data.Subject, data.NormalizedEmail, hash, wechatOnboardingCleanupPurpose} {
		if strings.Contains(ciphertext, private) {
			t.Fatalf("cleanup ciphertext leaked private value %q", private)
		}
	}
	payload, err := store.openCleanup(hash, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if payload.ProviderSessionID != data.ProviderSessionID || payload.TokenHash != hash {
		t.Fatalf("opened cleanup payload = %#v", payload)
	}
	if _, err := store.openCleanup(session.HashToken("other-mfa-token"), ciphertext); !errors.Is(err, errWeChatOnboardingCleanupInvalid) {
		t.Fatalf("swapped cleanup ciphertext error = %v", err)
	}
}
