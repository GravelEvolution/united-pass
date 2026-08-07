package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestProviderSessionCredentialValidate(t *testing.T) {
	cases := []struct {
		name    string
		cred    ProviderSessionCredential
		wantErr bool
	}{
		{"v1 valid", ProviderSessionCredential{Version: ProviderSessionCredentialVersion1, Provider: "zitadel", SessionID: "s1"}, false},
		{"v1 missing id", ProviderSessionCredential{Version: ProviderSessionCredentialVersion1, Provider: "zitadel"}, true},
		{"v1 with token", ProviderSessionCredential{Version: ProviderSessionCredentialVersion1, Provider: "zitadel", SessionID: "s1", SessionToken: "t"}, true},
		{"v2 valid", ProviderSessionCredential{Version: ProviderSessionCredentialVersion2, Provider: "zitadel", SessionID: "s1", SessionToken: "t"}, false},
		{"v2 missing id", ProviderSessionCredential{Version: ProviderSessionCredentialVersion2, Provider: "zitadel", SessionToken: "t"}, true},
		{"v2 missing token", ProviderSessionCredential{Version: ProviderSessionCredentialVersion2, Provider: "zitadel", SessionID: "s1"}, true},
		{"unknown version", ProviderSessionCredential{Version: 99, SessionID: "s1", SessionToken: "t"}, true},
	}
	for _, tc := range cases {
		if err := tc.cred.Validate(); (err != nil) != tc.wantErr {
			t.Fatalf("%s: Validate err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}

	// Only a complete Version-2 credential can finalize an OAuth
	// authorization request (legacy sessions fail closed into re-login).
	if !(ProviderSessionCredential{Version: ProviderSessionCredentialVersion2, SessionID: "s1", SessionToken: "t"}).CanFinalizeAuthorization() {
		t.Fatal("complete v2 credential must finalize")
	}
	if (ProviderSessionCredential{Version: ProviderSessionCredentialVersion1, SessionID: "s1"}).CanFinalizeAuthorization() {
		t.Fatal("legacy v1 credential must never finalize")
	}
}

func TestSealAndDecryptProviderSessionCredential(t *testing.T) {
	svc := newTestService(testEncryptor())
	ctx := context.Background()

	cred := ProviderSessionCredential{
		Version:      ProviderSessionCredentialVersion2,
		Provider:     "zitadel",
		SessionID:    "session-123",
		SessionToken: "secret-provider-token",
	}
	sealed, err := svc.SealProviderSessionCredential(cred)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// The at-rest form is ciphertext: never the plaintext token or ID.
	if strings.Contains(string(sealed), "secret-provider-token") ||
		strings.Contains(string(sealed), "session-123") {
		t.Fatal("sealed credential leaks plaintext")
	}

	got, err := svc.DecryptProviderSessionCredential(ctx, sealed)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != cred {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// Missing ciphertext fails closed as a legacy/absent credential.
	if _, err := svc.DecryptProviderSessionCredential(ctx, ""); !errors.Is(err, ErrProviderSessionCredentialMissing) {
		t.Fatalf("empty ciphertext must report missing, got %v", err)
	}

	// Tampered ciphertext never yields a credential.
	if _, err := svc.DecryptProviderSessionCredential(ctx, sealed+"x"); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}

	// Sealing requires an encryptor (no plaintext downgrade).
	noEnc := newTestService(nil)
	if _, err := noEnc.SealProviderSessionCredential(cred); !errors.Is(err, ErrMissingEncryptionKey) {
		t.Fatalf("seal without encryptor must fail, got %v", err)
	}
	if _, err := noEnc.DecryptProviderSessionCredential(ctx, sealed); !errors.Is(err, ErrMissingEncryptionKey) {
		t.Fatalf("decrypt without encryptor must fail, got %v", err)
	}

	// Invalid credentials never seal.
	if _, err := svc.SealProviderSessionCredential(ProviderSessionCredential{Version: ProviderSessionCredentialVersion2, SessionID: "s1"}); err == nil {
		t.Fatal("token-less v2 credential must not seal")
	}
}

func TestCreateSessionSealsVersion2Credential(t *testing.T) {
	store := newFakeStore()
	svc := NewService(store, SystemClock{}, time.Hour, 30*time.Hour, 15*time.Minute, 5*time.Minute, testEncryptor())
	ctx := context.Background()

	input := CreateSessionInput{
		UserID:                   identity.UserID("user_cred_test"),
		Provider:                 "fake",
		ProviderSessionReference: "provider-session-ref",
		ProviderSessionToken:     "provider-session-token",
		AuthenticationMethods:    []auth.AuthenticationMethod{auth.MethodPassword},
	}
	result, err := svc.CreateSession(ctx, input)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	stored := store.sessions[result.TokenHash]
	if stored.ProviderSessionCredential == "" {
		t.Fatal("expected a sealed provider session credential")
	}
	// Bearer material is ciphertext only.
	if strings.Contains(string(stored.ProviderSessionCredential), "provider-session-token") {
		t.Fatal("provider session token stored in plaintext")
	}
	// The legacy reference stays encrypted for revocation compatibility.
	if stored.ProviderSessionReference == "provider-session-ref" {
		t.Fatal("provider session reference stored in plaintext")
	}

	cred, err := svc.DecryptProviderSessionCredential(ctx, stored.ProviderSessionCredential)
	if err != nil {
		t.Fatalf("decrypt stored credential: %v", err)
	}
	if cred.Version != ProviderSessionCredentialVersion2 ||
		cred.Provider != "fake" ||
		cred.SessionID != "provider-session-ref" ||
		cred.SessionToken != "provider-session-token" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
	if !cred.CanFinalizeAuthorization() {
		t.Fatal("sealed credential must be finalizing")
	}
}

func TestCreateSessionLegacyPathWithoutToken(t *testing.T) {
	store := newFakeStore()
	svc := NewService(store, SystemClock{}, time.Hour, 30*time.Hour, 15*time.Minute, 5*time.Minute, testEncryptor())
	ctx := context.Background()

	// No token: the legacy path stores only the encrypted reference and no
	// credential — such sessions cannot finalize OAuth authorization
	// requests and fail closed into re-login (ADR-0005 §3).
	result, err := svc.CreateSession(ctx, CreateSessionInput{
		UserID:                   identity.UserID("user_legacy_test"),
		Provider:                 "fake",
		ProviderSessionReference: "legacy-ref",
		AuthenticationMethods:    []auth.AuthenticationMethod{auth.MethodPassword},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	stored := store.sessions[result.TokenHash]
	if stored.ProviderSessionCredential != "" {
		t.Fatal("legacy session must carry no credential")
	}
	if _, err := svc.DecryptProviderSessionCredential(ctx, stored.ProviderSessionCredential); !errors.Is(err, ErrProviderSessionCredentialMissing) {
		t.Fatalf("legacy session must report a missing credential, got %v", err)
	}

	// A token without a session reference is a wiring bug, not a
	// downgradable case.
	if _, err := svc.CreateSession(ctx, CreateSessionInput{
		UserID:                identity.UserID("user_bad_test"),
		Provider:              "fake",
		ProviderSessionToken:  "orphan-token",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
	}); err == nil {
		t.Fatal("token without reference must fail")
	}
}
