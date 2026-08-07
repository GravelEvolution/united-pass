package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
		{"v1 valid", NewProviderSessionCredential(ProviderSessionCredentialVersion1, "zitadel", "s1", ""), false},
		{"v1 missing id", NewProviderSessionCredential(ProviderSessionCredentialVersion1, "zitadel", "", ""), true},
		{"v1 with token", NewProviderSessionCredential(ProviderSessionCredentialVersion1, "zitadel", "s1", "t"), true},
		{"v2 valid", NewProviderSessionCredential(ProviderSessionCredentialVersion2, "zitadel", "s1", "t"), false},
		{"v2 missing id", NewProviderSessionCredential(ProviderSessionCredentialVersion2, "zitadel", "", "t"), true},
		{"v2 missing token", NewProviderSessionCredential(ProviderSessionCredentialVersion2, "zitadel", "s1", ""), true},
		{"missing provider", NewProviderSessionCredential(ProviderSessionCredentialVersion2, "", "s1", "t"), true},
		{"unknown version", NewProviderSessionCredential(99, "zitadel", "s1", "t"), true},
		{"oversized session id", NewProviderSessionCredential(ProviderSessionCredentialVersion2, "zitadel", strings.Repeat("s", 201), "t"), true},
		{"oversized session token", NewProviderSessionCredential(ProviderSessionCredentialVersion2, "zitadel", "s1", strings.Repeat("t", 201)), true},
	}
	for _, tc := range cases {
		if err := tc.cred.Validate(); (err != nil) != tc.wantErr {
			t.Fatalf("%s: Validate err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}

	// Only a complete Version-2 credential can finalize an OAuth
	// authorization request (legacy sessions fail closed into re-login).
	if !NewProviderSessionCredential(ProviderSessionCredentialVersion2, "zitadel", "s1", "t").CanFinalizeAuthorization() {
		t.Fatal("complete v2 credential must finalize")
	}
	if NewProviderSessionCredential(ProviderSessionCredentialVersion1, "zitadel", "s1", "").CanFinalizeAuthorization() {
		t.Fatal("legacy v1 credential must never finalize")
	}
}

func TestSealAndDecryptProviderSessionCredential(t *testing.T) {
	svc := newTestService(testEncryptor())
	ctx := context.Background()

	cred := NewProviderSessionCredential(
		ProviderSessionCredentialVersion2,
		"zitadel",
		"session-123",
		"secret-provider-token",
	)
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
		t.Fatalf("roundtrip mismatch: version=%d provider=%q sessionId=%q",
			got.Version(), got.Provider(), got.SessionID())
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
	if _, err := svc.SealProviderSessionCredential(NewProviderSessionCredential(ProviderSessionCredentialVersion2, "zitadel", "s1", "")); err == nil {
		t.Fatal("token-less v2 credential must not seal")
	}
}

// TestProviderSessionCredentialNeverLeaks replicates the P3.1 callback
// leak battery: every rendering path a log line, panic dump, debugger or
// serializer could take must stay redacted for the runtime credential.
func TestProviderSessionCredentialNeverLeaks(t *testing.T) {
	cred := NewProviderSessionCredential(
		ProviderSessionCredentialVersion2,
		"zitadel",
		"session-123",
		"secret-provider-token",
	)

	renderings := []string{
		cred.String(),
		cred.GoString(),
		fmt.Sprintf("%v", cred),
		fmt.Sprintf("%+v", cred),
		fmt.Sprintf("%#v", cred),
		fmt.Sprintf("%q", cred),
		fmt.Sprintf("%s", cred),
		fmt.Sprintf("%v", &cred),
		fmt.Sprintf("%+v", &cred),
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("credential", "cred", cred)
	renderings = append(renderings, buf.String())

	// Marshaling the runtime type itself must never produce the token:
	// serialization happens exclusively through the private wire DTO.
	marshaled, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renderings = append(renderings, string(marshaled))

	for _, rendered := range renderings {
		if strings.Contains(rendered, "secret-provider-token") || strings.Contains(rendered, "session-123") {
			t.Fatalf("credential leaked: %q", rendered)
		}
	}

	// The narrow getters still expose the values to the decision seam.
	if cred.SessionID() != "session-123" || cred.SessionToken() != "secret-provider-token" {
		t.Fatal("narrow seam getters broken")
	}
}

// TestProviderSessionTokenNeverLeaks pins the same guarantee on the
// in-memory bearer carrier crossing the auth → session boundary.
func TestProviderSessionTokenNeverLeaks(t *testing.T) {
	token := auth.NewProviderSessionToken("secret-provider-token")

	renderings := []string{
		token.String(),
		token.GoString(),
		fmt.Sprintf("%v", token),
		fmt.Sprintf("%+v", token),
		fmt.Sprintf("%#v", token),
		fmt.Sprintf("%q", token),
		fmt.Sprintf("%v", &token),
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("token", "token", token)
	renderings = append(renderings, buf.String())
	marshaled, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renderings = append(renderings, string(marshaled))

	for _, rendered := range renderings {
		if strings.Contains(rendered, "secret-provider-token") {
			t.Fatalf("provider session token leaked: %q", rendered)
		}
	}
	if token.Empty() || token.Token() != "secret-provider-token" {
		t.Fatal("narrow seam accessors broken")
	}
	if !auth.NewProviderSessionToken("").Empty() {
		t.Fatal("empty token must report Empty")
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
		ProviderSessionToken:     auth.NewProviderSessionToken("provider-session-token"),
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
	if cred.Version() != ProviderSessionCredentialVersion2 ||
		cred.Provider() != "fake" ||
		cred.SessionID() != "provider-session-ref" ||
		cred.SessionToken() != "provider-session-token" {
		t.Fatalf("unexpected credential: version=%d provider=%q sessionId=%q",
			cred.Version(), cred.Provider(), cred.SessionID())
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
		ProviderSessionToken:  auth.NewProviderSessionToken("orphan-token"),
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
	}); err == nil {
		t.Fatal("token without reference must fail")
	}
}
