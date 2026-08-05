//go:build integration

// Package zitadel integration tests exercise the adapter against a real
// ZITADEL instance (see docker-compose.zitadel.yml and
// scripts/zitadel-init.sh). They are skipped unless the following variables
// are set:
//
//	UP_TEST_ZITADEL_BASE_URL     e.g. http://localhost:8080
//	UP_TEST_ZITADEL_KEY_FILE     path to the service account key.json
//	UP_TEST_ZITADEL_USER         login name of the test human user
//	UP_TEST_ZITADEL_PASSWORD     password of the test human user
//	UP_TEST_ZITADEL_TOTP_CODE    current TOTP code (only when the user has TOTP)
//
// The test verifies the full login flow, first-login identity mapping, MFA,
// revocation and readiness against the running instance.
package zitadel

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func testZitadelConfig(t *testing.T) config.AuthProviderConfig {
	t.Helper()
	baseURL := os.Getenv("UP_TEST_ZITADEL_BASE_URL")
	keyFile := os.Getenv("UP_TEST_ZITADEL_KEY_FILE")
	if baseURL == "" || keyFile == "" {
		t.Skip("UP_TEST_ZITADEL_BASE_URL / UP_TEST_ZITADEL_KEY_FILE not set; skipping ZITADEL integration tests")
	}
	return config.AuthProviderConfig{
		Provider:              ProviderName,
		BaseURL:               baseURL,
		ServiceAccountKeyFile: keyFile,
		ProjectID:             os.Getenv("UP_TEST_ZITADEL_PROJECT_ID"),
		Domain:                "localhost",
	}
}

// recordingLinker records the provider subjects it resolved and always
// returns an active user.
type recordingLinker struct {
	mu       chan struct{} // unused; kept simple for the test
	subjects []string
}

func (l *recordingLinker) GetOrCreateUserByProviderSubject(_ context.Context, _, _ string, info identity.ProviderUserInfo) (identity.User, error) {
	l.subjects = append(l.subjects, info.Subject)
	return identity.User{
		ID:     identity.UserID("user_test_local"),
		Status: identity.UserStatusActive,
	}, nil
}

func TestIntegration_ZitadelAuthenticatorE2E(t *testing.T) {
	cfg := testZitadelConfig(t)
	user := os.Getenv("UP_TEST_ZITADEL_USER")
	password := os.Getenv("UP_TEST_ZITADEL_PASSWORD")
	if user == "" || password == "" {
		t.Skip("UP_TEST_ZITADEL_USER / UP_TEST_ZITADEL_PASSWORD not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sdk, err := NewSDKClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewSDKClient: %v", err)
	}
	defer sdk.Close()

	linker := &recordingLinker{}
	a := NewAuthenticator(sdk.SessionServiceV2(), sdk.UserServiceV2(), linker, cfg.ProjectID, cfg.Domain, nil)

	// Readiness: the service account must be able to reach the API.
	if err := a.Check(ctx); err != nil {
		t.Fatalf("provider readiness: %v", err)
	}

	// Step 1: password authentication.
	res, err := a.BeginPasswordAuthentication(ctx, auth.PasswordAuthenticationInput{
		Identifier: user,
		Password:   password,
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}

	switch res.Status {
	case auth.StatusAuthenticated:
		t.Logf("authenticated without MFA (subject=%s)", linker.subjects[len(linker.subjects)-1])
		if res.UserID != identity.UserID("user_test_local") {
			t.Errorf("local user id = %q, want user_test_local", res.UserID)
		}
		if res.ProviderSessionReference == "" {
			t.Error("provider session reference must be set after authentication")
		}
		// Step 3: revoke the provider session.
		if err := a.RevokeProviderSession(ctx, res.ProviderSessionReference); err != nil {
			t.Fatalf("RevokeProviderSession: %v", err)
		}

	case auth.StatusMFARequired:
		t.Logf("MFA required; available methods: %v", res.AvailableMethods)
		code := os.Getenv("UP_TEST_ZITADEL_TOTP_CODE")
		if code == "" {
			t.Skip("MFA required but UP_TEST_ZITADEL_TOTP_CODE not set")
		}
		// Step 2: complete MFA with the TOTP code.
		completed, err := a.CompleteMFA(ctx, auth.MFAChallengeInput{
			MFAToken: res.MFAToken,
			Method:   auth.MFAMethodTOTP,
			Code:     code,
		})
		if err != nil {
			t.Fatalf("CompleteMFA: %v", err)
		}
		if completed.Status != auth.StatusAuthenticated {
			t.Fatalf("MFA completion status = %q, want authenticated", completed.Status)
		}
		if len(linker.subjects) == 0 {
			t.Error("identity linker was not called after MFA completion")
		}
		// Step 3: revoke the provider session.
		if err := a.RevokeProviderSession(ctx, completed.ProviderSessionReference); err != nil {
			t.Fatalf("RevokeProviderSession: %v", err)
		}

	case auth.StatusInvalidCredentials:
		t.Fatalf("invalid credentials for configured test user: check UP_TEST_ZITADEL_USER/PASSWORD")

	default:
		t.Fatalf("unexpected status: %q", res.Status)
	}
}

func TestIntegration_ZitadelAuthenticatorWrongPassword(t *testing.T) {
	cfg := testZitadelConfig(t)
	user := os.Getenv("UP_TEST_ZITADEL_USER")
	password := os.Getenv("UP_TEST_ZITADEL_PASSWORD")
	if user == "" || password == "" {
		t.Skip("UP_TEST_ZITADEL_USER / UP_TEST_ZITADEL_PASSWORD not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sdk, err := NewSDKClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewSDKClient: %v", err)
	}
	defer sdk.Close()

	a := NewAuthenticator(sdk.SessionServiceV2(), sdk.UserServiceV2(), &recordingLinker{}, cfg.ProjectID, cfg.Domain, nil)

	res, err := a.BeginPasswordAuthentication(ctx, auth.PasswordAuthenticationInput{
		Identifier: user,
		Password:   "definitely-wrong-password",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusInvalidCredentials {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusInvalidCredentials)
	}
}
