//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
)

// TestIntegration_ResolveConsentClient verifies the provider-identity
// lookup used by consent resolution: hydration, anti-enumeration for
// unknown identities, and invisibility of soft-deleted records.
func TestIntegration_ResolveConsentClient(t *testing.T) {
	_, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-lookup-owner")
	appID, clientID := provisionTestApp(t, appRepo, "lookup-app", ownerID)
	ctx := context.Background()

	providerClientID := "prov-client-" + string(clientID)

	t.Run("hydrated facts", func(t *testing.T) {
		facts, err := appRepo.ResolveConsentClient(ctx, "zitadel", providerClientID)
		if err != nil {
			t.Fatalf("ResolveConsentClient: %v", err)
		}
		if facts.Client.ID != clientID || facts.Application.ID != appID {
			t.Fatalf("facts mismatch: %+v", facts)
		}
		if facts.Client.Status != applications.StatusActive ||
			facts.Application.Status != applications.StatusActive {
			t.Fatalf("statuses: client=%s app=%s", facts.Client.Status, facts.Application.Status)
		}
		if facts.Application.OwnerName == "" {
			t.Fatal("owner display name not joined")
		}
		if len(facts.Client.RedirectURIs) != 2 {
			t.Fatalf("redirect uris = %+v", facts.Client.RedirectURIs)
		}
		if len(facts.Client.Scopes) != 2 {
			t.Fatalf("scopes = %v", facts.Client.Scopes)
		}
	})

	t.Run("unknown identities", func(t *testing.T) {
		for _, tc := range []struct{ provider, clientID string }{
			{"zitadel", "prov-client-does-not-exist"},
			{"fake", providerClientID}, // same id, different provider
			{"", providerClientID},
			{"zitadel", ""},
		} {
			if _, err := appRepo.ResolveConsentClient(ctx, tc.provider, tc.clientID); !errors.Is(err, consent.ErrClientUnknown) {
				t.Fatalf("(%q,%q): err = %v, want ErrClientUnknown", tc.provider, tc.clientID, err)
			}
		}
	})

	t.Run("disabled client still resolves for domain-side denial", func(t *testing.T) {
		client, err := appRepo.GetClient(ctx, appID, clientID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if err := appRepo.SetClientStatus(ctx, clientID, applications.StatusDisabled, client.Version); err != nil {
			t.Fatalf("SetClientStatus: %v", err)
		}
		facts, err := appRepo.ResolveConsentClient(ctx, "zitadel", providerClientID)
		if err != nil {
			t.Fatalf("ResolveConsentClient: %v", err)
		}
		if facts.Client.Status != applications.StatusDisabled {
			t.Fatalf("status = %s", facts.Client.Status)
		}
	})

	t.Run("soft-deleted application is invisible", func(t *testing.T) {
		// Deleting an application requires no live clients, so retire the
		// client through the two-step deletion flow first.
		delOp := newTestOperation(appID, clientID, applications.ProviderOperationDelete)
		if err := appRepo.MarkClientDeleting(ctx, clientID, delOp); err != nil {
			t.Fatalf("MarkClientDeleting: %v", err)
		}
		if err := appRepo.CompleteClientDeletion(ctx, clientID, delOp.ID); err != nil {
			t.Fatalf("CompleteClientDeletion: %v", err)
		}
		app, err := appRepo.GetApplication(ctx, appID)
		if err != nil {
			t.Fatalf("GetApplication: %v", err)
		}
		if err := appRepo.DeleteApplication(ctx, appID, app.Version); err != nil {
			t.Fatalf("DeleteApplication: %v", err)
		}
		if _, err := appRepo.ResolveConsentClient(ctx, "zitadel", providerClientID); !errors.Is(err, consent.ErrClientUnknown) {
			t.Fatalf("err = %v, want ErrClientUnknown after deletion", err)
		}
	})
}

// TestIntegration_ResolutionEndToEnd runs the full side-effect free
// resolution pipeline against real PostgreSQL records and the fake
// provider: every union outcome plus the guarantee that the GET writes
// nothing (no operation rows, no grants, no provider completions).
func TestIntegration_ResolutionEndToEnd(t *testing.T) {
	grants, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-e2e-owner")
	userID := createConsentUser(t, users, "consent-e2e-user", "consent-e2e-user@example.com")
	appID, clientID := provisionTestApp(t, appRepo, "e2e-app", ownerID)
	ctx := context.Background()

	// The seeded client uses consent_mode=always; switch it to
	// first_authorization so reuse can be exercised.
	client, err := appRepo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	client.ConsentMode = applications.ConsentModeFirstAuthorization
	if err := appRepo.UpdateClientConfig(ctx, clientID, applications.ClientConfigUpdate{
		Name:         client.Name,
		LogoutURI:    client.LogoutURI,
		ConsentMode:  applications.ConsentModeFirstAuthorization,
		RedirectURIs: client.RedirectURIs,
		Scopes:       client.Scopes,
	}, client.Version); err != nil {
		t.Fatalf("UpdateClientConfig: %v", err)
	}

	providerClientID := "prov-client-" + string(clientID)
	provider := consent.NewFakeAuthRequestProvider()
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-valid", ClientID: providerClientID,
		Scopes: []string{"openid", "profile"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC(),
	})
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-consent", ClientID: providerClientID,
		Scopes: []string{"openid", "profile"}, RedirectURI: "https://app.example.com/callback",
		Prompts: []consent.Prompt{consent.PromptConsent}, CreatedAt: time.Now().UTC(),
	})
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-evil", ClientID: providerClientID,
		Scopes: []string{"openid", "profile"}, RedirectURI: "https://evil.example/steal",
		CreatedAt: time.Now().UTC(),
	})
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-unknown-client", ClientID: "prov-client-does-not-exist",
		Scopes: []string{"openid"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC(),
	})
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-bad-scope", ClientID: providerClientID,
		Scopes: []string{"openid", "admin:read"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC(),
	})

	svc, err := consent.NewResolutionService(provider, appRepo, grants, "zitadel",
		func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatalf("NewResolutionService: %v", err)
	}

	sessionInput := func(authRequestID string) consent.ResolutionInput {
		return consent.ResolutionInput{
			AuthRequestID: authRequestID,
			Session: &consent.ResolutionSession{
				UserID:             userID,
				AuthenticationTime: time.Now().UTC().Add(-time.Minute),
			},
		}
	}

	t.Run("anonymous resolves unauthenticated", func(t *testing.T) {
		res, err := svc.Resolve(ctx, consent.ResolutionInput{AuthRequestID: "V2-int-valid"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != consent.ResolutionUnauthenticated {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("authenticated without grant resolves valid", func(t *testing.T) {
		res, err := svc.Resolve(ctx, sessionInput("V2-int-valid"))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != consent.ResolutionValid {
			t.Fatalf("status = %q", res.Status)
		}
		if res.ApplicationName != "e2e-app" || res.ApplicationOwner == "" {
			t.Fatalf("application facts: %+v", res)
		}
		if res.RedirectHost != "app.example.com" {
			t.Fatalf("redirect host = %q", res.RedirectHost)
		}
		if len(res.Scopes) != 2 || res.Scopes[0].Scope != "openid" || res.Scopes[0].Label != "OpenID" {
			t.Fatalf("scopes = %+v", res.Scopes)
		}
	})

	t.Run("resolution is side-effect free", func(t *testing.T) {
		var opCount, grantCount int
		if err := grants.pool.QueryRow(ctx,
			`SELECT count(*) FROM oauth_authorization_decision_operations`).Scan(&opCount); err != nil {
			t.Fatalf("count operations: %v", err)
		}
		if err := grants.pool.QueryRow(ctx,
			`SELECT count(*) FROM oauth_authorization_grants`).Scan(&grantCount); err != nil {
			t.Fatalf("count grants: %v", err)
		}
		if opCount != 0 || grantCount != 0 {
			t.Fatalf("resolution wrote rows: ops=%d grants=%d", opCount, grantCount)
		}
		for _, id := range []string{"V2-int-valid", "V2-int-consent", "V2-int-evil"} {
			if provider.Completions(id) != 0 {
				t.Fatalf("resolution completed provider request %s", id)
			}
		}
	})

	// Commit an Allow through the real §5 flow so reuse evaluation runs
	// against a genuine grant row.
	op := allowOperationFor("V2-int-seed", consent.CompletionAllow, userID, clientID,
		[]string{"openid", "profile", "offline_access"})
	stored := claimAndProve(t, grants, op)
	if err := grants.CommitAllowDecision(ctx, consent.AllowCommit{OperationID: stored.ID}); err != nil {
		t.Fatalf("CommitAllowDecision: %v", err)
	}

	t.Run("reusable grant resolves already_authorized", func(t *testing.T) {
		res, err := svc.Resolve(ctx, sessionInput("V2-int-valid"))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != consent.ResolutionAlreadyAuthorized {
			t.Fatalf("status = %q", res.Status)
		}
		if res.ApplicationName != "e2e-app" || res.RedirectHost != "app.example.com" {
			t.Fatalf("reuse facts: %+v", res)
		}
	})

	t.Run("prompt consent forces the consent screen", func(t *testing.T) {
		res, err := svc.Resolve(ctx, sessionInput("V2-int-consent"))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != consent.ResolutionValid {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("redirect mismatch exposes parsed host only", func(t *testing.T) {
		res, err := svc.Resolve(ctx, sessionInput("V2-int-evil"))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != consent.ResolutionRedirectMismatch || res.AttemptedRedirectHost != "evil.example" {
			t.Fatalf("resolution = %+v", res)
		}
	})

	t.Run("unknown local client", func(t *testing.T) {
		res, err := svc.Resolve(ctx, sessionInput("V2-int-unknown-client"))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != consent.ResolutionClientNotFound {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("scope outside the client catalog", func(t *testing.T) {
		res, err := svc.Resolve(ctx, sessionInput("V2-int-bad-scope"))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != consent.ResolutionScopeNotAllowed ||
			len(res.DisallowedScopes) != 1 || res.DisallowedScopes[0] != "admin:read" {
			t.Fatalf("resolution = %+v", res)
		}
	})

	t.Run("vanished provider request resolves expired", func(t *testing.T) {
		res, err := svc.Resolve(ctx, consent.ResolutionInput{AuthRequestID: "V2-int-gone"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != consent.ResolutionExpired || res.ExpiredAt.IsZero() {
			t.Fatalf("resolution = %+v", res)
		}
	})

	t.Run("still side-effect free after the full matrix", func(t *testing.T) {
		var opCount int
		if err := grants.pool.QueryRow(ctx,
			`SELECT count(*) FROM oauth_authorization_decision_operations`).Scan(&opCount); err != nil {
			t.Fatalf("count operations: %v", err)
		}
		if opCount != 1 { // only the seeded Allow operation exists
			t.Fatalf("operations = %d, want exactly the seeded one", opCount)
		}
	})
}
