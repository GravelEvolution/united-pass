//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the authorization interaction gateway service
//

package consent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// flippingGrantReader serves the inner store's grants until flipped; with
// afterFirst set, the first read stays valid and every later read reports
// the grant gone — simulating a revocation landing between the gateway
// pre-check and the authoritative re-check inside DecideSilently.
type flippingGrantReader struct {
	inner      *fakeGrantStore
	flipped    bool
	afterFirst bool
	calls      int
}

func (f *flippingGrantReader) GetGrant(ctx context.Context, userID identity.UserID, clientID applications.OAuthClientID) (Grant, error) {
	if f.afterFirst {
		f.calls++
		if f.calls > 1 {
			return Grant{}, ErrGrantNotFound
		}
	}
	if f.flipped {
		return Grant{}, ErrGrantNotFound
	}
	return f.inner.GetGrant(ctx, userID, clientID)
}

// racingGrantStore exposes the full GrantStore to the decision service
// while routing grant reads through the same flipping reader, so the
// gateway pre-check and the authoritative re-check observe different grant
// states.
type racingGrantStore struct {
	*fakeGrantStore
	reader *flippingGrantReader
}

func (r *racingGrantStore) GetGrant(ctx context.Context, userID identity.UserID, clientID applications.OAuthClientID) (Grant, error) {
	return r.reader.GetGrant(ctx, userID, clientID)
}

// gatewayFixture wires the gateway on the shared fakes with one reusable
// grant seeded for (user_01TEST, cli_test).
type gatewayFixture struct {
	gateway  *InteractionGatewayService
	provider *FakeAuthRequestProvider
	store    *fakeGrantStore
	reader   *fakeCredentialReader
	grants   *flippingGrantReader
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	provider := NewFakeAuthRequestProvider()
	store := newFakeGrantStore()
	store.grants["user_01TEST|cli_test"] = Grant{
		ID:       GrantID("grant_gw_1"),
		UserID:   identity.UserID("user_01TEST"),
		ClientID: applications.OAuthClientID("cli_test"),
		Status:   GrantActive,
		Scopes:   []string{"openid", "profile"},
	}
	resolver := &stubClientResolver{facts: baseFacts()}
	grants := &flippingGrantReader{inner: store}
	resolution := newTestService(t, provider, resolver, grants)
	decisions := newDecisionService(t, provider, resolver, &racingGrantStore{fakeGrantStore: store, reader: grants})
	reader := &fakeCredentialReader{cred: v2Credential()}
	gateway, err := NewInteractionGatewayService(
		provider, resolver, grants, resolution, decisions, "zitadel", testClock())
	if err != nil {
		t.Fatalf("NewInteractionGatewayService: %v", err)
	}
	return &gatewayFixture{gateway: gateway, provider: provider, store: store, reader: reader, grants: grants}
}

func noneView() *AuthRequestView {
	view := baseView()
	view.Prompts = []Prompt{PromptNone}
	return view
}

func gatewaySession() *DecisionSession { return decisionSession(testNow.Add(-5 * time.Minute)) }

func TestNewInteractionGatewayServiceRequiresAllSeams(t *testing.T) {
	provider := NewFakeAuthRequestProvider()
	store := newFakeGrantStore()
	resolver := &stubClientResolver{facts: baseFacts()}
	resolution := newTestService(t, provider, resolver, store)
	decisions := newDecisionService(t, provider, resolver, store)

	if _, err := NewInteractionGatewayService(nil, resolver, store, resolution, decisions, "zitadel", testClock()); err == nil {
		t.Fatal("nil provider accepted")
	}
	if _, err := NewInteractionGatewayService(provider, nil, store, resolution, decisions, "zitadel", testClock()); err == nil {
		t.Fatal("nil client resolver accepted")
	}
	if _, err := NewInteractionGatewayService(provider, resolver, nil, resolution, decisions, "zitadel", testClock()); err == nil {
		t.Fatal("nil grant reader accepted")
	}
	if _, err := NewInteractionGatewayService(provider, resolver, store, nil, decisions, "zitadel", testClock()); err == nil {
		t.Fatal("nil resolution service accepted")
	}
	if _, err := NewInteractionGatewayService(provider, resolver, store, resolution, nil, "zitadel", testClock()); err == nil {
		t.Fatal("nil decision service accepted")
	}
	if _, err := NewInteractionGatewayService(provider, resolver, store, resolution, decisions, "", testClock()); err == nil {
		t.Fatal("empty provider name accepted")
	}
	if _, err := NewInteractionGatewayService(provider, resolver, store, resolution, decisions, "zitadel", nil); err == nil {
		t.Fatal("nil clock accepted")
	}
}

func TestGatewayRouteUnknownRequestFailsLocally(t *testing.T) {
	fx := newGatewayFixture(t)
	action, err := fx.gateway.Route(context.Background(), "V2-missing", nil, nil)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionLocalFailure || action.Failure != LocalFailureExpired {
		t.Fatalf("action = %+v, want local expired failure", action)
	}
}

func TestGatewayRouteInvalidIDFailsLocally(t *testing.T) {
	fx := newGatewayFixture(t)
	action, err := fx.gateway.Route(context.Background(), "", nil, nil)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionLocalFailure || action.Failure != LocalFailureBadRequest {
		t.Fatalf("action = %+v, want local bad-request failure", action)
	}
}

func TestGatewayRouteStructuralPromptValidationPrecedesSemantics(t *testing.T) {
	cases := []struct {
		name    string
		prompts []Prompt
	}{
		{"unknown prompt", []Prompt{PromptUnspecified}},
		{"out-of-range prompt value", []Prompt{Prompt(42)}},
		{"none combined with login", []Prompt{PromptNone, PromptLogin}},
		{"none combined with create", []Prompt{PromptNone, PromptCreate}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newGatewayFixture(t)
			view := baseView()
			view.Prompts = tc.prompts
			fx.provider.AddRequest(view)

			action, err := fx.gateway.Route(context.Background(), view.ID, gatewaySession(), fx.reader)
			if err != nil {
				t.Fatalf("Route: %v", err)
			}
			if action.Kind != ActionLocalFailure || action.Failure != LocalFailureBadRequest {
				t.Fatalf("action = %+v, want local failure (no reinterpretation)", action)
			}
			if fx.provider.Completions(view.ID) != 0 {
				t.Fatal("invalid combination must never reach a provider callback")
			}
			if len(fx.store.ops) != 0 {
				t.Fatal("invalid combination must never claim an operation")
			}
		})
	}
}

func TestGatewayRoutePromptCreateFailsRequestNotSupported(t *testing.T) {
	fx := newGatewayFixture(t)
	view := baseView()
	view.Prompts = []Prompt{PromptCreate}
	fx.provider.AddRequest(view)

	action, err := fx.gateway.Route(context.Background(), view.ID, nil, nil)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionProviderCallback {
		t.Fatalf("action = %+v, want provider callback", action)
	}
	if !strings.Contains(action.Outcome.RedirectURL(), "error=request_not_supported") {
		t.Fatalf("callback = %q", action.Outcome.RedirectURL())
	}
	op := fx.store.operationOf(t)
	if op.CompletionKind != CompletionRequestNotSupported || op.Status != DecisionOperationSucceeded {
		t.Fatalf("operation = %+v", op)
	}
}

func TestGatewayRoutePromptSelectAccountFailsAccountSelection(t *testing.T) {
	fx := newGatewayFixture(t)
	view := baseView()
	view.Prompts = []Prompt{PromptSelectAccount}
	fx.provider.AddRequest(view)

	action, err := fx.gateway.Route(context.Background(), view.ID, gatewaySession(), fx.reader)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionProviderCallback ||
		!strings.Contains(action.Outcome.RedirectURL(), "error=account_selection_required") {
		t.Fatalf("action = %+v", action)
	}
	op := fx.store.operationOf(t)
	if op.CompletionKind != CompletionAccountSelectionNeeded {
		t.Fatalf("operation = %+v", op)
	}
	if op.LocalUserID != "user_01TEST" {
		t.Fatalf("known session must bind the audit actor, got %q", op.LocalUserID)
	}
}

func TestGatewayPromptNoneWithoutSessionFailsLoginRequired(t *testing.T) {
	fx := newGatewayFixture(t)
	fx.provider.AddRequest(noneView())

	action, err := fx.gateway.Route(context.Background(), "V2-request-1", nil, nil)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionProviderCallback ||
		!strings.Contains(action.Outcome.RedirectURL(), "error=login_required") {
		t.Fatalf("action = %+v", action)
	}
	op := fx.store.operationOf(t)
	if op.CompletionKind != CompletionLoginRequired || op.LocalUserID != "" {
		t.Fatalf("operation = %+v", op)
	}
}

func TestGatewayPromptNoneStaleSessionFailsLoginRequired(t *testing.T) {
	fx := newGatewayFixture(t)
	view := noneView()
	zero := time.Duration(0)
	view.MaxAge = &zero // forces the post-request freshness proof
	fx.provider.AddRequest(view)

	// Authenticated BEFORE the request was created: never satisfies.
	action, err := fx.gateway.Route(context.Background(), view.ID, gatewaySession(), fx.reader)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionProviderCallback ||
		!strings.Contains(action.Outcome.RedirectURL(), "error=login_required") {
		t.Fatalf("action = %+v", action)
	}
}

func TestGatewayPromptNoneNonReusableGrantFailsConsentRequired(t *testing.T) {
	fx := newGatewayFixture(t)
	fx.provider.AddRequest(noneView())
	fx.grants.flipped = true // no active grant

	action, err := fx.gateway.Route(context.Background(), "V2-request-1", gatewaySession(), fx.reader)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionProviderCallback ||
		!strings.Contains(action.Outcome.RedirectURL(), "error=consent_required") {
		t.Fatalf("action = %+v", action)
	}
	op := fx.store.operationOf(t)
	if op.CompletionKind != CompletionConsentRequired {
		t.Fatalf("operation = %+v", op)
	}
	if op.LocalUserID != "user_01TEST" || op.ClientID != "cli_test" {
		t.Fatalf("audit bindings = %+v", op)
	}
}

func TestGatewayPromptNoneSilentAllowHappyPath(t *testing.T) {
	fx := newGatewayFixture(t)
	fx.provider.AddRequest(noneView())

	action, err := fx.gateway.Route(context.Background(), "V2-request-1", gatewaySession(), fx.reader)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionProviderCallback {
		t.Fatalf("action = %+v, want provider callback", action)
	}
	if !strings.Contains(action.Outcome.RedirectURL(), "code=fake-code-V2-request-1") {
		t.Fatalf("callback = %q", action.Outcome.RedirectURL())
	}
	op := fx.store.operationOf(t)
	if op.CompletionKind != CompletionAllow || op.Status != DecisionOperationSucceeded {
		t.Fatalf("operation = %+v", op)
	}
	if fx.store.allowCommits != 1 {
		t.Fatalf("allow commits = %d, want 1", fx.store.allowCommits)
	}
	grant, err := fx.store.GetGrant(context.Background(), "user_01TEST", "cli_test")
	if err != nil || grant.Status != GrantActive {
		t.Fatalf("grant after silent allow = %+v, err = %v", grant, err)
	}
}

func TestGatewayPromptNoneRevocationRaceFallsBackToConsentRequired(t *testing.T) {
	fx := newGatewayFixture(t)
	fx.provider.AddRequest(noneView())
	// The pre-check reads the active grant; DecideSilently's authoritative
	// re-check sees it revoked. The silent completion must NOT happen.
	fx.grants.afterFirst = true

	action, err := fx.gateway.Route(context.Background(), "V2-request-1", gatewaySession(), fx.reader)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionProviderCallback ||
		!strings.Contains(action.Outcome.RedirectURL(), "error=consent_required") {
		t.Fatalf("action = %+v, want consent_required fallback", action)
	}
	if fx.store.allowCommits != 0 {
		t.Fatal("revoked grant must never be silently committed")
	}
	// Exactly one operation: the consent_required completion (the silent
	// attempt exited before its claim).
	op := fx.store.operationOf(t)
	if op.CompletionKind != CompletionConsentRequired {
		t.Fatalf("operation = %+v", op)
	}
}

func TestGatewayPromptNoneMissingCredentialFailsLoginRequired(t *testing.T) {
	fx := newGatewayFixture(t)
	fx.provider.AddRequest(noneView())
	// Legacy session without a sealed Version-2 credential: only a fresh
	// login can produce one (ADR-0005 §3).
	fx.reader.err = session.ErrProviderSessionCredentialMissing

	action, err := fx.gateway.Route(context.Background(), "V2-request-1", gatewaySession(), fx.reader)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if action.Kind != ActionProviderCallback ||
		!strings.Contains(action.Outcome.RedirectURL(), "error=login_required") {
		t.Fatalf("action = %+v, want login_required for legacy sessions", action)
	}
	if fx.store.allowCommits != 0 {
		t.Fatal("missing credential must never produce an allow commit")
	}
}

func TestGatewayInteractiveRoutesByResolution(t *testing.T) {
	t.Run("no session goes to login", func(t *testing.T) {
		fx := newGatewayFixture(t)
		fx.provider.AddRequest(baseView())
		action, err := fx.gateway.Route(context.Background(), "V2-request-1", nil, nil)
		if err != nil {
			t.Fatalf("Route: %v", err)
		}
		if action.Kind != ActionRedirectLogin {
			t.Fatalf("action = %+v, want redirect to login", action)
		}
	})
	t.Run("fresh session needing consent goes to authorize", func(t *testing.T) {
		fx := newGatewayFixture(t)
		fx.provider.AddRequest(baseView())
		fx.grants.flipped = true // no reusable grant
		action, err := fx.gateway.Route(context.Background(), "V2-request-1", gatewaySession(), fx.reader)
		if err != nil {
			t.Fatalf("Route: %v", err)
		}
		if action.Kind != ActionRedirectAuthorize {
			t.Fatalf("action = %+v, want redirect to authorize", action)
		}
	})
	t.Run("interactive already_authorized still goes to authorize", func(t *testing.T) {
		// ADR-0005 §7: the frontend owns the no-form continuation into
		// the decision endpoint; the gateway never silent-completes an
		// interactive request.
		fx := newGatewayFixture(t)
		fx.provider.AddRequest(baseView())
		action, err := fx.gateway.Route(context.Background(), "V2-request-1", gatewaySession(), fx.reader)
		if err != nil {
			t.Fatalf("Route: %v", err)
		}
		if action.Kind != ActionRedirectAuthorize {
			t.Fatalf("action = %+v, want redirect to authorize", action)
		}
		if fx.provider.Completions("V2-request-1") != 0 || fx.store.allowCommits != 0 {
			t.Fatal("interactive routing must never complete the request")
		}
	})
	t.Run("unknown client fails locally", func(t *testing.T) {
		fx := newGatewayFixture(t)
		fx.provider.AddRequest(baseView())
		fx.grants.flipped = true
		// Rebuild the gateway on a failing client resolver.
		resolver := &stubClientResolver{err: ErrClientUnknown}
		resolution := newTestService(t, fx.provider, resolver, fx.grants)
		decisions := newDecisionService(t, fx.provider, resolver, fx.store)
		gateway, err := NewInteractionGatewayService(
			fx.provider, resolver, fx.grants, resolution, decisions, "zitadel", testClock())
		if err != nil {
			t.Fatalf("NewInteractionGatewayService: %v", err)
		}
		action, err := gateway.Route(context.Background(), "V2-request-1", gatewaySession(), fx.reader)
		if err != nil {
			t.Fatalf("Route: %v", err)
		}
		if action.Kind != ActionLocalFailure || action.Failure != LocalFailureBadRequest {
			t.Fatalf("action = %+v, want local failure", action)
		}
	})
	t.Run("prompt=login forces the login page even with a session", func(t *testing.T) {
		fx := newGatewayFixture(t)
		view := baseView()
		view.Prompts = []Prompt{PromptLogin}
		fx.provider.AddRequest(view)
		action, err := fx.gateway.Route(context.Background(), view.ID, gatewaySession(), fx.reader)
		if err != nil {
			t.Fatalf("Route: %v", err)
		}
		if action.Kind != ActionRedirectLogin {
			t.Fatalf("action = %+v, want redirect to login", action)
		}
	})
}

func TestGatewayProviderTransportFailurePropagates(t *testing.T) {
	fx := newGatewayFixture(t)
	fx.provider.AddRequest(baseView())
	fx.provider.InjectGetError(NewProviderError(ClassProviderUnavailable, nil))

	_, err := fx.gateway.Route(context.Background(), "V2-request-1", nil, nil)
	if err == nil {
		t.Fatal("transport failure must propagate to the HTTP layer")
	}
}
