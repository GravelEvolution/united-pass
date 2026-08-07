//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the resolution service
//

package consent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// Test doubles for the resolution seams.

type stubAuthRequestReader struct {
	view *AuthRequestView
	err  error
}

func (s *stubAuthRequestReader) GetAuthRequest(_ context.Context, _ string) (*AuthRequestView, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.view, nil
}

type stubClientResolver struct {
	facts ConsentClientFacts
	err   error
}

func (s *stubClientResolver) ResolveConsentClient(_ context.Context, _, _ string) (ConsentClientFacts, error) {
	return s.facts, s.err
}

type stubGrantReader struct {
	grant Grant
	err   error
}

func (s *stubGrantReader) GetGrant(_ context.Context, _ identity.UserID, _ applications.OAuthClientID) (Grant, error) {
	return s.grant, s.err
}

var testNow = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

func testClock() func() time.Time { return func() time.Time { return testNow } }

// baseFacts returns an effective client/application pair: both active,
// first_authorization consent, redirect and scopes covering the default
// request view.
func baseFacts() ConsentClientFacts {
	return ConsentClientFacts{
		Client: applications.OAuthClient{
			ID:          applications.OAuthClientID("cli_test"),
			ConsentMode: applications.ConsentModeFirstAuthorization,
			Status:      applications.StatusActive,
			RedirectURIs: []applications.RedirectURI{
				{URI: "https://rp.example/callback"},
			},
			Scopes: []string{"openid", "profile", "offline_access"},
		},
		Application: applications.Application{
			ID:          applications.ApplicationID("app_test"),
			Name:        "Example App",
			Description: "An example application",
			OwnerName:   "Owner Zhang",
			Status:      applications.StatusActive,
		},
	}
}

func baseView() *AuthRequestView {
	return &AuthRequestView{
		ID:          "V2-request-1",
		ClientID:    "provider-client-1",
		Scopes:      []string{"openid", "profile"},
		RedirectURI: "https://rp.example/callback",
		CreatedAt:   testNow.Add(-time.Minute),
	}
}

func newTestService(t *testing.T, provider AuthRequestReader, clients ConsentClientResolver, grants GrantReader) *ResolutionService {
	t.Helper()
	svc, err := NewResolutionService(provider, clients, grants, "zitadel", testClock())
	if err != nil {
		t.Fatalf("NewResolutionService: %v", err)
	}
	return svc
}

func resolvedSession() *ResolutionSession {
	return &ResolutionSession{
		UserID:             identity.UserID("user_01TEST"),
		AuthenticationTime: testNow.Add(-5 * time.Minute),
	}
}

// freshSession authenticated AFTER baseView's CreatedAt (testNow-1min): the
// minimal re-authentication proof for prompt=login / max_age=0.
func freshSession() *ResolutionSession {
	return &ResolutionSession{
		UserID:             identity.UserID("user_01TEST"),
		AuthenticationTime: testNow.Add(-30 * time.Second),
	}
}

func TestNewResolutionServiceRequiresAllSeams(t *testing.T) {
	provider := &stubAuthRequestReader{}
	clients := &stubClientResolver{}
	grants := &stubGrantReader{}

	if _, err := NewResolutionService(nil, clients, grants, "zitadel", testClock()); err == nil {
		t.Fatal("nil provider accepted")
	}
	if _, err := NewResolutionService(provider, nil, grants, "zitadel", testClock()); err == nil {
		t.Fatal("nil client resolver accepted")
	}
	if _, err := NewResolutionService(provider, clients, nil, "zitadel", testClock()); err == nil {
		t.Fatal("nil grant reader accepted")
	}
	if _, err := NewResolutionService(provider, clients, grants, "", testClock()); err == nil {
		t.Fatal("empty provider name accepted")
	}
	if _, err := NewResolutionService(provider, clients, grants, "zitadel", nil); err == nil {
		t.Fatal("nil clock accepted")
	}
}

func TestResolveValidHappyPath(t *testing.T) {
	svc := newTestService(t,
		&stubAuthRequestReader{view: baseView()},
		&stubClientResolver{facts: baseFacts()},
		&stubGrantReader{err: ErrGrantNotFound})

	res, err := svc.Resolve(context.Background(), ResolutionInput{
		AuthRequestID: "V2-request-1",
		Session:       resolvedSession(),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != ResolutionValid {
		t.Fatalf("status = %q, want valid", res.Status)
	}
	if res.ApplicationName != "Example App" || res.ApplicationOwner != "Owner Zhang" ||
		res.ApplicationDescription != "An example application" {
		t.Fatalf("application fields mismatch: %+v", res)
	}
	if res.RedirectHost != "rp.example" {
		t.Fatalf("redirect host = %q", res.RedirectHost)
	}
	if len(res.Scopes) != 2 {
		t.Fatalf("scopes = %+v", res.Scopes)
	}
	if res.Scopes[0].Scope != "openid" || res.Scopes[0].Label != "OpenID" || res.Scopes[0].Description == "" {
		t.Fatalf("openid catalog mapping missing: %+v", res.Scopes[0])
	}
	if res.Scopes[1].Scope != "profile" || res.Scopes[1].Label != "基本资料" {
		t.Fatalf("profile catalog mapping missing: %+v", res.Scopes[1])
	}
}

// TestResolveIsSideEffectFree pins the complete frozen invariant set of the
// resolution GET (ADR-0005 §12): even wired against fully write-capable
// seams, Resolve must leave every write surface untouched —
//
//	operation Claim/write   == 0
//	provider completion     == 0  (attempts, not merely successes)
//	grant write             == 0
//	audit write             == 0  (operation rows and commits ARE the audit
//	                             trail; the service holds no audit seam)
//
// across every outcome branch of the frozen union.
func TestResolveIsSideEffectFree(t *testing.T) {
	redirectMismatch := baseView()
	redirectMismatch.RedirectURI = "https://evil.example/steal"
	disallowedScope := baseView()
	disallowedScope.Scopes = []string{"openid", "admin:read"}

	cases := []struct {
		name       string
		view       *AuthRequestView
		resolver   *stubClientResolver
		seedGrant  bool
		session    *ResolutionSession
		wantStatus ResolutionStatus
	}{
		{"valid consent required", baseView(), &stubClientResolver{facts: baseFacts()}, false, resolvedSession(), ResolutionValid},
		{"already authorized", baseView(), &stubClientResolver{facts: baseFacts()}, true, resolvedSession(), ResolutionAlreadyAuthorized},
		{"unauthenticated", baseView(), &stubClientResolver{facts: baseFacts()}, false, nil, ResolutionUnauthenticated},
		{"client not found", baseView(), &stubClientResolver{err: ErrClientUnknown}, false, resolvedSession(), ResolutionClientNotFound},
		{"redirect mismatch", redirectMismatch, &stubClientResolver{facts: baseFacts()}, false, resolvedSession(), ResolutionRedirectMismatch},
		{"scope not allowed", disallowedScope, &stubClientResolver{facts: baseFacts()}, false, resolvedSession(), ResolutionScopeNotAllowed},
	}

	assertReadOnly := func(provider *FakeAuthRequestProvider, store *fakeGrantStore, grantsBefore int) {
		t.Helper()
		if provider.CompletionAttempts() != 0 {
			t.Fatal("resolution GET attempted a provider completion")
		}
		if store.ClaimCalls() != 0 || store.OperationRows() != 0 {
			t.Fatal("resolution GET claimed or wrote an operation row")
		}
		if store.RecordProofCalls() != 0 || store.FailCalls() != 0 {
			t.Fatal("resolution GET mutated an operation state")
		}
		if allow, deny, errored := store.CommitCalls(); allow+deny+errored != 0 {
			t.Fatal("resolution GET committed a decision")
		}
		if store.GrantRows() != grantsBefore {
			t.Fatal("resolution GET wrote a grant")
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := NewFakeAuthRequestProvider()
			provider.AddRequest(tc.view)
			store := newFakeGrantStore()
			if tc.seedGrant {
				store.grants["user_01TEST|cli_test"] = Grant{
					ID:       GrantID("grt_side_effect"),
					UserID:   identity.UserID("user_01TEST"),
					ClientID: applications.OAuthClientID("cli_test"),
					Status:   GrantActive,
					Scopes:   []string{"openid", "profile"},
				}
			}
			grantsBefore := store.GrantRows()
			svc := newTestService(t, provider, tc.resolver, store)

			res, err := svc.Resolve(context.Background(), ResolutionInput{
				AuthRequestID: tc.view.ID,
				Session:       tc.session,
			})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (branch not actually exercised)", res.Status, tc.wantStatus)
			}
			assertReadOnly(provider, store, grantsBefore)
		})
	}

	t.Run("expired", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		provider.AddRequest(baseView())
		store := newFakeGrantStore()
		grantsBefore := store.GrantRows()
		svc := newTestService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-gone-1",
			Session:       resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionExpired {
			t.Fatalf("status = %q, want expired (branch not actually exercised)", res.Status)
		}
		assertReadOnly(provider, store, grantsBefore)
	})
}

func TestResolveExpiredOnVanishedRequests(t *testing.T) {
	for _, class := range []ErrorClass{ClassNotFound, ClassExpired, ClassAlreadyCompleted} {
		svc := newTestService(t,
			&stubAuthRequestReader{err: NewProviderError(class, nil)},
			&stubClientResolver{}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
		if err != nil {
			t.Fatalf("%s: Resolve: %v", class, err)
		}
		if res.Status != ResolutionExpired {
			t.Fatalf("%s: status = %q, want expired", class, res.Status)
		}
		if !res.ExpiredAt.Equal(testNow) {
			t.Fatalf("%s: expiredAt = %v, want determination time", class, res.ExpiredAt)
		}
	}
}

func TestResolveProviderTransportFailurePropagates(t *testing.T) {
	providerErr := NewProviderError(ClassProviderUnavailable, nil)
	svc := newTestService(t,
		&stubAuthRequestReader{err: providerErr},
		&stubClientResolver{}, &stubGrantReader{})

	_, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
	if !errors.Is(err, providerErr) {
		t.Fatalf("err = %v, want provider error propagated", err)
	}
}

func TestResolveRejectsMalformedAuthRequestID(t *testing.T) {
	svc := newTestService(t,
		&stubAuthRequestReader{view: baseView()},
		&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

	if _, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: ""}); err == nil {
		t.Fatal("empty id accepted")
	}
	long := make([]byte, MaxAuthRequestIDLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: string(long)}); err == nil {
		t.Fatal("oversized id accepted")
	}
}

func TestResolveClientNotFound(t *testing.T) {
	t.Run("unknown client", func(t *testing.T) {
		svc := newTestService(t,
			&stubAuthRequestReader{view: baseView()},
			&stubClientResolver{err: ErrClientUnknown}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionClientNotFound {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("disabled client", func(t *testing.T) {
		facts := baseFacts()
		facts.Client.Status = applications.StatusDisabled
		svc := newTestService(t,
			&stubAuthRequestReader{view: baseView()},
			&stubClientResolver{facts: facts}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionClientNotFound {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("disabled application", func(t *testing.T) {
		facts := baseFacts()
		facts.Application.Status = applications.StatusDisabled
		svc := newTestService(t,
			&stubAuthRequestReader{view: baseView()},
			&stubClientResolver{facts: facts}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionClientNotFound {
			t.Fatalf("status = %q", res.Status)
		}
	})
}

func TestResolveRedirectMismatchReturnsParsedHostOnly(t *testing.T) {
	view := baseView()
	view.RedirectURI = "https://evil.example/steal?x=1"
	svc := newTestService(t,
		&stubAuthRequestReader{view: view},
		&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

	res, err := svc.Resolve(context.Background(), ResolutionInput{
		AuthRequestID: "V2-request-1", Session: resolvedSession(),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != ResolutionRedirectMismatch {
		t.Fatalf("status = %q", res.Status)
	}
	if res.AttemptedRedirectHost != "evil.example" {
		t.Fatalf("attempted host = %q, want parsed host only", res.AttemptedRedirectHost)
	}
}

func TestResolveRedirectMismatchUnparseablePlaceholder(t *testing.T) {
	view := baseView()
	view.RedirectURI = "://%%no-host"
	svc := newTestService(t,
		&stubAuthRequestReader{view: view},
		&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

	res, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != ResolutionRedirectMismatch || res.AttemptedRedirectHost != "(invalid)" {
		t.Fatalf("resolution = %+v", res)
	}
}

func TestResolveScopeNotAllowed(t *testing.T) {
	view := baseView()
	view.Scopes = []string{"openid", "admin:write", "admin:read", "admin:write"}
	svc := newTestService(t,
		&stubAuthRequestReader{view: view},
		&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

	res, err := svc.Resolve(context.Background(), ResolutionInput{
		AuthRequestID: "V2-request-1", Session: resolvedSession(),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != ResolutionScopeNotAllowed {
		t.Fatalf("status = %q", res.Status)
	}
	if len(res.DisallowedScopes) != 2 ||
		res.DisallowedScopes[0] != "admin:read" || res.DisallowedScopes[1] != "admin:write" {
		t.Fatalf("disallowed = %v, want deduplicated sorted [admin:read admin:write]", res.DisallowedScopes)
	}
}

func TestResolveEmptyScopesNotAllowed(t *testing.T) {
	view := baseView()
	view.Scopes = nil
	svc := newTestService(t,
		&stubAuthRequestReader{view: view},
		&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

	res, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != ResolutionScopeNotAllowed || len(res.DisallowedScopes) != 0 {
		t.Fatalf("resolution = %+v", res)
	}
}

// TestResolveScopeCanonicalization pins that resolution shares the single
// P3.2 NormalizeScopes boundary with the decision execution: anything the
// claim would reject can never be advertised as continuable by the GET,
// and every downstream consumer (catalog check, reuse, UI) sees the same
// deduplicated sorted set.
func TestResolveScopeCanonicalization(t *testing.T) {
	t.Run("scope flood fails closed like the claim", func(t *testing.T) {
		view := baseView()
		view.Scopes = make([]string, 33)
		for i := range view.Scopes {
			view.Scopes[i] = "openid" // 33 tokens: duplicates do not matter
		}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrantForFreshness()})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionScopeNotAllowed || len(res.DisallowedScopes) != 0 {
			t.Fatalf("resolution = %+v, want scope_not_allowed without echoing raw tokens", res)
		}
	})

	t.Run("distinct scope flood fails closed", func(t *testing.T) {
		view := baseView()
		view.Scopes = make([]string, 33)
		for i := range view.Scopes {
			view.Scopes[i] = "scope-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionScopeNotAllowed {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("whitespace token fails closed", func(t *testing.T) {
		view := baseView()
		view.Scopes = []string{"openid", "open id"}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionScopeNotAllowed {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("oversized token fails closed", func(t *testing.T) {
		view := baseView()
		view.Scopes = []string{"openid", string(make([]rune, MaxScopeTokenLen+1))}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionScopeNotAllowed {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("duplicates deduplicate into a deterministic UI set", func(t *testing.T) {
		view := baseView()
		view.Scopes = []string{"profile", "openid", "profile", "openid"}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{err: ErrGrantNotFound})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionValid {
			t.Fatalf("status = %q", res.Status)
		}
		if len(res.Scopes) != 2 || res.Scopes[0].Scope != "openid" || res.Scopes[1].Scope != "profile" {
			t.Fatalf("scopes = %+v, want deduplicated sorted [openid profile]", res.Scopes)
		}
	})

	t.Run("duplicates reuse the normalized set against grants", func(t *testing.T) {
		view := baseView()
		view.Scopes = []string{"openid", "openid", "profile", "profile"}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrantForFreshness()})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionAlreadyAuthorized {
			t.Fatalf("status = %q, want already_authorized via normalized subset check", res.Status)
		}
	})
}

func TestResolveUnauthenticated(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		svc := newTestService(t,
			&stubAuthRequestReader{view: baseView()},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionUnauthenticated {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("prompt login with stale session", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptLogin}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionUnauthenticated {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("max_age zero with stale session", func(t *testing.T) {
		view := baseView()
		zero := time.Duration(0)
		view.MaxAge = &zero
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionUnauthenticated {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("max_age exceeded", func(t *testing.T) {
		view := baseView()
		maxAge := time.Minute
		view.MaxAge = &maxAge // session authenticated 5 minutes ago
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionUnauthenticated {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("max_age satisfied proceeds", func(t *testing.T) {
		view := baseView()
		maxAge := time.Hour
		view.MaxAge = &maxAge
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{err: ErrGrantNotFound})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionValid {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("prompt login without creation time fails closed", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptLogin}
		view.CreatedAt = time.Time{} // no proof anchor available
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrantForFreshness()})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: freshSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionUnauthenticated {
			t.Fatalf("status = %q, want unauthenticated without proof anchor", res.Status)
		}
	})
}

func reusableGrantForFreshness() Grant {
	return Grant{
		ID:       GrantID("grt_test"),
		UserID:   identity.UserID("user_01TEST"),
		ClientID: applications.OAuthClientID("cli_test"),
		Status:   GrantActive,
		Scopes:   []string{"openid", "profile", "email"},
	}
}

// TestResolveAuthenticationFreshness pins the single shared freshness
// predicate (ADR-0005 §9): prompt=login and max_age=0 are satisfied only
// by an authentication after the auth request was created, so a completed
// re-login resumes instead of looping, while the pre-request session never
// satisfies the force flag.
func TestResolveAuthenticationFreshness(t *testing.T) {
	t.Run("prompt login after re-authentication proceeds", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptLogin}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{err: ErrGrantNotFound})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: freshSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionValid {
			t.Fatalf("status = %q, want valid after re-authentication", res.Status)
		}
	})

	t.Run("prompt login after re-authentication reuses a grant", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptLogin}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrantForFreshness()})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: freshSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionAlreadyAuthorized {
			t.Fatalf("status = %q, want already_authorized", res.Status)
		}
	})

	t.Run("prompt login plus consent after re-authentication shows consent", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptLogin, PromptConsent}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrantForFreshness()})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: freshSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionValid {
			t.Fatalf("status = %q, want valid (consent screen), not reuse or re-login", res.Status)
		}
	})

	t.Run("max_age zero after re-authentication proceeds", func(t *testing.T) {
		view := baseView()
		zero := time.Duration(0)
		view.MaxAge = &zero
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{err: ErrGrantNotFound})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: freshSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionValid {
			t.Fatalf("status = %q, want valid after re-authentication", res.Status)
		}
	})
}

func TestResolveGrantReuse(t *testing.T) {
	reusableGrant := Grant{
		ID:       GrantID("grt_test"),
		UserID:   identity.UserID("user_01TEST"),
		ClientID: applications.OAuthClientID("cli_test"),
		Status:   GrantActive,
		Scopes:   []string{"openid", "profile", "email"},
	}

	t.Run("already authorized", func(t *testing.T) {
		svc := newTestService(t,
			&stubAuthRequestReader{view: baseView()},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrant})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionAlreadyAuthorized {
			t.Fatalf("status = %q", res.Status)
		}
		if res.ApplicationName != "Example App" || res.RedirectHost != "rp.example" {
			t.Fatalf("reuse fields mismatch: %+v", res)
		}
	})

	t.Run("revoked grant never enables reuse", func(t *testing.T) {
		grant := reusableGrant
		grant.Status = GrantRevoked
		svc := newTestService(t,
			&stubAuthRequestReader{view: baseView()},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: grant})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionValid {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("consent mode always forces consent", func(t *testing.T) {
		facts := baseFacts()
		facts.Client.ConsentMode = applications.ConsentModeAlways
		svc := newTestService(t,
			&stubAuthRequestReader{view: baseView()},
			&stubClientResolver{facts: facts},
			&stubGrantReader{grant: reusableGrant})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionValid {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("scope expansion forces consent", func(t *testing.T) {
		view := baseView()
		view.Scopes = []string{"openid", "offline_access"} // not covered by grant
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrant})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionValid {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("prompt consent forces consent despite reusable grant", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptConsent}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrant})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionValid {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("grant store failure propagates", func(t *testing.T) {
		storeErr := errors.New("postgres: connection lost")
		svc := newTestService(t,
			&stubAuthRequestReader{view: baseView()},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{err: storeErr})

		_, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if !errors.Is(err, storeErr) {
			t.Fatalf("err = %v, want store error", err)
		}
	})
}

// TestValidatePromptStructureIsStructureOnly pins the single shared prompt
// rule consumed by the gateway, resolution, interactive decision and silent
// decision paths: only unknown values and none combinations are rejected.
// create and select_account are structurally VALID — their meaning stays
// with each caller (gateway error callbacks vs interactive rejection) and
// must never collapse into a generic structural rejection (ADR-0005 §9).
func TestValidatePromptStructureIsStructureOnly(t *testing.T) {
	structurallyValid := [][]Prompt{
		nil,
		{PromptNone},
		{PromptLogin},
		{PromptConsent},
		{PromptCreate},
		{PromptSelectAccount},
		{PromptLogin, PromptConsent},
	}
	for _, prompts := range structurallyValid {
		view := baseView()
		view.Prompts = prompts
		if err := validatePromptStructure(view); err != nil {
			t.Fatalf("prompts %v must be structurally valid, got %v", prompts, err)
		}
	}

	structurallyInvalid := [][]Prompt{
		{PromptUnspecified},
		{Prompt(42)},
		{PromptLogin, Prompt(42)},
		{PromptNone, PromptLogin},
		{PromptNone, PromptCreate},
		{PromptNone, PromptSelectAccount},
	}
	for _, prompts := range structurallyInvalid {
		view := baseView()
		view.Prompts = prompts
		if err := validatePromptStructure(view); !errors.Is(err, errPromptSetInvalid) {
			t.Fatalf("prompts %v must fail closed, got %v", prompts, err)
		}
	}
}

func TestResolveNonInteractivePrompts(t *testing.T) {
	reusableGrant := Grant{
		ID:       GrantID("grt_test"),
		UserID:   identity.UserID("user_01TEST"),
		ClientID: applications.OAuthClientID("cli_test"),
		Status:   GrantActive,
		Scopes:   []string{"openid", "profile"},
	}

	t.Run("prompt create rejected", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptCreate}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		_, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
		if !errors.Is(err, ErrResolutionNotInteractive) {
			t.Fatalf("err = %v, want ErrResolutionNotInteractive", err)
		}
	})

	t.Run("prompt select_account rejected", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptSelectAccount}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		_, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
		if !errors.Is(err, ErrResolutionNotInteractive) {
			t.Fatalf("err = %v, want ErrResolutionNotInteractive", err)
		}
	})

	t.Run("none combined with other prompts rejected", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptNone, PromptLogin}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		_, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
		if !errors.Is(err, ErrResolutionNotInteractive) {
			t.Fatalf("err = %v, want ErrResolutionNotInteractive", err)
		}
	})

	t.Run("prompt none with silent reuse", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptNone}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrant})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionAlreadyAuthorized {
			t.Fatalf("status = %q", res.Status)
		}
	})

	t.Run("prompt none without reuse rejected", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptNone}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{err: ErrGrantNotFound})

		_, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if !errors.Is(err, ErrResolutionNotInteractive) {
			t.Fatalf("err = %v, want ErrResolutionNotInteractive", err)
		}
	})

	t.Run("prompt none without session rejected", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptNone}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		_, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
		if !errors.Is(err, ErrResolutionNotInteractive) {
			t.Fatalf("err = %v, want ErrResolutionNotInteractive", err)
		}
	})

	t.Run("prompt none with exceeded max_age cannot silently reuse", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptNone}
		maxAge := time.Minute // session authenticated 5 minutes ago
		view.MaxAge = &maxAge
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrant})

		_, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if !errors.Is(err, ErrResolutionNotInteractive) {
			t.Fatalf("err = %v, want ErrResolutionNotInteractive despite reusable grant", err)
		}
	})

	t.Run("prompt none with satisfied max_age silently reuses", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptNone}
		maxAge := time.Hour
		view.MaxAge = &maxAge
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()},
			&stubGrantReader{grant: reusableGrant})

		res, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Status != ResolutionAlreadyAuthorized {
			t.Fatalf("status = %q", res.Status)
		}
	})

	// Adapter linkage: the zitadel adapter maps every unknown provider
	// enum onto PromptUnspecified (promptFromProto); resolution must fail
	// closed on it instead of silently accepting it.
	t.Run("prompt unspecified rejected", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{PromptUnspecified}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		_, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if !errors.Is(err, ErrResolutionNotInteractive) {
			t.Fatalf("err = %v, want ErrResolutionNotInteractive", err)
		}
	})

	t.Run("out-of-range prompt rejected", func(t *testing.T) {
		view := baseView()
		view.Prompts = []Prompt{Prompt(99)}
		svc := newTestService(t,
			&stubAuthRequestReader{view: view},
			&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

		_, err := svc.Resolve(context.Background(), ResolutionInput{
			AuthRequestID: "V2-request-1", Session: resolvedSession(),
		})
		if !errors.Is(err, ErrResolutionNotInteractive) {
			t.Fatalf("err = %v, want ErrResolutionNotInteractive", err)
		}
	})
}

func TestResolveEvaluationOrder(t *testing.T) {
	// Redirect mismatch outranks scope problems, scope problems outrank
	// session state: each earlier layer must win regardless of later
	// failures.
	view := baseView()
	view.RedirectURI = "https://evil.example/callback"
	view.Scopes = []string{"admin:everything"}
	svc := newTestService(t,
		&stubAuthRequestReader{view: view},
		&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

	res, err := svc.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Status != ResolutionRedirectMismatch {
		t.Fatalf("status = %q, want redirect_mismatch first", res.Status)
	}

	view2 := baseView()
	view2.Scopes = []string{"admin:everything"}
	svc2 := newTestService(t,
		&stubAuthRequestReader{view: view2},
		&stubClientResolver{facts: baseFacts()}, &stubGrantReader{})

	res2, err := svc2.Resolve(context.Background(), ResolutionInput{AuthRequestID: "V2-request-1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res2.Status != ResolutionScopeNotAllowed {
		t.Fatalf("status = %q, want scope_not_allowed before session checks", res2.Status)
	}
}
