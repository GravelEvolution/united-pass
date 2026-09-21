//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the shared session promotion pipeline (ADR-0007 F1)
//

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
)

// fakeSecurityGate is a configurable SecurityStateGate recording every
// promotion evaluation and recovery trigger.
type fakeSecurityGate struct {
	mu            sync.Mutex
	verdict       securitystate.PromotionVerdict
	observed      bool
	lastUser      identity.UserID
	lastEpoch     securitystate.Epoch
	evalCalls     int
	recoveryCalls []identity.UserID
}

func (g *fakeSecurityGate) EvaluatePromotion(_ context.Context, userID identity.UserID, recordEpoch securitystate.Epoch) (securitystate.PromotionVerdict, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.evalCalls++
	g.lastUser = userID
	g.lastEpoch = recordEpoch
	return g.verdict, g.observed
}

func (g *fakeSecurityGate) TriggerRecovery(userID identity.UserID) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.recoveryCalls = append(g.recoveryCalls, userID)
}

func (g *fakeSecurityGate) recoveries() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.recoveryCalls)
}

func (g *fakeSecurityGate) evaluations() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.evalCalls
}

// fakeStatusChecker gates user-status replay (B1 seam).
type fakeStatusChecker struct {
	err error
}

func (c *fakeStatusChecker) CanUseSession(context.Context, identity.UserID) error { return c.err }

var middlewareUser = identity.UserID("user_mw")

// middlewareEnv wires a real session.Service over the in-memory store plus a
// fake security gate and returns the middleware test attributes.
func middlewareEnv(t *testing.T) (*session.Service, *fakeSessionStore, SessionCookieAttributes) {
	t.Helper()
	store := newFakeSessionStore()
	svc := session.NewService(store, session.SystemClock{},
		12*time.Hour, 720*time.Hour, 30*time.Minute, 5*time.Minute, nil)
	cfg := config.Config{}
	cfg.Session.CookieSameSite = "lax"
	return svc, store, CookieAttributesFromConfig(cfg.Session)
}

func mintMiddlewareSession(t *testing.T, svc *session.Service) session.CreateSessionResult {
	t.Helper()
	result, err := svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID:                middlewareUser,
		Provider:              "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		UserAgent:             "middleware-test-agent",
		ClientIP:              "203.0.113.99",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return result
}

// clearedCookies returns the names of cookies the response explicitly clears.
func clearedCookies(resp *http.Response) map[string]bool {
	cleared := map[string]bool{}
	for _, c := range resp.Cookies() {
		if c.MaxAge <= 0 || c.Value == "" {
			cleared[c.Name] = true
		}
	}
	return cleared
}

// TestRequireSession_PromotionMatrix covers the F1 shared pipeline on the
// authenticated path: promotion, epoch-stale clearing (the pinned
// exception), transient denial without clearing, and recovery triggering.
func TestRequireSession_PromotionMatrix(t *testing.T) {
	svc, _, attrs := middlewareEnv(t)
	checker := &fakeStatusChecker{}

	newRouter := func(gate SecurityStateGate) http.Handler {
		r := chi.NewRouter()
		r.Use(RequireSession(svc, checker, gate, attrs, discardLogger()))
		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := PrincipalFromContext(r.Context()); !ok {
				t.Error("promoted request must carry a principal")
			}
			if _, ok := SessionRecordFromContext(r.Context()); !ok {
				t.Error("promoted request must carry a session record")
			}
			w.WriteHeader(http.StatusOK)
		})
		return r
	}

	do := func(h http.Handler, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	t.Run("allowed verdict promotes with principal and record", func(t *testing.T) {
		result := mintMiddlewareSession(t, svc)
		gate := &fakeSecurityGate{verdict: securitystate.PromotionAllowed}
		w := do(newRouter(gate), result.SessionToken)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if gate.evaluations() != 1 {
			t.Fatalf("gate evaluations = %d, want 1 (shared validator invoked)", gate.evaluations())
		}
		if len(clearedCookies(w.Result())) != 0 {
			t.Fatal("a promoted request must not clear cookies")
		}
	})

	t.Run("epoch stale clears both cookies (pinned exception)", func(t *testing.T) {
		result := mintMiddlewareSession(t, svc)
		gate := &fakeSecurityGate{verdict: securitystate.PromotionEpochStale}
		w := do(newRouter(gate), result.SessionToken)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		cleared := clearedCookies(w.Result())
		if !cleared[SessionCookieName] || !cleared[CSRFCookieName] {
			t.Fatalf("cleared = %v, want both session and csrf cookies cleared", cleared)
		}
	})

	t.Run("transient denial fails closed without clearing cookies", func(t *testing.T) {
		result := mintMiddlewareSession(t, svc)
		gate := &fakeSecurityGate{verdict: securitystate.PromotionDeniedTransient}
		w := do(newRouter(gate), result.SessionToken)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if len(clearedCookies(w.Result())) != 0 {
			t.Fatal("a transient denial must never clear cookies")
		}
	})

	t.Run("observed non-terminal intent triggers opportunistic recovery", func(t *testing.T) {
		result := mintMiddlewareSession(t, svc)
		gate := &fakeSecurityGate{verdict: securitystate.PromotionDeniedTransient, observed: true}
		w := do(newRouter(gate), result.SessionToken)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if gate.recoveries() != 1 {
			t.Fatalf("recovery triggers = %d, want 1", gate.recoveries())
		}
	})

	t.Run("missing cookie denies without touching the gate", func(t *testing.T) {
		gate := &fakeSecurityGate{verdict: securitystate.PromotionAllowed}
		r := chi.NewRouter()
		r.Use(RequireSession(svc, checker, gate, attrs, discardLogger()))
		r.Get("/me", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if gate.evaluations() != 0 {
			t.Fatal("an anonymous request must never reach the security gate")
		}
	})

	t.Run("disabled user stays invalid without cookie clearing (B1)", func(t *testing.T) {
		result := mintMiddlewareSession(t, svc)
		gate := &fakeSecurityGate{verdict: securitystate.PromotionAllowed}
		disabled := &fakeStatusChecker{err: identity.ErrUserNotFound}
		r := chi.NewRouter()
		r.Use(RequireSession(svc, disabled, gate, attrs, discardLogger()))
		r.Get("/me", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: result.SessionToken})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if len(clearedCookies(w.Result())) != 0 {
			t.Fatal("account invalidation must follow the frozen no-clearing rule")
		}
		if gate.evaluations() != 0 {
			t.Fatal("a user-status failure short-circuits before the security gate")
		}
	})
}

func TestRequireSessionRejectsPreCutoverIdentityOnlyWeChatBearer(t *testing.T) {
	for _, test := range []struct {
		name       string
		provider   string
		methods    []auth.AuthenticationMethod
		wantStatus int
		wantDelete bool
	}{
		{
			name: "legacy WeChat bearer has no mandatory phone assurance", provider: wechat.ProviderName,
			methods: []auth.AuthenticationMethod{auth.MethodFederated}, wantStatus: http.StatusUnauthorized, wantDelete: true,
		},
		{
			name: "strict WeChat bearer carries server-only assurance", provider: wechat.ProviderName,
			methods: []auth.AuthenticationMethod{auth.MethodFederated, auth.MethodWeChatPhoneVerified}, wantStatus: http.StatusOK,
		},
		{
			name: "legacy existing-account password and federated session is rejected", provider: "zitadel",
			methods: []auth.AuthenticationMethod{auth.MethodPassword, auth.MethodFederated}, wantStatus: http.StatusUnauthorized, wantDelete: true,
		},
		{
			name: "strict existing-account session carries mandatory phone assurance", provider: "zitadel",
			methods: []auth.AuthenticationMethod{auth.MethodPassword, auth.MethodFederated, auth.MethodWeChatPhoneVerified}, wantStatus: http.StatusOK,
		},
		{
			name: "pure password native session keeps its own contract", provider: "zitadel",
			methods: []auth.AuthenticationMethod{auth.MethodPassword}, wantStatus: http.StatusOK,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, _, attrs := middlewareEnv(t)
			created, err := svc.CreateSession(t.Context(), session.CreateSessionInput{
				UserID: middlewareUser, ClientKind: session.ClientKindMiniProgram,
				Provider: test.provider, AuthenticationMethods: test.methods,
				UserAgent: "middleware-test-agent", ClientIP: "203.0.113.99",
			})
			if err != nil {
				t.Fatal(err)
			}
			router := chi.NewRouter()
			router.Use(RequireSession(svc, &fakeStatusChecker{}, &fakeSecurityGate{verdict: securitystate.PromotionAllowed}, attrs, discardLogger()))
			router.Get("/api/v1/me", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			req.Header.Set("X-UnitedPass-Client", session.ClientKindMiniProgram)
			req.Header.Set(AuthorizationHeaderName, "Bearer "+created.SessionToken)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, test.wantStatus, rr.Body.String())
			}
			_, _, validateErr := svc.ValidateSession(t.Context(), created.SessionToken)
			if test.wantDelete {
				if !errors.Is(validateErr, session.ErrSessionNotFound) {
					t.Fatalf("legacy session was not deleted: %v", validateErr)
				}
			} else if validateErr != nil {
				t.Fatalf("valid native session was deleted or rejected: %v", validateErr)
			}
		})
	}
}

func TestRequireSessionDeletesPreCutoverQRBrowserSession(t *testing.T) {
	svc, _, attrs := middlewareEnv(t)
	created, err := svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID: middlewareUser, Provider: legacyQRAuthSessionProvider,
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodFederated},
		UserAgent:             "middleware-test-agent", ClientIP: "203.0.113.99",
	})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Use(RequireSession(svc, &fakeStatusChecker{}, &fakeSecurityGate{verdict: securitystate.PromotionAllowed}, attrs, discardLogger()))
	router.Get("/me", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: created.SessionToken})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, _, err := svc.ValidateSession(t.Context(), created.SessionToken); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("legacy QR session was not deleted: %v", err)
	}
	cleared := clearedCookies(rr.Result())
	if !cleared[SessionCookieName] || !cleared[CSRFCookieName] {
		t.Fatalf("legacy QR cookies were not cleared: %#v", cleared)
	}
}

func TestOptionalSessionDeletesPreCutoverQRAndDegradesToAnonymous(t *testing.T) {
	svc, _, attrs := middlewareEnv(t)
	created, err := svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID: middlewareUser, Provider: legacyQRAuthSessionProvider,
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodFederated},
		UserAgent:             "middleware-test-agent", ClientIP: "203.0.113.99",
	})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Use(OptionalSession(svc, &fakeStatusChecker{}, &fakeSecurityGate{verdict: securitystate.PromotionAllowed}, attrs, discardLogger()))
	router.Get("/interaction", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := PrincipalFromContext(r.Context()); ok {
			t.Error("legacy QR session was promoted on optional-auth path")
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/interaction", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: created.SessionToken})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, _, err := svc.ValidateSession(t.Context(), created.SessionToken); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("legacy QR session was not deleted: %v", err)
	}
	cleared := clearedCookies(rr.Result())
	if !cleared[SessionCookieName] || !cleared[CSRFCookieName] {
		t.Fatalf("legacy QR cookies were not cleared: %#v", cleared)
	}
}

// TestOptionalSession_SharesTheSameValidator covers the F1 requirement on the
// anonymous-tolerant path: identical verdicts, identical cookie policy —
// epoch stale clears cookies even here, transient denial degrades to
// anonymous without touching them.
func TestOptionalSession_SharesTheSameValidator(t *testing.T) {
	svc, _, attrs := middlewareEnv(t)
	checker := &fakeStatusChecker{}

	var sawPrincipal bool
	newRouter := func(gate SecurityStateGate) http.Handler {
		sawPrincipal = false
		r := chi.NewRouter()
		r.Use(OptionalSession(svc, checker, gate, attrs, discardLogger()))
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			_, sawPrincipal = PrincipalFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		return r
	}

	do := func(h http.Handler, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if token != "" {
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	t.Run("anonymous request proceeds without principal", func(t *testing.T) {
		gate := &fakeSecurityGate{verdict: securitystate.PromotionAllowed}
		w := do(newRouter(gate), "")
		if w.Code != http.StatusOK || sawPrincipal {
			t.Fatalf("status = %d principal = %v, want anonymous passthrough", w.Code, sawPrincipal)
		}
		if gate.evaluations() != 0 {
			t.Fatal("no cookie means no gate evaluation")
		}
	})

	t.Run("promoted session carries the principal", func(t *testing.T) {
		result := mintMiddlewareSession(t, svc)
		gate := &fakeSecurityGate{verdict: securitystate.PromotionAllowed}
		w := do(newRouter(gate), result.SessionToken)
		if w.Code != http.StatusOK || !sawPrincipal {
			t.Fatalf("status = %d principal = %v, want promoted", w.Code, sawPrincipal)
		}
	})

	t.Run("epoch stale clears both cookies and degrades to anonymous", func(t *testing.T) {
		result := mintMiddlewareSession(t, svc)
		gate := &fakeSecurityGate{verdict: securitystate.PromotionEpochStale}
		w := do(newRouter(gate), result.SessionToken)
		if w.Code != http.StatusOK || sawPrincipal {
			t.Fatalf("status = %d principal = %v, want anonymous after stale death", w.Code, sawPrincipal)
		}
		cleared := clearedCookies(w.Result())
		if !cleared[SessionCookieName] || !cleared[CSRFCookieName] {
			t.Fatalf("cleared = %v, want both cookies cleared on the optional path too", cleared)
		}
	})

	t.Run("transient denial degrades to anonymous without clearing cookies", func(t *testing.T) {
		result := mintMiddlewareSession(t, svc)
		gate := &fakeSecurityGate{verdict: securitystate.PromotionDeniedTransient, observed: true}
		w := do(newRouter(gate), result.SessionToken)
		if w.Code != http.StatusOK || sawPrincipal {
			t.Fatalf("status = %d principal = %v, want anonymous degradation", w.Code, sawPrincipal)
		}
		if len(clearedCookies(w.Result())) != 0 {
			t.Fatal("a transient denial must never clear cookies")
		}
		if gate.recoveries() != 1 {
			t.Fatalf("recovery triggers = %d, want 1", gate.recoveries())
		}
	})
}

// TestValidateAndPromote_ValidationFailureKeepsFrozenSemantics ensures a
// missing/expired session never clears cookies (frozen rule) and never
// reaches the security gate.
func TestValidateAndPromote_ValidationFailureKeepsFrozenSemantics(t *testing.T) {
	svc, _, attrs := middlewareEnv(t)
	checker := &fakeStatusChecker{}
	gate := &fakeSecurityGate{verdict: securitystate.PromotionAllowed}

	r := chi.NewRouter()
	r.Use(RequireSession(svc, checker, gate, attrs, discardLogger()))
	r.Get("/me", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "up-nonexistent-token"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if len(clearedCookies(w.Result())) != 0 {
		t.Fatal("authentication failure must not clear cookies (frozen rule)")
	}
	if gate.evaluations() != 0 {
		t.Fatal("an invalid session must never reach the security gate")
	}
}

func TestNativeMiniProgramBearerScopeIncludesExactDreamUPContentContracts(t *testing.T) {
	allowed := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/admin/dreamup/eligibility"},
		{http.MethodPost, "/api/v1/admin/dreamup/reauthentication"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/content"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/splash-ad"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/splash-poster-image-upload-intents"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/announcement-background-image-upload-intents"},
		{http.MethodPut, "/api/v1/admin/dreamup/events/evt_shanghai/splash-ad"},
		{http.MethodPut, "/api/v1/admin/dreamup/events/evt_shanghai/content/intro"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/announcements"},
		{http.MethodPatch, "/api/v1/admin/dreamup/events/evt_shanghai/announcements/content_1"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/contact-submissions/contact_1"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/applications/application_1/review-identity"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-point-image-upload-intents"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points/point_1/inspections"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-photo-uploads/upload_1/finalize"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-image-upload-intents"},
		{http.MethodPatch, "/api/v1/admin/dreamup/events/evt_shanghai/assets/asset_1"},
		{http.MethodPatch, "/api/v1/admin/dreamup/events/evt_shanghai/asset-reservations/reservation_1"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-units/unit_1/checkout"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-image-upload-intents"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-assignments/assignment_1/code-rotations"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/entity-codes/code_1/print-jobs"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/qr-print-jobs/print_1"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/qr-print-jobs/print_1/bulk"},
	}
	for _, test := range allowed {
		req := httptest.NewRequest(test.method, test.path, nil)
		if !nativeMiniProgramBearerRouteAllowed(req) {
			t.Errorf("native route rejected: %s %s", test.method, test.path)
		}
	}
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/admin/dreamup/eligibility"},
		{http.MethodGet, "/api/v1/admin/dreamup/reauthentication"},
		{http.MethodPost, "/api/v1/admin/dreamup/reauthentication/extra"},
		{http.MethodGet, "/api/v1/admin/dreamup/step-up/challenge"},
		{http.MethodPost, "/api/v1/admin/dreamup/step-up/enroll"},
		{http.MethodPost, "/api/v1/admin/dreamup/step-up/verify"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/content/intro"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/splash-ad"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/splash-poster-image-upload-intents"},
		{http.MethodPut, "/api/v1/admin/dreamup/events/evt_shanghai/splash-poster-image-upload-intents/extra"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/announcement-background-image-upload-intents"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/announcement-background-image-upload-intents/extra"},
		{http.MethodPut, "/api/v1/admin/dreamup/events/evt_shanghai/announcements"},
		{http.MethodPatch, "/api/v1/admin/dreamup/events/evt_shanghai/announcements"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/contact-submissions/contact_1/extra"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/applications/application_1/review-identity"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/applications/application_1/review-identity/extra"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-point-image-upload-intents"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-point-image-upload-intents/extra"},
		{http.MethodDelete, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points/point_1"},
		{http.MethodPut, "/api/v1/admin/dreamup/events/evt_shanghai/asset-image-upload-intents"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-image-upload-intents/extra"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/assets/asset_1/code-rotations"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-units/unit_1"},
		{http.MethodPatch, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-image-upload-intents"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-image-upload-intents/extra"},
		{http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/entity-codes/code_1/print-jobs/extra"},
		{http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/qr-print-jobs/print_1/bulk/extra"},
	} {
		req := httptest.NewRequest(test.method, test.path, nil)
		if nativeMiniProgramBearerRouteAllowed(req) {
			t.Errorf("native route over-broadened: %s %s", test.method, test.path)
		}
	}
}

func TestRequireSessionAllowsNativeDreamUPReviewIdentityRoute(t *testing.T) {
	svc, _, attrs := middlewareEnv(t)
	created, err := svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID: middlewareUser, ClientKind: session.ClientKindMiniProgram,
		Provider: "zitadel", AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		UserAgent: "middleware-test-agent", ClientIP: "203.0.113.99",
	})
	if err != nil {
		t.Fatal(err)
	}

	const path = "/api/v1/admin/dreamup/events/evt_shanghai/applications/application_1/review-identity"
	reached := false
	router := chi.NewRouter()
	router.Use(RequireSession(svc, &fakeStatusChecker{}, &fakeSecurityGate{verdict: securitystate.PromotionAllowed}, attrs, discardLogger()))
	router.Post(path, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if _, ok := PrincipalFromContext(r.Context()); !ok {
			t.Error("native review-identity request must carry the promoted principal")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("X-UnitedPass-Client", session.ClientKindMiniProgram)
	req.Header.Set(AuthorizationHeaderName, "Bearer "+created.SessionToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent || !reached {
		t.Fatalf("status=%d reached=%v body=%s", recorder.Code, reached, recorder.Body.String())
	}
}

func TestRequireSessionRejectsRetiredNativeDreamUPSecurityQuestionRoutes(t *testing.T) {
	svc, _, attrs := middlewareEnv(t)
	created, err := svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID: middlewareUser, ClientKind: session.ClientKindMiniProgram,
		Provider: "zitadel", AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		UserAgent: "middleware-test-agent", ClientIP: "203.0.113.99",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/admin/dreamup/step-up/challenge"},
		{http.MethodPost, "/api/v1/admin/dreamup/step-up/enroll"},
		{http.MethodPost, "/api/v1/admin/dreamup/step-up/verify"},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			reached := false
			router := chi.NewRouter()
			router.Use(RequireSession(svc, &fakeStatusChecker{}, &fakeSecurityGate{verdict: securitystate.PromotionAllowed}, attrs, discardLogger()))
			router.MethodFunc(test.method, test.path, func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			})
			req := httptest.NewRequest(test.method, test.path, nil)
			req.Header.Set("X-UnitedPass-Client", session.ClientKindMiniProgram)
			req.Header.Set(AuthorizationHeaderName, "Bearer "+created.SessionToken)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusUnauthorized || reached {
				t.Fatalf("status=%d reached=%v body=%s", recorder.Code, reached, recorder.Body.String())
			}
		})
	}
}
