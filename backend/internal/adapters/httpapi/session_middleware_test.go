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
