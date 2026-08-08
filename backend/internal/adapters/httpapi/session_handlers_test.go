//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-08
// Description: Unit tests for the session inventory HTTP handlers
//

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const sessionInvUser = identity.UserID("user_session_inv")

// sessionInventoryEnv wires a real session.Service over the in-memory store
// and mounts the inventory routes behind an injected authentication context.
type sessionInventoryEnv struct {
	svc     *session.Service
	current session.CreateSessionResult
}

func newSessionInventoryEnv(t *testing.T) *sessionInventoryEnv {
	t.Helper()
	store := newFakeSessionStore()
	svc := session.NewService(store, session.SystemClock{},
		12*time.Hour, 720*time.Hour, 30*time.Minute, 5*time.Minute, nil)

	current, err := svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID:                sessionInvUser,
		Provider:              "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		UserAgent:             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0 Safari/537.36",
		ClientIP:              "203.0.113.42",
	})
	if err != nil {
		t.Fatalf("create current session: %v", err)
	}
	return &sessionInventoryEnv{svc: svc, current: current}
}

func (e *sessionInventoryEnv) router(injectPrincipal bool) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := request.WithID(req.Context(), "req-test-session-inv")
			if injectPrincipal {
				ctx = WithPrincipal(ctx, session.Principal{
					UserID:             sessionInvUser,
					SessionID:          e.current.Record.SessionID,
					AuthenticationTime: time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC),
				})
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	h := NewSessionHandlers(e.svc, discardLogger())
	r.Get("/me/sessions", h.ListSessions)
	r.Delete("/me/sessions", h.RevokeAllOthers)
	r.Delete("/me/sessions/{sessionId}", h.RevokeSession)
	return r
}

func TestListSessionsWireShape(t *testing.T) {
	env := newSessionInventoryEnv(t)

	rec := httptest.NewRecorder()
	env.router(true).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/me/sessions", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var views []sessionView
	if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("got %d sessions, want 1", len(views))
	}
	v := views[0]
	if !v.IsCurrent {
		t.Error("current session must be flagged isCurrent")
	}
	if v.DeviceName != "macOS" || v.ClientName != "Chrome" {
		t.Errorf("display = (%q, %q), want (macOS, Chrome)", v.DeviceName, v.ClientName)
	}
	if v.IPAddressMasked != "203.0.113.*" {
		t.Errorf("ipAddressMasked = %q, want 203.0.113.*", v.IPAddressMasked)
	}
	if v.ApproximateLocation != nil {
		t.Errorf("approximateLocation = %v, want null", *v.ApproximateLocation)
	}
	if v.SessionID != string(env.current.Record.SessionID) {
		t.Errorf("sessionId = %q, want %q", v.SessionID, env.current.Record.SessionID)
	}
	// approximateLocation must serialize as explicit null, not be omitted.
	if !jsonContains(rec.Body.Bytes(), `"approximateLocation":null`) {
		t.Errorf("body must carry approximateLocation:null, got %s", rec.Body.String())
	}
}

func TestListSessionsRequiresSession(t *testing.T) {
	env := newSessionInventoryEnv(t)
	rec := httptest.NewRecorder()
	env.router(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/me/sessions", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRevokeSessionHappyPath(t *testing.T) {
	env := newSessionInventoryEnv(t)
	other, err := env.svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID:                sessionInvUser,
		Provider:              "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
	})
	if err != nil {
		t.Fatalf("create other: %v", err)
	}

	rec := httptest.NewRecorder()
	env.router(true).ServeHTTP(rec,
		httptest.NewRequest(http.MethodDelete, "/me/sessions/"+string(other.Record.SessionID), nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}

	// The list now contains only the current session.
	list := httptest.NewRecorder()
	env.router(true).ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/me/sessions", nil))
	var views []sessionView
	if err := json.Unmarshal(list.Body.Bytes(), &views); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(views) != 1 || !views[0].IsCurrent {
		t.Fatalf("after revoke, list = %d sessions, want only current", len(views))
	}
}

func TestRevokeSessionCurrentIsConflict(t *testing.T) {
	env := newSessionInventoryEnv(t)
	rec := httptest.NewRecorder()
	env.router(true).ServeHTTP(rec,
		httptest.NewRequest(http.MethodDelete, "/me/sessions/"+string(env.current.Record.SessionID), nil))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeSessionCurrent)
}

func TestRevokeSessionUnknownIsNotFound(t *testing.T) {
	env := newSessionInventoryEnv(t)
	rec := httptest.NewRecorder()
	env.router(true).ServeHTTP(rec,
		httptest.NewRequest(http.MethodDelete, "/me/sessions/deadbeefdeadbeef", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeSessionNotFound)
}

func TestRevokeSessionForeignIsNotFound(t *testing.T) {
	env := newSessionInventoryEnv(t)
	// A session belonging to another user must be indistinguishable from an
	// unknown one.
	foreign, err := env.svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID:                identity.UserID("user_session_other"),
		Provider:              "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
	})
	if err != nil {
		t.Fatalf("create foreign: %v", err)
	}

	rec := httptest.NewRecorder()
	env.router(true).ServeHTTP(rec,
		httptest.NewRequest(http.MethodDelete, "/me/sessions/"+string(foreign.Record.SessionID), nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for foreign target; body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeSessionNotFound)
}

func TestRevokeAllOthersPreservesCurrent(t *testing.T) {
	env := newSessionInventoryEnv(t)
	for i := 0; i < 3; i++ {
		if _, err := env.svc.CreateSession(t.Context(), session.CreateSessionInput{
			UserID:                sessionInvUser,
			Provider:              "fake",
			AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		}); err != nil {
			t.Fatalf("create other %d: %v", i, err)
		}
	}

	rec := httptest.NewRecorder()
	env.router(true).ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/me/sessions", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Revoked int `json:"revoked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Revoked != 3 {
		t.Fatalf("revoked = %d, want 3", body.Revoked)
	}

	// Only the current session survives.
	list := httptest.NewRecorder()
	env.router(true).ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/me/sessions", nil))
	var views []sessionView
	if err := json.Unmarshal(list.Body.Bytes(), &views); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(views) != 1 || !views[0].IsCurrent {
		t.Fatalf("after bulk revoke, list = %d sessions, want only current", len(views))
	}
}

func TestRevokeAllOthersRequiresSession(t *testing.T) {
	env := newSessionInventoryEnv(t)
	rec := httptest.NewRecorder()
	env.router(false).ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/me/sessions", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// jsonContains reports whether the raw JSON body contains a literal fragment.
func jsonContains(body []byte, fragment string) bool {
	return len(body) > 0 && containsString(string(body), fragment)
}

func containsString(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// assertErrorCode decodes the standard error envelope and checks the code.
func assertErrorCode(t *testing.T, body []byte, want string) {
	t.Helper()
	var envelope ErrorResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if envelope.Error.Code != want {
		t.Errorf("error code = %q, want %q", envelope.Error.Code, want)
	}
}
