//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the password change handler (ADR-0006 §6)
//

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const newPasswordPlaintext = "brand-new-secret"

// --- Test fakes ---

// fakePasswordChanger is a configurable auth.PasswordManager double
// recording the received (redacted-wrapped) password.
type fakePasswordChanger struct {
	err       error
	mu        sync.Mutex
	userIDs   []identity.UserID
	passwords []string
}

func (f *fakePasswordChanger) SetPassword(_ context.Context, userID identity.UserID, newPassword auth.SecretPassword) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userIDs = append(f.userIDs, userID)
	f.passwords = append(f.passwords, newPassword.Password())
	return f.err
}

func (f *fakePasswordChanger) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.userIDs)
}

// fakeSessionAuditor records durable session security audit rows.
type fakeSessionAuditor struct {
	mu     sync.Mutex
	events []session.SecurityAuditEvent
}

func (f *fakeSessionAuditor) RecordSessionEvent(_ context.Context, ev session.SecurityAuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeSessionAuditor) rows() []session.SecurityAuditEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]session.SecurityAuditEvent(nil), f.events...)
}

// --- Test harness ---

var passwordUser = identity.UserID("user_password")

// passwordEnv wires a real session.Service over the in-memory store, a fake
// password authority, reauth grants and the durable audit seam, and mounts
// the password route behind an injected authentication context.
type passwordEnv struct {
	handlers *PasswordHandlers
	store    *fakeSessionStore
	svc      *session.Service
	changer  *fakePasswordChanger
	grants   *memReauthGrants
	auditor  *fakeSessionAuditor
	logs     *bytes.Buffer
	current  session.CreateSessionResult
	other    session.CreateSessionResult
}

func newPasswordEnv(t *testing.T) *passwordEnv {
	t.Helper()
	store := newFakeSessionStore()
	svc := session.NewService(store, session.SystemClock{},
		12*time.Hour, 720*time.Hour, 30*time.Minute, 5*time.Minute, nil)

	current, err := svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID:                passwordUser,
		Provider:              "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		UserAgent:             "password-test-agent",
		ClientIP:              "203.0.113.77",
	})
	if err != nil {
		t.Fatalf("create current session: %v", err)
	}
	other, err := svc.CreateSession(t.Context(), session.CreateSessionInput{
		UserID:                passwordUser,
		Provider:              "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		UserAgent:             "password-test-agent-other",
		ClientIP:              "203.0.113.78",
	})
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}

	changer := &fakePasswordChanger{}
	grants := newMemReauthGrants()
	auditor := &fakeSessionAuditor{}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))

	cfg := config.Config{}
	cfg.Session.CookieSameSite = "lax"

	handlers := NewPasswordHandlers(changer, NewReauthGrants(grants), svc, auditor, cfg, logger)
	return &passwordEnv{
		handlers: handlers, store: store, svc: svc, changer: changer,
		grants: grants, auditor: auditor, logs: logs, current: current, other: other,
	}
}

func (e *passwordEnv) router(injectPrincipal bool) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := request.WithID(req.Context(), "req-test-password")
			if injectPrincipal {
				ctx = WithPrincipal(ctx, session.Principal{
					UserID:             passwordUser,
					SessionID:          e.current.Record.SessionID,
					AuthenticationTime: time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC),
				})
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Post("/me/security/password", e.handlers.ChangePassword)
	return r
}

// mintGrant seeds a consumable account.password.change grant bound to the
// current session.
func (e *passwordEnv) mintGrant(t *testing.T, token string) {
	t.Helper()
	data := auth.ReauthGrantData{
		UserID:    passwordUser,
		SessionID: string(e.current.Record.SessionID),
		Action:    auth.ReauthActionPasswordChange,
		CreatedAt: time.Now(),
	}
	if err := e.grants.CreateGrant(t.Context(), session.HashToken(token), data, time.Minute); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// doPasswordChange issues POST /me/security/password with the current
// session cookie and the given body/headers.
func (e *passwordEnv) doPasswordChange(t *testing.T, injectPrincipal bool, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/me/security/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: e.current.SessionToken})
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.router(injectPrincipal).ServeHTTP(w, req)
	return w
}

// issuedCookies extracts the re-issued up_session / up_csrf cookies from a
// response (nil when absent).
func issuedCookies(w *httptest.ResponseRecorder) (sessionCookie, csrfCookie *http.Cookie) {
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case SessionCookieName:
			sessionCookie = c
		case CSRFCookieName:
			csrfCookie = c
		}
	}
	return sessionCookie, csrfCookie
}

// --- Happy path: rotate + revoke others + audit ---

// TestChangePassword_Success pins the frozen success flow: provider change,
// current session rotated (SessionID stable, fresh tokens, old token dead),
// every other session revoked, cookies re-issued, durable audit — and the
// plaintext never appears in logs, audit payloads or the stored record.
func TestChangePassword_Success(t *testing.T) {
	env := newPasswordEnv(t)
	env.mintGrant(t, "grant-pwd-1")

	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-1"})

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}

	// Provider received exactly one call with the new password only.
	if env.changer.calls() != 1 {
		t.Fatalf("provider calls = %d, want 1", env.changer.calls())
	}
	if env.changer.userIDs[0] != passwordUser || env.changer.passwords[0] != newPasswordPlaintext {
		t.Errorf("provider got (%q, %q), want (%q, %q)", env.changer.userIDs[0], env.changer.passwords[0], passwordUser, newPasswordPlaintext)
	}

	// Cookies re-issued: fresh session token + fresh CSRF token.
	sessCookie, csrfCookie := issuedCookies(rec)
	if sessCookie == nil || csrfCookie == nil {
		t.Fatal("response must re-issue both the up_session and up_csrf cookies")
	}
	if sessCookie.Value == env.current.SessionToken {
		t.Error("the re-issued session token must differ from the old one")
	}
	if sessCookie.Value == csrfCookie.Value {
		t.Error("session and CSRF tokens must differ")
	}

	// Old token dead, new token live under the stable SessionID.
	if _, err := env.store.Get(t.Context(), session.HashToken(env.current.SessionToken)); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("old token lookup = %v, want ErrSessionNotFound", err)
	}
	rotated, err := env.store.Get(t.Context(), session.HashToken(sessCookie.Value))
	if err != nil {
		t.Fatalf("rotated record lookup: %v", err)
	}
	if rotated.SessionID != env.current.Record.SessionID {
		t.Errorf("SessionID = %q, want stable %q", rotated.SessionID, env.current.Record.SessionID)
	}
	if rotated.CSRFTokenHash != session.HashToken(csrfCookie.Value) {
		t.Error("the rotated record must bind the new CSRF token hash")
	}
	if rotated.ExpiresAt != env.current.Record.ExpiresAt {
		t.Error("rotation must never extend the absolute deadline")
	}

	// All other sessions revoked; the current one survives (rotated).
	records, err := env.svc.ListUserSessions(t.Context(), passwordUser)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(records) != 1 || records[0].SessionID != env.current.Record.SessionID {
		t.Fatalf("live sessions = %d (want exactly the rotated current session)", len(records))
	}
	if _, err := env.store.Get(t.Context(), session.HashToken(env.other.SessionToken)); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("other session lookup = %v, want ErrSessionNotFound (revoked)", err)
	}

	// Durable audit: exactly one account.password_changed row, no password
	// material anywhere in the payload.
	rows := env.auditor.rows()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	ev := rows[0]
	if ev.EventType != EventPasswordChanged || ev.ActorUserID != passwordUser || ev.SessionID != env.current.Record.SessionID {
		t.Errorf("audit row = %+v, want account.password_changed for the caller", ev)
	}
	if ev.Result != session.AuditOutcomeSuccess || ev.Operation != auth.ReauthActionPasswordChange {
		t.Errorf("audit row = %+v, want success + account.password.change operation", ev)
	}
	raw, _ := json.Marshal(ev)
	if strings.Contains(string(raw), newPasswordPlaintext) {
		t.Error("the durable audit payload must never carry password material")
	}

	// The password never reaches logs or the stored record.
	if strings.Contains(env.logs.String(), newPasswordPlaintext) {
		t.Error("the plaintext password leaked into structured logs")
	}
	recordRaw, _ := json.Marshal(rotated)
	if strings.Contains(string(recordRaw), newPasswordPlaintext) {
		t.Error("the plaintext password leaked into the stored session record")
	}
}

// --- Pinned point 1: currentPassword is never accepted ---

// TestChangePassword_CurrentPasswordRejected pins that the mutation never
// re-accepts a current password: the frozen wire shape has no such field, so
// a body carrying one is rejected outright and the provider is never called.
func TestChangePassword_CurrentPasswordRejected(t *testing.T) {
	env := newPasswordEnv(t)
	env.mintGrant(t, "grant-pwd-2")

	rec := env.doPasswordChange(t, true,
		`{"currentPassword":"old-secret","newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-2"})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown field rejected); body=%s", rec.Code, rec.Body.String())
	}
	if env.changer.calls() != 0 {
		t.Error("the provider must never see a request that carries currentPassword")
	}
}

// TestChangePassword_EmptyNewPassword covers the missing/empty newPassword
// guard: 400, provider never called.
func TestChangePassword_EmptyNewPassword(t *testing.T) {
	env := newPasswordEnv(t)
	env.mintGrant(t, "grant-pwd-3")

	rec := env.doPasswordChange(t, true, `{"newPassword":""}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-3"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if env.changer.calls() != 0 {
		t.Error("the provider must never be called with an empty password")
	}
}

// --- Reauth grant gate ---

// TestChangePassword_RequiresGrant covers the step-up gate: an absent or a
// foreign-action grant denies the mutation before the provider is called.
func TestChangePassword_RequiresGrant(t *testing.T) {
	// Absent grant.
	env := newPasswordEnv(t)
	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("absent grant: status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), CodeReauthenticationReq) {
		t.Errorf("absent grant body = %s, want %s", rec.Body.String(), CodeReauthenticationReq)
	}
	if env.changer.calls() != 0 {
		t.Error("the provider must never be called without a consumable grant")
	}

	// Grant minted for a different action.
	env.mintGrantForeignAction(t, "grant-pwd-foreign")
	rec = env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-foreign"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign action grant: status = %d, want 403", rec.Code)
	}
	if env.changer.calls() != 0 {
		t.Error("a foreign-action grant must never authorize a password change")
	}
}

// mintGrantForeignAction seeds a grant bound to a different account action.
func (e *passwordEnv) mintGrantForeignAction(t *testing.T, token string) {
	t.Helper()
	data := auth.ReauthGrantData{
		UserID:    passwordUser,
		SessionID: string(e.current.Record.SessionID),
		Action:    auth.ReauthActionTOTPRemove,
		CreatedAt: time.Now(),
	}
	if err := e.grants.CreateGrant(t.Context(), session.HashToken(token), data, time.Minute); err != nil {
		t.Fatalf("seed foreign grant: %v", err)
	}
}

// --- Pinned point 2: provider failure ⇒ zero local side effects ---

// TestChangePassword_ProviderFailureZeroSideEffects pins fail-closed
// semantics: a provider failure returns the stable
// provider.password_change_failed error and leaves every local artifact
// untouched — no rotation, no revocation, no audit, no cookie change.
func TestChangePassword_ProviderFailureZeroSideEffects(t *testing.T) {
	env := newPasswordEnv(t)
	env.changer.err = auth.ErrPasswordChangeFailed
	env.mintGrant(t, "grant-pwd-4")

	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-4"})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), CodePasswordChangeFailed) {
		t.Errorf("body = %s, want stable code %s", rec.Body.String(), CodePasswordChangeFailed)
	}

	// Zero local side effects: both sessions intact under their original
	// tokens, the CSRF binding untouched, no cookie re-issue, no audit.
	if _, err := env.store.Get(t.Context(), session.HashToken(env.current.SessionToken)); err != nil {
		t.Errorf("current session must survive a provider failure: %v", err)
	}
	if _, err := env.store.Get(t.Context(), session.HashToken(env.other.SessionToken)); err != nil {
		t.Errorf("other session must survive a provider failure: %v", err)
	}
	if sessCookie, _ := issuedCookies(rec); sessCookie != nil {
		t.Error("no cookies may be re-issued on a provider failure")
	}
	if len(env.auditor.rows()) != 0 {
		t.Error("no durable audit row may be written on a provider failure")
	}
}

// --- Pinned point 3+ race: vanished session ---

// TestChangePassword_VanishedSessionRace pins the production race the
// reviewer called out: the provider call succeeds, but a concurrent
// logout/revocation already removed the session. Rotation fails closed, the
// caller is forced back to login, and no partial success is reported.
func TestChangePassword_VanishedSessionRace(t *testing.T) {
	env := newPasswordEnv(t)
	env.mintGrant(t, "grant-pwd-5")

	// The concurrent winner: the current session is deleted before the
	// handler reaches rotation (RequireSession is bypassed in unit tests by
	// the injected principal, which is exactly the race window).
	if err := env.svc.DeleteSession(t.Context(), env.current.SessionToken); err != nil {
		t.Fatalf("simulate concurrent logout: %v", err)
	}

	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-5"})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (re-login required); body=%s", rec.Code, rec.Body.String())
	}
	// The provider call still happened (the password changed) — the client
	// must not be told it succeeded.
	if env.changer.calls() != 1 {
		t.Fatalf("provider calls = %d, want 1", env.changer.calls())
	}
	// Cookies cleared so the dead token never lingers in the browser.
	sessCookie, csrfCookie := issuedCookies(rec)
	if sessCookie == nil || sessCookie.MaxAge >= 0 || csrfCookie == nil || csrfCookie.MaxAge >= 0 {
		t.Error("both cookies must be cleared after a vanished-session rotation failure")
	}
	// No resurrected session, no audit row for the incomplete flow.
	if records, _ := env.svc.ListUserSessions(t.Context(), passwordUser); len(records) != 1 {
		// only "other" survives; the vanished current session stays gone
		t.Fatalf("live sessions = %d, want 1 (only the untouched other session)", len(records))
	}
	for _, ev := range env.auditor.rows() {
		if ev.EventType == EventPasswordChanged {
			t.Error("no password_changed audit row may be written when rotation failed")
		}
	}
}

// TestChangePassword_RotateInfraFailureOldTokenNeverSurvives pins the
// fail-closed rotation failure: when the store's atomic rotation fails after
// the provider succeeded, the old token must never stay usable — the current
// session is forced down and the caller re-authenticates.
func TestChangePassword_RotateInfraFailureOldTokenNeverSurvives(t *testing.T) {
	env := newPasswordEnv(t)
	env.store.rotateErr = errors.New("redis exploded mid-script")
	env.mintGrant(t, "grant-pwd-6")

	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-6"})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := env.store.Get(t.Context(), session.HashToken(env.current.SessionToken)); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("old token = %v, want ErrSessionNotFound — the old token must never survive a password change", err)
	}
	sessCookie, csrfCookie := issuedCookies(rec)
	if sessCookie == nil || sessCookie.MaxAge >= 0 || csrfCookie == nil || csrfCookie.MaxAge >= 0 {
		t.Error("both cookies must be cleared after a failed rotation")
	}
	if len(env.auditor.rows()) != 0 {
		t.Error("no durable audit row may be written when rotation failed")
	}
}

// --- Revoke-others failure: rotated cookies still issued, response fails ---

// TestChangePassword_RevokeOthersFailure pins the partial-failure path: the
// password changed and the rotation succeeded, so the caller keeps a working
// rotated session — but the response fails closed (never pretend success)
// and no durable audit row is written (partial bulk outcomes stay out of the
// invariant, per the frozen P4.1 precedent).
func TestChangePassword_RevokeOthersFailure(t *testing.T) {
	env := newPasswordEnv(t)
	env.store.revokeOthersErr = errors.New("redis walk failed")
	env.mintGrant(t, "grant-pwd-7")

	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-7"})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	// The caller must not be stranded: rotated cookies are re-issued and
	// the rotated token validates.
	sessCookie, csrfCookie := issuedCookies(rec)
	if sessCookie == nil || csrfCookie == nil {
		t.Fatal("rotated cookies must still be re-issued so the caller is not stranded")
	}
	if _, _, err := env.svc.ValidateSession(t.Context(), sessCookie.Value); err != nil {
		t.Errorf("rotated token must validate: %v", err)
	}
	for _, ev := range env.auditor.rows() {
		if ev.EventType == EventPasswordChanged {
			t.Error("no password_changed audit row may be written on a partial failure")
		}
	}
}

// --- No principal ⇒ 401 ---

func TestChangePassword_NoPrincipal(t *testing.T) {
	env := newPasswordEnv(t)
	rec := env.doPasswordChange(t, false, `{"newPassword":"`+newPasswordPlaintext+`"}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if env.changer.calls() != 0 {
		t.Error("the provider must never be called without an authenticated principal")
	}
}
