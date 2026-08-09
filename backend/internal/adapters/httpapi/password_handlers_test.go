//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the password change handler (ADR-0006 §6, amended by ADR-0007)
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
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
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

// fakeMutationAuthority is an in-memory MutationAuthority mirroring the
// ADR-0007 PostgreSQL ledger semantics for unit tests: single-winner
// acquisition (B4), atomic outcome-record + epoch advancement (the ordering
// invariant), confirmed-failure settlement with the epoch untouched, and
// settlement driving rotate + generation-scoped cleanup (F4).
type fakeMutationAuthority struct {
	mu      sync.Mutex
	epochs  map[identity.UserID]securitystate.Epoch
	intents map[identity.UserID]securitystate.Intent
	settled []securitystate.Intent
	nextID  int64
	cleaner securitystate.SettlementCleaner

	acquireErr error
	recordErr  error
	cleanupErr error
}

func newFakeMutationAuthority() *fakeMutationAuthority {
	return &fakeMutationAuthority{
		epochs:  map[identity.UserID]securitystate.Epoch{},
		intents: map[identity.UserID]securitystate.Intent{},
	}
}

func (f *fakeMutationAuthority) epochLocked(userID identity.UserID) securitystate.Epoch {
	if e, ok := f.epochs[userID]; ok {
		return e
	}
	return 1
}

func (f *fakeMutationAuthority) Acquire(_ context.Context, userID identity.UserID) (securitystate.Intent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquireErr != nil {
		return securitystate.Intent{}, f.acquireErr
	}
	if _, held := f.intents[userID]; held {
		return securitystate.Intent{}, securitystate.ErrIntentHeld
	}
	f.nextID++
	intent := securitystate.Intent{
		UserID:         userID,
		IntentID:       f.nextID,
		Status:         securitystate.IntentActive,
		EpochAtAcquire: f.epochLocked(userID),
	}
	f.intents[userID] = intent
	return intent, nil
}

func (f *fakeMutationAuthority) SettleConfirmedFailure(_ context.Context, userID identity.UserID, intentID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	intent, ok := f.intents[userID]
	if !ok || intent.IntentID != intentID || intent.Status != securitystate.IntentActive {
		return securitystate.ErrFenceLost
	}
	intent.Status = securitystate.IntentSettled
	intent.ProviderOutcome = securitystate.ProviderOutcomeConfirmedFailure
	delete(f.intents, userID)
	f.settled = append(f.settled, intent)
	return nil
}

func (f *fakeMutationAuthority) RecordOutcome(_ context.Context, userID identity.UserID, intentID int64, outcome securitystate.ProviderOutcome) (securitystate.Epoch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordErr != nil {
		return 0, f.recordErr
	}
	intent, ok := f.intents[userID]
	if !ok || intent.IntentID != intentID || intent.Status != securitystate.IntentActive {
		return 0, securitystate.ErrFenceLost
	}
	newEpoch := f.epochLocked(userID) + 1
	f.epochs[userID] = newEpoch
	intent.Status = securitystate.IntentOutcomeRecorded
	intent.ProviderOutcome = outcome
	f.intents[userID] = intent
	return newEpoch, nil
}

func (f *fakeMutationAuthority) SettleIntent(ctx context.Context, intent securitystate.Intent, newEpoch securitystate.Epoch, rotate securitystate.RotateFunc) (securitystate.SettlementResult, error) {
	f.mu.Lock()
	cleanupErr := f.cleanupErr
	cleaner := f.cleaner
	if current, ok := f.intents[intent.UserID]; ok && current.IntentID == intent.IntentID {
		current.Status = securitystate.IntentLocalSettlement
		f.intents[intent.UserID] = current
	}
	f.mu.Unlock()

	var rotated, vanished, rotateFailed bool
	if rotate != nil {
		gone, err := rotate(ctx)
		switch {
		case err != nil:
			rotateFailed = true
		case gone:
			vanished = true
		default:
			rotated = true
		}
	}

	if cleanupErr != nil {
		f.terminalize(intent, securitystate.SettlementOutcomeDegraded)
		return securitystate.SettlementResult{Outcome: securitystate.SettlementOutcomeDegraded, Rotated: rotated}, cleanupErr
	}
	if cleaner != nil {
		if _, err := cleaner.RevokeSessionsBeforeEpoch(ctx, intent.UserID, newEpoch); err != nil {
			f.terminalize(intent, securitystate.SettlementOutcomeDegraded)
			return securitystate.SettlementResult{Outcome: securitystate.SettlementOutcomeDegraded, Rotated: rotated}, err
		}
	}

	outcome := securitystate.SettlementOutcomeSettled
	switch {
	case intent.ProviderOutcome == securitystate.ProviderOutcomeUnknown:
		outcome = securitystate.SettlementOutcomeDegraded
	case rotateFailed:
		outcome = securitystate.SettlementOutcomeDegraded
	case rotate != nil && vanished:
		outcome = securitystate.SettlementOutcomeSettledRelogin
	}
	f.terminalize(intent, outcome)
	return securitystate.SettlementResult{Outcome: outcome, Rotated: rotated}, nil
}

func (f *fakeMutationAuthority) terminalize(intent securitystate.Intent, outcome securitystate.SettlementOutcome) {
	f.mu.Lock()
	defer f.mu.Unlock()
	intent.Status = securitystate.IntentSettled
	intent.SettlementOutcome = outcome
	delete(f.intents, intent.UserID)
	f.settled = append(f.settled, intent)
}

func (f *fakeMutationAuthority) currentEpoch(userID identity.UserID) securitystate.Epoch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.epochLocked(userID)
}

func (f *fakeMutationAuthority) liveIntent(userID identity.UserID) (securitystate.Intent, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.intents[userID]
	return i, ok
}

func (f *fakeMutationAuthority) settledIntents() []securitystate.Intent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]securitystate.Intent(nil), f.settled...)
}

// --- Test harness ---

var passwordUser = identity.UserID("user_password")

// passwordEnv wires a real session.Service over the in-memory store (which
// also serves as the generation-scoped settlement cleaner), a fake password
// authority, reauth grants, the fake mutation authority and the durable
// audit seam, and mounts the password route behind an injected
// authentication context.
type passwordEnv struct {
	handlers *PasswordHandlers
	store    *fakeSessionStore
	svc      *session.Service
	changer  *fakePasswordChanger
	grants   *memReauthGrants
	security *fakeMutationAuthority
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
	security := newFakeMutationAuthority()
	security.cleaner = svc
	auditor := &fakeSessionAuditor{}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))

	cfg := config.Config{}
	cfg.Session.CookieSameSite = "lax"

	handlers := NewPasswordHandlers(changer, NewReauthGrants(grants, nil), svc, security, auditor,
		time.Second, 2*time.Second, cfg, logger)
	return &passwordEnv{
		handlers: handlers, store: store, svc: svc, changer: changer,
		grants: grants, security: security, auditor: auditor, logs: logs,
		current: current, other: other,
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
// current session, stamped with the current security epoch.
func (e *passwordEnv) mintGrant(t *testing.T, token string) {
	t.Helper()
	data := auth.ReauthGrantData{
		UserID:        passwordUser,
		SessionID:     string(e.current.Record.SessionID),
		Action:        auth.ReauthActionPasswordChange,
		SecurityEpoch: e.security.currentEpoch(passwordUser),
		CreatedAt:     time.Now(),
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

// --- Happy path: intent fence + epoch advancement + rotate + cleanup + audit ---

// TestChangePassword_Success pins the ADR-0007 settlement flow: durable
// intent acquired before the provider call, provider change, epoch advanced
// exactly once with the outcome record, current session rotated and
// re-stamped to the new epoch, every pre-change session revoked through the
// generation-scoped cleanup (never the generation-unaware bulk revoke),
// cookies re-issued, durable audit carrying both outcome facts — and the
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

	// The epoch advanced exactly once and no intent lingers.
	if epoch := env.security.currentEpoch(passwordUser); epoch != 2 {
		t.Errorf("epoch = %d, want 2 (advanced exactly once)", epoch)
	}
	if _, held := env.security.liveIntent(passwordUser); held {
		t.Error("a live intent must never survive a fully settled mutation")
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

	// Old token dead, new token live under the stable SessionID,
	// re-stamped to the new epoch.
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
	if rotated.SecurityEpoch != 2 {
		t.Errorf("rotated record epoch = %d, want 2 (re-stamped to the new epoch)", rotated.SecurityEpoch)
	}
	if rotated.CSRFTokenHash != session.HashToken(csrfCookie.Value) {
		t.Error("the rotated record must bind the new CSRF token hash")
	}
	if rotated.ExpiresAt != env.current.Record.ExpiresAt {
		t.Error("rotation must never extend the absolute deadline")
	}

	// Generation-scoped cleanup: every pre-change session is revoked; only
	// the rotated, re-stamped current session survives (B1/F4).
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

	// Durable audit (Decision 5): exactly one account.password_changed row
	// carrying both orthogonal outcome facts and the forensic context; no
	// password material anywhere in the payload.
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
	if ev.ProviderOutcome != string(securitystate.ProviderOutcomeSuccess) {
		t.Errorf("audit providerOutcome = %q, want success", ev.ProviderOutcome)
	}
	if ev.SettlementOutcome != string(securitystate.SettlementOutcomeSettled) {
		t.Errorf("audit settlementOutcome = %q, want settled", ev.SettlementOutcome)
	}
	if ev.IntentID == 0 || ev.FromEpoch != 1 || ev.ToEpoch != 2 {
		t.Errorf("audit forensic context = (intent %d, epoch %d->%d), want (non-zero, 1->2)", ev.IntentID, ev.FromEpoch, ev.ToEpoch)
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
		UserID:        passwordUser,
		SessionID:     string(e.current.Record.SessionID),
		Action:        auth.ReauthActionTOTPRemove,
		SecurityEpoch: e.security.currentEpoch(passwordUser),
		CreatedAt:     time.Now(),
	}
	if err := e.grants.CreateGrant(t.Context(), session.HashToken(token), data, time.Minute); err != nil {
		t.Fatalf("seed foreign grant: %v", err)
	}
}

// --- B4: single-winner fencing before the provider call ---

// TestChangePassword_ConcurrentMutationRejectedBeforeProvider pins the B4
// closure: while another mutation holds the user's durable intent, a second
// mutation fails closed BEFORE any provider call with the stable
// password.change_in_progress — zero provider calls, zero side effects.
func TestChangePassword_ConcurrentMutationRejectedBeforeProvider(t *testing.T) {
	env := newPasswordEnv(t)
	env.mintGrant(t, "grant-pwd-b4")

	// The concurrent winner already holds the intent.
	if _, err := env.security.Acquire(t.Context(), passwordUser); err != nil {
		t.Fatalf("seed held intent: %v", err)
	}

	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-b4"})

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), CodePasswordChangeInProgress) {
		t.Errorf("body = %s, want stable code %s", rec.Body.String(), CodePasswordChangeInProgress)
	}
	if env.changer.calls() != 0 {
		t.Error("a concurrent second mutation must never reach the provider")
	}
	if epoch := env.security.currentEpoch(passwordUser); epoch != 1 {
		t.Errorf("epoch = %d, want 1 (unchanged by a rejected mutation)", epoch)
	}
	if len(env.auditor.rows()) != 0 {
		t.Error("no durable audit row may be written for a rejected mutation")
	}
}

// TestChangePassword_AcquireFailureFailsClosed pins fail-closed acquisition:
// an authoritative-store failure before the provider call yields a 500 with
// zero provider calls and zero side effects.
func TestChangePassword_AcquireFailureFailsClosed(t *testing.T) {
	env := newPasswordEnv(t)
	env.security.acquireErr = errors.New("postgres down")
	env.mintGrant(t, "grant-pwd-acq")

	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-acq"})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if env.changer.calls() != 0 {
		t.Error("the provider must never be called when intent acquisition fails")
	}
	if len(env.auditor.rows()) != 0 {
		t.Error("no durable audit row may be written when acquisition fails")
	}
}

// --- Decision 2 row 1: confirmed failure ⇒ zero local side effects ---

// TestChangePassword_ProviderFailureZeroSideEffects pins fail-closed
// semantics for a confirmed provider rejection: the stable
// provider.password_change_failed error, the intent settled with the epoch
// unchanged, and every local artifact untouched — no rotation, no
// revocation, no audit, no cookie change.
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
	// tokens, no cookie re-issue, no audit, the epoch unchanged.
	if _, err := env.store.Get(t.Context(), session.HashToken(env.current.SessionToken)); err != nil {
		t.Errorf("current session must survive a confirmed provider failure: %v", err)
	}
	if _, err := env.store.Get(t.Context(), session.HashToken(env.other.SessionToken)); err != nil {
		t.Errorf("other session must survive a confirmed provider failure: %v", err)
	}
	if sessCookie, _ := issuedCookies(rec); sessCookie != nil {
		t.Error("no cookies may be re-issued on a confirmed provider failure")
	}
	if len(env.auditor.rows()) != 0 {
		t.Error("no durable audit row may be written on a confirmed provider failure")
	}
	if epoch := env.security.currentEpoch(passwordUser); epoch != 1 {
		t.Errorf("epoch = %d, want 1 (confirmed failure never advances the epoch)", epoch)
	}
	if _, held := env.security.liveIntent(passwordUser); held {
		t.Error("the intent must be settled after a confirmed failure")
	}
	settled := env.security.settledIntents()
	if len(settled) != 1 || settled[0].ProviderOutcome != securitystate.ProviderOutcomeConfirmedFailure {
		t.Errorf("settled intents = %+v, want exactly one confirmed_failure settlement", settled)
	}
}

// --- Decision 2 row 5: unknown outcome ⇒ epoch advanced, re-login forced ---

// TestChangePassword_UnknownOutcomeForcesRelogin pins the unknown-outcome
// row: a transport-ambiguous provider result advances the epoch (fail
// closed), settles degraded, never reports success, never rotates a new
// credential, clears both cookies and forces re-login — with the durable
// audit preserving providerOutcome=unknown (B5/F5).
func TestChangePassword_UnknownOutcomeForcesRelogin(t *testing.T) {
	env := newPasswordEnv(t)
	env.changer.err = auth.ErrPasswordChangeUnknown
	env.mintGrant(t, "grant-pwd-unknown")

	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-unknown"})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (re-login forced); body=%s", rec.Code, rec.Body.String())
	}
	// Cookies cleared, never re-issued.
	sessCookie, csrfCookie := issuedCookies(rec)
	if sessCookie == nil || sessCookie.MaxAge >= 0 || csrfCookie == nil || csrfCookie.MaxAge >= 0 {
		t.Error("both cookies must be cleared on an unknown outcome")
	}
	// The epoch advanced exactly once (fail closed) and the barrier is gone.
	if epoch := env.security.currentEpoch(passwordUser); epoch != 2 {
		t.Errorf("epoch = %d, want 2 (unknown advances the epoch fail closed)", epoch)
	}
	if _, held := env.security.liveIntent(passwordUser); held {
		t.Error("the intent must be settled after the unknown settlement")
	}
	// Every pre-change session is invalid regardless of Redis state.
	if records, _ := env.svc.ListUserSessions(t.Context(), passwordUser); len(records) != 0 {
		t.Errorf("live sessions = %d, want 0 (unknown invalidates the whole generation)", len(records))
	}
	// Durable audit on the unknown path: providerOutcome stays
	// distinguishable from success (F5), settlement degraded.
	rows := env.auditor.rows()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	if rows[0].ProviderOutcome != string(securitystate.ProviderOutcomeUnknown) {
		t.Errorf("audit providerOutcome = %q, want unknown", rows[0].ProviderOutcome)
	}
	if rows[0].SettlementOutcome != string(securitystate.SettlementOutcomeDegraded) {
		t.Errorf("audit settlementOutcome = %q, want degraded", rows[0].SettlementOutcome)
	}
}

// --- Decision 2 row 3: vanished session ⇒ settled_relogin ---

// TestChangePassword_VanishedSessionRace pins the production race: the
// provider call succeeds, but a concurrent logout/revocation already removed
// the session. The epoch still advanced first (B1: account invalidation
// never depends on rotation), the caller is forced back to login, no partial
// success is reported — and the durable audit is written with settlement
// settled_relogin (B5).
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
		t.Error("both cookies must be cleared after a vanished-session settlement")
	}
	// The epoch advanced and every pre-change session is gone.
	if epoch := env.security.currentEpoch(passwordUser); epoch != 2 {
		t.Errorf("epoch = %d, want 2", epoch)
	}
	if records, _ := env.svc.ListUserSessions(t.Context(), passwordUser); len(records) != 0 {
		t.Fatalf("live sessions = %d, want 0 (whole generation invalid)", len(records))
	}
	// Durable audit is mandatory on this committed path (B5), carrying the
	// settled_relogin settlement outcome.
	rows := env.auditor.rows()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1 (a provider-committed path may never vanish from durable history)", len(rows))
	}
	if rows[0].ProviderOutcome != string(securitystate.ProviderOutcomeSuccess) {
		t.Errorf("audit providerOutcome = %q, want success", rows[0].ProviderOutcome)
	}
	if rows[0].SettlementOutcome != string(securitystate.SettlementOutcomeSettledRelogin) {
		t.Errorf("audit settlementOutcome = %q, want settled_relogin", rows[0].SettlementOutcome)
	}
}

// --- Decision 2 row 4: rotation infra failure ⇒ degraded, old token dies ---

// TestChangePassword_RotateInfraFailureOldTokenNeverSurvives pins the
// degraded rotation path: when rotation fails after the epoch advanced, the
// response never reports success — and the old token still dies because the
// generation-scoped cleanup revokes every session stamped before the new
// epoch (account invalidation never depends on rotation, B1).
func TestChangePassword_RotateInfraFailureOldTokenNeverSurvives(t *testing.T) {
	env := newPasswordEnv(t)
	env.store.rotateErr = errors.New("redis exploded mid-script")
	env.mintGrant(t, "grant-pwd-6")

	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-6"})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (degraded settlement); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), CodeSettlementDegraded) {
		t.Errorf("body = %s, want stable code %s", rec.Body.String(), CodeSettlementDegraded)
	}
	// The old token dies through the generation-scoped cleanup even though
	// rotation failed: it is still stamped before the new epoch.
	if _, err := env.store.Get(t.Context(), session.HashToken(env.current.SessionToken)); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("old token = %v, want ErrSessionNotFound — the old token must never survive a password change", err)
	}
	if sessCookie, _ := issuedCookies(rec); sessCookie != nil {
		t.Error("no rotated cookies may be issued when rotation failed")
	}
	// Durable audit is mandatory on this committed path (B5), degraded.
	rows := env.auditor.rows()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	if rows[0].SettlementOutcome != string(securitystate.SettlementOutcomeDegraded) {
		t.Errorf("audit settlementOutcome = %q, want degraded", rows[0].SettlementOutcome)
	}
}

// --- Cleanup failure: rotated cookies still issued, response fails closed ---

// TestChangePassword_CleanupFailure pins the partial-failure path: the
// password changed, the epoch advanced and the rotation succeeded, so the
// caller keeps a working rotated credential — but the cleanup failure
// degrades the settlement, the response fails closed (never pretend success)
// and the durable audit records settlement degraded (B5).
func TestChangePassword_CleanupFailure(t *testing.T) {
	env := newPasswordEnv(t)
	env.store.revokeEpochErr = errors.New("redis walk failed")
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
	// Durable audit on the degraded committed path (B5).
	rows := env.auditor.rows()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1 (a provider-committed path may never vanish from durable history)", len(rows))
	}
	if rows[0].ProviderOutcome != string(securitystate.ProviderOutcomeSuccess) {
		t.Errorf("audit providerOutcome = %q, want success", rows[0].ProviderOutcome)
	}
	if rows[0].SettlementOutcome != string(securitystate.SettlementOutcomeDegraded) {
		t.Errorf("audit settlementOutcome = %q, want degraded", rows[0].SettlementOutcome)
	}
}

// --- RecordOutcome failure: fail closed, never report success ---

// TestChangePassword_RecordOutcomeFailure pins the fail-closed corner where
// the outcome record + epoch advancement itself fails after a committed
// provider call. A lost fence means a takeover already established the
// boundary (401 + cleared cookies); any other authoritative-store failure
// degrades without ever reporting success.
func TestChangePassword_RecordOutcomeFailure(t *testing.T) {
	// Fence lost: takeover already recorded the outcome and advanced the
	// epoch exactly once — the old generation is dead.
	env := newPasswordEnv(t)
	env.security.recordErr = securitystate.ErrFenceLost
	env.mintGrant(t, "grant-pwd-fence")
	rec := env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-fence"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("fence lost: status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if sessCookie, csrfCookie := issuedCookies(rec); sessCookie == nil || sessCookie.MaxAge >= 0 || csrfCookie == nil || csrfCookie.MaxAge >= 0 {
		t.Error("fence lost: both cookies must be cleared")
	}
	if len(env.auditor.rows()) != 1 {
		t.Errorf("fence lost: audit rows = %d, want 1 (the committed path must still be audited)", len(env.auditor.rows()))
	}

	// Generic authoritative-store failure: 500 degraded, never success.
	env = newPasswordEnv(t)
	env.security.recordErr = errors.New("postgres down mid-transaction")
	env.mintGrant(t, "grant-pwd-record")
	rec = env.doPasswordChange(t, true, `{"newPassword":"`+newPasswordPlaintext+`"}`,
		map[string]string{"X-Reauthentication-Token": "grant-pwd-record"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("record failure: status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), CodeSettlementDegraded) {
		t.Errorf("record failure body = %s, want stable code %s", rec.Body.String(), CodeSettlementDegraded)
	}
	if epoch := env.security.currentEpoch(passwordUser); epoch != 1 {
		t.Errorf("record failure: epoch = %d, want 1 (a failed record never advances the epoch)", epoch)
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
