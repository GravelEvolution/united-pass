//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the server bootstrap wiring
//

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

func newTestServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func testConfig() config.Config {
	return config.Config{
		Environment:         config.EnvironmentDevelopment,
		HTTPAddr:            "127.0.0.1:0",
		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         15 * time.Second,
		WriteTimeout:        15 * time.Second,
		IdleTimeout:         30 * time.Second,
		ShutdownTimeout:     3 * time.Second,
		MaxRequestBodyBytes: 1 << 20,
		LogLevel:            "info",
	}
}

// TestGracefulShutdownCompletesInflight verifies that Shutdown stops accepting
// new connections while letting an in-flight request finish successfully.
func TestGracefulShutdownCompletesInflight(t *testing.T) {
	cfg := testConfig()
	srv := newTestServer(t, cfg)

	// Replace the health route with a slow handler to simulate in-flight work.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	var reached, released atomic.Bool
	srv.HTTP.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		// Block until the test signals release, simulating long work.
		for !released.Load() {
			time.Sleep(5 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	})

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.HTTP.Serve(ln)
	}()

	// Fire a request that will stay in-flight.
	done := make(chan struct{})
	go func() {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			t.Errorf("in-flight request error: %v", err)
			close(done)
			return
		}
		resp.Body.Close()
		close(done)
	}()

	// Wait until the handler is actually running.
	waitFor(t, func() bool { return reached.Load() }, time.Second)

	// Initiate graceful shutdown in a goroutine; it must block on the in-flight
	// request until we release it.
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- srv.Shutdown(context.Background())
	}()

	// The shutdown should not complete while the request is still running.
	select {
	case <-shutdownDone:
		t.Fatal("shutdown completed before in-flight request finished")
	case <-time.After(100 * time.Millisecond):
	}

	// Release the handler so the request completes and shutdown can finish.
	released.Store(true)

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdown returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not complete within timeout")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not complete")
	}
}

// TestGracefulShutdownStopsNewRequests verifies that after Shutdown is called
// the listener no longer accepts connections.
func TestGracefulShutdownStopsNewRequests(t *testing.T) {
	cfg := testConfig()
	srv := newTestServer(t, cfg)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() { _ = srv.HTTP.Serve(ln) }()

	// Confirm the server is accepting requests.
	waitFor(t, func() bool {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	}, time.Second)

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// New connections should now be refused.
	_, err = http.Get("http://" + addr + "/healthz")
	if err == nil {
		t.Fatal("expected connection refused after shutdown")
	}
}

// TestNewServerMountsHealthRoutes verifies the router serves the operational
// endpoints after wiring.
func TestNewServerMountsHealthRoutes(t *testing.T) {
	srv := newTestServer(t, testConfig())

	healthRec := newRequest(srv.Router, http.MethodGet, "/healthz")
	if healthRec.Code != http.StatusOK {
		t.Errorf("healthz status = %d, want %d", healthRec.Code, http.StatusOK)
	}

	readyRec := newRequest(srv.Router, http.MethodGet, "/readyz")
	if readyRec.Code != http.StatusOK {
		t.Errorf("readyz status = %d, want %d", readyRec.Code, http.StatusOK)
	}
}

// TestNewServerPanicRecordsAccessLog verifies that the real NewServer
// middleware ordering (AccessLog outer, Recovery inner) ensures AccessLog
// captures the 500 status when a handler panics. This guards against
// regressions where Recovery sits outside AccessLog, in which case AccessLog
// would never log the request because the panic unwinds past it.
func TestNewServerPanicRecordsAccessLog(t *testing.T) {
	cfg := testConfig()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Mount a panic handler on the real router. The Router field is typed
	// http.Handler but NewServer always returns a *chi.Mux.
	router, ok := srv.Router.(*chi.Mux)
	if !ok {
		t.Fatal("expected Router to be *chi.Mux")
	}
	router.Get("/test-panic", func(w http.ResponseWriter, r *http.Request) {
		panic("test panic from bootstrap test")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-panic", nil)
	srv.Router.ServeHTTP(rec, req)

	// Recovery must produce a 500 error envelope.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	logOutput := logBuf.String()

	// AccessLog (outer) must have recorded the request with status 500.
	if !strings.Contains(logOutput, "http request") {
		t.Errorf("access log entry missing: %s", logOutput)
	}
	if !strings.Contains(logOutput, "status=500") {
		t.Errorf("access log should record status=500 after panic: %s", logOutput)
	}

	// Recovery (inner) must have logged the panic.
	if !strings.Contains(logOutput, "panic recovered") {
		t.Errorf("panic recovery log missing: %s", logOutput)
	}
}

func newRequest(handler http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	handler.ServeHTTP(rec, req)
	return rec
}

// fakeProjectVerifier stands in for the ZITADEL provisioner in readiness
// checker tests.
type fakeProjectVerifier struct{ err error }

func (f fakeProjectVerifier) VerifyProject(context.Context) error { return f.err }

// TestProjectReadinessChecker verifies the provisioning project checker
// reports the configured project readability outcome, so /readyz fails when
// the project is unreachable or the service account lacks permission.
func TestProjectReadinessChecker(t *testing.T) {
	checker := newProjectReadinessChecker(fakeProjectVerifier{}, time.Second)
	if checker.Name() != "auth_project" {
		t.Errorf("Name() = %q, want %q", checker.Name(), "auth_project")
	}
	if err := checker.Check(context.Background()); err != nil {
		t.Errorf("Check() with healthy project: %v, want nil", err)
	}

	failing := newProjectReadinessChecker(fakeProjectVerifier{err: errors.New("project not found")}, time.Second)
	err := failing.Check(context.Background())
	if err == nil {
		t.Fatal("Check() with unreachable project: want error, got nil")
	}
	if !strings.Contains(err.Error(), "auth project") {
		t.Errorf("Check() error = %v, want prefixed with %q", err, "auth project")
	}
}

// waitFor polls condition until it returns true or the timeout elapses.
func waitFor(t *testing.T, condition func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition never became true within timeout")
}

// TestNewServerRejectsUnknownProviderInProduction verifies that an unknown
// authentication provider fails startup in production.
func TestNewServerRejectsUnknownProviderInProduction(t *testing.T) {
	cfg := testConfig()
	cfg.Environment = config.EnvironmentProduction
	cfg.Auth.Provider = "not-a-real-provider"
	cfg.Auth.BaseURL = "https://auth.example.com"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewServer(cfg, logger); err == nil {
		t.Fatal("expected error for unknown provider in production")
	}
}

// TestNewServerRejectsZitadelWithoutDatabase verifies that the ZITADEL
// adapter refuses to start without database configuration (identity mapping
// requires the local user store).
func TestNewServerRejectsZitadelWithoutDatabase(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.Provider = "zitadel"
	cfg.Auth.BaseURL = "https://auth.example.com"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewServer(cfg, logger); err == nil {
		t.Fatal("expected error for zitadel provider without database")
	}
}

// TestNewServerRejectsProductionWithoutProvider ensures production cannot
// silently fall back to the development fake.
func TestNewServerRejectsProductionWithoutProvider(t *testing.T) {
	cfg := testConfig()
	cfg.Environment = config.EnvironmentProduction

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewServer(cfg, logger); err == nil {
		t.Fatal("expected error for production without provider")
	}
}

// TestNewServerAllowsFakeInDevelopment verifies the fake authenticator is
// accepted for local development.
func TestNewServerAllowsFakeInDevelopment(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.Provider = "fake"
	srv := newTestServer(t, cfg)
	if srv == nil {
		t.Fatal("expected a server in development with fake provider")
	}
}

// TestNewServerAllowsNoProviderInDevelopment verifies that no provider
// configuration at all still permits the fake in development.
func TestNewServerAllowsNoProviderInDevelopment(t *testing.T) {
	srv := newTestServer(t, testConfig())
	if srv == nil {
		t.Fatal("expected a server in development without a provider")
	}
}

// TestNewServerRejectsUnknownProviderInDevelopment verifies that an unknown
// or not-yet-implemented provider fails startup in development too, so it
// cannot silently fall back to the fake. See ADR-0003.
func TestNewServerRejectsUnknownProviderInDevelopment(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.Provider = "not-a-real-provider"
	cfg.Auth.BaseURL = "https://auth.example.com"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewServer(cfg, logger); err == nil {
		t.Fatal("expected error for unknown provider in development")
	}
}

// TestNewServerRejectsInvalidEncryptionKey verifies that a malformed session
// encryption key prevents startup (fail closed) instead of degrading to
// plaintext.
func TestNewServerRejectsInvalidEncryptionKey(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.Provider = "fake"
	cfg.Session.EncryptionKey = "!!!not-base64!!!"
	cfg.Session.EncryptionKeyID = "v1"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewServer(cfg, logger); err == nil {
		t.Fatal("expected error for invalid session encryption key")
	}
}

// TestNewServerAcceptsValidEncryptionKeyInDevelopment verifies a well-formed
// key is accepted and wired into the session service.
func TestNewServerAcceptsValidEncryptionKeyInDevelopment(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.Provider = "fake"
	cfg.Session.EncryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	cfg.Session.EncryptionKeyID = "development-v1"
	srv := newTestServer(t, cfg)
	if srv == nil {
		t.Fatal("expected a server with a valid encryption key")
	}
}

// TestFakeProviderWithDatabaseServesCurrentUser verifies that when a database
// is configured but the authenticator is the development fake, a successful
// login is followed by a 200 from /api/v1/me instead of 401. This is the
// regression test for the wiring bug found during acceptance testing: the
// database-backed userChecker and userReader rejected fake users whose IDs
// do not exist in PostgreSQL.
//
// It requires a real PostgreSQL and Redis instance; the test is skipped when
// UP_TEST_DATABASE_URL or UP_TEST_REDIS_URL is not set. Run with:
//
//	UP_TEST_DATABASE_URL=postgres://... UP_TEST_REDIS_URL=redis://... \
//	go test ./internal/bootstrap/ -run TestFakeProviderWithDatabaseServesCurrentUser
func TestFakeProviderWithDatabaseServesCurrentUser(t *testing.T) {
	dbURL := os.Getenv("UP_TEST_DATABASE_URL")
	redisURL := os.Getenv("UP_TEST_REDIS_URL")
	if dbURL == "" || redisURL == "" {
		t.Skip("UP_TEST_DATABASE_URL and UP_TEST_REDIS_URL required for this test")
	}

	cfg := testConfig()
	cfg.Auth.Provider = "fake"
	cfg.Session.EncryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	cfg.Session.EncryptionKeyID = "test-v1"
	// testConfig() leaves zero-value durations; supply the same defaults as
	// config.Load() so sessions do not expire instantly and login is not
	// rate-limited at limit=0 (count 1 > limit 0).
	cfg.Session.TTL = 12 * time.Hour
	cfg.Session.RememberTTL = 720 * time.Hour
	cfg.Session.IdleTTL = 2 * time.Hour
	cfg.Session.TouchInterval = 5 * time.Minute
	cfg.MFA.ChallengeTTL = 5 * time.Minute
	cfg.MFA.MaxAttempts = 5
	cfg.RateLimit.LoginLimit = 10
	cfg.RateLimit.LoginWindow = 15 * time.Minute
	cfg.RateLimit.MFALimit = 10
	cfg.RateLimit.MFAWindow = 15 * time.Minute
	cfg.Database.URL = dbURL
	cfg.Database.Schema = "united_pass_test"
	cfg.Database.MaxConns = 5
	cfg.Database.MinConns = 1
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Redis.URL = redisURL
	cfg.Redis.KeyPrefix = "up:test:bootstrap:"
	cfg.Redis.PoolSize = 5
	cfg.Redis.ConnectTimeout = 10 * time.Second

	srv := newTestServer(t, cfg)
	t.Cleanup(func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Logf("shutdown: %v", err)
		}
	})

	// 1. Login with the no-MFA dev user.
	loginBody := strings.NewReader(`{"identifier":"zhixing.lin","password":"TestPassword123!"}`)
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	srv.Router.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, want 204; body=%s", loginRec.Code, loginRec.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == httpapi.SessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("up_session cookie not set after login")
	}

	// 2. /api/v1/me must return 200 (fake user reader), not 401 (database
	// lookup failure for the hardcoded fake user ID).
	meRec := httptest.NewRecorder()
	meReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	meReq.AddCookie(sessionCookie)
	srv.Router.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("/api/v1/me status = %d, want 200; body=%s", meRec.Code, meRec.Body.String())
	}
	if !strings.Contains(meRec.Body.String(), `"userId":"user_01JZDEVTEST001"`) {
		t.Errorf("/api/v1/me body missing expected userId: %s", meRec.Body.String())
	}
}

// TestToCanonicalSecurityEventMapsSessionTarget verifies that the session
// adapter carries the target session ID and the provider-cleanup failure
// class through the generic payload seam into the canonical durable event,
// and keeps the application/client columns empty (ADR-0006 §2).
func TestToCanonicalSecurityEventMapsSessionTarget(t *testing.T) {
	occurredAt := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	ev := toCanonicalSecurityEvent(session.SecurityAuditEvent{
		EventType:    session.EventSessionRevokedOther,
		ActorUserID:  identity.UserID("user_audit"),
		SessionID:    session.SessionID("sess_target"),
		Operation:    "session.revoke",
		Result:       session.AuditOutcomeSuccess,
		FailureClass: "network",
		OccurredAt:   occurredAt,
	}, "req-1")

	if ev.EventType != session.EventSessionRevokedOther {
		t.Errorf("EventType = %q, want %q", ev.EventType, session.EventSessionRevokedOther)
	}
	if ev.ActorUserID != identity.UserID("user_audit") {
		t.Errorf("ActorUserID = %q, want user_audit", ev.ActorUserID)
	}
	if ev.RequestID != "req-1" {
		t.Errorf("RequestID = %q, want req-1", ev.RequestID)
	}
	if ev.Operation != "session.revoke" {
		t.Errorf("Operation = %q, want session.revoke", ev.Operation)
	}
	if ev.Result != applications.SecurityEventSuccess {
		t.Errorf("Result = %q, want success", ev.Result)
	}
	if ev.FailureClass != "network" {
		t.Errorf("FailureClass = %q, want network", ev.FailureClass)
	}
	if ev.TargetKey != "session_id" || ev.TargetID != "sess_target" {
		t.Errorf("target seam = %q/%q, want session_id/sess_target", ev.TargetKey, ev.TargetID)
	}
	if ev.ApplicationID != "" || ev.ClientID != "" {
		t.Errorf("session events must not reference application/client, got %q/%q", ev.ApplicationID, ev.ClientID)
	}
	if ev.EventID == "" {
		t.Error("EventID must be generated")
	}
	if !ev.OccurredAt.Equal(occurredAt) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, occurredAt)
	}
}

func TestToCanonicalSecurityEventMapsBulkRevokeForensics(t *testing.T) {
	ev := toCanonicalSecurityEvent(session.SecurityAuditEvent{
		EventType:            session.EventSessionsRevokedOthers,
		ActorUserID:          identity.UserID("user_audit"),
		SessionID:            session.SessionID("sess_current"),
		Operation:            "session.revoke_all_others",
		Result:               session.AuditOutcomeDenied,
		FailureClass:         "internal",
		AffectedCount:        2,
		ProviderFailureClass: "timeout",
		OccurredAt:           time.Now().UTC(),
	}, "req-bulk")

	if ev.Result != applications.SecurityEventDenied || ev.FailureClass != "internal" {
		t.Errorf("bulk result/failure class = %q/%q", ev.Result, ev.FailureClass)
	}
	if ev.TargetKey != "session_id" || ev.TargetID != "sess_current" {
		t.Errorf("bulk target seam = %q/%q", ev.TargetKey, ev.TargetID)
	}
	if ev.Extra["revoked_count"] != "2" || ev.Extra["provider_failure_class"] != "timeout" {
		t.Errorf("P4.8 forensic extras = %v", ev.Extra)
	}
}
