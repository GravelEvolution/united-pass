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
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/GravelEvolution/united-pass/backend/internal/accountcontact"
	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/integrationboundary"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
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

func TestNewAliyunSMSClientFailsClosedBeforeWiring(t *testing.T) {
	valid := config.AliyunSMSConfig{
		Enabled:         true,
		AccessKeyID:     "test-access-key-id",
		AccessKeySecret: "test-access-key-secret",
		SignName:        "test-sign",
		TemplateCode:    "SMS_123456789",
		Endpoint:        "https://dysmsapi.aliyuncs.com/",
	}
	if _, err := newAliyunSMSClient(valid); err != nil {
		t.Fatalf("newAliyunSMSClient rejected valid config: %v", err)
	}

	invalidEndpoint := valid
	invalidEndpoint.Endpoint = "https://attacker.example/"
	if _, err := newAliyunSMSClient(invalidEndpoint); err == nil || !strings.Contains(err.Error(), "official Aliyun HTTPS origin") {
		t.Fatalf("newAliyunSMSClient endpoint error = %v", err)
	}

	missingSecret := valid
	missingSecret.AccessKeySecret = ""
	if _, err := newAliyunSMSClient(missingSecret); err == nil || !strings.Contains(err.Error(), "access key secret") {
		t.Fatalf("newAliyunSMSClient credential error = %v", err)
	}
}

// prepareBootstrapTestDatabase makes the database-backed bootstrap regression
// test hermetic. The API server deliberately never runs migrations at startup,
// so a test that opts into a real database must prepare its dedicated test
// schema explicitly instead of depending on another package or CI step to run
// first.
func prepareBootstrapTestDatabase(t *testing.T, databaseURL, schema string) {
	t.Helper()
	if schema == "" {
		schema = "united_pass_test"
	}
	if !config.ValidSchemaIdentifier(schema) {
		t.Fatalf("test schema %q is not a valid PostgreSQL identifier", schema)
	}

	connConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	if connConfig.RuntimeParams == nil {
		connConfig.RuntimeParams = make(map[string]string)
	}
	connConfig.RuntimeParams["search_path"] = schema

	db := stdlib.OpenDB(*connConfig)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(context.Background(), "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	goose.SetTableName(pgx.Identifier{schema, "goose_db_version"}.Sanitize())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set migration dialect: %v", err)
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	var migrationsDir string
	for range 5 {
		candidate := filepath.Join(dir, "migrations")
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			migrationsDir = candidate
			break
		}
		dir = filepath.Dir(dir)
	}
	if migrationsDir == "" {
		t.Fatal("migrations directory not found")
	}
	if err := goose.UpContext(context.Background(), db, migrationsDir); err != nil {
		t.Fatalf("apply test migrations: %v", err)
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

func TestDreamUPAdminDisabledReturns404WithoutReadingKeyrings(t *testing.T) {
	cfg := testConfig()
	cfg.DreamUPAdmin = config.DreamUPAdminConfig{
		Enabled:                        false,
		ChallengeEncryptionKeyringPath: `Z:\unreadable\challenge.json`, ChallengeEncryptionCurrentKeyID: "same",
		ChallengePepperKeyringPath: `Z:\unreadable\pepper.json`, ChallengePepperCurrentKeyID: "same",
		ProtectedReasonKeyringPath: `Z:\unreadable\reason.json`, ProtectedReasonCurrentKeyID: "same",
		RateLimitKeyringPath: `Z:\unreadable\rate.json`, RateLimitCurrentKeyID: "same",
		OperationFingerprintKeyringPath: `Z:\unreadable\fingerprint.json`, OperationFingerprintCurrentKeyID: "same",
	}
	srv := newTestServer(t, cfg)
	recorder := httptest.NewRecorder()
	srv.Router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/step-up/challenge?eventId=evt_a", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, path := range []string{
		"/.well-known/dreamup-admin-jwks.json",
		"/api/v1/admin/dreamup/eligibility",
		"/api/v1/admin/dreamup/events",
		"/api/v1/admin/dreamup/events/evt_a/content",
	} {
		recorder = httptest.NewRecorder()
		srv.Router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("disabled path %s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestDreamUPAdminEnabledFailsClosedWhenKeyringCannotLoad(t *testing.T) {
	cfg := testConfig()
	cfg.DreamUPAdmin = config.DreamUPAdminConfig{
		Enabled:                        true,
		ChallengeEncryptionKeyringPath: `Z:\unreadable\challenge.json`, ChallengeEncryptionCurrentKeyID: "ce-1",
		ChallengePepperKeyringPath: `Z:\unreadable\pepper.json`, ChallengePepperCurrentKeyID: "cp-1",
		ProtectedReasonKeyringPath: `Z:\unreadable\reason.json`, ProtectedReasonCurrentKeyID: "pr-1",
		RateLimitKeyringPath: `Z:\unreadable\rate.json`, RateLimitCurrentKeyID: "rl-1",
		OperationFingerprintKeyringPath: `Z:\unreadable\fingerprint.json`, OperationFingerprintCurrentKeyID: "of-1",
		FreshLoginMaxAge: 5 * time.Minute, GeneralFreshness: 30 * time.Minute, HighRiskFreshness: 5 * time.Minute,
		RateLimit: 5, RateWindow: 15 * time.Minute, LockDuration: 30 * time.Minute, Argon2MaxConcurrent: 2,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewServer(cfg, logger); err == nil || !strings.Contains(err.Error(), "DreamUP admin") {
		t.Fatalf("error=%v", err)
	}
}

func TestDreamUPAdminSecurityMaterialRejectsSessionAndCrossPurposeKeyReuse(t *testing.T) {
	temp := t.TempDir()
	writeRing := func(name, id string, value byte) string {
		t.Helper()
		path := filepath.Join(temp, name+".json")
		encoded := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
		if err := os.WriteFile(path, []byte(`{"keys":{"`+id+`":"`+encoded+`"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cfg := config.Config{DreamUPAdmin: config.DreamUPAdminConfig{
		Enabled:                        true,
		ChallengeEncryptionKeyringPath: writeRing("challenge", "ce-1", 1), ChallengeEncryptionCurrentKeyID: "ce-1",
		ChallengePepperKeyringPath: writeRing("pepper", "cp-1", 2), ChallengePepperCurrentKeyID: "cp-1",
		ProtectedReasonKeyringPath: writeRing("reason", "pr-1", 3), ProtectedReasonCurrentKeyID: "pr-1",
		RateLimitKeyringPath: writeRing("rate", "rl-1", 4), RateLimitCurrentKeyID: "rl-1",
		OperationFingerprintKeyringPath: writeRing("operation", "of-1", 5), OperationFingerprintCurrentKeyID: "of-1",
	}}
	if _, err := loadDreamUPAdminSecurityMaterial(cfg); err != nil {
		t.Fatalf("unique material rejected: %v", err)
	}
	cfg.Session.EncryptionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	if _, err := loadDreamUPAdminSecurityMaterial(cfg); err == nil {
		t.Fatal("operation fingerprint key reused as session encryption key")
	}
	cfg.Session.EncryptionKey = ""
	cfg.DreamUPAdmin.RateLimitKeyringPath = cfg.DreamUPAdmin.ChallengePepperKeyringPath
	cfg.DreamUPAdmin.RateLimitCurrentKeyID = cfg.DreamUPAdmin.ChallengePepperCurrentKeyID
	if _, err := loadDreamUPAdminSecurityMaterial(cfg); err == nil {
		t.Fatal("cross-purpose key reuse accepted")
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

func TestNewServerRejectsOnboardingWithoutDedicatedEncryptionMaterialBeforeInfrastructure(t *testing.T) {
	cfg := testConfig()
	cfg.WeChatMiniProgram.Enabled = true
	cfg.WeChatMiniProgram.RegistrationEnabled = true
	cfg.WeChatMiniProgram.OnboardingEnabled = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, err := NewServer(cfg, logger)
	if err == nil || !strings.Contains(err.Error(), "dedicated key and key ID are required") {
		t.Fatalf("NewServer error = %v, want dedicated onboarding key failure", err)
	}
}

func TestNewServerRejectsOnboardingWithoutSecurityNotificationTransportBeforeInfrastructure(t *testing.T) {
	cfg := testConfig()
	cfg.WeChatMiniProgram.Enabled = true
	cfg.WeChatMiniProgram.RegistrationEnabled = true
	cfg.WeChatMiniProgram.OnboardingEnabled = true
	cfg.WeChatMiniProgram.OnboardingEncryptionKey = bootstrapTestAESKey(0x22)
	cfg.WeChatMiniProgram.OnboardingEncryptionKeyID = "wechat-onboarding-v1"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, err := NewServer(cfg, logger)
	if err == nil || !strings.Contains(err.Error(), "security notification transport is unavailable") {
		t.Fatalf("NewServer error = %v, want notification transport failure", err)
	}
}

func TestWeChatOnboardingEncryptorIsCryptographicallySeparatedFromSessions(t *testing.T) {
	sessionKey := bootstrapTestAESKey(0x11)
	onboardingKey := bootstrapTestAESKey(0x22)
	cfg := testConfig()
	cfg.Session.EncryptionKey = sessionKey
	cfg.Session.EncryptionKeyID = "session-v1"
	cfg.WeChatMiniProgram.OnboardingEnabled = true
	cfg.WeChatMiniProgram.OnboardingEncryptionKey = onboardingKey
	cfg.WeChatMiniProgram.OnboardingEncryptionKeyID = "wechat-onboarding-v1"

	onboardingEncryptor, err := newWeChatOnboardingEncryptor(cfg)
	if err != nil {
		t.Fatalf("newWeChatOnboardingEncryptor: %v", err)
	}
	sessionEncryptor, err := newSessionEncryptor(cfg)
	if err != nil {
		t.Fatalf("newSessionEncryptor: %v", err)
	}
	onboardingCiphertext, err := onboardingEncryptor.Encrypt("private-onboarding-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(onboardingCiphertext, "wechat-onboarding-v1:") {
		t.Fatalf("unexpected onboarding key ID: %q", onboardingCiphertext)
	}
	if _, err := sessionEncryptor.Decrypt(onboardingCiphertext); err == nil {
		t.Fatal("session AEAD decrypted an onboarding challenge")
	}
	sessionCiphertext, err := sessionEncryptor.Encrypt("private-provider-session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := onboardingEncryptor.Decrypt(sessionCiphertext); err == nil {
		t.Fatal("onboarding AEAD decrypted a provider session")
	}
}

func TestWeChatOnboardingEncryptorRetainsHistoricalCleanupKeys(t *testing.T) {
	oldKey := bootstrapTestAESKey(0x21)
	currentKey := bootstrapTestAESKey(0x22)
	oldEncryptor, err := session.NewAESGCMEncryptor(oldKey, "wechat-onboarding-v1")
	if err != nil {
		t.Fatal(err)
	}
	cleanupCiphertext, err := oldEncryptor.Encrypt("provider-session-awaiting-revocation")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.WeChatMiniProgram.OnboardingEnabled = true
	cfg.WeChatMiniProgram.OnboardingEncryptionKey = currentKey
	cfg.WeChatMiniProgram.OnboardingEncryptionKeyID = "wechat-onboarding-v2"
	cfg.WeChatMiniProgram.OnboardingRetainedDecryptionKeys = `{"wechat-onboarding-v1":"` + oldKey + `"}`

	keyring, err := newWeChatOnboardingEncryptor(cfg)
	if err != nil {
		t.Fatalf("newWeChatOnboardingEncryptor: %v", err)
	}
	plain, err := keyring.Decrypt(cleanupCiphertext)
	if err != nil || plain != "provider-session-awaiting-revocation" {
		t.Fatalf("retained cleanup decrypt = %q, %v", plain, err)
	}
	currentCiphertext, err := keyring.Encrypt("new-obligation")
	if err != nil || !strings.HasPrefix(currentCiphertext, "wechat-onboarding-v2:") {
		t.Fatalf("current encryption = %q, %v", currentCiphertext, err)
	}
}

func TestWeChatOnboardingEncryptorRejectsMissingMalformedOrReusedKeys(t *testing.T) {
	valid := testConfig()
	valid.WeChatMiniProgram.OnboardingEnabled = true
	valid.WeChatMiniProgram.OnboardingEncryptionKey = bootstrapTestAESKey(0x22)
	valid.WeChatMiniProgram.OnboardingEncryptionKeyID = "wechat-onboarding-v1"
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{
		{name: "missing", mutate: func(cfg *config.Config) { cfg.WeChatMiniProgram.OnboardingEncryptionKey = "" }, wantErr: "required"},
		{name: "malformed", mutate: func(cfg *config.Config) { cfg.WeChatMiniProgram.OnboardingEncryptionKey = "not-base64" }, wantErr: "base64-encoded"},
		{name: "wrong length", mutate: func(cfg *config.Config) {
			cfg.WeChatMiniProgram.OnboardingEncryptionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
		}, wantErr: "32 bytes"},
		{name: "unsafe key id", mutate: func(cfg *config.Config) { cfg.WeChatMiniProgram.OnboardingEncryptionKeyID = "wechat:v1" }, wantErr: "must not contain ':'"},
		{name: "session key reuse", mutate: func(cfg *config.Config) {
			cfg.Session.EncryptionKey = cfg.WeChatMiniProgram.OnboardingEncryptionKey
		}, wantErr: "distinct from the session encryption key"},
		{name: "session key reuse with alternate base64 whitespace", mutate: func(cfg *config.Config) {
			key := cfg.WeChatMiniProgram.OnboardingEncryptionKey
			cfg.Session.EncryptionKey = key[:8] + "\n" + key[8:]
		}, wantErr: "distinct from the session encryption key"},
		{name: "retained malformed", mutate: func(cfg *config.Config) {
			cfg.WeChatMiniProgram.OnboardingRetainedDecryptionKeys = `{`
		}, wantErr: "retained decryption keyring is invalid"},
		{name: "retained session key reuse", mutate: func(cfg *config.Config) {
			cfg.Session.EncryptionKey = bootstrapTestAESKey(0x33)
			cfg.WeChatMiniProgram.OnboardingRetainedDecryptionKeys = `{"wechat-onboarding-v0":"` + cfg.Session.EncryptionKey + `"}`
		}, wantErr: "retained key material must be distinct"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if _, err := newWeChatOnboardingEncryptor(cfg); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}

	disabled := valid
	disabled.WeChatMiniProgram.OnboardingEnabled = false
	disabled.WeChatMiniProgram.OnboardingEncryptionKey = "not-base64"
	if encryptor, err := newWeChatOnboardingEncryptor(disabled); err != nil || encryptor != nil {
		t.Fatalf("disabled onboarding loaded encryption material: encryptor=%T err=%v", encryptor, err)
	}
}

func bootstrapTestAESKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

// TestFakeProviderWithDatabaseServesCurrentUser verifies that when a database
// is configured but the authenticator is the development fake, a successful
// login is followed by a 200 from /api/v1/me instead of 401. This is the
// regression test for the wiring bug found during acceptance testing: the
// database-backed userChecker and userReader rejected fake users whose IDs
// do not exist in PostgreSQL.
//
// It requires the disposable local integration matrix. The run token is the
// explicit opt-in: database and Redis variables alone may be inherited from a
// broader CI job and must not turn this integration-backed check into a unit
// test dependency. Run with:
//
//	UP_TEST_DISPOSABLE_RUN_TOKEN=... UP_TEST_DATABASE_URL=postgres://... \
//	UP_TEST_REDIS_URL=redis://... \
//	go test ./internal/bootstrap/ -run TestFakeProviderWithDatabaseServesCurrentUser
func TestFakeProviderWithDatabaseServesCurrentUser(t *testing.T) {
	runToken := os.Getenv(integrationboundary.RunTokenEnvironment)
	if runToken == "" {
		t.Skip("UP_TEST_DISPOSABLE_RUN_TOKEN required to opt in to this integration-backed test")
	}
	dbURL := os.Getenv("UP_TEST_DATABASE_URL")
	redisURL := os.Getenv("UP_TEST_REDIS_URL")
	if dbURL == "" || redisURL == "" {
		t.Fatal("UP_TEST_DATABASE_URL and UP_TEST_REDIS_URL required after integration opt-in")
	}
	dbSchema := os.Getenv("UP_TEST_DATABASE_SCHEMA")
	redisPrefix := os.Getenv("UP_TEST_REDIS_KEY_PREFIX")
	if err := integrationboundary.ValidatePostgres(dbURL, dbSchema, runToken); err != nil {
		t.Fatalf("PostgreSQL integration boundary rejected: %v", err)
	}
	if err := integrationboundary.ValidateRedis(redisURL, redisPrefix, runToken); err != nil {
		t.Fatalf("Redis integration boundary rejected: %v", err)
	}
	prepareBootstrapTestDatabase(t, dbURL, dbSchema)

	cfg := testConfig()
	cfg.Auth.Provider = "fake"
	cfg.OAuth.PublicOrigin = "http://united-pass.localhost"
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
	cfg.Database.Schema = dbSchema
	cfg.Database.MaxConns = 5
	cfg.Database.MinConns = 1
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Redis.URL = redisURL
	cfg.Redis.KeyPrefix = redisPrefix + "bootstrap:"
	cfg.Redis.PoolSize = 5
	cfg.Redis.ConnectTimeout = 10 * time.Second

	srv := newTestServer(t, cfg)
	t.Cleanup(func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownContext); err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	})

	// 1. Login with the no-MFA dev user.
	loginBody := strings.NewReader(`{"identifier":"zhixing.lin","password":"TestPassword123!"}`)
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", cfg.OAuth.PublicOrigin)
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

type registrationEmailValidatorStub struct {
	err error
}

func (s registrationEmailValidatorStub) Validate(context.Context, string) error {
	return s.err
}

func TestAccountContactEmailValidatorMapsDeliveryPolicyErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "accepted"},
		{name: "definitive invalid address", err: registration.ErrInvalidInput, want: accountcontact.ErrInvalidInput},
		{name: "temporary DNS outage", err: registration.ErrUnavailable, want: accountcontact.ErrUnavailable},
		{name: "unexpected policy failure", err: errors.New("resolver failed"), want: accountcontact.ErrUnavailable},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			validator := &accountContactEmailValidator{inner: registrationEmailValidatorStub{err: test.err}}
			err := validator.Validate(t.Context(), "person@example.com")
			if test.want == nil && err != nil {
				t.Fatalf("Validate error = %v, want nil", err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Validate error = %v, want %v", err, test.want)
			}
		})
	}
}
