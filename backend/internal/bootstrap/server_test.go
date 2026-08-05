package bootstrap

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
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

// TestNewServerRejectsUnimplementedProviderInProduction verifies the
// production safety boundary: a production deployment must not start with an
// unimplemented authentication provider (the development fake would otherwise
// serve as the identity provider).
func TestNewServerRejectsUnimplementedProviderInProduction(t *testing.T) {
	cfg := testConfig()
	cfg.Environment = config.EnvironmentProduction
	cfg.Auth.Provider = "zitadel"
	cfg.Auth.BaseURL = "https://auth.example.com"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewServer(cfg, logger); err == nil {
		t.Fatal("expected error for unimplemented provider in production")
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
