//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the authentication handlers
//

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// --- Test Fakes ---

// fakeSessionStore is an in-memory session.Store for testing.
type fakeSessionStore struct {
	mu       sync.Mutex
	sessions map[string]session.SessionRecord
	// rotateErr / revokeOthersErr inject infrastructure failures into the
	// rotation and bulk-revocation paths (nil = healthy).
	rotateErr       error
	revokeOthersErr error
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{sessions: make(map[string]session.SessionRecord)}
}

func (s *fakeSessionStore) Create(_ context.Context, tokenHash string, record session.SessionRecord, _, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[tokenHash] = record
	return nil
}

func (s *fakeSessionStore) Get(_ context.Context, tokenHash string) (session.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.sessions[tokenHash]
	if !ok {
		return session.SessionRecord{}, session.ErrSessionNotFound
	}
	return r, nil
}

func (s *fakeSessionStore) Delete(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, tokenHash)
	return nil
}

func (s *fakeSessionStore) Touch(_ context.Context, tokenHash string, record session.SessionRecord, _, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[tokenHash]; !ok {
		return session.ErrSessionNotFound
	}
	s.sessions[tokenHash] = record
	return nil
}

func (s *fakeSessionStore) Rotate(_ context.Context, oldHash, newHash string, newRecord session.SessionRecord, _, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotateErr != nil {
		return s.rotateErr
	}
	if _, ok := s.sessions[oldHash]; !ok {
		// Mirrors the frozen Redis semantics: rotating a vanished session
		// must never resurrect it.
		return session.ErrSessionNotFound
	}
	s.sessions[newHash] = newRecord
	delete(s.sessions, oldHash)
	return nil
}

func (s *fakeSessionStore) resolveLocked(userID identity.UserID, sessionID session.SessionID) (string, session.SessionRecord, error) {
	for hash, r := range s.sessions {
		if r.SessionID == sessionID {
			if r.UserID != userID {
				return "", session.SessionRecord{}, session.ErrSessionNotFound
			}
			return hash, r, nil
		}
	}
	return "", session.SessionRecord{}, session.ErrSessionNotFound
}

func (s *fakeSessionStore) GetBySessionID(_ context.Context, userID identity.UserID, sessionID session.SessionID, now time.Time, idleTTL time.Duration) (session.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, record, err := s.resolveLocked(userID, sessionID)
	if err != nil {
		return session.SessionRecord{}, err
	}
	if record.IsExpired(now, idleTTL) {
		return session.SessionRecord{}, session.ErrSessionNotFound
	}
	return record, nil
}

func (s *fakeSessionStore) DeleteBySessionID(_ context.Context, userID identity.UserID, sessionID session.SessionID, now time.Time, idleTTL time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, record, err := s.resolveLocked(userID, sessionID)
	if err != nil {
		return err
	}
	if record.IsExpired(now, idleTTL) {
		delete(s.sessions, hash)
		return session.ErrSessionNotFound
	}
	delete(s.sessions, hash)
	return nil
}

func (s *fakeSessionStore) ListUserSessions(_ context.Context, userID identity.UserID, now time.Time, idleTTL time.Duration) ([]session.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var records []session.SessionRecord
	for _, r := range s.sessions {
		if r.UserID != userID || r.IsExpired(now, idleTTL) {
			continue
		}
		records = append(records, r)
	}
	return records, nil
}

func (s *fakeSessionStore) RevokeAllOtherSessions(_ context.Context, userID identity.UserID, currentSessionID session.SessionID, now time.Time, idleTTL time.Duration) ([]session.SessionRecord, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revokeOthersErr != nil {
		return nil, 0, s.revokeOthersErr
	}
	var victims []session.SessionRecord
	for hash, r := range s.sessions {
		if r.UserID != userID || r.SessionID == currentSessionID {
			continue
		}
		if r.IsExpired(now, idleTTL) {
			delete(s.sessions, hash)
			continue
		}
		delete(s.sessions, hash)
		victims = append(victims, r)
	}
	return victims, len(victims), nil
}

// fakeMFAStore is an in-memory MFAChallengeStore for testing. It models the
// claim lock as a map of tokenHash -> claimID, mirroring the Redis adapter's
// separate claim key semantics.
type fakeMFAStore struct {
	mu         sync.Mutex
	challenges map[string]auth.MFAChallengeData
	attempts   map[string]int
	claims     map[string]string // tokenHash -> claimID
}

func newFakeMFAStore() *fakeMFAStore {
	return &fakeMFAStore{
		challenges: make(map[string]auth.MFAChallengeData),
		attempts:   make(map[string]int),
		claims:     make(map[string]string),
	}
}

func (m *fakeMFAStore) Create(_ context.Context, hash string, data auth.MFAChallengeData, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenges[hash] = data
	return nil
}

func (m *fakeMFAStore) Get(_ context.Context, hash string) (auth.MFAChallengeData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.challenges[hash]
	if !ok {
		return auth.MFAChallengeData{}, auth.ErrMFAChallengeNotFound
	}
	return d, nil
}

func (m *fakeMFAStore) Claim(_ context.Context, hash, claimID string) (auth.MFAChallengeData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.challenges[hash]; !ok {
		return auth.MFAChallengeData{}, auth.ErrMFAChallengeNotFound
	}
	if owner, ok := m.claims[hash]; ok && owner != claimID {
		return auth.MFAChallengeData{}, auth.ErrMFAChallengeClaimed
	}
	m.claims[hash] = claimID
	return m.challenges[hash], nil
}

func (m *fakeMFAStore) Consume(_ context.Context, hash, claimID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if owner, ok := m.claims[hash]; !ok || owner != claimID {
		return auth.ErrMFAChallengeNotHeld
	}
	if _, ok := m.challenges[hash]; !ok {
		return auth.ErrMFAChallengeNotFound
	}
	delete(m.challenges, hash)
	delete(m.attempts, hash)
	delete(m.claims, hash)
	return nil
}

func (m *fakeMFAStore) Release(_ context.Context, hash, claimID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if owner, ok := m.claims[hash]; !ok || owner != claimID {
		return auth.ErrMFAChallengeNotHeld
	}
	delete(m.claims, hash)
	return nil
}

func (m *fakeMFAStore) IncrementAttempts(_ context.Context, hash string, maxAttempts int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts[hash]++
	count := m.attempts[hash]
	if count > maxAttempts {
		return count, auth.ErrMFAMaxAttemptsExceeded
	}
	return count, nil
}

// fakeRateChecker is a RateChecker that always allows.
type fakeRateChecker struct{}

func (fakeRateChecker) CheckLogin(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	return true, 0, nil
}
func (fakeRateChecker) CheckMFA(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	return true, 0, nil
}

// fakeUserReader is an in-memory UserReader for testing.
type fakeUserReader struct {
	users map[identity.UserID]identity.User
}

func (r *fakeUserReader) GetByID(_ context.Context, userID identity.UserID) (identity.User, error) {
	u, ok := r.users[userID]
	if !ok {
		return identity.User{}, identity.ErrUserNotFound
	}
	return u, nil
}

// fakeUserChecker is a UserStatusChecker for testing.
type fakeUserChecker struct {
	users map[identity.UserID]identity.UserStatus
}

func (c *fakeUserChecker) CanUseSession(_ context.Context, userID identity.UserID) error {
	status, ok := c.users[userID]
	if !ok {
		return identity.ErrUserNotFound
	}
	if !status.CanAuthenticate() {
		return identity.ErrUserNotFound
	}
	return nil
}

// --- Test Helpers ---

func TestGenerateClaimID(t *testing.T) {
	first, err := generateClaimID()
	if err != nil {
		t.Fatalf("generateClaimID: %v", err)
	}
	if len(first) != 32 { // 16 random bytes hex-encoded
		t.Errorf("claimID length = %d, want 32", len(first))
	}
	second, err := generateClaimID()
	if err != nil {
		t.Fatalf("generateClaimID second: %v", err)
	}
	if first == second {
		t.Error("two generated claim IDs are identical; expected uniqueness")
	}
}

func testSessionConfig() config.Config {
	return config.Config{
		Environment:         config.EnvironmentDevelopment,
		HTTPAddr:            ":0",
		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         15 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         60 * time.Second,
		ShutdownTimeout:     30 * time.Second,
		MaxRequestBodyBytes: 1 << 20,
		LogLevel:            "debug",
		Session: config.SessionConfig{
			TTL:            12 * time.Hour,
			RememberTTL:    720 * time.Hour,
			IdleTTL:        2 * time.Hour,
			TouchInterval:  5 * time.Minute,
			CookieSecure:   false,
			CookieSameSite: "lax",
		},
		MFA: config.MFAConfig{
			ChallengeTTL: 5 * time.Minute,
			MaxAttempts:  5,
		},
		RateLimit: config.RateLimitConfig{
			LoginLimit:  10,
			LoginWindow: 15 * time.Minute,
			MFALimit:    10,
			MFAWindow:   15 * time.Minute,
		},
	}
}

func testUser() identity.User {
	return identity.User{
		ID:          identity.UserID("user_01TEST001"),
		Status:      identity.UserStatusActive,
		DisplayName: "测试用户",
		Nickname:    "测试",
		Email:       "test@example.com",
		Phone:       "13812345678",
		Personas:    []identity.Persona{identity.PersonaConsumer},
	}
}

func setupAuthHandlers(t *testing.T) (*AuthHandlers, *auth.FakeAuthenticator, *fakeSessionStore, *fakeMFAStore, config.Config) {
	t.Helper()
	cfg := testSessionConfig()
	fakeAuth := auth.NewFakeAuthenticator()
	fakeAuth.AddUser(auth.FakeUser{
		UserID:     identity.UserID("user_01TEST001"),
		Identifier: "testuser",
		Password:   "TestPassword123!",
		UserStatus: identity.UserStatusActive,
		Provider:   "fake",
		SessionRef: "fake-ref-001",
	})
	fakeAuth.AddUser(auth.FakeUser{
		UserID:      identity.UserID("user_01TEST002"),
		Identifier:  "mfauser",
		Password:    "TestPassword123!",
		UserStatus:  identity.UserStatusActive,
		Provider:    "fake",
		SessionRef:  "fake-ref-002",
		RequiresMFA: true,
		MFAMethods:  []auth.MFAMethod{auth.MFAMethodTOTP},
		MFACode:     "123456",
	})

	store := newFakeSessionStore()
	sessionSvc := session.NewService(store, session.SystemClock{},
		cfg.Session.TTL, cfg.Session.RememberTTL,
		cfg.Session.IdleTTL, cfg.Session.TouchInterval,
		testEncryptor())

	mfaStore := newFakeMFAStore()
	rateChecker := fakeRateChecker{}
	userChecker := &fakeUserChecker{
		users: map[identity.UserID]identity.UserStatus{
			"user_01TEST001": identity.UserStatusActive,
			"user_01TEST002": identity.UserStatusActive,
		},
	}

	h := NewAuthHandlers(fakeAuth, sessionSvc, mfaStore, rateChecker, userChecker, cfg, testLogger())
	return h, fakeAuth, store, mfaStore, cfg
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&strings.Builder{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testEncryptor returns an AES-GCM encryptor with a fixed 32-byte key for
// tests. Provider session references must be encrypted at rest, so session
// services in tests always receive an encryptor.
func testEncryptor() session.Encryptor {
	enc, err := session.NewAESGCMEncryptor("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "test-v1")
	if err != nil {
		panic(err)
	}
	return enc
}

func doRequest(handler http.Handler, method, path string, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	var req *http.Request
	if bodyReader != nil {
		req = httptest.NewRequest(method, path, bodyReader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func extractCookies(rr *httptest.ResponseRecorder) (sessionToken, csrfToken string) {
	for _, c := range rr.Result().Cookies() {
		switch c.Name {
		case SessionCookieName:
			sessionToken = c.Value
		case CSRFCookieName:
			csrfToken = c.Value
		}
	}
	return
}

// --- Login Tests ---

func TestLoginSuccess(t *testing.T) {
	h, _, store, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)

	body := `{"identifier":"testuser","password":"TestPassword123!"}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	sessionToken, csrfToken := extractCookies(rr)
	if sessionToken == "" {
		t.Error("up_session cookie not set")
	}
	if csrfToken == "" {
		t.Error("up_csrf cookie not set")
	}

	// Verify session was stored.
	hash := session.HashToken(sessionToken)
	record, err := store.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("session not found in store: %v", err)
	}
	if record.UserID != identity.UserID("user_01TEST001") {
		t.Errorf("session UserID: got %q, want user_01TEST001", record.UserID)
	}
	if record.CSRFTokenHash != session.HashToken(csrfToken) {
		t.Error("CSRF token hash mismatch")
	}
}

func TestLoginPersistsPeerIPNotForwardedHeader(t *testing.T) {
	h, _, store, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)

	body := `{"identifier":"testuser","password":"TestPassword123!"}`
	req := httptest.NewRequest("POST", "/api/v1/auth/sessions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Untrusted proxy header: it must never reach persisted session
	// metadata (P4.0 freeze: no new proxy-header trust).
	req.Header.Set("X-Forwarded-For", "203.0.113.66")
	req.RemoteAddr = "198.51.100.9:43210"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	sessionToken, _ := extractCookies(rr)
	record, err := store.Get(context.Background(), session.HashToken(sessionToken))
	if err != nil {
		t.Fatalf("session not found in store: %v", err)
	}
	if record.IPAddressMasked != "198.51.100.*" {
		t.Errorf("persisted IPAddressMasked = %q, want the transport peer 198.51.100.*", record.IPAddressMasked)
	}
}

func TestPeerIPIgnoresProxyHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.7:55123"
	req.Header.Set("X-Forwarded-For", "203.0.113.66, 10.0.0.1")
	if got := peerIP(req); got != "192.0.2.7" {
		t.Errorf("peerIP = %q, want 192.0.2.7", got)
	}
	// Addresses without a host:port shape pass through unchanged.
	req.RemoteAddr = "/tmp/unix.sock"
	if got := peerIP(req); got != "/tmp/unix.sock" {
		t.Errorf("peerIP unix addr = %q, want /tmp/unix.sock", got)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	h, _, _, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)

	body := `{"identifier":"testuser","password":"wrongpassword"}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.Error.Code != CodeUnauthorized {
		t.Errorf("error code: got %q, want %q", resp.Error.Code, CodeUnauthorized)
	}
}

func TestLoginMFARequired(t *testing.T) {
	h, _, _, mfaStore, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)

	body := `{"identifier":"mfauser","password":"TestPassword123!"}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusAccepted, rr.Body.String())
	}

	var resp mfaRequiredResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "mfa_required" {
		t.Errorf("status: got %q, want mfa_required", resp.Status)
	}
	if resp.MFAToken == "" {
		t.Error("mfaToken is empty")
	}
	if len(resp.AvailableMethods) == 0 {
		t.Error("availableMethods is empty")
	}

	// Verify challenge was stored.
	hash := session.HashToken(resp.MFAToken)
	challenge, err := mfaStore.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("MFA challenge not stored: %v", err)
	}

	// SECURITY: the browser-visible mfaToken must be a fresh opaque token and
	// must never leak the provider session handle (the fake's SessionRef is
	// "fake-session-ref-002"). The provider session ID is stored server-side
	// only.
	if strings.Contains(resp.MFAToken, challenge.ProviderSessionID) {
		t.Error("mfaToken must not contain the provider session ID")
	}
	if challenge.ProviderSessionID == "" {
		t.Error("challenge must store the provider session ID server-side")
	}
	if len(resp.MFAToken) < 32 {
		t.Errorf("mfaToken too short (%d chars); want a random opaque token", len(resp.MFAToken))
	}
}

func TestLoginMissingFields(t *testing.T) {
	h, _, _, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)

	body := `{"identifier":"testuser"}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestLoginMalformedJSON(t *testing.T) {
	h, _, _, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)

	body := `{not valid json`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestLoginUnknownField(t *testing.T) {
	h, _, _, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)

	body := `{"identifier":"testuser","password":"TestPassword123!","extraField":"bad"}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestLoginMultipleJSONObjects(t *testing.T) {
	h, _, _, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)

	body := `{"identifier":"testuser","password":"TestPassword123!"}{"extra":"object"}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// --- MFA Tests ---

func TestMFASuccess(t *testing.T) {
	h, _, store, mfaStore, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	// Step 1: Login to get MFA token.
	body := `{"identifier":"mfauser","password":"TestPassword123!"}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("login status: got %d, want %d", rr.Code, http.StatusAccepted)
	}

	var mfaResp mfaRequiredResponse
	json.Unmarshal(rr.Body.Bytes(), &mfaResp)

	// Step 2: Complete MFA.
	mfaBody := fmt.Sprintf(`{"mfaToken":"%s","method":"totp","code":"123456"}`, mfaResp.MFAToken)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", mfaBody)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("MFA status: got %d, want %d. Body: %s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	sessionToken, csrfToken := extractCookies(rr)
	if sessionToken == "" {
		t.Error("up_session cookie not set after MFA")
	}
	if csrfToken == "" {
		t.Error("up_csrf cookie not set after MFA")
	}

	// Verify session was created.
	hash := session.HashToken(sessionToken)
	record, err := store.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("session not found: %v", err)
	}
	if record.UserID != identity.UserID("user_01TEST002") {
		t.Errorf("session UserID: got %q, want user_01TEST002", record.UserID)
	}

	// The MFA challenge must be consumed after success: replaying the same
	// MFA token must not be possible.
	mfaTokenHash := session.HashToken(mfaResp.MFAToken)
	if _, err := mfaStore.Get(context.Background(), mfaTokenHash); !errors.Is(err, auth.ErrMFAChallengeNotFound) {
		t.Errorf("MFA challenge should be consumed after success, got err: %v", err)
	}
}

// TestMFACompletionHonorsRemember locks the ADR-0006 §1 remember repair: the
// remember choice made at login time travels with the MFA challenge and must
// reach the final session (TTL and flag), never silently downgraded.
func TestMFACompletionHonorsRemember(t *testing.T) {
	h, _, store, mfaStore, cfg := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	body := `{"identifier":"mfauser","password":"TestPassword123!","remember":true}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("login status: got %d, want %d", rr.Code, http.StatusAccepted)
	}

	var mfaResp mfaRequiredResponse
	json.Unmarshal(rr.Body.Bytes(), &mfaResp)

	// The challenge itself carries the remember choice across the MFA step.
	challenge, err := mfaStore.Get(context.Background(), session.HashToken(mfaResp.MFAToken))
	if err != nil {
		t.Fatalf("challenge not stored: %v", err)
	}
	if !challenge.Remember {
		t.Fatal("MFA challenge must carry remember=true from login")
	}

	mfaBody := fmt.Sprintf(`{"mfaToken":"%s","method":"totp","code":"123456"}`, mfaResp.MFAToken)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", mfaBody)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("MFA status: got %d, want %d. Body: %s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	sessionToken, _ := extractCookies(rr)
	record, err := store.Get(context.Background(), session.HashToken(sessionToken))
	if err != nil {
		t.Fatalf("session not found: %v", err)
	}
	if !record.Remember {
		t.Error("session created after MFA must keep remember=true")
	}
	// The expiry follows the remember TTL, not the short default.
	wantTTL := cfg.Session.RememberTTL
	gotTTL := time.Until(record.ExpiresAt)
	if gotTTL < wantTTL-time.Minute {
		t.Errorf("session TTL %v must follow remember TTL %v", gotTTL, wantTTL)
	}
}

// TestMFACompletionDefaultShortTTL is the negative half of the remember
// repair: without remember the MFA-completed session keeps the short TTL.
func TestMFACompletionDefaultShortTTL(t *testing.T) {
	h, _, store, _, cfg := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	body := `{"identifier":"mfauser","password":"TestPassword123!"}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", body)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("login status: got %d, want %d", rr.Code, http.StatusAccepted)
	}

	var mfaResp mfaRequiredResponse
	json.Unmarshal(rr.Body.Bytes(), &mfaResp)

	mfaBody := fmt.Sprintf(`{"mfaToken":"%s","method":"totp","code":"123456"}`, mfaResp.MFAToken)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", mfaBody)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("MFA status: got %d, want %d", rr.Code, http.StatusNoContent)
	}

	sessionToken, _ := extractCookies(rr)
	record, err := store.Get(context.Background(), session.HashToken(sessionToken))
	if err != nil {
		t.Fatalf("session not found: %v", err)
	}
	if record.Remember {
		t.Error("session must not be remembered without remember=true")
	}
	gotTTL := time.Until(record.ExpiresAt)
	if gotTTL > cfg.Session.TTL+time.Minute {
		t.Errorf("session TTL %v must follow the short TTL %v without remember", gotTTL, cfg.Session.TTL)
	}
}

func TestMFAWrongCode(t *testing.T) {
	h, _, _, mfaStore, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	// Login to get MFA token.
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", `{"identifier":"mfauser","password":"TestPassword123!"}`)
	var mfaResp mfaRequiredResponse
	json.Unmarshal(rr.Body.Bytes(), &mfaResp)

	// Submit wrong code.
	mfaBody := fmt.Sprintf(`{"mfaToken":"%s","method":"totp","code":"000000"}`, mfaResp.MFAToken)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", mfaBody)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}

	// A failed verification releases the claim: the challenge must still
	// exist so the user can retry.
	mfaTokenHash := session.HashToken(mfaResp.MFAToken)
	if _, err := mfaStore.Get(context.Background(), mfaTokenHash); err != nil {
		t.Fatalf("challenge should still exist after wrong code: %v", err)
	}
}

func TestMFARequiresCodeForTOTP(t *testing.T) {
	h, _, _, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", `{"identifier":"mfauser","password":"TestPassword123!"}`)
	var mfaResp mfaRequiredResponse
	json.Unmarshal(rr.Body.Bytes(), &mfaResp)

	// totp without code must be rejected before any provider call.
	mfaBody := fmt.Sprintf(`{"mfaToken":"%s","method":"totp"}`, mfaResp.MFAToken)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", mfaBody)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestMFARecoveryCodeUnsupported(t *testing.T) {
	h, _, _, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", `{"identifier":"mfauser","password":"TestPassword123!"}`)
	var mfaResp mfaRequiredResponse
	json.Unmarshal(rr.Body.Bytes(), &mfaResp)

	// recovery_code is not implemented: a generic 401 without provider call.
	mfaBody := fmt.Sprintf(`{"mfaToken":"%s","method":"recovery_code","code":"abc"}`, mfaResp.MFAToken)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", mfaBody)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
}

// setupPasskeyHandlers builds a handler set whose MFA user also supports
// passkey, to exercise the full WebAuthn HTTP contract.
func setupPasskeyHandlers(t *testing.T) *AuthHandlers {
	t.Helper()
	cfg := testSessionConfig()
	fakeAuth := auth.NewFakeAuthenticator()
	fakeAuth.AddUser(auth.FakeUser{
		UserID:      identity.UserID("user_pk_001"),
		Identifier:  "pkuser",
		Password:    "TestPassword123!",
		UserStatus:  identity.UserStatusActive,
		Provider:    "fake",
		SessionRef:  "fake-ref-pk",
		RequiresMFA: true,
		MFAMethods:  []auth.MFAMethod{auth.MFAMethodTOTP, auth.MFAMethodPasskey},
		MFACode:     "123456",
	})

	store := newFakeSessionStore()
	sessionSvc := session.NewService(store, session.SystemClock{},
		cfg.Session.TTL, cfg.Session.RememberTTL,
		cfg.Session.IdleTTL, cfg.Session.TouchInterval,
		testEncryptor())
	mfaStore := newFakeMFAStore()

	return NewAuthHandlers(fakeAuth, sessionSvc, mfaStore, fakeRateChecker{},
		&fakeUserChecker{users: map[identity.UserID]identity.UserStatus{"user_pk_001": identity.UserStatusActive}},
		cfg, nil)
}

func TestMFAPasskeyAssertionWiredThrough(t *testing.T) {
	h := setupPasskeyHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	// Step 1: login requires MFA (passkey among the methods).
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", `{"identifier":"pkuser","password":"TestPassword123!"}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("login status: got %d, want %d", rr.Code, http.StatusAccepted)
	}
	var mfaResp mfaRequiredResponse
	json.Unmarshal(rr.Body.Bytes(), &mfaResp)
	if len(mfaResp.AvailableMethods) != 2 {
		t.Fatalf("availableMethods = %v, want [totp passkey]", mfaResp.AvailableMethods)
	}

	// Step 2: passkey without an assertion is rejected as a bad request.
	badBody := fmt.Sprintf(`{"mfaToken":"%s","method":"passkey"}`, mfaResp.MFAToken)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", badBody)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status without assertion: got %d, want %d", rr.Code, http.StatusBadRequest)
	}

	// Step 3: passkey with an assertion completes authentication. The fake
	// always succeeds once the assertion reaches the adapter.
	assertion := `{"id":"assertion-1","response":{"authenticatorData":"abc"}}`
	pkBody := fmt.Sprintf(`{"mfaToken":"%s","method":"passkey","passkeyAssertion":%s}`, mfaResp.MFAToken, assertion)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", pkBody)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	sessionToken, _ := extractCookies(rr)
	if sessionToken == "" {
		t.Error("up_session cookie not set after passkey MFA")
	}
}

func TestMFAChallengeAlreadyClaimed(t *testing.T) {
	h, _, _, mfaStore, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	// Login to get MFA token.
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", `{"identifier":"mfauser","password":"TestPassword123!"}`)
	var mfaResp mfaRequiredResponse
	json.Unmarshal(rr.Body.Bytes(), &mfaResp)

	// Simulate a concurrent verification already holding the claim lock.
	mfaTokenHash := session.HashToken(mfaResp.MFAToken)
	if _, err := mfaStore.Claim(context.Background(), mfaTokenHash, "concurrent-claim-id"); err != nil {
		t.Fatalf("pre-claim: %v", err)
	}

	// The HTTP request must be rejected (429) because the claim is already
	// held by another request.
	mfaBody := fmt.Sprintf(`{"mfaToken":"%s","method":"totp","code":"123456"}`, mfaResp.MFAToken)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", mfaBody)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusTooManyRequests, rr.Body.String())
	}
}

// consumeFailingMFAStore wraps a fakeMFAStore and makes Consume always fail,
// simulating a Redis error or an expired challenge during verification.
type consumeFailingMFAStore struct {
	*fakeMFAStore
}

func (m *consumeFailingMFAStore) Consume(_ context.Context, hash, claimID string) error {
	return errors.New("redis: simulated consume failure")
}

// TestMFAConsumeFailCloses verifies that when consuming the challenge fails
// after successful provider verification, no session is created (fail
// closed).
func TestMFAConsumeFailCloses(t *testing.T) {
	h, _, _, mfaStore, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	// Login to get MFA token.
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", `{"identifier":"mfauser","password":"TestPassword123!"}`)
	var mfaResp mfaRequiredResponse
	json.Unmarshal(rr.Body.Bytes(), &mfaResp)

	// Swap the store so Consume fails even though verification succeeds.
	h.mfaStore = &consumeFailingMFAStore{fakeMFAStore: mfaStore}

	mfaBody := fmt.Sprintf(`{"mfaToken":"%s","method":"totp","code":"123456"}`, mfaResp.MFAToken)
	rr = doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", mfaBody)

	// No session may be created: consumption failure must fail closed.
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
	if _, csrf := extractCookies(rr); csrf != "" {
		t.Error("no session should be created when consumption fails")
	}
}

func TestMFAExpiredChallenge(t *testing.T) {
	h, _, _, mfaStore, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions/mfa", h.CompleteMFA)

	// Submit MFA with a non-existent token.
	mfaBody := `{"mfaToken":"nonexistent-token","method":"totp","code":"123456"}`
	rr := doRequest(mux, "POST", "/api/v1/auth/sessions/mfa", mfaBody)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	// Verify the store is empty (no challenges).
	if len(mfaStore.challenges) != 0 {
		t.Error("expected empty MFA store")
	}
}

// --- Logout Tests ---

func TestLogoutSuccess(t *testing.T) {
	h, _, store, _, cfg := setupAuthHandlers(t)
	mux := http.NewServeMux()

	// Build a session first.
	sessionSvc := session.NewService(store, session.SystemClock{},
		cfg.Session.TTL, cfg.Session.RememberTTL,
		cfg.Session.IdleTTL, cfg.Session.TouchInterval,
		testEncryptor())

	result, err := sessionSvc.CreateSession(context.Background(), session.CreateSessionInput{
		UserID:                identity.UserID("user_01TEST001"),
		Provider:              "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{},
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Wire logout with session middleware.
	cookieAttrs := CookieAttributesFromConfig(cfg.Session)

	mux.HandleFunc("DELETE /api/v1/auth/session", func(w http.ResponseWriter, r *http.Request) {
		// Simulate session middleware.
		principal, record, err := sessionSvc.ValidateSession(r.Context(), result.SessionToken)
		if err != nil {
			WriteUnauthorized(w, r)
			return
		}
		ctx := WithPrincipal(r.Context(), principal)
		ctx = WithSessionRecord(ctx, record)
		h.Logout(w, r.WithContext(ctx))
	})

	sessionCookie := &http.Cookie{Name: SessionCookieName, Value: result.SessionToken}
	csrfCookie := &http.Cookie{Name: CSRFCookieName, Value: result.CSRFToken}

	req := httptest.NewRequest("DELETE", "/api/v1/auth/session", nil)
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set(CSRFHeaderName, result.CSRFToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusNoContent)
	}

	// Verify session was deleted.
	_, err = store.Get(context.Background(), result.TokenHash)
	if err != session.ErrSessionNotFound {
		t.Errorf("expected session deleted, got err: %v", err)
	}

	// Verify cookies were cleared.
	for _, c := range rr.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge != -1 {
			t.Error("session cookie not cleared")
		}
		if c.Name == CSRFCookieName && c.MaxAge != -1 {
			t.Error("CSRF cookie not cleared")
		}
	}
	_ = cookieAttrs
}

func TestLogoutWithoutCSRF(t *testing.T) {
	h, _, store, _, cfg := setupAuthHandlers(t)

	sessionSvc := session.NewService(store, session.SystemClock{},
		cfg.Session.TTL, cfg.Session.RememberTTL,
		cfg.Session.IdleTTL, cfg.Session.TouchInterval,
		testEncryptor())

	result, _ := sessionSvc.CreateSession(context.Background(), session.CreateSessionInput{
		UserID: identity.UserID("user_01TEST001"),
	})

	// CSRF middleware should reject.
	csrfMiddleware := RequireCSRF()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Logout(w, r)
	}))

	sessionCookie := &http.Cookie{Name: SessionCookieName, Value: result.SessionToken}
	// No CSRF cookie or header.

	req := httptest.NewRequest("DELETE", "/api/v1/auth/session", nil)
	req.AddCookie(sessionCookie)
	// Add session record to context.
	principal, record, _ := sessionSvc.ValidateSession(context.Background(), result.SessionToken)
	ctx := WithPrincipal(context.Background(), principal)
	ctx = WithSessionRecord(ctx, record)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	csrfMiddleware.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestLogoutCSRFMismatch(t *testing.T) {
	h, _, store, _, cfg := setupAuthHandlers(t)

	sessionSvc := session.NewService(store, session.SystemClock{},
		cfg.Session.TTL, cfg.Session.RememberTTL,
		cfg.Session.IdleTTL, cfg.Session.TouchInterval,
		testEncryptor())

	result, _ := sessionSvc.CreateSession(context.Background(), session.CreateSessionInput{
		UserID: identity.UserID("user_01TEST001"),
	})

	csrfMiddleware := RequireCSRF()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Logout(w, r)
	}))

	sessionCookie := &http.Cookie{Name: SessionCookieName, Value: result.SessionToken}
	csrfCookie := &http.Cookie{Name: CSRFCookieName, Value: "wrong-csrf-value"}

	req := httptest.NewRequest("DELETE", "/api/v1/auth/session", nil)
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set(CSRFHeaderName, "different-header-value")

	principal, record, _ := sessionSvc.ValidateSession(context.Background(), result.SessionToken)
	ctx := WithPrincipal(context.Background(), principal)
	ctx = WithSessionRecord(ctx, record)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	csrfMiddleware.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// --- Current User Tests ---

func TestGetCurrentUserSuccess(t *testing.T) {
	user := testUser()

	userReader := &fakeUserReader{
		users: map[identity.UserID]identity.User{user.ID: user},
	}
	permResolver := permissions.NewDefaultResolver()
	h := NewAccountHandlers(userReader, permResolver)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		ctx := WithPrincipal(r.Context(), session.Principal{UserID: user.ID})
		h.GetCurrentUser(w, r.WithContext(ctx))
	})

	rr := doRequest(mux, "GET", "/api/v1/me", "")

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp currentUserResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.UserID != string(user.ID) {
		t.Errorf("userId: got %q, want %q", resp.UserID, user.ID)
	}
	if resp.Email != user.Email {
		t.Errorf("email: got %q, want %q", resp.Email, user.Email)
	}
	if resp.PhoneMasked == user.Phone {
		t.Error("phone should be masked, not raw")
	}
	if len(resp.Personas) != 1 || resp.Personas[0] != "consumer" {
		t.Errorf("personas: got %v, want [consumer]", resp.Personas)
	}
	if resp.EmployeeProfile != nil {
		t.Error("employeeProfile should be null in Phase 1")
	}

	// Verify Cache-Control header.
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control: got %q, want no-store", rr.Header().Get("Cache-Control"))
	}
}

func TestGetCurrentUserWithoutSession(t *testing.T) {
	userReader := &fakeUserReader{users: make(map[identity.UserID]identity.User)}
	permResolver := permissions.NewDefaultResolver()
	h := NewAccountHandlers(userReader, permResolver)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me", h.GetCurrentUser)

	rr := doRequest(mux, "GET", "/api/v1/me", "")

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestGetPermissionsSuccess(t *testing.T) {
	userID := identity.UserID("user_01TEST001")
	userReader := &fakeUserReader{
		users: map[identity.UserID]identity.User{userID: testUser()},
	}
	permResolver := permissions.NewDefaultResolver()
	h := NewAccountHandlers(userReader, permResolver)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me/permissions", func(w http.ResponseWriter, r *http.Request) {
		ctx := WithPrincipal(r.Context(), session.Principal{UserID: userID})
		h.GetPermissions(w, r.WithContext(ctx))
	})

	rr := doRequest(mux, "GET", "/api/v1/me/permissions", "")

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var caps permissions.Capabilities
	if err := json.Unmarshal(rr.Body.Bytes(), &caps); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Default resolver is fail-closed: all capabilities should be false.
	if caps.UserRead {
		t.Error("userRead should be false (fail-closed)")
	}
	if caps.ProviderManage {
		t.Error("providerManage should be false (fail-closed)")
	}

	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control: got %q, want no-store", rr.Header().Get("Cache-Control"))
	}
}

func TestGetPermissionsWithoutSession(t *testing.T) {
	userReader := &fakeUserReader{users: make(map[identity.UserID]identity.User)}
	permResolver := permissions.NewDefaultResolver()
	h := NewAccountHandlers(userReader, permResolver)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me/permissions", h.GetPermissions)

	rr := doRequest(mux, "GET", "/api/v1/me/permissions", "")

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// --- Cookie Attribute Tests ---

func TestSessionCookieAttributes(t *testing.T) {
	cfg := testSessionConfig()
	cfg.Session.CookieSecure = true
	cfg.Session.CookieSameSite = "strict"
	attrs := CookieAttributesFromConfig(cfg.Session)

	if !attrs.Secure {
		t.Error("Secure should be true")
	}
	if attrs.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite: got %v, want %v", attrs.SameSite, http.SameSiteStrictMode)
	}
}

func TestCookieClearing(t *testing.T) {
	cfg := testSessionConfig()
	attrs := CookieAttributesFromConfig(cfg.Session)

	rr := httptest.NewRecorder()
	ClearSessionCookie(rr, attrs)
	ClearCSRFCookie(rr, attrs)

	sessionCleared := false
	csrfCleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge == -1 {
			sessionCleared = true
		}
		if c.Name == CSRFCookieName && c.MaxAge == -1 {
			csrfCleared = true
		}
	}
	if !sessionCleared {
		t.Error("session cookie was not cleared")
	}
	if !csrfCleared {
		t.Error("CSRF cookie was not cleared")
	}
}

// --- Error Envelope Test ---

func TestErrorEnvelopeFormat(t *testing.T) {
	h, _, _, _, _ := setupAuthHandlers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/sessions", h.Login)

	rr := doRequest(mux, "POST", "/api/v1/auth/sessions", `{"identifier":"testuser","password":"wrong"}`)

	var resp ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error.Code == "" {
		t.Error("error code is empty")
	}
	if resp.Error.Message == "" {
		t.Error("error message is empty")
	}
}

// --- Permission Resolver Tests ---

func TestPermissionResolverFailClosed(t *testing.T) {
	r := permissions.NewDefaultResolver()
	caps, err := r.Resolve(context.Background(), "any-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if caps != permissions.NoCapabilities() {
		t.Error("default resolver should return no capabilities")
	}
}

func TestPermissionDevOverride(t *testing.T) {
	base := permissions.NewDefaultResolver()
	r := permissions.NewDevOverrideResolver(base, config.PermissionConfig{
		DevOverrideEnabled: true,
		DevOverrideUserID:  "user_admin",
	})

	// Override user gets all capabilities.
	caps, _ := r.Resolve(context.Background(), identity.UserID("user_admin"))
	if caps != permissions.AllCapabilities() {
		t.Error("dev override user should get all capabilities")
	}

	// Non-override user gets no capabilities.
	caps, _ = r.Resolve(context.Background(), identity.UserID("user_regular"))
	if caps != permissions.NoCapabilities() {
		t.Error("non-override user should get no capabilities")
	}
}
