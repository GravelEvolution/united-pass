package httpapi

import (
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

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// --- Test fakes ---

type fakeReauthAuth struct {
	verifyResult auth.AuthenticationResult
	verifyErr    error
	mfaResult    auth.AuthenticationResult
	mfaErr       error
	verifyCalls  int
	revokeErr    error
	revoked      []string
}

func (f *fakeReauthAuth) VerifyUserPassword(_ context.Context, _ identity.UserID, _ string) (auth.AuthenticationResult, error) {
	f.verifyCalls++
	return f.verifyResult, f.verifyErr
}

func (f *fakeReauthAuth) CompleteMFA(_ context.Context, _ auth.MFAChallengeInput) (auth.AuthenticationResult, error) {
	return f.mfaResult, f.mfaErr
}

func (f *fakeReauthAuth) RevokeProviderSession(_ context.Context, sessionReference string) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revoked = append(f.revoked, sessionReference)
	return nil
}

// memReauthChallenges is an in-memory ReauthChallengeStore mirroring the
// Redis claim/consume semantics.
type memReauthChallenges struct {
	mu        sync.Mutex
	data      map[string]auth.ReauthChallengeData
	attempts  map[string]int
	claimed   map[string]string
	createErr error
}

func newMemReauthChallenges() *memReauthChallenges {
	return &memReauthChallenges{
		data:     make(map[string]auth.ReauthChallengeData),
		attempts: make(map[string]int),
		claimed:  make(map[string]string),
	}
}

func (m *memReauthChallenges) CreateChallenge(_ context.Context, tokenHash string, data auth.ReauthChallengeData, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	m.data[tokenHash] = data
	return nil
}

func (m *memReauthChallenges) ClaimChallenge(_ context.Context, tokenHash, claimID string) (auth.ReauthChallengeData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.claimed[tokenHash] != "" {
		return auth.ReauthChallengeData{}, auth.ErrReauthChallengeClaimed
	}
	data, ok := m.data[tokenHash]
	if !ok {
		return auth.ReauthChallengeData{}, auth.ErrReauthChallengeNotFound
	}
	m.claimed[tokenHash] = claimID
	return data, nil
}

func (m *memReauthChallenges) ReleaseChallenge(_ context.Context, tokenHash, claimID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.claimed[tokenHash] != claimID {
		return auth.ErrReauthChallengeNotHeld
	}
	delete(m.claimed, tokenHash)
	return nil
}

func (m *memReauthChallenges) ConsumeChallenge(_ context.Context, tokenHash, claimID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.claimed[tokenHash] != claimID {
		return auth.ErrReauthChallengeNotHeld
	}
	if _, ok := m.data[tokenHash]; !ok {
		return auth.ErrReauthChallengeNotFound
	}
	delete(m.data, tokenHash)
	delete(m.attempts, tokenHash)
	delete(m.claimed, tokenHash)
	return nil
}

func (m *memReauthChallenges) IncrementChallengeAttempts(_ context.Context, tokenHash string, maxAttempts int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[tokenHash]; !ok {
		return 0, auth.ErrReauthChallengeNotFound
	}
	m.attempts[tokenHash]++
	if m.attempts[tokenHash] > maxAttempts {
		return m.attempts[tokenHash], auth.ErrReauthMaxAttemptsExceeded
	}
	return m.attempts[tokenHash], nil
}

// memReauthGrants is an in-memory ReauthGrantStore with atomic single-use
// consumption.
type memReauthGrants struct {
	mu        sync.Mutex
	data      map[string]auth.ReauthGrantData
	createErr error
}

func newMemReauthGrants() *memReauthGrants {
	return &memReauthGrants{data: make(map[string]auth.ReauthGrantData)}
}

func (m *memReauthGrants) CreateGrant(_ context.Context, tokenHash string, data auth.ReauthGrantData, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	m.data[tokenHash] = data
	return nil
}

func (m *memReauthGrants) ConsumeGrant(_ context.Context, tokenHash string) (auth.ReauthGrantData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.data[tokenHash]
	if !ok {
		return auth.ReauthGrantData{}, auth.ErrReauthGrantNotFound
	}
	delete(m.data, tokenHash)
	return data, nil
}

type fakeReauthRate struct {
	allow bool
	err   error
}

func (f *fakeReauthRate) CheckReauth(_ context.Context, _, _ string, _ int, _ time.Duration) (bool, time.Duration, error) {
	return f.allow, 30 * time.Second, f.err
}

type capturedReauthEvent struct {
	eventType    string
	result       applications.SecurityEventResult
	failureClass string
	action       string
}

type fakeReauthAuditor struct {
	mu     sync.Mutex
	events []capturedReauthEvent
}

func (f *fakeReauthAuditor) RecordEvent(_ context.Context, eventType string, _ identity.UserID, _ applications.ApplicationID, _ applications.OAuthClientID, _, operation string, result applications.SecurityEventResult, failureClass string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, capturedReauthEvent{eventType: eventType, result: result, failureClass: failureClass, action: operation})
}

func (f *fakeReauthAuditor) has(eventType string, result applications.SecurityEventResult) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ev := range f.events {
		if ev.eventType == eventType && ev.result == result {
			return true
		}
	}
	return false
}

// --- Test harness ---

type reauthEnv struct {
	handlers   *ReauthHandlers
	authz      *fakeReauthAuth
	challenges *memReauthChallenges
	grants     *memReauthGrants
	rate       *fakeReauthRate
	auditor    *fakeReauthAuditor
}

func newReauthEnv() *reauthEnv {
	authz := &fakeReauthAuth{}
	challenges := newMemReauthChallenges()
	grants := newMemReauthGrants()
	rate := &fakeReauthRate{allow: true}
	auditor := &fakeReauthAuditor{}
	handlers := NewReauthHandlers(authz, challenges, grants, rate, auditor,
		5*time.Minute, 5*time.Minute, 5, 10, 15*time.Minute, slog.Default())
	return &reauthEnv{handlers: handlers, authz: authz, challenges: challenges, grants: grants, rate: rate, auditor: auditor}
}

var reauthPrincipal = session.Principal{
	UserID:    identity.UserID("user_actor"),
	SessionID: session.SessionID("sess-1"),
}

func reauthRouter(h *ReauthHandlers, principal session.Principal) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := WithPrincipal(req.Context(), principal)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Post("/auth/reauthentication", h.Request)
	r.Post("/auth/reauthentication/mfa", h.CompleteMFA)
	return r
}

func doReauthJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

const reauthRotateBody = `{"action":"client.secret.rotate","applicationId":"app_test1","clientId":"clt_test1","password":"pw"}`

func decodeReauthToken(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		ReauthToken string `json:"reauthToken"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ReauthToken == "" {
		t.Fatal("response must carry a reauthToken")
	}
	return body.ReauthToken
}

// --- Request endpoint ---

func TestReauthRequest_GrantedImmediately(t *testing.T) {
	env := newReauthEnv()
	env.authz.verifyResult = auth.AuthenticationResult{Status: auth.StatusAuthenticated}
	router := reauthRouter(env.handlers, reauthPrincipal)

	w := doReauthJSON(t, router, "/auth/reauthentication", reauthRotateBody)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"status":"granted"`) {
		t.Errorf("body = %s, want granted status", w.Body.String())
	}
	token := decodeReauthToken(t, w)

	// The grant is consumable exactly once with the matching binding.
	grants := NewReauthGrants(env.grants)
	if err := grants.VerifyAndConsume(context.Background(), token, "client.secret.rotate", "sess-1", "app_test1", "clt_test1"); err != nil {
		t.Fatalf("verify grant: %v", err)
	}
	if err := grants.VerifyAndConsume(context.Background(), token, "client.secret.rotate", "sess-1", "app_test1", "clt_test1"); !errors.Is(err, auth.ErrReauthGrantNotFound) {
		t.Fatalf("reuse err = %v, want ErrReauthGrantNotFound", err)
	}
	if !env.auditor.has(applications.EventReauthenticationRequested, applications.SecurityEventSuccess) ||
		!env.auditor.has(applications.EventReauthenticationSucceeded, applications.SecurityEventSuccess) {
		t.Error("expected requested + succeeded audit events")
	}
}

func TestReauthRequest_RevokesProviderSessionOnGrant(t *testing.T) {
	env := newReauthEnv()
	env.authz.verifyResult = auth.AuthenticationResult{
		Status:                   auth.StatusAuthenticated,
		ProviderSessionReference: "ref-1",
	}
	router := reauthRouter(env.handlers, reauthPrincipal)

	w := doReauthJSON(t, router, "/auth/reauthentication", reauthRotateBody)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// The temporary provider session must not outlive the grant issuance.
	if len(env.authz.revoked) != 1 || env.authz.revoked[0] != "ref-1" {
		t.Errorf("revoked = %v, want [ref-1]", env.authz.revoked)
	}
}

func TestReauthRequest_RevokeFailureStillGrantsButAudits(t *testing.T) {
	env := newReauthEnv()
	env.authz.verifyResult = auth.AuthenticationResult{
		Status:                   auth.StatusAuthenticated,
		ProviderSessionReference: "ref-1",
	}
	env.authz.revokeErr = errors.New("provider down")
	router := reauthRouter(env.handlers, reauthPrincipal)

	w := doReauthJSON(t, router, "/auth/reauthentication", reauthRotateBody)
	// Revocation is best-effort: the local grant outcome stands, but the
	// failed revocation is recorded as a security event.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !env.auditor.has(applications.EventProviderSessionRevokeFailed, applications.SecurityEventDenied) {
		t.Error("expected provider_session.revoke_failed audit event")
	}
}

func TestReauthRequest_MFARequired(t *testing.T) {
	env := newReauthEnv()
	env.authz.verifyResult = auth.AuthenticationResult{
		Status:            auth.StatusMFARequired,
		ProviderSessionID: "ps-1",
		AvailableMethods:  []auth.MFAMethod{auth.MFAMethodTOTP, auth.MFAMethodPasskey},
	}
	router := reauthRouter(env.handlers, reauthPrincipal)

	w := doReauthJSON(t, router, "/auth/reauthentication", reauthRotateBody)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Status           string   `json:"status"`
		AvailableMethods []string `json:"availableMethods"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "mfa_required" || len(body.AvailableMethods) != 2 {
		t.Errorf("body = %+v, want mfa_required with 2 methods", body)
	}
	// The challenge is stored server-side; the provider session ID never
	// reaches the response.
	if strings.Contains(w.Body.String(), "ps-1") {
		t.Error("provider session ID must never be exposed")
	}
	if len(env.challenges.data) != 1 {
		t.Fatalf("challenges = %d, want 1", len(env.challenges.data))
	}
}

func TestReauthRequest_InvalidPassword(t *testing.T) {
	env := newReauthEnv()
	env.authz.verifyResult = auth.AuthenticationResult{Status: auth.StatusInvalidCredentials}
	router := reauthRouter(env.handlers, reauthPrincipal)

	w := doReauthJSON(t, router, "/auth/reauthentication", reauthRotateBody)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !env.auditor.has(applications.EventReauthenticationFailed, applications.SecurityEventDenied) {
		t.Error("expected denied reauthentication.failed event")
	}
	if len(env.grants.data) != 0 {
		t.Error("no grant may be issued for invalid credentials")
	}
}

func TestReauthRequest_ValidationFailures(t *testing.T) {
	env := newReauthEnv()
	env.authz.verifyResult = auth.AuthenticationResult{Status: auth.StatusAuthenticated}
	router := reauthRouter(env.handlers, reauthPrincipal)

	cases := []struct {
		name string
		body string
	}{
		{"unknown action", `{"action":"client.secret.reveal","applicationId":"app_test1","clientId":"clt_test1","password":"pw"}`},
		{"missing password", `{"action":"client.delete","applicationId":"app_test1","clientId":"clt_test1"}`},
		{"missing application id", `{"action":"application.delete","password":"pw"}`},
		{"malformed application id", `{"action":"application.delete","applicationId":"bogus","password":"pw"}`},
		{"client action missing client id", `{"action":"client.delete","applicationId":"app_test1","password":"pw"}`},
		{"unknown field", `{"action":"application.delete","applicationId":"app_test1","password":"pw","extra":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doReauthJSON(t, router, "/auth/reauthentication", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
		})
	}
	if env.authz.verifyCalls != 0 {
		t.Error("validation failures must never reach the provider")
	}
}

func TestReauthRequest_RateLimited(t *testing.T) {
	env := newReauthEnv()
	env.rate.allow = false
	env.authz.verifyResult = auth.AuthenticationResult{Status: auth.StatusAuthenticated}
	router := reauthRouter(env.handlers, reauthPrincipal)

	w := doReauthJSON(t, router, "/auth/reauthentication", reauthRotateBody)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if env.authz.verifyCalls != 0 {
		t.Error("rate-limited requests must never reach the provider")
	}
}

func TestReauthRequest_RateCheckerFailureFailsClosed(t *testing.T) {
	env := newReauthEnv()
	env.rate.err = errors.New("redis down")
	env.authz.verifyResult = auth.AuthenticationResult{Status: auth.StatusAuthenticated}
	router := reauthRouter(env.handlers, reauthPrincipal)

	w := doReauthJSON(t, router, "/auth/reauthentication", reauthRotateBody)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (fail closed)", w.Code)
	}
}

// --- MFA completion endpoint ---

func startReauthChallenge(t *testing.T, env *reauthEnv) string {
	t.Helper()
	env.authz.verifyResult = auth.AuthenticationResult{
		Status:            auth.StatusMFARequired,
		ProviderSessionID: "ps-1",
		AvailableMethods:  []auth.MFAMethod{auth.MFAMethodTOTP},
	}
	router := reauthRouter(env.handlers, reauthPrincipal)
	w := doReauthJSON(t, router, "/auth/reauthentication", reauthRotateBody)
	if w.Code != http.StatusAccepted {
		t.Fatalf("challenge status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	return decodeReauthToken(t, w)
}

func TestReauthCompleteMFA_SuccessIssuesGrant(t *testing.T) {
	env := newReauthEnv()
	challengeToken := startReauthChallenge(t, env)

	env.authz.mfaResult = auth.AuthenticationResult{Status: auth.StatusAuthenticated}
	router := reauthRouter(env.handlers, reauthPrincipal)
	w := doReauthJSON(t, router, "/auth/reauthentication/mfa",
		`{"reauthToken":"`+challengeToken+`","method":"totp","code":"123456"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	grantToken := decodeReauthToken(t, w)

	// The grant inherits the challenge binding.
	grants := NewReauthGrants(env.grants)
	if err := grants.VerifyAndConsume(context.Background(), grantToken, "client.secret.rotate", "sess-1", "app_test1", "clt_test1"); err != nil {
		t.Fatalf("verify grant: %v", err)
	}
	// The challenge is single-use.
	w2 := doReauthJSON(t, router, "/auth/reauthentication/mfa",
		`{"reauthToken":"`+challengeToken+`","method":"totp","code":"123456"}`)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("challenge reuse status = %d, want 401", w2.Code)
	}
}

func TestReauthCompleteMFA_RevokesProviderSessionOnGrant(t *testing.T) {
	env := newReauthEnv()
	challengeToken := startReauthChallenge(t, env)

	env.authz.mfaResult = auth.AuthenticationResult{
		Status:                   auth.StatusAuthenticated,
		ProviderSessionReference: "ref-2",
	}
	router := reauthRouter(env.handlers, reauthPrincipal)
	w := doReauthJSON(t, router, "/auth/reauthentication/mfa",
		`{"reauthToken":"`+challengeToken+`","method":"totp","code":"123456"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(env.authz.revoked) != 1 || env.authz.revoked[0] != "ref-2" {
		t.Errorf("revoked = %v, want [ref-2]", env.authz.revoked)
	}
}

func TestReauthCompleteMFA_ExpiredChallengeRevokesProviderSession(t *testing.T) {
	env := newReauthEnv()
	challengeToken := startReauthChallenge(t, env)

	env.authz.mfaResult = auth.AuthenticationResult{Status: auth.StatusExpired}
	router := reauthRouter(env.handlers, reauthPrincipal)
	w := doReauthJSON(t, router, "/auth/reauthentication/mfa",
		`{"reauthToken":"`+challengeToken+`","method":"totp","code":"123456"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	// The challenge's provider session must not outlive the consumed challenge.
	if len(env.authz.revoked) != 1 || env.authz.revoked[0] != "ps-1" {
		t.Errorf("revoked = %v, want [ps-1]", env.authz.revoked)
	}
}

func TestReauthCompleteMFA_WrongCodeUsesAttemptBudget(t *testing.T) {
	env := newReauthEnv()
	challengeToken := startReauthChallenge(t, env)
	env.authz.mfaResult = auth.AuthenticationResult{Status: auth.StatusInvalidCredentials}
	router := reauthRouter(env.handlers, reauthPrincipal)

	for i := 0; i < 5; i++ {
		w := doReauthJSON(t, router, "/auth/reauthentication/mfa",
			`{"reauthToken":"`+challengeToken+`","method":"totp","code":"000000"}`)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401; body=%s", i, w.Code, w.Body.String())
		}
	}
	// The sixth attempt exhausts the budget and consumes the challenge.
	w := doReauthJSON(t, router, "/auth/reauthentication/mfa",
		`{"reauthToken":"`+challengeToken+`","method":"totp","code":"000000"}`)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("exhausted status = %d, want 429; body=%s", w.Code, w.Body.String())
	}
	if len(env.challenges.data) != 0 {
		t.Error("exhausted challenge must be consumed")
	}
	if !env.auditor.has(applications.EventReauthenticationFailed, applications.SecurityEventDenied) {
		t.Error("expected denied reauthentication.failed events")
	}
	// Exhausting the budget is terminal: the challenge's provider session
	// must be revoked.
	if len(env.authz.revoked) != 1 || env.authz.revoked[0] != "ps-1" {
		t.Errorf("revoked = %v, want [ps-1]", env.authz.revoked)
	}
}

func TestReauthCompleteMFA_SessionBindingMismatch(t *testing.T) {
	env := newReauthEnv()
	challengeToken := startReauthChallenge(t, env)

	// A different session tries to complete the challenge.
	other := session.Principal{UserID: identity.UserID("user_actor"), SessionID: "sess-other"}
	router := reauthRouter(env.handlers, other)
	w := doReauthJSON(t, router, "/auth/reauthentication/mfa",
		`{"reauthToken":"`+challengeToken+`","method":"totp","code":"123456"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if len(env.challenges.data) != 0 {
		t.Error("mismatched completion must consume the challenge")
	}
	if env.authz.mfaResult.Status == auth.StatusAuthenticated && len(env.grants.data) != 0 {
		t.Error("no grant may be issued on binding mismatch")
	}
	// Binding mismatch is terminal: the challenge's provider session must
	// be revoked.
	if len(env.authz.revoked) != 1 || env.authz.revoked[0] != "ps-1" {
		t.Errorf("revoked = %v, want [ps-1]", env.authz.revoked)
	}
}

func TestReauthCompleteMFA_Validation(t *testing.T) {
	env := newReauthEnv()
	router := reauthRouter(env.handlers, reauthPrincipal)

	cases := []struct {
		name string
		body string
	}{
		{"missing token", `{"method":"totp","code":"123456"}`},
		{"missing method", `{"reauthToken":"tok"}`},
		{"totp without code", `{"reauthToken":"tok","method":"totp"}`},
		{"passkey without assertion", `{"reauthToken":"tok","method":"passkey"}`},
		{"unsupported method", `{"reauthToken":"tok","method":"recovery_code","code":"1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doReauthJSON(t, router, "/auth/reauthentication/mfa", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// --- Grant verifier ---

func TestReauthGrants_BindingChecks(t *testing.T) {
	grants := newMemReauthGrants()
	verifier := NewReauthGrants(grants)
	ctx := context.Background()

	data := auth.ReauthGrantData{
		UserID:        "user_actor",
		SessionID:     "sess-1",
		Action:        "client.secret.rotate",
		ApplicationID: "app_test1",
		ClientID:      "clt_test1",
		CreatedAt:     time.Now().UTC(),
	}
	if err := grants.CreateGrant(ctx, session.HashToken("tok-1"), data, time.Minute); err != nil {
		t.Fatalf("create grant: %v", err)
	}

	// Wrong action fails closed (grant is consumed either way).
	if err := verifier.VerifyAndConsume(ctx, "tok-1", "client.delete", "sess-1", "app_test1", "clt_test1"); err == nil {
		t.Fatal("action mismatch must fail")
	}
	if err := verifier.VerifyAndConsume(ctx, "tok-1", "client.secret.rotate", "sess-1", "app_test1", "clt_test1"); !errors.Is(err, auth.ErrReauthGrantNotFound) {
		t.Fatalf("reuse err = %v, want ErrReauthGrantNotFound", err)
	}

	cases := []struct {
		name      string
		sessionID string
		appID     applications.ApplicationID
		clientID  applications.OAuthClientID
	}{
		{"session mismatch", "sess-2", "app_test1", "clt_test1"},
		{"application mismatch", "sess-1", "app_other", "clt_test1"},
		{"client mismatch", "sess-1", "app_test1", "clt_other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := grants.CreateGrant(ctx, session.HashToken("tok-2"), data, time.Minute); err != nil {
				t.Fatalf("create grant: %v", err)
			}
			if err := verifier.VerifyAndConsume(ctx, "tok-2", "client.secret.rotate", tc.sessionID, tc.appID, tc.clientID); err == nil {
				t.Fatal("binding mismatch must fail")
			}
		})
	}

	// Empty token fails closed without touching the store.
	if err := verifier.VerifyAndConsume(ctx, "", "client.secret.rotate", "sess-1", "app_test1", "clt_test1"); err == nil {
		t.Fatal("empty token must fail")
	}
}
