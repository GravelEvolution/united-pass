//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the account security factor handlers
//

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// --- Test fakes ---

type passkeyConfirmCall struct {
	passkeyID  string
	name       string
	credential json.RawMessage
}

// fakeFactorManager is a configurable auth.FactorManager double recording
// every lifecycle call.
type fakeFactorManager struct {
	beginTOTPErr        error
	totpEnrollment      auth.TOTPEnrollment
	beginTOTPCalls      int
	confirmTOTPErr      error
	confirmTOTPCodes    []string
	removeTOTPErr       error
	removeTOTPCalls     int
	beginPasskeyErr     error
	passkeyEnrollment   auth.PasskeyEnrollment
	beginPasskeyCalls   int
	confirmPasskeyErr   error
	confirmPasskeyCalls []passkeyConfirmCall
	removePasskeyErr    error
	removedPasskeys     []string
	listPasskeys        []auth.PasskeyInfo
	listPasskeysErr     error
	summary             auth.FactorSummary
	summaryErr          error
}

func (f *fakeFactorManager) BeginTOTPEnrollment(_ context.Context, _ identity.UserID) (auth.TOTPEnrollment, error) {
	f.beginTOTPCalls++
	return f.totpEnrollment, f.beginTOTPErr
}

func (f *fakeFactorManager) ConfirmTOTPEnrollment(_ context.Context, _ identity.UserID, code string) error {
	f.confirmTOTPCodes = append(f.confirmTOTPCodes, code)
	return f.confirmTOTPErr
}

func (f *fakeFactorManager) RemoveTOTP(_ context.Context, _ identity.UserID) error {
	f.removeTOTPCalls++
	return f.removeTOTPErr
}

func (f *fakeFactorManager) BeginPasskeyEnrollment(_ context.Context, _ identity.UserID) (auth.PasskeyEnrollment, error) {
	f.beginPasskeyCalls++
	return f.passkeyEnrollment, f.beginPasskeyErr
}

func (f *fakeFactorManager) ConfirmPasskeyEnrollment(_ context.Context, _ identity.UserID, passkeyID, name string, publicKeyCredential json.RawMessage) error {
	f.confirmPasskeyCalls = append(f.confirmPasskeyCalls, passkeyConfirmCall{
		passkeyID:  passkeyID,
		name:       name,
		credential: publicKeyCredential,
	})
	return f.confirmPasskeyErr
}

func (f *fakeFactorManager) RemovePasskey(_ context.Context, _ identity.UserID, passkeyID string) error {
	f.removedPasskeys = append(f.removedPasskeys, passkeyID)
	return f.removePasskeyErr
}

func (f *fakeFactorManager) ListPasskeys(_ context.Context, _ identity.UserID) ([]auth.PasskeyInfo, error) {
	return f.listPasskeys, f.listPasskeysErr
}

func (f *fakeFactorManager) FactorSummary(_ context.Context, _ identity.UserID) (auth.FactorSummary, error) {
	return f.summary, f.summaryErr
}

// memEnrollments is an in-memory EnrollmentTokenStore mirroring the Redis
// GETDEL single-winner semantics.
type memEnrollments struct {
	mu        sync.Mutex
	data      map[string]auth.EnrollmentData
	createErr error
}

func newMemEnrollments() *memEnrollments {
	return &memEnrollments{data: make(map[string]auth.EnrollmentData)}
}

func (m *memEnrollments) CreateEnrollment(_ context.Context, tokenHash string, data auth.EnrollmentData, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	m.data[tokenHash] = data
	return nil
}

func (m *memEnrollments) ConsumeEnrollment(_ context.Context, tokenHash string) (auth.EnrollmentData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.data[tokenHash]
	if !ok {
		return auth.EnrollmentData{}, auth.ErrEnrollmentNotFound
	}
	delete(m.data, tokenHash)
	return data, nil
}

func (m *memEnrollments) size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.data)
}

// --- Test harness ---

var securityPrincipal = session.Principal{
	UserID:    identity.UserID("user_security"),
	SessionID: session.SessionID("sess-sec"),
}

type securityEnv struct {
	handlers *SecurityHandlers
	factors  *fakeFactorManager
	grants   *memReauthGrants
	enroll   *memEnrollments
}

func newSecurityEnv() *securityEnv {
	factors := &fakeFactorManager{}
	grants := newMemReauthGrants()
	enroll := newMemEnrollments()
	handlers := NewSecurityHandlers(factors, NewReauthGrants(grants), enroll, 5*time.Minute, discardLogger())
	return &securityEnv{handlers: handlers, factors: factors, grants: grants, enroll: enroll}
}

func (e *securityEnv) router(injectPrincipal bool) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			if injectPrincipal {
				ctx = WithPrincipal(ctx, securityPrincipal)
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Get("/me/security", e.handlers.GetSecurityFactors)
	r.Post("/me/security/totp/enrollment", e.handlers.BeginTOTPEnrollment)
	r.Post("/me/security/totp/enrollment/confirm", e.handlers.ConfirmTOTPEnrollment)
	r.Delete("/me/security/totp", e.handlers.RemoveTOTP)
	r.Post("/me/security/passkeys/enrollment", e.handlers.BeginPasskeyEnrollment)
	r.Post("/me/security/passkeys/enrollment/confirm", e.handlers.ConfirmPasskeyEnrollment)
	r.Delete("/me/security/passkeys/{passkeyId}", e.handlers.RemovePasskey)
	return r
}

// mintGrant seeds a consumable step-up grant bound to the harness principal.
func (e *securityEnv) mintGrant(t *testing.T, token, action, target string) {
	t.Helper()
	data := auth.ReauthGrantData{
		UserID:    securityPrincipal.UserID,
		SessionID: string(securityPrincipal.SessionID),
		Action:    action,
		Target:    target,
		CreatedAt: time.Now(),
	}
	if err := e.grants.CreateGrant(t.Context(), session.HashToken(token), data, time.Minute); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

func doSecurityJSON(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeEnrollmentToken(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		EnrollmentToken string `json:"enrollmentToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (body=%s)", err, w.Body.String())
	}
	if body.EnrollmentToken == "" {
		t.Fatalf("response must carry an enrollmentToken; body=%s", w.Body.String())
	}
	return body.EnrollmentToken
}

func reauthHeader(token string) map[string]string {
	return map[string]string{"X-Reauthentication-Token": token}
}

// --- GET /me/security ---

func TestGetSecurityFactors_SummaryShape(t *testing.T) {
	env := newSecurityEnv()
	env.factors.summary = auth.FactorSummary{
		PasswordSet: true,
		TOTPEnabled: true,
		Passkeys: []auth.PasskeyInfo{
			{ID: "pk-1", State: auth.PasskeyStateActive}, // CreatedAt nil => null
		},
	}

	rec := doSecurityJSON(t, env.router(true), http.MethodGet, "/me/security", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var view securitySummaryView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !view.Password.Set || !view.TOTP.Enabled {
		t.Errorf("summary = %+v, want password.set=true totp.enabled=true", view)
	}
	if len(view.Passkeys) != 1 || view.Passkeys[0].PasskeyID != "pk-1" || view.Passkeys[0].State != "active" {
		t.Errorf("passkeys = %+v, want one active pk-1", view.Passkeys)
	}
	if view.RecoveryCodes.Available || view.RecoveryCodes.DeferredReason != "provider_unsupported" {
		t.Errorf("recoveryCodes = %+v, want fixed deferred payload", view.RecoveryCodes)
	}
	// createdAt must serialize as explicit null when the provider gives none.
	if !strings.Contains(rec.Body.String(), `"createdAt":null`) {
		t.Errorf("body must carry createdAt:null, got %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"deferredReason":"provider_unsupported"`) {
		t.Errorf("body must carry the frozen deferredReason, got %s", rec.Body.String())
	}
}

func TestGetSecurityFactors_RequiresPrincipal(t *testing.T) {
	env := newSecurityEnv()
	rec := doSecurityJSON(t, env.router(false), http.MethodGet, "/me/security", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestGetSecurityFactors_ProviderFailure(t *testing.T) {
	env := newSecurityEnv()
	env.factors.summaryErr = auth.ErrProviderUnavailable
	rec := doSecurityJSON(t, env.router(true), http.MethodGet, "/me/security", "", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeProviderUnavailable {
		t.Errorf("code = %q, want %q", body.Code, CodeProviderUnavailable)
	}
}

// --- TOTP lifecycle ---

func TestBeginTOTPEnrollment_Success(t *testing.T) {
	env := newSecurityEnv()
	env.factors.totpEnrollment = auth.TOTPEnrollment{Secret: "SECRET123", OTPAuthURI: "otpauth://totp/x?secret=SECRET123"}
	env.mintGrant(t, "grant-totp-begin", auth.ReauthActionTOTPEnroll, "")

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment",
		"", reauthHeader("grant-totp-begin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	var body struct {
		EnrollmentToken string `json:"enrollmentToken"`
		Secret          string `json:"secret"`
		OTPAuthURI      string `json:"otpauthUri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Secret != "SECRET123" || body.OTPAuthURI != "otpauth://totp/x?secret=SECRET123" {
		t.Errorf("secret material = (%q, %q), want provider values", body.Secret, body.OTPAuthURI)
	}
	if body.EnrollmentToken == "" {
		t.Fatal("response must carry an enrollmentToken")
	}

	// The grant is single-use and the enrollment challenge is stored.
	if err := NewReauthGrants(env.grants).VerifyAndConsume(t.Context(), "grant-totp-begin",
		auth.ReauthActionTOTPEnroll, "sess-sec", "", "", ""); !errors.Is(err, auth.ErrReauthGrantNotFound) {
		t.Fatalf("grant reuse err = %v, want ErrReauthGrantNotFound", err)
	}
	if env.enroll.size() != 1 {
		t.Fatalf("stored enrollments = %d, want 1", env.enroll.size())
	}
}

func TestBeginTOTPEnrollment_RequiresGrant(t *testing.T) {
	env := newSecurityEnv()
	env.factors.totpEnrollment = auth.TOTPEnrollment{Secret: "S", OTPAuthURI: "u"}

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeReauthenticationReq {
		t.Errorf("code = %q, want %q", body.Code, CodeReauthenticationReq)
	}
	if env.factors.beginTOTPCalls != 0 {
		t.Error("provider must not be touched without a grant")
	}
	if env.enroll.size() != 0 {
		t.Error("no enrollment may be issued without a grant")
	}
}

func TestBeginTOTPEnrollment_WrongActionGrant(t *testing.T) {
	env := newSecurityEnv()
	env.mintGrant(t, "grant-wrong", auth.ReauthActionTOTPRemove, "")

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment",
		"", reauthHeader("grant-wrong"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if env.factors.beginTOTPCalls != 0 {
		t.Error("a remove grant must never authorize an enrollment")
	}
}

func TestBeginTOTPEnrollment_AlreadySet(t *testing.T) {
	env := newSecurityEnv()
	env.factors.beginTOTPErr = auth.ErrFactorAlreadySet
	env.mintGrant(t, "grant-dup", auth.ReauthActionTOTPEnroll, "")

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment",
		"", reauthHeader("grant-dup"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeFactorAlreadySet {
		t.Errorf("code = %q, want %q", body.Code, CodeFactorAlreadySet)
	}
	if env.enroll.size() != 0 {
		t.Error("no enrollment token may be issued on provider failure")
	}
}

func TestBeginTOTPEnrollment_StoreFailureFailsClosed(t *testing.T) {
	env := newSecurityEnv()
	env.factors.totpEnrollment = auth.TOTPEnrollment{Secret: "S", OTPAuthURI: "u"}
	env.enroll.createErr = context.DeadlineExceeded
	env.mintGrant(t, "grant-store-fail", auth.ReauthActionTOTPEnroll, "")

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment",
		"", reauthHeader("grant-store-fail"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func totpBegin(t *testing.T, env *securityEnv) string {
	t.Helper()
	env.factors.totpEnrollment = auth.TOTPEnrollment{Secret: "SECRET123", OTPAuthURI: "otpauth://totp/x"}
	token := "grant-totp-" + t.Name()
	env.mintGrant(t, token, auth.ReauthActionTOTPEnroll, "")
	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment",
		"", reauthHeader(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("begin status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	return decodeEnrollmentToken(t, rec)
}

func TestConfirmTOTPEnrollment_Success(t *testing.T) {
	env := newSecurityEnv()
	token := totpBegin(t, env)

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment/confirm",
		`{"enrollmentToken":"`+token+`","code":"123456"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"confirmed"`) {
		t.Errorf("body = %s, want status confirmed", rec.Body.String())
	}
	if len(env.factors.confirmTOTPCodes) != 1 || env.factors.confirmTOTPCodes[0] != "123456" {
		t.Errorf("confirmed codes = %v, want [123456]", env.factors.confirmTOTPCodes)
	}
	if env.enroll.size() != 0 {
		t.Error("enrollment must be consumed by the confirmation")
	}
}

func TestConfirmTOTPEnrollment_WrongCodeConsumesEnrollment(t *testing.T) {
	env := newSecurityEnv()
	token := totpBegin(t, env)
	env.factors.confirmTOTPErr = auth.ErrInvalidFactorCode

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment/confirm",
		`{"enrollmentToken":"`+token+`","code":"000000"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeFactorInvalid {
		t.Errorf("code = %q, want %q", body.Code, CodeFactorInvalid)
	}

	// A wrong code consumes the enrollment: retry with the same token fails.
	rec2 := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment/confirm",
		`{"enrollmentToken":"`+token+`","code":"123456"}`, nil)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("retry status = %d, want 403", rec2.Code)
	}
	if body := decodeErrorBody(t, rec2); body.Code != CodeEnrollmentInvalid {
		t.Errorf("retry code = %q, want %q", body.Code, CodeEnrollmentInvalid)
	}
}

func TestConfirmTOTPEnrollment_EmptyCode(t *testing.T) {
	env := newSecurityEnv()
	token := totpBegin(t, env)

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment/confirm",
		`{"enrollmentToken":"`+token+`"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	// Validation happens before the enrollment is consumed.
	if env.enroll.size() != 1 {
		t.Error("an invalid request body must not consume the enrollment")
	}
}

func TestConfirmTOTPEnrollment_EmptyToken(t *testing.T) {
	env := newSecurityEnv()
	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment/confirm",
		`{"code":"123456"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeEnrollmentInvalid {
		t.Errorf("code = %q, want %q", body.Code, CodeEnrollmentInvalid)
	}
	if len(env.factors.confirmTOTPCodes) != 0 {
		t.Error("provider must not be touched without an enrollment token")
	}
}

func TestConfirmTOTPEnrollment_BindingMismatch(t *testing.T) {
	cases := []struct {
		name string
		data auth.EnrollmentData
	}{
		{"wrong user", auth.EnrollmentData{UserID: "user_other", SessionID: "sess-sec", Kind: auth.EnrollmentTOTP}},
		{"wrong session", auth.EnrollmentData{UserID: securityPrincipal.UserID, SessionID: "sess-other", Kind: auth.EnrollmentTOTP}},
		{"wrong kind", auth.EnrollmentData{UserID: securityPrincipal.UserID, SessionID: "sess-sec", Kind: auth.EnrollmentPasskey}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newSecurityEnv()
			if err := env.enroll.CreateEnrollment(t.Context(), session.HashToken("tok-fx"), tc.data, time.Minute); err != nil {
				t.Fatalf("seed enrollment: %v", err)
			}
			rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/totp/enrollment/confirm",
				`{"enrollmentToken":"tok-fx","code":"123456"}`, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
			}
			if body := decodeErrorBody(t, rec); body.Code != CodeEnrollmentInvalid {
				t.Errorf("code = %q, want %q", body.Code, CodeEnrollmentInvalid)
			}
			if len(env.factors.confirmTOTPCodes) != 0 {
				t.Error("a mismatched enrollment must never reach the provider")
			}
		})
	}
}

func TestRemoveTOTP_SuccessWithReadback(t *testing.T) {
	env := newSecurityEnv()
	env.factors.summary = auth.FactorSummary{PasswordSet: true}
	env.mintGrant(t, "grant-totp-remove", auth.ReauthActionTOTPRemove, "")

	rec := doSecurityJSON(t, env.router(true), http.MethodDelete, "/me/security/totp",
		"", reauthHeader("grant-totp-remove"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if env.factors.removeTOTPCalls != 1 {
		t.Fatalf("remove calls = %d, want 1", env.factors.removeTOTPCalls)
	}
	var view securitySummaryView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if view.TOTP.Enabled {
		t.Error("readback must reflect the provider state (totp removed)")
	}
}

func TestRemoveTOTP_NotEnrolled(t *testing.T) {
	env := newSecurityEnv()
	env.factors.removeTOTPErr = auth.ErrFactorNotSet
	env.mintGrant(t, "grant-totp-remove-404", auth.ReauthActionTOTPRemove, "")

	rec := doSecurityJSON(t, env.router(true), http.MethodDelete, "/me/security/totp",
		"", reauthHeader("grant-totp-remove-404"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeFactorNotFound {
		t.Errorf("code = %q, want %q", body.Code, CodeFactorNotFound)
	}
}

func TestRemoveTOTP_ReadbackFailure(t *testing.T) {
	env := newSecurityEnv()
	env.factors.summaryErr = auth.ErrProviderUnavailable
	env.mintGrant(t, "grant-totp-remove-rb", auth.ReauthActionTOTPRemove, "")

	rec := doSecurityJSON(t, env.router(true), http.MethodDelete, "/me/security/totp",
		"", reauthHeader("grant-totp-remove-rb"))
	// Removal succeeded but the provider readback failed: report the
	// provider failure instead of a guessed state.
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
}

// --- Passkey lifecycle ---

const passkeyCreationOptions = `{"challenge":"Y2hhbGxlbmdl","rp":{"name":"United Pass"},"user":{"id":"dXNlcg"}}`

func TestBeginPasskeyEnrollment_Success(t *testing.T) {
	env := newSecurityEnv()
	env.factors.passkeyEnrollment = auth.PasskeyEnrollment{
		PasskeyID:       "pk-new",
		CreationOptions: json.RawMessage(passkeyCreationOptions),
	}
	env.mintGrant(t, "grant-pk-begin", auth.ReauthActionPasskeyEnroll, "")

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/passkeys/enrollment",
		"", reauthHeader("grant-pk-begin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	// Creation options must be embedded as a raw JSON object, never an
	// escaped string.
	if !strings.Contains(rec.Body.String(), `"publicKeyCredentialCreationOptions":{"challenge"`) {
		t.Errorf("body must embed creation options verbatim, got %s", rec.Body.String())
	}
	var body struct {
		EnrollmentToken string          `json:"enrollmentToken"`
		PasskeyID       string          `json:"passkeyId"`
		CreationOptions json.RawMessage `json:"publicKeyCredentialCreationOptions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.PasskeyID != "pk-new" || body.EnrollmentToken == "" {
		t.Fatalf("body = %+v, want passkeyId pk-new + enrollmentToken", body)
	}

	// The stored enrollment is bound to the provider-issued passkeyId.
	data, err := env.enroll.ConsumeEnrollment(t.Context(), session.HashToken(body.EnrollmentToken))
	if err != nil {
		t.Fatalf("consume stored enrollment: %v", err)
	}
	if data.Kind != auth.EnrollmentPasskey || data.Target != "pk-new" {
		t.Errorf("enrollment binding = (%q, %q), want (passkey, pk-new)", data.Kind, data.Target)
	}
}

func passkeyBegin(t *testing.T, env *securityEnv) (token, passkeyID string) {
	t.Helper()
	env.factors.passkeyEnrollment = auth.PasskeyEnrollment{
		PasskeyID:       "pk-" + t.Name(),
		CreationOptions: json.RawMessage(passkeyCreationOptions),
	}
	grant := "grant-pk-" + t.Name()
	env.mintGrant(t, grant, auth.ReauthActionPasskeyEnroll, "")
	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/passkeys/enrollment",
		"", reauthHeader(grant))
	if rec.Code != http.StatusOK {
		t.Fatalf("begin status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		EnrollmentToken string `json:"enrollmentToken"`
		PasskeyID       string `json:"passkeyId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode begin body: %v", err)
	}
	return body.EnrollmentToken, body.PasskeyID
}

func TestConfirmPasskeyEnrollment_Success(t *testing.T) {
	env := newSecurityEnv()
	token, passkeyID := passkeyBegin(t, env)

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/passkeys/enrollment/confirm",
		`{"enrollmentToken":"`+token+`","publicKeyCredential":{"id":"cred-1","type":"public-key"},"passkeyName":"MacBook"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"confirmed"`) ||
		!strings.Contains(rec.Body.String(), `"passkeyId":"`+passkeyID+`"`) {
		t.Errorf("body = %s, want confirmed + passkeyId", rec.Body.String())
	}
	if len(env.factors.confirmPasskeyCalls) != 1 {
		t.Fatalf("confirm calls = %d, want 1", len(env.factors.confirmPasskeyCalls))
	}
	call := env.factors.confirmPasskeyCalls[0]
	if call.passkeyID != passkeyID || call.name != "MacBook" {
		t.Errorf("call = (%q, %q), want (%q, MacBook)", call.passkeyID, call.name, passkeyID)
	}
	if string(call.credential) != `{"id":"cred-1","type":"public-key"}` {
		t.Errorf("credential = %s, want verbatim browser payload", string(call.credential))
	}
}

func TestConfirmPasskeyEnrollment_BadAttestation(t *testing.T) {
	env := newSecurityEnv()
	token, _ := passkeyBegin(t, env)
	env.factors.confirmPasskeyErr = auth.ErrInvalidFactorCode

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/passkeys/enrollment/confirm",
		`{"enrollmentToken":"`+token+`","publicKeyCredential":{"id":"bad"}}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeFactorInvalid {
		t.Errorf("code = %q, want %q", body.Code, CodeFactorInvalid)
	}
}

func TestConfirmPasskeyEnrollment_MissingCredential(t *testing.T) {
	env := newSecurityEnv()
	token, _ := passkeyBegin(t, env)

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/passkeys/enrollment/confirm",
		`{"enrollmentToken":"`+token+`"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	// Validation precedes enrollment consumption.
	if env.enroll.size() != 1 {
		t.Error("an invalid request body must not consume the enrollment")
	}
}

func TestConfirmPasskeyEnrollment_TOTPTokenRejected(t *testing.T) {
	env := newSecurityEnv()
	totpToken := totpBegin(t, env)

	rec := doSecurityJSON(t, env.router(true), http.MethodPost, "/me/security/passkeys/enrollment/confirm",
		`{"enrollmentToken":"`+totpToken+`","publicKeyCredential":{"id":"cred-1"}}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeEnrollmentInvalid {
		t.Errorf("code = %q, want %q", body.Code, CodeEnrollmentInvalid)
	}
	if len(env.factors.confirmPasskeyCalls) != 0 {
		t.Error("a TOTP enrollment must never confirm a passkey")
	}
}

func TestRemovePasskey_SuccessWithReadback(t *testing.T) {
	env := newSecurityEnv()
	env.factors.summary = auth.FactorSummary{PasswordSet: true}
	env.mintGrant(t, "grant-pk-remove", auth.ReauthActionPasskeyRemove, "pk-A")

	rec := doSecurityJSON(t, env.router(true), http.MethodDelete, "/me/security/passkeys/pk-A",
		"", reauthHeader("grant-pk-remove"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(env.factors.removedPasskeys) != 1 || env.factors.removedPasskeys[0] != "pk-A" {
		t.Errorf("removed = %v, want [pk-A]", env.factors.removedPasskeys)
	}
	if !strings.Contains(rec.Body.String(), `"passkeys":[]`) {
		t.Errorf("body must carry the fresh provider readback, got %s", rec.Body.String())
	}
}

func TestRemovePasskey_GrantTargetMismatch(t *testing.T) {
	env := newSecurityEnv()
	env.mintGrant(t, "grant-pk-mismatch", auth.ReauthActionPasskeyRemove, "pk-A")

	// A grant minted for pk-A can never remove pk-B.
	rec := doSecurityJSON(t, env.router(true), http.MethodDelete, "/me/security/passkeys/pk-B",
		"", reauthHeader("grant-pk-mismatch"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeReauthenticationReq {
		t.Errorf("code = %q, want %q", body.Code, CodeReauthenticationReq)
	}
	if len(env.factors.removedPasskeys) != 0 {
		t.Error("provider must not be touched on target mismatch")
	}
}

func TestRemovePasskey_NotFound(t *testing.T) {
	env := newSecurityEnv()
	env.factors.removePasskeyErr = auth.ErrFactorNotSet
	env.mintGrant(t, "grant-pk-404", auth.ReauthActionPasskeyRemove, "pk-gone")

	rec := doSecurityJSON(t, env.router(true), http.MethodDelete, "/me/security/passkeys/pk-gone",
		"", reauthHeader("grant-pk-404"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeFactorNotFound {
		t.Errorf("code = %q, want %q", body.Code, CodeFactorNotFound)
	}
}
