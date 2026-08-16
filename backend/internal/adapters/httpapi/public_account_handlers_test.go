//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Public account lifecycle security and settlement tests
//

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type publicAccountStoreStub struct {
	binding     auth.PublicAccountBinding
	createErr   error
	getErr      error
	findErr     error
	activateErr error
	created     bool
	activated   bool
}

func (s *publicAccountStoreStub) CreatePendingRegistration(
	_ context.Context,
	userID identity.UserID,
	provider, tenant, _ string,
	info identity.ProviderUserInfo,
) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.created = true
	s.binding = auth.PublicAccountBinding{
		UserID: userID, Provider: provider, ProviderTenantID: tenant,
		ProviderSubject: info.Subject, Email: info.Email, Status: identity.UserStatusPending,
	}
	return nil
}

func (s *publicAccountStoreStub) GetPublicAccountBinding(
	context.Context, identity.UserID, string, string,
) (auth.PublicAccountBinding, error) {
	if s.getErr != nil {
		return auth.PublicAccountBinding{}, s.getErr
	}
	return s.binding, nil
}

func (s *publicAccountStoreStub) FindPasswordResetBinding(
	context.Context, string, string, string,
) (auth.PublicAccountBinding, error) {
	if s.findErr != nil {
		return auth.PublicAccountBinding{}, s.findErr
	}
	return s.binding, nil
}

func (s *publicAccountStoreStub) ActivatePendingRegistration(
	_ context.Context,
	_ auth.PublicAccountBinding,
) error {
	if s.activateErr != nil {
		return s.activateErr
	}
	s.activated = true
	return nil
}

type publicAccountProviderStub struct {
	info              identity.ProviderUserInfo
	registerErr       error
	findErr           error
	beginResetErr     error
	resetErr          error
	verifyErr         error
	registrationInput auth.RegistrationInput
	resetURL          string
	resetPassword     string
	deletedSubject    string
	verified          bool
}

func (s *publicAccountProviderStub) Register(_ context.Context, input auth.RegistrationInput) (identity.ProviderUserInfo, error) {
	s.registrationInput = input
	return s.info, s.registerErr
}
func (s *publicAccountProviderStub) DeleteRegisteredUser(_ context.Context, subject string) error {
	s.deletedSubject = subject
	return nil
}
func (s *publicAccountProviderStub) FindPasswordResetIdentity(context.Context, string) (identity.ProviderUserInfo, error) {
	return s.info, s.findErr
}
func (s *publicAccountProviderStub) BeginPasswordReset(_ context.Context, _ string, resetURL string) error {
	s.resetURL = resetURL
	return s.beginResetErr
}
func (s *publicAccountProviderStub) ResetPassword(
	_ context.Context,
	_, _ string,
	password auth.SecretPassword,
) error {
	s.resetPassword = password.Password()
	return s.resetErr
}
func (s *publicAccountProviderStub) VerifyRegistrationEmail(context.Context, string, string, string) error {
	s.verified = true
	return s.verifyErr
}

type publicRateCheckerStub struct {
	allowed bool
	err     error
	calls   int
}

func (s *publicRateCheckerStub) CheckContact(
	context.Context, string, string, int, time.Duration,
) (bool, time.Duration, error) {
	s.calls++
	return s.allowed, time.Minute, s.err
}

func newPublicAccountHandlerForTest(
	store *publicAccountStoreStub,
	provider *publicAccountProviderStub,
	security MutationAuthority,
	auditor session.SecurityAuditor,
) *PublicAccountHandlers {
	return NewPublicAccountHandlers(
		store, provider, &publicRateCheckerStub{allowed: true}, security, auditor,
		testEncryptor(), "zitadel", "project_1", "https://portal.example.test",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

func publicJSONRequest(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "https://portal.example.test"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://portal.example.test")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.RemoteAddr = "192.0.2.1:4321"
	return req
}

func lifecycleErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return body.Error.Code
}

func TestPublicRegistrationCreatesPendingExplicitBinding(t *testing.T) {
	store := &publicAccountStoreStub{}
	provider := &publicAccountProviderStub{info: identity.ProviderUserInfo{
		Subject: "provider-user-1", Email: "user@example.test", DisplayName: "new.user",
	}}
	handler := newPublicAccountHandlerForTest(store, provider, nil, nil)
	recorder := httptest.NewRecorder()
	handler.Register(recorder, publicJSONRequest("/api/v1/registrations", `{
		"username":"new.user","email":"User@Example.Test",
		"password":"correct-horse-12","termsAccepted":true
	}`))

	if recorder.Code != http.StatusCreated || !store.created {
		t.Fatalf("status = %d, created = %v, body = %s", recorder.Code, store.created, recorder.Body.String())
	}
	if provider.registrationInput.Password.Password() != "correct-horse-12" {
		t.Fatal("provider did not receive the request-local password")
	}
	if provider.registrationInput.Email != "user@example.test" ||
		!strings.Contains(provider.registrationInput.EmailVerificationURL, "code={{.Code}}") {
		t.Fatalf("unexpected provider registration input: %+v", provider.registrationInput)
	}
	if store.binding.Status != identity.UserStatusPending || store.binding.ProviderSubject != "provider-user-1" {
		t.Fatalf("unexpected pending binding: %+v", store.binding)
	}
}

func TestPublicRegistrationRejectsCrossOriginBeforeProvider(t *testing.T) {
	store := &publicAccountStoreStub{}
	provider := &publicAccountProviderStub{info: identity.ProviderUserInfo{Subject: "provider-user-1"}}
	handler := newPublicAccountHandlerForTest(store, provider, nil, nil)
	req := publicJSONRequest("/api/v1/registrations", `{"username":"new.user","email":"user@example.test","password":"correct-horse-12","termsAccepted":true}`)
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	recorder := httptest.NewRecorder()
	handler.Register(recorder, req)
	if recorder.Code != http.StatusForbidden || provider.registrationInput.Username != "" {
		t.Fatalf("status = %d, provider input = %+v", recorder.Code, provider.registrationInput)
	}
}

func TestPublicRegistrationCompensatesLocalFailure(t *testing.T) {
	store := &publicAccountStoreStub{createErr: errors.New("database unavailable")}
	provider := &publicAccountProviderStub{info: identity.ProviderUserInfo{
		Subject: "provider-user-1", Email: "user@example.test",
	}}
	handler := newPublicAccountHandlerForTest(store, provider, nil, nil)
	recorder := httptest.NewRecorder()
	handler.Register(recorder, publicJSONRequest("/api/v1/registrations", `{"username":"new.user","email":"user@example.test","password":"correct-horse-12","termsAccepted":true}`))
	if recorder.Code != http.StatusInternalServerError || provider.deletedSubject != "provider-user-1" {
		t.Fatalf("status = %d, compensated subject = %q", recorder.Code, provider.deletedSubject)
	}
}

func TestPasswordResetRequestIsEnumerationSafe(t *testing.T) {
	store := &publicAccountStoreStub{findErr: auth.ErrPublicAccountNotFound}
	provider := &publicAccountProviderStub{findErr: auth.ErrPublicAccountNotFound}
	handler := newPublicAccountHandlerForTest(store, provider, nil, nil)
	recorder := httptest.NewRecorder()
	handler.RequestPasswordReset(recorder, publicJSONRequest(
		"/api/v1/password-reset-requests", `{"identifier":"nobody@example.test"}`,
	))
	if recorder.Code != http.StatusAccepted || recorder.Body.Len() != 0 {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
	}
}

func TestPasswordResetSuccessAdvancesEpochAndAudits(t *testing.T) {
	userID := identity.UserID("user_1")
	store := &publicAccountStoreStub{binding: auth.PublicAccountBinding{
		UserID: userID, Provider: "zitadel", ProviderTenantID: "project_1",
		ProviderSubject: "provider-user-1", Email: "user@example.test", Status: identity.UserStatusActive,
	}}
	provider := &publicAccountProviderStub{}
	security := newFakeMutationAuthority()
	auditor := &fakeSessionAuditor{}
	handler := newPublicAccountHandlerForTest(store, provider, security, auditor)
	token, err := handler.sealToken(lifecyclePasswordReset, userID, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ResetPassword(recorder, publicJSONRequest("/api/v1/password-resets", `{
		"token":"`+token+`","code":"ABC123","newPassword":"new-secure-password"
	}`))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if provider.resetPassword != "new-secure-password" || security.currentEpoch(userID) != 2 {
		t.Fatalf("password = %q, epoch = %d", provider.resetPassword, security.currentEpoch(userID))
	}
	rows := auditor.rows()
	if len(rows) != 1 || rows[0].EventType != "account.password_reset" || rows[0].ToEpoch != 2 {
		t.Fatalf("unexpected audit rows: %+v", rows)
	}
}

func TestPasswordResetConfirmedRejectionLeavesEpochUnchanged(t *testing.T) {
	userID := identity.UserID("user_1")
	store := &publicAccountStoreStub{binding: auth.PublicAccountBinding{
		UserID: userID, ProviderSubject: "provider-user-1", Status: identity.UserStatusActive,
	}}
	provider := &publicAccountProviderStub{resetErr: auth.ErrLifecycleRejected}
	security := newFakeMutationAuthority()
	handler := newPublicAccountHandlerForTest(store, provider, security, nil)
	token, _ := handler.sealToken(lifecyclePasswordReset, userID, time.Now().UTC().Add(time.Hour))
	recorder := httptest.NewRecorder()
	handler.ResetPassword(recorder, publicJSONRequest("/api/v1/password-resets", `{"token":"`+token+`","code":"ABC123","newPassword":"new-secure-password"}`))
	if recorder.Code != http.StatusUnprocessableEntity || security.currentEpoch(userID) != 1 {
		t.Fatalf("status = %d, epoch = %d", recorder.Code, security.currentEpoch(userID))
	}
}

func TestEmailVerificationActivatesOnlyPendingBinding(t *testing.T) {
	userID := identity.UserID("user_1")
	store := &publicAccountStoreStub{binding: auth.PublicAccountBinding{
		UserID: userID, Provider: "zitadel", ProviderTenantID: "project_1",
		ProviderSubject: "provider-user-1", Email: "user@example.test", Status: identity.UserStatusPending,
	}}
	provider := &publicAccountProviderStub{}
	handler := newPublicAccountHandlerForTest(store, provider, nil, nil)
	token, _ := handler.sealToken(lifecycleRegistration, userID, time.Now().UTC().Add(time.Hour))
	recorder := httptest.NewRecorder()
	handler.VerifyEmail(recorder, publicJSONRequest("/api/v1/email-verifications", `{"token":"`+token+`","code":"ABC123"}`))
	if recorder.Code != http.StatusNoContent || !provider.verified || !store.activated {
		t.Fatalf("status = %d, verified = %v, activated = %v", recorder.Code, provider.verified, store.activated)
	}
}

func TestLifecycleTokenExpiryIsStableAndSkipsProvider(t *testing.T) {
	store := &publicAccountStoreStub{}
	provider := &publicAccountProviderStub{}
	handler := newPublicAccountHandlerForTest(store, provider, nil, nil)
	handler.now = func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) }
	token, _ := handler.sealToken(lifecycleRegistration, "user_1", handler.now().Add(-time.Second))
	recorder := httptest.NewRecorder()
	handler.VerifyEmail(recorder, publicJSONRequest("/api/v1/email-verifications", `{"token":"`+token+`","code":"ABC123"}`))
	if recorder.Code != http.StatusGone || lifecycleErrorCode(t, recorder) != CodeLifecycleTokenExpired {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if provider.verified {
		t.Fatal("expired local capability reached the provider")
	}
}

func TestPasswordResetRequestBuildsOpaqueBoundURL(t *testing.T) {
	userID := identity.UserID("user_1")
	store := &publicAccountStoreStub{binding: auth.PublicAccountBinding{
		UserID: userID, ProviderSubject: "provider-user-1", Status: identity.UserStatusActive,
	}}
	provider := &publicAccountProviderStub{info: identity.ProviderUserInfo{Subject: "provider-user-1"}}
	handler := newPublicAccountHandlerForTest(store, provider, nil, nil)
	recorder := httptest.NewRecorder()
	handler.RequestPasswordReset(recorder, publicJSONRequest("/api/v1/password-reset-requests", `{"identifier":"user@example.test"}`))
	if recorder.Code != http.StatusAccepted || provider.resetURL == "" {
		t.Fatalf("status = %d, reset URL = %q", recorder.Code, provider.resetURL)
	}
	parsed, err := url.Parse(provider.resetURL)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := handler.openToken(parsed.Query().Get("token"), lifecyclePasswordReset)
	if err != nil || payload.UserID != userID || parsed.Query().Get("code") != "{{.Code}}" {
		t.Fatalf("payload = %+v, code = %q, err = %v", payload, parsed.Query().Get("code"), err)
	}
}
