package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/passwordreset"
)

type passwordResetServiceStub struct {
	requestInput  passwordreset.RequestInput
	requestErr    error
	requestCalls  int
	confirmInput  passwordreset.ConfirmInput
	confirmErr    error
	confirmResult passwordreset.ConfirmResult
	confirmCalls  int
}

func (s *passwordResetServiceStub) Request(_ context.Context, input passwordreset.RequestInput) error {
	s.requestCalls++
	s.requestInput = input
	return s.requestErr
}

func (s *passwordResetServiceStub) Confirm(_ context.Context, input passwordreset.ConfirmInput) (passwordreset.ConfirmResult, error) {
	s.confirmCalls++
	s.confirmInput = input
	return s.confirmResult, s.confirmErr
}

type passwordResetRateStub struct {
	deny           bool
	err            error
	retryAfter     time.Duration
	ipLimit        int
	accountLimit   int
	identifierHash string
	calls          int
}

func (s *passwordResetRateStub) CheckPasswordReset(_ context.Context, _ string, identifierHash string, ipLimit, accountLimit int, _ time.Duration) (bool, time.Duration, error) {
	s.calls++
	s.identifierHash = identifierHash
	s.ipLimit = ipLimit
	s.accountLimit = accountLimit
	if s.err != nil {
		return false, 0, s.err
	}
	return !s.deny, s.retryAfter, nil
}

func newPasswordResetTestHandlers(service PasswordResetService, rate PasswordResetRateChecker) *PasswordResetHandlers {
	return NewPasswordResetHandlers(service, rate, PasswordResetPolicy{}, nil)
}

func newPasswordResetTestRouter(handlers *PasswordResetHandlers) http.Handler {
	router := chi.NewRouter()
	handlers.Mount(router)
	return router
}

func performPasswordResetRequest(t *testing.T, handlers *PasswordResetHandlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-reset", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handlers.Request(recorder, request)
	return recorder
}

func performPasswordResetConfirm(t *testing.T, handlers *PasswordResetHandlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-reset/confirm", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handlers.Confirm(recorder, request)
	return recorder
}

func TestPasswordResetRequestAlwaysAccepted(t *testing.T) {
	service := &passwordResetServiceStub{}
	rate := &passwordResetRateStub{}
	handlers := newPasswordResetTestHandlers(service, rate)

	recorder := performPasswordResetRequest(t, handlers, `{"identifier":"unknown@example.com"}`)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", recorder.Code)
	}
	if service.requestCalls != 1 || service.requestInput.Identifier != "unknown@example.com" {
		t.Fatalf("unexpected service call: %+v", service.requestInput)
	}
	if rate.identifierHash == "" || rate.identifierHash == "unknown@example.com" {
		t.Fatalf("identifier must reach the limiter hashed: %q", rate.identifierHash)
	}
}

func TestPasswordResetRequestRejectsEmptyIdentifier(t *testing.T) {
	service := &passwordResetServiceStub{}
	handlers := newPasswordResetTestHandlers(service, &passwordResetRateStub{})

	recorder := performPasswordResetRequest(t, handlers, `{"identifier":"   "}`)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", recorder.Code)
	}
	if service.requestCalls != 0 {
		t.Fatalf("service must not be called for an empty identifier")
	}
}

func TestPasswordResetRequestRateLimited(t *testing.T) {
	service := &passwordResetServiceStub{}
	rate := &passwordResetRateStub{deny: true, retryAfter: 42 * time.Second}
	handlers := newPasswordResetTestHandlers(service, rate)

	recorder := performPasswordResetRequest(t, handlers, `{"identifier":"ving@example.com"}`)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", recorder.Code)
	}
	if recorder.Header().Get("Retry-After") != "42" {
		t.Fatalf("unexpected Retry-After: %q", recorder.Header().Get("Retry-After"))
	}
	if service.requestCalls != 0 {
		t.Fatalf("service must not be called when rate limited")
	}
}

func TestPasswordResetRequestFailsClosedWhenLimiterErrors(t *testing.T) {
	service := &passwordResetServiceStub{}
	handlers := newPasswordResetTestHandlers(service, &passwordResetRateStub{err: errors.New("redis down")})

	recorder := performPasswordResetRequest(t, handlers, `{"identifier":"ving@example.com"}`)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", recorder.Code)
	}
	if service.requestCalls != 0 {
		t.Fatalf("service must not be called when the limiter fails closed")
	}
}

func TestPasswordResetConfirmSucceeds(t *testing.T) {
	service := &passwordResetServiceStub{confirmResult: passwordreset.ConfirmResult{UserID: "user_1", RevokedSessions: 2}}
	rate := &passwordResetRateStub{}
	handlers := newPasswordResetTestHandlers(service, rate)

	recorder := performPasswordResetConfirm(t, handlers, `{"token":"raw-token","newPassword":"Ving123456789."}`)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
	if service.confirmInput.Token != "raw-token" || service.confirmInput.NewPassword != "Ving123456789." {
		t.Fatalf("unexpected confirm input: %+v", service.confirmInput)
	}
	if rate.accountLimit != 0 {
		t.Fatalf("confirmation must not open an account bucket: %d", rate.accountLimit)
	}
}

func TestPasswordResetConfirmWeakPassword(t *testing.T) {
	service := &passwordResetServiceStub{confirmErr: passwordreset.ErrWeakPassword}
	handlers := newPasswordResetTestHandlers(service, &passwordResetRateStub{})

	recorder := performPasswordResetConfirm(t, handlers, `{"token":"raw-token","newPassword":"short"}`)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", recorder.Code)
	}
	var body ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body.Error.Code != CodeValidation || len(body.Error.FieldErrors) != 1 || body.Error.FieldErrors[0].Field != "newPassword" {
		t.Fatalf("unexpected error body: %+v", body.Error)
	}
}

func TestPasswordResetConfirmInvalidToken(t *testing.T) {
	service := &passwordResetServiceStub{confirmErr: passwordreset.ErrInvalidToken}
	handlers := newPasswordResetTestHandlers(service, &passwordResetRateStub{})

	recorder := performPasswordResetConfirm(t, handlers, `{"token":"unknown","newPassword":"Ving123456789."}`)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", recorder.Code)
	}
	var body ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body.Error.Code != CodePasswordResetTokenInvalid {
		t.Fatalf("unexpected error code: %q", body.Error.Code)
	}
}

func TestPasswordResetConfirmProviderFailure(t *testing.T) {
	service := &passwordResetServiceStub{confirmErr: passwordreset.ErrPasswordChangeFailed}
	handlers := newPasswordResetTestHandlers(service, &passwordResetRateStub{})

	recorder := performPasswordResetConfirm(t, handlers, `{"token":"raw-token","newPassword":"Ving123456789."}`)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", recorder.Code)
	}
}

func TestPasswordResetHandlersMountRoutes(t *testing.T) {
	service := &passwordResetServiceStub{}
	handlers := newPasswordResetTestHandlers(service, &passwordResetRateStub{})
	router := newPasswordResetTestRouter(handlers)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/auth/password-reset", strings.NewReader(`{"identifier":"ving@example.com"}`)))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected mounted request route to answer 202, got %d", recorder.Code)
	}
}
