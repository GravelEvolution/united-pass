package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/phoneverify"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

func TestRequestPhoneChangeRequiresHumanVerificationBeforeSendingSMS(t *testing.T) {
	service := &phoneVerifyServiceStub{}
	risk := &riskServiceStub{decision: riskdefense.Decision{Challenge: &riskdefense.Challenge{
		Token: "opaque-challenge", Level: riskdefense.LevelHigh, Method: riskdefense.MethodInteractiveCAPTCHA,
		ExpiresAt: time.Now().Add(time.Minute), ProviderReady: true, Provider: "moonstone_image_digits",
	}}}
	handler := NewPhoneVerifyHandlers(
		service, "https://auth.example.test", nil,
		WithPhoneVerifyRiskGuard(NewRiskGuard(risk, nil, SessionCookieAttributes{}, time.Hour, 10*time.Minute)),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/phone-change", strings.NewReader(`{"phone":"13800138000"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://auth.example.test")
	req.Header.Set("User-Agent", "test-browser")
	req = req.WithContext(WithPrincipal(req.Context(), session.Principal{UserID: identity.UserID("user_1")}))
	recorder := httptest.NewRecorder()

	handler.RequestPhoneChange(recorder, req)

	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), CodeStepUpRequired) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.requestCalls != 0 {
		t.Fatal("SMS delivery was attempted before the human verification challenge completed")
	}
	if risk.assessed.Operation != riskdefense.OperationPhoneChange {
		t.Fatalf("assessed operation=%q", risk.assessed.Operation)
	}
	if risk.assessed.IdentifierHash != hashRiskValue("user_1\x00+8613800138000") {
		t.Fatalf("identifier hash=%q", risk.assessed.IdentifierHash)
	}
	if strings.Contains(recorder.Body.String(), "13800138000") {
		t.Fatalf("phone number leaked into the challenge response: %s", recorder.Body.String())
	}
}

func TestRequestPhoneChangeRejectsInvalidNumberBeforeRiskOrSMS(t *testing.T) {
	service := &phoneVerifyServiceStub{}
	risk := &riskServiceStub{decision: riskdefense.Decision{Allow: true}}
	handler := NewPhoneVerifyHandlers(
		service, "https://auth.example.test", nil,
		WithPhoneVerifyRiskGuard(NewRiskGuard(risk, nil, SessionCookieAttributes{}, time.Hour, 10*time.Minute)),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/phone-change", strings.NewReader(`{"phone":"12345"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://auth.example.test")
	req.Header.Set("User-Agent", "test-browser")
	req = req.WithContext(WithPrincipal(req.Context(), session.Principal{UserID: identity.UserID("user_1")}))
	recorder := httptest.NewRecorder()

	handler.RequestPhoneChange(recorder, req)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if risk.assessed.IdentifierHash != "" || service.requestCalls != 0 {
		t.Fatalf("invalid number reached risk defense or SMS: signal=%#v calls=%d", risk.assessed, service.requestCalls)
	}
}

func TestRequestPhoneChangeIsRateLimitedPerAccount(t *testing.T) {
	service := &phoneVerifyServiceStub{}
	rate := &phoneChangeRateStub{allowed: false, retry: 2500 * time.Millisecond}
	handler := NewPhoneVerifyHandlers(
		service, "https://auth.example.test", nil,
		WithPhoneVerifyRateChecker(rate, 3, time.Minute),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/phone-change", strings.NewReader(`{"phone":"+37257013843"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://auth.example.test")
	req.Header.Set("User-Agent", "test-browser")
	req = req.WithContext(WithPrincipal(req.Context(), session.Principal{UserID: identity.UserID("user_1")}))
	recorder := httptest.NewRecorder()

	handler.RequestPhoneChange(recorder, req)

	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "3" {
		t.Fatalf("status=%d retry-after=%q body=%s", recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
	}
	if rate.keyHash != hashRiskValue("user_1") || service.requestCalls != 0 {
		t.Fatalf("rate key=%q calls=%d", rate.keyHash, service.requestCalls)
	}
}

func TestVerifyPhoneChangeReturnsExplicitConflict(t *testing.T) {
	handler := NewPhoneVerifyHandlers(&phoneVerifyServiceStub{verifyErr: phoneverify.ErrPhoneConflict}, "https://auth.example.test", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/phone-change/verify", strings.NewReader(`{"requestId":"phone_verify_request","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://auth.example.test")
	req = req.WithContext(WithPrincipal(req.Context(), session.Principal{UserID: identity.UserID("user_target")}))
	recorder := httptest.NewRecorder()

	handler.VerifyPhoneChange(recorder, req)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code":"account.phone_conflict"`) ||
		!strings.Contains(recorder.Body.String(), "未自动合并或覆盖") {
		t.Fatalf("conflict response=%s", recorder.Body.String())
	}
}

type phoneVerifyServiceStub struct {
	verifyErr    error
	requestCalls int
}

func (s *phoneVerifyServiceStub) Request(context.Context, phoneverify.RequestInput) (phoneverify.RequestResult, error) {
	s.requestCalls++
	return phoneverify.RequestResult{RequestID: "phone_verify_stub"}, nil
}

func (s *phoneVerifyServiceStub) Verify(context.Context, phoneverify.VerifyInput) (string, error) {
	return "", s.verifyErr
}

type phoneChangeRateStub struct {
	allowed bool
	retry   time.Duration
	keyHash string
}

func (s *phoneChangeRateStub) CheckAccountPhoneChangeBegin(_ context.Context, _, keyHash string, _ int, _ time.Duration) (bool, time.Duration, error) {
	s.keyHash = keyHash
	return s.allowed, s.retry, nil
}
