package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

type riskServiceStub struct {
	decision  riskdefense.Decision
	complete  riskdefense.CompleteResult
	assessErr error
	assessed  riskdefense.Signal
	finished  riskdefense.Completion
}

func (s *riskServiceStub) EnsureDevice(_ context.Context, current string) (string, error) {
	if current != "" {
		return current, nil
	}
	if s.decision.DeviceIDToken != "" {
		return s.decision.DeviceIDToken, nil
	}
	return "server-device", nil
}

func (s *riskServiceStub) Assess(_ context.Context, signal riskdefense.Signal) (riskdefense.Decision, error) {
	s.assessed = signal
	return s.decision, s.assessErr
}

func TestRiskGuardRegistrationPassesTrustedNetworkAndMapsActiveChallengeTo429(t *testing.T) {
	stub := &riskServiceStub{assessErr: &riskdefense.RateLimitError{RetryAfter: 2500 * time.Millisecond}}
	guard := NewRiskGuard(stub, nil, SessionCookieAttributes{Secure: true, SameSite: http.SameSiteLaxMode}, time.Hour, 10*time.Minute)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/registrations", nil)
	req.Header.Set("User-Agent", "test-browser")
	recorder := httptest.NewRecorder()
	networkHash := hashRiskValue("203.0.113.0/24")

	if guard.RequireRegistration(recorder, req, hashRiskValue("intent@example.com"), networkHash) {
		t.Fatal("active registration challenge unexpectedly allowed request")
	}
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "3" {
		t.Fatalf("status=%d retry-after=%q body=%s", recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
	}
	if stub.assessed.Operation != riskdefense.OperationRegistration || stub.assessed.ClientNetworkHash != networkHash {
		t.Fatalf("assessed signal=%#v", stub.assessed)
	}
}
func (s *riskServiceStub) Complete(_ context.Context, completion riskdefense.Completion) (riskdefense.CompleteResult, error) {
	s.finished = completion
	return s.complete, nil
}

func TestRiskGuardWritesStableStepUpContractWithoutSubjectiveData(t *testing.T) {
	expires := time.Date(2026, 8, 25, 10, 5, 0, 0, time.UTC)
	stub := &riskServiceStub{decision: riskdefense.Decision{
		DeviceIDToken: "server-device",
		Challenge: &riskdefense.Challenge{
			Token: "opaque-challenge", Level: riskdefense.LevelMedium,
			Method: riskdefense.MethodAutomationCost, Difficulty: 18,
			ExpiresAt: expires, ProviderReady: true,
		},
	}}
	guard := NewRiskGuard(stub, nil, SessionCookieAttributes{Secure: true, SameSite: http.SameSiteLaxMode}, time.Hour, 10*time.Minute)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions", nil)
	req.Header.Set("User-Agent", "test-browser")
	recorder := httptest.NewRecorder()

	if guard.Require(recorder, req, riskdefense.OperationLogin, hashRiskValue("alice@example.com")) {
		t.Fatal("risk challenge unexpectedly allowed request")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d", recorder.Code)
	}
	var body ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != CodeStepUpRequired || body.Error.StepUp == nil || body.Error.StepUp.Method != "automation_cost" || body.Error.StepUp.Algorithm != "sha256_leading_zero_bits" || body.Error.StepUp.CompletionPath != "/api/v1/auth/step-up" {
		t.Fatalf("response=%s", recorder.Body.String())
	}
	if strings.Contains(strings.ToLower(recorder.Body.String()), "alice") || stub.assessed.IdentifierHash != hashRiskValue("alice@example.com") {
		t.Fatalf("identifier leaked or was not hashed: body=%s signal=%#v", recorder.Body.String(), stub.assessed)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != RiskDeviceCookieName || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("device cookie=%#v", cookies)
	}
}

func TestRiskGuardCompletionSetsShortLivedHttpOnlyTrust(t *testing.T) {
	stub := &riskServiceStub{complete: riskdefense.CompleteResult{TrustToken: "trust-token", ExpiresAt: time.Now().Add(10 * time.Minute)}}
	guard := NewRiskGuard(stub, nil, SessionCookieAttributes{Secure: true, SameSite: http.SameSiteStrictMode}, time.Hour, 10*time.Minute)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/step-up", strings.NewReader(`{"challengeToken":"challenge","nonce":"42"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-browser")
	req.AddCookie(&http.Cookie{Name: RiskDeviceCookieName, Value: "server-device"})
	recorder := httptest.NewRecorder()

	guard.Complete(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if stub.finished.ChallengeToken != "challenge" || stub.finished.Nonce != "42" || stub.finished.DeviceIDToken != "server-device" {
		t.Fatalf("completion=%#v", stub.finished)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != DeviceTrustCookieName || cookies[0].Value != "trust-token" || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("trust cookie=%#v", cookies)
	}
}
