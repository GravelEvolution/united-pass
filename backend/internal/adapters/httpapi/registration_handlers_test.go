package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

type registrationServiceStub struct {
	createInput registration.CreateInput
	verifyInput registration.VerifyInput
	resendToken string
	createErr   error
	verifyErr   error
	resendErr   error
}

func (s *registrationServiceStub) Create(_ context.Context, input registration.CreateInput) (registration.CreateResult, error) {
	s.createInput = input
	return registration.CreateResult{RegistrationToken: "opaque-token", ExpiresAt: time.Date(2026, 8, 18, 13, 0, 0, 0, time.UTC)}, s.createErr
}
func (s *registrationServiceStub) Verify(_ context.Context, input registration.VerifyInput) (registration.VerifyResult, error) {
	s.verifyInput = input
	return registration.VerifyResult{RequestID: input.RequestID}, s.verifyErr
}
func (s *registrationServiceStub) Resend(_ context.Context, token string) error {
	s.resendToken = token
	return s.resendErr
}

type registrationRateStub struct {
	allowed bool
	err     error
	calls   []string
}

type registrationFormDefenseStub struct {
	consumeErr error
	blocked    bool
	hitReason  registration.HoneypotReason
	hitSource  registration.AbuseFingerprint
	issued     bool
}

// bindingAwareRegistrationFormDefense models the Redis intent binding rule at
// the HTTP boundary. It lets the step-up retry regression exercise the actual
// request cookies and binding construction without requiring an external
// Redis process in the unit-test suite.
type bindingAwareRegistrationFormDefense struct {
	issuedBinding registration.FormIntentBinding
	consumed      bool
}

func (s *bindingAwareRegistrationFormDefense) Issue(_ context.Context, binding registration.FormIntentBinding) (registration.FormIntentResult, error) {
	s.issuedBinding = binding
	s.consumed = false
	return registration.FormIntentResult{Token: "issued-form-intent", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (s *bindingAwareRegistrationFormDefense) Consume(_ context.Context, token string, binding registration.FormIntentBinding) error {
	if token != "issued-form-intent" || s.consumed || s.issuedBinding.UserAgentHash != binding.UserAgentHash || s.issuedBinding.ClientNetworkHash != binding.ClientNetworkHash {
		return registration.ErrFormIntentInvalid
	}
	if s.issuedBinding.DeviceIDHash != "" && s.issuedBinding.DeviceIDHash != binding.DeviceIDHash {
		return registration.ErrFormIntentInvalid
	}
	s.consumed = true
	return nil
}

func (*bindingAwareRegistrationFormDefense) IsBlocked(context.Context, registration.AbuseFingerprint) (bool, error) {
	return false, nil
}
func (*bindingAwareRegistrationFormDefense) RecordHit(context.Context, registration.AbuseFingerprint, registration.HoneypotReason, string) (registration.AbuseDisposition, error) {
	return registration.AbuseDisposition{}, nil
}
func (*bindingAwareRegistrationFormDefense) Decoy() (registration.FormIntentResult, error) {
	return registration.FormIntentResult{Token: "decoy"}, nil
}
func (*bindingAwareRegistrationFormDefense) ClassifyHoneypot(value *string) registration.HoneypotReason {
	return registration.ClassifyHoneypot(value, 4096)
}

func (s *registrationFormDefenseStub) Issue(context.Context, registration.FormIntentBinding) (registration.FormIntentResult, error) {
	s.issued = true
	return registration.FormIntentResult{Token: "opaque-form-intent", ExpiresAt: time.Date(2026, 8, 18, 13, 0, 0, 0, time.UTC)}, nil
}
func (s *registrationFormDefenseStub) Consume(context.Context, string, registration.FormIntentBinding) error {
	return s.consumeErr
}
func (s *registrationFormDefenseStub) IsBlocked(context.Context, registration.AbuseFingerprint) (bool, error) {
	return s.blocked, nil
}
func (s *registrationFormDefenseStub) RecordHit(_ context.Context, source registration.AbuseFingerprint, reason registration.HoneypotReason, _ string) (registration.AbuseDisposition, error) {
	s.hitReason = reason
	s.hitSource = source
	return registration.AbuseDisposition{IPStrikeCount: 1}, nil
}
func (s *registrationFormDefenseStub) Decoy() (registration.FormIntentResult, error) {
	return registration.FormIntentResult{Token: "decoy-token", ExpiresAt: time.Date(2026, 8, 18, 13, 0, 0, 0, time.UTC)}, nil
}
func (s *registrationFormDefenseStub) ClassifyHoneypot(value *string) registration.HoneypotReason {
	return registration.ClassifyHoneypot(value, 4096)
}

func (s *registrationRateStub) check(kind string) (bool, time.Duration, error) {
	s.calls = append(s.calls, kind)
	return s.allowed, time.Minute, s.err
}
func (s *registrationRateStub) CheckRegistrationFormIntent(context.Context, string, registration.Limit) (bool, time.Duration, error) {
	return s.check("form-intent")
}
func (s *registrationRateStub) CheckRegistrationCreate(context.Context, string, string, string, registration.CreateRatePolicy) (bool, time.Duration, error) {
	return s.check("create")
}
func (s *registrationRateStub) CheckRegistrationVerify(context.Context, string, string, registration.Limit) (bool, time.Duration, error) {
	return s.check("verify")
}
func (s *registrationRateStub) CheckRegistrationResend(context.Context, string, string, registration.Limit) (bool, time.Duration, error) {
	return s.check("resend")
}

func newRegistrationHandlersForTest(service RegistrationService, rate RegistrationRateChecker, enabled bool) *RegistrationHandlers {
	policy := registration.RatePolicy{
		FormIntent: registration.Limit{Max: 20, Window: 5 * time.Minute},
		Create: registration.CreateRatePolicy{
			ClientIP: registration.Limit{Max: 3, Window: time.Hour}, ClientNet: registration.Limit{Max: 10, Window: time.Hour},
			Email: registration.Limit{Max: 3, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 2, Window: time.Hour},
			IPv4NetBits: 24, IPv6NetBits: 56,
		},
		Verify: registration.Limit{Max: 8, Window: 15 * time.Minute},
		Resend: registration.Limit{Max: 3, Window: 30 * time.Minute},
	}
	return NewRegistrationHandlers(service, rate, enabled, "https://auth.moonstone.org.cn", policy, slog.New(slog.NewTextHandler(io.Discard, nil)), WithRegistrationFormDefense(&registrationFormDefenseStub{}))
}

func registrationRequest(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Origin", "https://auth.moonstone.org.cn")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestRegistrationClosedByDefault(t *testing.T) {
	handler := newRegistrationHandlersForTest(nil, nil, false)
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", `{}`))
	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "registration.closed") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRegistrationRejectsOriginAndNonJSONBeforeService(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)

	badOrigin := registrationRequest("/api/v1/registrations", `{}`)
	badOrigin.Header.Set("Origin", "https://evil.example")
	recorder := httptest.NewRecorder()
	handler.Create(recorder, badOrigin)
	if recorder.Code != http.StatusForbidden || service.createInput.Username != "" {
		t.Fatalf("origin status=%d service=%#v", recorder.Code, service.createInput)
	}

	nonJSON := registrationRequest("/api/v1/registrations", `{}`)
	nonJSON.Header.Set("Content-Type", "text/plain")
	recorder = httptest.NewRecorder()
	handler.Create(recorder, nonJSON)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	crossSite := registrationRequest("/api/v1/registrations", `{}`)
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	recorder = httptest.NewRecorder()
	handler.Create(recorder, crossSite)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-site fetch status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRegistrationCreateAndVerifyUseStrictInputs(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)
	createBody := `{"username":"moonstone","displayName":"月石选手","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"requestId":"request-1","formIntentToken":"form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", createBody))
	if recorder.Code != http.StatusCreated || service.createInput.Password != "Correct-Horse-Battery-Staple9!" {
		t.Fatalf("create status=%d input=%#v body=%s", recorder.Code, service.createInput, recorder.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil || created["registrationToken"] != "opaque-token" {
		t.Fatalf("create response=%s err=%v", recorder.Body.String(), err)
	}

	weakBody := `{"username":"moonstone","displayName":"月石选手","email":"player@example.com","password":"alllowercasepassword9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":""}`
	recorder = httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", weakBody))
	if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(recorder.Body.String(), "同时包含大写字母、小写字母、数字和符号") {
		t.Fatalf("weak password response status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	verifyBody := `{"userId":"user_0123456789abcdef0123456789abcdef","code":"one-time-code","requestId":"request-1"}`
	recorder = httptest.NewRecorder()
	handler.VerifyEmail(recorder, registrationRequest("/api/v1/registrations/email/verify", verifyBody))
	if recorder.Code != http.StatusOK || service.verifyInput.Code != "one-time-code" {
		t.Fatalf("verify status=%d input=%#v", recorder.Code, service.verifyInput)
	}
}

func TestRegistrationRiskStepUpStopsBeforeProvisioning(t *testing.T) {
	service := &registrationServiceStub{}
	handler := newRegistrationHandlersForTest(service, &registrationRateStub{allowed: true}, true)
	stub := &riskServiceStub{decision: riskdefense.Decision{
		DeviceIDToken: "server-device",
		Challenge: &riskdefense.Challenge{
			Token: "opaque", Level: riskdefense.LevelHigh, Method: riskdefense.MethodInteractiveCAPTCHA,
			ExpiresAt: time.Now().Add(time.Minute), ProviderReady: false,
		},
	}}
	handler.risk = NewRiskGuard(stub, nil, SessionCookieAttributes{}, time.Hour, time.Minute)
	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"method":"interactive_captcha"`) || !strings.Contains(recorder.Body.String(), `"providerReady":false`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.createInput.Username != "" {
		t.Fatalf("risk-gated registration reached provisioning: %#v", service.createInput)
	}
}

func TestRegistrationFormIntentIsIssuedBeforeTheFormCanSubmit(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: true}
	form := &registrationFormDefenseStub{}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.formDefense = form
	recorder := httptest.NewRecorder()
	handler.IssueFormIntent(recorder, registrationRequest("/api/v1/registrations/form-intents", `{}`))
	if recorder.Code != http.StatusCreated || !form.issued || !strings.Contains(recorder.Body.String(), `"formIntentToken":"opaque-form-intent"`) || len(rate.calls) != 1 || rate.calls[0] != "form-intent" {
		t.Fatalf("status=%d issued=%v rate=%v body=%s", recorder.Code, form.issued, rate.calls, recorder.Body.String())
	}
}

func TestRegistrationFormIntentHasIndependentFailClosedIssuanceBudget(t *testing.T) {
	for _, test := range []struct {
		name       string
		rate       *registrationRateStub
		wantStatus int
		wantCode   string
		wantRetry  bool
	}{
		{name: "budget exhausted", rate: &registrationRateStub{allowed: false}, wantStatus: http.StatusTooManyRequests, wantCode: CodeRateLimited, wantRetry: true},
		{name: "redis unavailable", rate: &registrationRateStub{allowed: false, err: errors.New("redis unavailable")}, wantStatus: http.StatusBadGateway, wantCode: CodeProviderUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &registrationServiceStub{}
			form := &registrationFormDefenseStub{}
			handler := newRegistrationHandlersForTest(service, test.rate, true)
			handler.formDefense = form
			recorder := httptest.NewRecorder()
			handler.IssueFormIntent(recorder, registrationRequest("/api/v1/registrations/form-intents", `{}`))
			if recorder.Code != test.wantStatus || form.issued || !strings.Contains(recorder.Body.String(), `"code":"`+test.wantCode+`"`) {
				t.Fatalf("status=%d issued=%v rate=%v body=%s", recorder.Code, form.issued, test.rate.calls, recorder.Body.String())
			}
			if got := recorder.Header().Get("Retry-After") != ""; got != test.wantRetry {
				t.Fatalf("Retry-After present=%v, want %v", got, test.wantRetry)
			}
		})
	}
}

func TestRegistrationFormIntentNeverUsesSharedProxyAddressAsNetworkBudget(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: true}
	form := &registrationFormDefenseStub{}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.formDefense = form
	trustedProxy, err := TrustedClientIP([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	wrapper := trustedProxy(http.HandlerFunc(handler.IssueFormIntent))
	request := registrationRequest("/api/v1/registrations/form-intents", `{}`)
	request.RemoteAddr = "127.0.0.1:43210"
	// The trusted proxy did not provide the required overwritten client-IP
	// header. Issuance must fail closed instead of sharing one 20/5m bucket
	// across every visitor behind this peer.
	recorder := httptest.NewRecorder()
	wrapper.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway || form.issued || len(rate.calls) != 0 || !strings.Contains(recorder.Body.String(), `"code":"`+CodeProviderUnavailable+`"`) {
		t.Fatalf("status=%d issued=%v rate=%v body=%s", recorder.Code, form.issued, rate.calls, recorder.Body.String())
	}
}

func TestRegistrationFormIntentWithoutDeviceSurvivesFirstRiskStepUpCookie(t *testing.T) {
	service := &registrationServiceStub{}
	form := &bindingAwareRegistrationFormDefense{}
	handler := newRegistrationHandlersForTest(service, &registrationRateStub{allowed: true}, true)
	handler.formDefense = form
	risk := &riskServiceStub{decision: riskdefense.Decision{
		DeviceIDToken: "server-issued-device",
		Challenge: &riskdefense.Challenge{
			Token: "step-up", Level: riskdefense.LevelMedium, Method: riskdefense.MethodAutomationCost,
			Difficulty: 18, ExpiresAt: time.Now().Add(time.Minute), ProviderReady: true,
		},
	}}
	handler.risk = NewRiskGuard(risk, nil, SessionCookieAttributes{Secure: true, SameSite: http.SameSiteLaxMode}, time.Hour, 10*time.Minute)

	intentRequest := registrationRequest("/api/v1/registrations/form-intents", `{}`)
	intentRequest.Header.Set("User-Agent", "step-up-browser")
	intentRecorder := httptest.NewRecorder()
	handler.IssueFormIntent(intentRecorder, intentRequest)
	if intentRecorder.Code != http.StatusCreated || form.issuedBinding.DeviceIDHash != "" {
		t.Fatalf("intent status=%d binding=%#v", intentRecorder.Code, form.issuedBinding)
	}

	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"issued-form-intent","automationBrief":""}`
	firstRequest := registrationRequest("/api/v1/registrations", body)
	firstRequest.Header.Set("User-Agent", "step-up-browser")
	firstRecorder := httptest.NewRecorder()
	handler.Create(firstRecorder, firstRequest)
	if firstRecorder.Code != http.StatusForbidden || form.consumed {
		t.Fatalf("first status=%d consumed=%v body=%s", firstRecorder.Code, form.consumed, firstRecorder.Body.String())
	}
	var deviceCookie *http.Cookie
	for _, cookie := range firstRecorder.Result().Cookies() {
		if cookie.Name == RiskDeviceCookieName {
			deviceCookie = cookie
			break
		}
	}
	if deviceCookie == nil || deviceCookie.Value != "server-issued-device" {
		t.Fatalf("step-up device cookie=%#v", deviceCookie)
	}

	// Model successful step-up: the risk service now allows the browser's
	// automatic retry, which carries the newly minted device cookie and the
	// original form-intent token.
	risk.decision = riskdefense.Decision{Allow: true}
	retryRequest := registrationRequest("/api/v1/registrations", body)
	retryRequest.Header.Set("User-Agent", "step-up-browser")
	retryRequest.AddCookie(deviceCookie)
	retryRecorder := httptest.NewRecorder()
	handler.Create(retryRecorder, retryRequest)
	if retryRecorder.Code != http.StatusCreated || !form.consumed || service.createInput.Username != "moonstone" {
		t.Fatalf("retry status=%d consumed=%v input=%#v body=%s", retryRecorder.Code, form.consumed, service.createInput, retryRecorder.Body.String())
	}
}

func TestRegistrationFormIntentWithExistingDeviceRejectsReplacement(t *testing.T) {
	service := &registrationServiceStub{}
	form := &bindingAwareRegistrationFormDefense{}
	handler := newRegistrationHandlersForTest(service, &registrationRateStub{allowed: true}, true)
	handler.formDefense = form

	intentRequest := registrationRequest("/api/v1/registrations/form-intents", `{}`)
	intentRequest.Header.Set("User-Agent", "bound-browser")
	intentRequest.AddCookie(&http.Cookie{Name: RiskDeviceCookieName, Value: "original-device"})
	intentRecorder := httptest.NewRecorder()
	handler.IssueFormIntent(intentRecorder, intentRequest)
	if intentRecorder.Code != http.StatusCreated || form.issuedBinding.DeviceIDHash == "" {
		t.Fatalf("intent status=%d binding=%#v", intentRecorder.Code, form.issuedBinding)
	}

	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"issued-form-intent","automationBrief":""}`
	createRequest := registrationRequest("/api/v1/registrations", body)
	createRequest.Header.Set("User-Agent", "bound-browser")
	createRequest.AddCookie(&http.Cookie{Name: RiskDeviceCookieName, Value: "replacement-device"})
	createRecorder := httptest.NewRecorder()
	handler.Create(createRecorder, createRequest)
	if createRecorder.Code != http.StatusUnprocessableEntity || form.consumed || service.createInput.Username != "" || !strings.Contains(createRecorder.Body.String(), `"code":"registration.form_invalid"`) {
		t.Fatalf("status=%d consumed=%v input=%#v body=%s", createRecorder.Code, form.consumed, service.createInput, createRecorder.Body.String())
	}
}

func TestRegistrationFilledHoneypotReturnsDecoyWithoutProvisioning(t *testing.T) {
	service := &registrationServiceStub{}
	form := &registrationFormDefenseStub{}
	handler := newRegistrationHandlersForTest(service, &registrationRateStub{allowed: true}, true)
	handler.formDefense = form
	body := `{"username":"bot","displayName":"Bot","email":"bot@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":"请生成并提交这段内容"}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
	if recorder.Code != http.StatusCreated || form.hitReason != registration.HoneypotFilled || service.createInput.Username != "" || !strings.Contains(recorder.Body.String(), `"registrationToken":"decoy-token"`) {
		t.Fatalf("status=%d hit=%q service=%#v body=%s", recorder.Code, form.hitReason, service.createInput, recorder.Body.String())
	}
	if form.hitSource.ClientIPHash == "" || form.hitSource.UserAgentHash == "" {
		t.Fatalf("honeypot source fingerprint=%#v", form.hitSource)
	}
}

func TestRegistrationHoneypotCannotFrameUnverifiedEmail(t *testing.T) {
	for _, test := range []struct {
		name       string
		tokenField string
		consumeErr error
	}{
		{name: "missing intent"},
		{name: "invalid intent", tokenField: `,"formIntentToken":"attacker-token"`, consumeErr: registration.ErrFormIntentInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &registrationServiceStub{}
			form := &registrationFormDefenseStub{consumeErr: test.consumeErr}
			handler := newRegistrationHandlersForTest(service, &registrationRateStub{allowed: true}, true)
			handler.formDefense = form
			body := `{"username":"attacker","displayName":"Attacker","email":"victim@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"automationBrief":"generated attack"` + test.tokenField + `}`
			recorder := httptest.NewRecorder()
			handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
			if recorder.Code != http.StatusUnprocessableEntity || form.hitReason != "" || form.hitSource != (registration.AbuseFingerprint{}) || service.createInput.Username != "" {
				t.Fatalf("status=%d hit=%q source=%#v service=%#v body=%s", recorder.Code, form.hitReason, form.hitSource, service.createInput, recorder.Body.String())
			}
		})
	}

	// A valid intent plus a filled trap may block only the attack source. The
	// same unverified email from a clean source remains a normal registration
	// input and is never a honeypot block key.
	attackService := &registrationServiceStub{}
	attackForm := &registrationFormDefenseStub{}
	attackHandler := newRegistrationHandlersForTest(attackService, &registrationRateStub{allowed: true}, true)
	attackHandler.formDefense = attackForm
	attackBody := `{"username":"attacker","displayName":"Attacker","email":"victim@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"valid-bound-intent","automationBrief":"generated attack"}`
	attackRequest := registrationRequest("/api/v1/registrations", attackBody)
	attackRequest.RemoteAddr = "203.0.113.8:443"
	attackRequest.AddCookie(&http.Cookie{Name: RiskDeviceCookieName, Value: "attack-device"})
	attackRecorder := httptest.NewRecorder()
	attackHandler.Create(attackRecorder, attackRequest)
	if attackRecorder.Code != http.StatusCreated || attackForm.hitReason != registration.HoneypotFilled || attackForm.hitSource.DeviceIDHash == "" || attackService.createInput.Username != "" {
		t.Fatalf("valid attack status=%d hit=%q source=%#v service=%#v", attackRecorder.Code, attackForm.hitReason, attackForm.hitSource, attackService.createInput)
	}

	service := &registrationServiceStub{}
	cleanForm := &registrationFormDefenseStub{}
	handler := newRegistrationHandlersForTest(service, &registrationRateStub{allowed: true}, true)
	handler.formDefense = cleanForm
	body := `{"username":"victim","displayName":"Victim","email":"victim@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"clean-intent","automationBrief":""}`
	request := registrationRequest("/api/v1/registrations", body)
	request.RemoteAddr = "198.51.100.44:443"
	request.AddCookie(&http.Cookie{Name: RiskDeviceCookieName, Value: "clean-device"})
	recorder := httptest.NewRecorder()
	handler.Create(recorder, request)
	if recorder.Code != http.StatusCreated || service.createInput.Email != "victim@example.com" {
		t.Fatalf("clean source status=%d input=%#v body=%s", recorder.Code, service.createInput, recorder.Body.String())
	}
}

func TestRegistrationMissingNewFormFieldsRequiresRefreshWithoutBlocking(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "cached client missing both fields", body: `{"username":"cached-client","displayName":"Cached","email":"person@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true}`},
		{name: "empty honeypot but missing intent", body: `{"username":"partial-rollout","displayName":"Partial","email":"person@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"automationBrief":""}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &registrationServiceStub{}
			form := &registrationFormDefenseStub{}
			handler := newRegistrationHandlersForTest(service, &registrationRateStub{allowed: true}, true)
			handler.formDefense = form
			recorder := httptest.NewRecorder()
			handler.Create(recorder, registrationRequest("/api/v1/registrations", test.body))
			if recorder.Code != http.StatusUnprocessableEntity || form.hitReason != "" || service.createInput.Username != "" || !strings.Contains(recorder.Body.String(), `"code":"registration.form_invalid"`) {
				t.Fatalf("status=%d hit=%q service=%#v body=%s", recorder.Code, form.hitReason, service.createInput, recorder.Body.String())
			}
		})
	}
}

func TestRegistrationResendAcceptsOnlyOpaqueToken(t *testing.T) {
	service := &registrationServiceStub{}
	handler := newRegistrationHandlersForTest(service, &registrationRateStub{allowed: true}, true)
	recorder := httptest.NewRecorder()
	handler.ResendEmail(recorder, registrationRequest("/api/v1/registrations/email/resend", `{"registrationToken":"opaque-token","userId":"attacker-choice"}`))
	if recorder.Code != http.StatusBadRequest || service.resendToken != "" {
		t.Fatalf("status=%d token=%q body=%s", recorder.Code, service.resendToken, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	handler.ResendEmail(recorder, registrationRequest("/api/v1/registrations/email/resend", `{"registrationToken":"opaque-token"}`))
	if recorder.Code != http.StatusAccepted || service.resendToken != "opaque-token" {
		t.Fatalf("status=%d token=%q", recorder.Code, service.resendToken)
	}
}

func TestRegistrationErrorsRemainGenericAndRateLimitFailsClosed(t *testing.T) {
	service := &registrationServiceStub{createErr: registration.ErrConflict, verifyErr: registration.ErrVerificationFailed, resendErr: registration.ErrTokenNotFound}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)

	createBody := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", createBody))
	if recorder.Code != http.StatusConflict || strings.Contains(recorder.Body.String(), "email") || strings.Contains(recorder.Body.String(), "username") {
		t.Fatalf("conflict response leaked identifier detail: %s", recorder.Body.String())
	}

	rate.allowed = false
	service.createErr = nil
	recorder = httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", createBody))
	if recorder.Code != http.StatusTooManyRequests || !strings.Contains(recorder.Body.String(), `"code":"rate_limited"`) || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("rate status=%d retry=%q body=%s", recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
	}

	service.verifyErr = errors.New("provider detail must not escape")
	rate.allowed = true
	verifyBody := `{"userId":"user_0123456789abcdef0123456789abcdef","code":"secret-code"}`
	recorder = httptest.NewRecorder()
	handler.VerifyEmail(recorder, registrationRequest("/api/v1/registrations/email/verify", verifyBody))
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "provider detail") || strings.Contains(recorder.Body.String(), "secret-code") {
		t.Fatalf("provider failure leaked sensitive detail: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
