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
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

type registrationServiceStub struct {
	createInput registration.CreateInput
	createCalls int
	verifyInput registration.VerifyInput
	resendToken string
	createErr   error
	verifyErr   error
	resendErr   error
}

func (s *registrationServiceStub) Create(_ context.Context, input registration.CreateInput) (registration.CreateResult, error) {
	s.createCalls++
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
	mu            sync.Mutex
	allowed       bool
	err           error
	calls         []string
	createLimit   int
	createCalls   int
	refundCalls   int
	refundErr     error
	refundNet     string
	refundEmail   string
	refundIntent  string
	cohortSubject registration.CreateRateSubject
	retryAfter    time.Duration
	chains        map[string]registrationRateChainStub
}

type registrationRateChainStub struct {
	binding string
	uses    int
	allowed bool
}

type registrationEmailRiskStub struct{}

func (registrationEmailRiskStub) Validate(context.Context, string) error { return nil }
func (registrationEmailRiskStub) Profile(email string) (registration.EmailDomainProfile, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[1] == "" {
		return registration.EmailDomainProfile{}, registration.ErrInvalidInput
	}
	return registration.EmailDomainProfile{Domain: strings.ToLower(parts[1]), Established: true}, nil
}
func (registrationEmailRiskStub) Assess(_ context.Context, email string) (registration.EmailAssessment, error) {
	profile, err := (registrationEmailRiskStub{}).Profile(email)
	if err != nil {
		return registration.EmailAssessment{}, err
	}
	return registration.EmailAssessment{Domain: profile.Domain, DomainGroup: profile.Domain, DomainEstablished: true, MXEstablished: true}, nil
}

type registrationAdmissionStub struct{ err error }

func (s registrationAdmissionStub) Acquire(context.Context, string, bool) (func(), error) {
	if s.err != nil {
		return nil, s.err
	}
	return func() {}, nil
}

type registrationFormDefenseStub struct {
	bindErr      error
	consumeErr   error
	blocked      bool
	hitReason    registration.HoneypotReason
	hitSource    registration.AbuseFingerprint
	issued       bool
	consumeCalls int
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

func (s *bindingAwareRegistrationFormDefense) BindEmail(_ context.Context, token string, binding registration.FormIntentBinding) error {
	if token != "issued-form-intent" || s.consumed || binding.EmailHash == "" || s.issuedBinding.UserAgentHash != binding.UserAgentHash || s.issuedBinding.ClientNetworkHash != binding.ClientNetworkHash || s.issuedBinding.DeviceIDHash != binding.DeviceIDHash || s.issuedBinding.OriginHash != binding.OriginHash {
		return registration.ErrFormIntentInvalid
	}
	if s.issuedBinding.EmailHash != "" && s.issuedBinding.EmailHash != binding.EmailHash {
		return registration.ErrFormIntentInvalid
	}
	s.issuedBinding.EmailHash = binding.EmailHash
	return nil
}

func (s *bindingAwareRegistrationFormDefense) Consume(_ context.Context, token string, binding registration.FormIntentBinding) error {
	if token != "issued-form-intent" || s.consumed || s.issuedBinding.UserAgentHash != binding.UserAgentHash || s.issuedBinding.ClientNetworkHash != binding.ClientNetworkHash || s.issuedBinding.OriginHash != binding.OriginHash || s.issuedBinding.EmailHash != binding.EmailHash {
		return registration.ErrFormIntentInvalid
	}
	if s.issuedBinding.DeviceIDHash == "" || s.issuedBinding.DeviceIDHash != binding.DeviceIDHash {
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
func (s *registrationFormDefenseStub) BindEmail(context.Context, string, registration.FormIntentBinding) error {
	return s.bindErr
}
func (s *registrationFormDefenseStub) Consume(context.Context, string, registration.FormIntentBinding) error {
	s.consumeCalls++
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
	return s.allowed, s.retryDuration(), s.err
}

func (s *registrationRateStub) retryDuration() time.Duration {
	if s.retryAfter > 0 {
		return s.retryAfter
	}
	return time.Minute
}
func (s *registrationRateStub) CheckRegistrationFormIntent(context.Context, string, registration.Limit) (bool, time.Duration, error) {
	return s.check("form-intent")
}
func (s *registrationRateStub) CheckRegistrationFormIntentGlobal(context.Context, string, registration.Limit, registration.AggregateRatePolicy) (bool, time.Duration, error) {
	return s.check("form-intent-global")
}
func (s *registrationRateStub) CheckRegistrationFormIntentDevice(context.Context, string, registration.Limit) (bool, time.Duration, error) {
	return s.check("form-intent-device")
}
func (s *registrationRateStub) CheckRegistrationCreate(context.Context, string, string, string, registration.CreateRatePolicy) (bool, time.Duration, error) {
	return s.check("create")
}
func (s *registrationRateStub) CheckRegistrationCreateChain(_ context.Context, _, network, emailHash, formIntentHash string, _ registration.CreateRatePolicy, _ time.Duration) (registration.CreateChainRateOutcome, time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.chains == nil {
		s.chains = make(map[string]registrationRateChainStub)
	}
	binding := network + "\x00" + emailHash
	if chain, exists := s.chains[formIntentHash]; exists {
		if chain.binding != binding {
			return registration.CreateChainRateBindingMismatch, time.Minute, nil
		}
		if !chain.allowed {
			return registration.CreateChainRateLimited, time.Minute, nil
		}
		if chain.uses >= 2 {
			return registration.CreateChainRateReplayExhausted, time.Minute, nil
		}
		chain.uses++
		s.chains[formIntentHash] = chain
		return registration.CreateChainRateReplayAllowed, 0, nil
	}
	s.createCalls++
	s.calls = append(s.calls, "create")
	if s.err != nil {
		return registration.CreateChainRateUnknown, s.retryDuration(), s.err
	}
	allowed := s.allowed && (s.createLimit <= 0 || s.createCalls <= s.createLimit)
	if !allowed {
		return registration.CreateChainRateLimited, s.retryDuration(), nil
	}
	s.chains[formIntentHash] = registrationRateChainStub{binding: binding, uses: 1, allowed: true}
	return registration.CreateChainRateFirstAllowed, 0, nil
}
func (s *registrationRateStub) CheckRegistrationCreateChainWithCohorts(ctx context.Context, subject registration.CreateRateSubject, policy registration.CreateRatePolicy, markerTTL time.Duration) (registration.CreateChainRateOutcome, time.Duration, error) {
	s.mu.Lock()
	s.cohortSubject = subject
	s.mu.Unlock()
	return s.CheckRegistrationCreateChain(ctx, subject.ClientIP, subject.ClientNetwork, subject.EmailHash+subject.MailboxFamilyHash+subject.DomainHash+strings.Join(subject.MXHashes, ""), subject.FormIntentHash, policy, markerTTL)
}
func (s *registrationRateStub) RefundRegistrationCreateEmail(_ context.Context, network, emailHash, formIntentHash string) (bool, error) {
	s.refundCalls++
	s.refundNet = network
	s.refundEmail = emailHash
	s.refundIntent = formIntentHash
	return s.refundErr == nil, s.refundErr
}
func (s *registrationRateStub) RefundRegistrationCreateCohorts(ctx context.Context, subject registration.CreateRateSubject, _ registration.CreateRatePolicy) (bool, error) {
	return s.RefundRegistrationCreateEmail(ctx, subject.ClientNetwork, subject.EmailHash, subject.FormIntentHash)
}
func (s *registrationRateStub) CheckRegistrationVerify(context.Context, string, string, registration.Limit) (bool, time.Duration, error) {
	return s.check("verify")
}
func (s *registrationRateStub) CheckRegistrationVerifyWithGlobal(context.Context, string, string, registration.Limit, registration.AggregateRatePolicy) (bool, time.Duration, error) {
	return s.check("verify")
}
func (s *registrationRateStub) CheckRegistrationResend(context.Context, string, string, registration.Limit) (bool, time.Duration, error) {
	return s.check("resend")
}

func newRegistrationHandlersForTest(service RegistrationService, rate RegistrationRateChecker, enabled bool) *RegistrationHandlers {
	policy := registration.RatePolicy{
		FormIntent:       registration.Limit{Max: 20, Window: 5 * time.Minute},
		FormIntentDevice: registration.Limit{Max: 6, Window: 5 * time.Minute},
		FormIntentGlobal: registration.AggregateRatePolicy{
			Burst: registration.Limit{Max: 30, Window: 10 * time.Second}, Sustained: registration.Limit{Max: 300, Window: 5 * time.Minute},
		},
		FormIntentTTL: 20 * time.Minute,
		AdmissionWait: time.Second,
		Create: registration.CreateRatePolicy{
			ClientIP: registration.Limit{Max: 3, Window: time.Hour}, ClientNet: registration.Limit{Max: 10, Window: time.Hour},
			Email: registration.Limit{Max: 3, Window: 24 * time.Hour}, ClientEmail: registration.Limit{Max: 2, Window: time.Hour},
			MailboxFamily: registration.Limit{Max: 3, Window: 24 * time.Hour},
			IPv4NetBits:   24, IPv6NetBits: 56,
		},
		Verify: registration.Limit{Max: 8, Window: 15 * time.Minute},
		VerifyGlobal: registration.AggregateRatePolicy{
			Burst: registration.Limit{Max: 20, Window: 10 * time.Second}, Sustained: registration.Limit{Max: 100, Window: 5 * time.Minute},
		},
		Resend: registration.Limit{Max: 3, Window: 30 * time.Minute},
	}
	handler := NewRegistrationHandlers(service, rate, enabled, "https://auth.moonstone.org.cn", policy, slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithRegistrationFormDefense(&registrationFormDefenseStub{}),
		WithRegistrationEmailRisk(registrationEmailRiskStub{}),
		WithRegistrationAdmission(registrationAdmissionStub{}),
	)
	handler.risk = NewRiskGuard(
		&riskServiceStub{decision: riskdefense.Decision{Allow: true}},
		nil,
		SessionCookieAttributes{},
		time.Hour,
		time.Minute,
	)
	return handler
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
	if rate.refundCalls != 0 {
		t.Fatalf("successful registration unexpectedly refunded email budget: refunds=%d", rate.refundCalls)
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

func TestRegistrationVerificationQueueOverflowStopsBeforeProvider(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.admission = registrationAdmissionStub{err: registration.ErrAdmissionBusy}
	verifyBody := `{"userId":"user_0123456789abcdef0123456789abcdef","code":"one-time-code"}`
	recorder := httptest.NewRecorder()
	handler.VerifyEmail(recorder, registrationRequest("/api/v1/registrations/email/verify", verifyBody))
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" || service.verifyInput != (registration.VerifyInput{}) {
		t.Fatalf("status=%d retry=%q providerInput=%#v body=%s", recorder.Code, recorder.Header().Get("Retry-After"), service.verifyInput, recorder.Body.String())
	}
}

func TestRegistrationRiskStepUpStopsBeforeProvisioning(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)
	stub := &riskServiceStub{decision: riskdefense.Decision{
		DeviceIDToken: "server-device",
		Challenge: &riskdefense.Challenge{
			Token: "opaque", Level: riskdefense.LevelHigh, Method: riskdefense.MethodInteractiveCAPTCHA,
			ExpiresAt: time.Now().Add(time.Minute), Provider: "moonstone_image_digits", ProviderReady: true,
			PublicPayload: []byte(`{"imageDataUrl":"data:image/png;base64,iVBORw0KGgo=","digits":5}`),
		},
	}}
	handler.risk = NewRiskGuard(stub, nil, SessionCookieAttributes{}, time.Hour, time.Minute)
	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"method":"interactive_captcha"`) || !strings.Contains(recorder.Body.String(), `"provider":"moonstone_image_digits"`) || !strings.Contains(recorder.Body.String(), `"providerReady":true`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.createInput.Username != "" || rate.createCalls != 0 || len(rate.calls) != 0 {
		t.Fatalf("risk-gated registration reached provisioning or spent create budget: input=%#v rate=%v calls=%d", service.createInput, rate.calls, rate.createCalls)
	}
}

func TestRegistrationFailsClosedWithoutMandatoryRiskGuard(t *testing.T) {
	service := &registrationServiceStub{}
	handler := newRegistrationHandlersForTest(service, &registrationRateStub{allowed: true}, true)
	handler.risk = nil
	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
	if recorder.Code != http.StatusBadGateway || service.createInput.Username != "" || !strings.Contains(recorder.Body.String(), `"code":"provider.unavailable"`) {
		t.Fatalf("status=%d input=%#v body=%s", recorder.Code, service.createInput, recorder.Body.String())
	}
}

func TestRegistrationRiskBindingCoversEmailFormIntentAndOrigin(t *testing.T) {
	base := registrationRiskIdentifier(" Player@Example.com ", "form-intent-1", "https://auth.moonstone.org.cn")
	if base != registrationRiskIdentifier("player@example.com", "form-intent-1", "https://auth.moonstone.org.cn") {
		t.Fatal("email normalization changed the registration risk binding")
	}
	for name, changed := range map[string]string{
		"email":  registrationRiskIdentifier("other@example.com", "form-intent-1", "https://auth.moonstone.org.cn"),
		"intent": registrationRiskIdentifier("player@example.com", "form-intent-2", "https://auth.moonstone.org.cn"),
		"origin": registrationRiskIdentifier("player@example.com", "form-intent-1", "https://evil.example"),
	} {
		if changed == base {
			t.Fatalf("%s was not bound into the registration risk identifier", name)
		}
	}
}

func TestRegistrationRateSubjectAggregatesReviewedMailboxAliases(t *testing.T) {
	handler := newRegistrationHandlersForTest(&registrationServiceStub{}, &registrationRateStub{allowed: true}, true)
	request := registrationRequest("/api/v1/registrations", `{}`)
	assessment := registration.EmailAssessment{Domain: "gmail.com", DomainGroup: "gmail.com", DomainEstablished: true, MXEstablished: true}
	first := handler.registrationCreateRateSubject(request, "victim.name+one@gmail.com", "intent-one", assessment)
	second := handler.registrationCreateRateSubject(request, "victimname+two@googlemail.com", "intent-two", assessment)
	if first.EmailHash == second.EmailHash || first.MailboxFamilyHash == "" || first.MailboxFamilyHash != second.MailboxFamilyHash {
		t.Fatalf("mailbox family aggregation failed: first=%#v second=%#v", first, second)
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
	if recorder.Code != http.StatusCreated || !form.issued || !strings.Contains(recorder.Body.String(), `"formIntentToken":"opaque-form-intent"`) ||
		len(rate.calls) != 2 || rate.calls[0] != "form-intent-global" || rate.calls[1] != "form-intent-device" {
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

func TestRegistrationFormIntentEstablishesDeviceBeforeRiskStepUp(t *testing.T) {
	service := &registrationServiceStub{}
	form := &bindingAwareRegistrationFormDefense{}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.formDefense = form
	risk := &riskServiceStub{decision: riskdefense.Decision{
		DeviceIDToken: "server-issued-device",
		Challenge: &riskdefense.Challenge{
			Token: "step-up", Level: riskdefense.LevelHigh, Method: riskdefense.MethodInteractiveCAPTCHA,
			Provider: "moonstone_image_digits", PublicPayload: []byte(`{"imageDataUrl":"data:image/png;base64,iVBORw0KGgo=","digits":5}`),
			ExpiresAt: time.Now().Add(time.Minute), ProviderReady: true,
		},
	}}
	handler.risk = NewRiskGuard(risk, nil, SessionCookieAttributes{Secure: true, SameSite: http.SameSiteLaxMode}, time.Hour, 10*time.Minute)

	intentRequest := registrationRequest("/api/v1/registrations/form-intents", `{}`)
	intentRequest.Header.Set("User-Agent", "step-up-browser")
	intentRecorder := httptest.NewRecorder()
	handler.IssueFormIntent(intentRecorder, intentRequest)
	if intentRecorder.Code != http.StatusCreated || form.issuedBinding.DeviceIDHash == "" || form.issuedBinding.OriginHash == "" {
		t.Fatalf("intent status=%d binding=%#v", intentRecorder.Code, form.issuedBinding)
	}
	var intentDeviceCookie *http.Cookie
	for _, cookie := range intentRecorder.Result().Cookies() {
		if cookie.Name == RiskDeviceCookieName {
			intentDeviceCookie = cookie
			break
		}
	}
	if intentDeviceCookie == nil || intentDeviceCookie.Value != "server-issued-device" {
		t.Fatalf("intent device cookie=%#v", intentDeviceCookie)
	}

	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"issued-form-intent","automationBrief":""}`
	firstRequest := registrationRequest("/api/v1/registrations", body)
	firstRequest.Header.Set("User-Agent", "step-up-browser")
	firstRequest.AddCookie(intentDeviceCookie)
	firstRecorder := httptest.NewRecorder()
	handler.Create(firstRecorder, firstRequest)
	if firstRecorder.Code != http.StatusForbidden || form.consumed || len(rate.calls) != 2 || rate.calls[0] != "form-intent-global" || rate.calls[1] != "form-intent-device" || !strings.Contains(firstRecorder.Body.String(), `"provider":"moonstone_image_digits"`) {
		t.Fatalf("first status=%d consumed=%v rate=%v body=%s", firstRecorder.Code, form.consumed, rate.calls, firstRecorder.Body.String())
	}
	if risk.assessed.ClientNetworkHash == "" || risk.assessed.ClientNetworkHash != form.issuedBinding.ClientNetworkHash {
		t.Fatalf("risk network=%q form-intent network=%q", risk.assessed.ClientNetworkHash, form.issuedBinding.ClientNetworkHash)
	}
	deviceCookie := intentDeviceCookie
	for _, cookie := range firstRecorder.Result().Cookies() {
		if cookie.Name == RiskDeviceCookieName {
			t.Fatalf("risk step-up unexpectedly replaced established device cookie: %#v", cookie)
		}
	}
	changedEmailBody := strings.Replace(body, "player@example.com", "other@example.com", 1)
	changedEmailRequest := registrationRequest("/api/v1/registrations", changedEmailBody)
	changedEmailRequest.Header.Set("User-Agent", "step-up-browser")
	changedEmailRequest.AddCookie(deviceCookie)
	changedEmailRecorder := httptest.NewRecorder()
	handler.Create(changedEmailRecorder, changedEmailRequest)
	if changedEmailRecorder.Code != http.StatusUnprocessableEntity || form.consumed || service.createCalls != 0 || !strings.Contains(changedEmailRecorder.Body.String(), `"code":"registration.form_invalid"`) {
		t.Fatalf("changed-email status=%d consumed=%v calls=%d body=%s", changedEmailRecorder.Code, form.consumed, service.createCalls, changedEmailRecorder.Body.String())
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
	if retryRecorder.Code != http.StatusCreated || !form.consumed || service.createInput.Username != "moonstone" || service.createCalls != 1 || len(rate.calls) != 3 || rate.createCalls != 1 {
		t.Fatalf("retry status=%d consumed=%v input=%#v rate=%v body=%s", retryRecorder.Code, form.consumed, service.createInput, rate.calls, retryRecorder.Body.String())
	}

	// The successful retry consumes the form intent. Reusing the same solved
	// browser trust and request body cannot mint a second registration token.
	replayRequest := registrationRequest("/api/v1/registrations", body)
	replayRequest.Header.Set("User-Agent", "step-up-browser")
	replayRequest.AddCookie(deviceCookie)
	replayRecorder := httptest.NewRecorder()
	handler.Create(replayRecorder, replayRequest)
	if replayRecorder.Code != http.StatusUnprocessableEntity || service.createCalls != 1 || !strings.Contains(replayRecorder.Body.String(), `"code":"registration.form_invalid"`) {
		t.Fatalf("replay status=%d body=%s", replayRecorder.Code, replayRecorder.Body.String())
	}
}

func TestRegistrationForgedFormIntentCannotSpendEmailRateOrAllocateChallenge(t *testing.T) {
	service := &registrationServiceStub{}
	form := &registrationFormDefenseStub{bindErr: registration.ErrFormIntentInvalid}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.formDefense = form
	// Model the automatic retry after a correctly completed CAPTCHA. Even with
	// valid step-up trust, a caller-invented form intent must stop before account
	// provisioning and therefore cannot receive a real registration token.
	risk := &riskServiceStub{decision: riskdefense.Decision{Allow: true}}
	handler.risk = NewRiskGuard(
		risk,
		nil,
		SessionCookieAttributes{},
		time.Hour,
		time.Minute,
	)
	body := `{"username":"direct-client","displayName":"Direct","email":"direct@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"caller-invented","automationBrief":""}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
	if recorder.Code != http.StatusUnprocessableEntity || service.createInput.Username != "" || len(rate.calls) != 0 || risk.assessed != (riskdefense.Signal{}) || !strings.Contains(recorder.Body.String(), `"code":"registration.form_invalid"`) {
		t.Fatalf("status=%d input=%#v rate=%v risk=%#v body=%s", recorder.Code, service.createInput, rate.calls, risk.assessed, recorder.Body.String())
	}
}

func TestRegistrationTooYoungIntentDoesNotSpendCreateChainOrAllocateChallenge(t *testing.T) {
	service := &registrationServiceStub{}
	form := &registrationFormDefenseStub{bindErr: registration.ErrFormIntentTooYoung}
	rate := &registrationRateStub{allowed: true}
	risk := &riskServiceStub{decision: riskdefense.Decision{Allow: true}}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.formDefense = form
	handler.risk = NewRiskGuard(risk, nil, SessionCookieAttributes{}, time.Hour, time.Minute)

	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"too-young","automationBrief":""}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
	if recorder.Code != http.StatusUnprocessableEntity || rate.createCalls != 0 || len(rate.calls) != 0 || risk.assessed != (riskdefense.Signal{}) || service.createCalls != 0 || !strings.Contains(recorder.Body.String(), `"code":"registration.form_not_ready"`) {
		t.Fatalf("status=%d rate=%v calls=%d risk=%#v creates=%d body=%s", recorder.Code, rate.calls, rate.createCalls, risk.assessed, service.createCalls, recorder.Body.String())
	}
}

func TestRegistrationCreateChainAllowsOnePostChallengeCommitRetryOnly(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: true, createLimit: 1}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.formDefense = &registrationFormDefenseStub{consumeErr: registration.ErrUnavailable}
	handler.risk = NewRiskGuard(&riskServiceStub{decision: riskdefense.Decision{Allow: true}}, nil, SessionCookieAttributes{}, time.Hour, time.Minute)
	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":""}`

	for attempt, want := range []int{http.StatusBadGateway, http.StatusBadGateway, http.StatusUnprocessableEntity} {
		recorder := httptest.NewRecorder()
		handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
		if recorder.Code != want {
			t.Fatalf("attempt %d status=%d want=%d body=%s", attempt+1, recorder.Code, want, recorder.Body.String())
		}
	}
	if rate.createCalls != 1 || service.createCalls != 0 {
		t.Fatalf("create-chain charges=%d provisions=%d, want one charge and no provisioning", rate.createCalls, service.createCalls)
	}
}

func TestRegistrationCreateChainRejectsChangedEmailBindingBeforeProvisioning(t *testing.T) {
	rate := &registrationRateStub{allowed: true}
	risk := &riskServiceStub{decision: riskdefense.Decision{Allow: true}}
	service := &registrationServiceStub{}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.risk = NewRiskGuard(risk, nil, SessionCookieAttributes{}, time.Hour, time.Minute)
	body := func(email string) string {
		return `{"username":"moonstone","displayName":"Moonstone","email":"` + email + `","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":""}`
	}

	first := httptest.NewRecorder()
	handler.Create(first, registrationRequest("/api/v1/registrations", body("first@example.com")))
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	handler.Create(second, registrationRequest("/api/v1/registrations", body("second@example.com")))
	if second.Code != http.StatusUnprocessableEntity || rate.createCalls != 1 || service.createCalls != 1 || !strings.Contains(second.Body.String(), `"code":"registration.form_invalid"`) {
		t.Fatalf("changed binding status=%d charges=%d provisions=%d body=%s", second.Code, rate.createCalls, service.createCalls, second.Body.String())
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
	if form.hitSource.ClientIPBlockEligible {
		t.Fatal("IP blocking was enabled without an explicitly trusted edge assertion policy")
	}
}

func TestRegistrationAdmissionOverflowDoesNotConsumeIntentOrCreateBudget(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: true}
	form := &registrationFormDefenseStub{}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.formDefense = form
	handler.admission = registrationAdmissionStub{err: registration.ErrAdmissionBusy}
	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "1" || service.createCalls != 0 || rate.createCalls != 0 || form.consumeCalls != 0 {
		t.Fatalf("status=%d retry=%q creates=%d rates=%d consumes=%d body=%s", recorder.Code, recorder.Header().Get("Retry-After"), service.createCalls, rate.createCalls, form.consumeCalls, recorder.Body.String())
	}
}

type unfamiliarRegistrationEmailRiskStub struct{}

func (unfamiliarRegistrationEmailRiskStub) Validate(context.Context, string) error { return nil }
func (unfamiliarRegistrationEmailRiskStub) Profile(string) (registration.EmailDomainProfile, error) {
	return registration.EmailDomainProfile{Domain: "rare.example", Established: false}, nil
}
func (unfamiliarRegistrationEmailRiskStub) Assess(context.Context, string) (registration.EmailAssessment, error) {
	return registration.EmailAssessment{Domain: "rare.example", DomainGroup: "rare.example", MXGroups: []string{"mail-operator.example"}}, nil
}

func TestRegistrationHashesUnfamiliarDomainAndMXIntoAtomicCreateDecision(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)
	handler.emailRisk = unfamiliarRegistrationEmailRiskStub{}
	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@rare.example","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()
	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if rate.cohortSubject.DomainHash != registration.HashAbuseValue("rare.example") || len(rate.cohortSubject.MXHashes) != 1 || rate.cohortSubject.MXHashes[0] != registration.HashAbuseValue("mail-operator.example") {
		t.Fatalf("cohort subject = %#v", rate.cohortSubject)
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

func TestRegistrationConflictRefundsOnlyTheBoundEmailBudget(t *testing.T) {
	service := &registrationServiceStub{createErr: registration.ErrConflict}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)
	body := `{"username":"moonstone","displayName":"Moonstone","email":"Player@Example.COM","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"conflict-form-token","automationBrief":""}`
	request := registrationRequest("/api/v1/registrations", body)
	request.RemoteAddr = "203.0.113.27:443"
	recorder := httptest.NewRecorder()

	handler.Create(recorder, request)

	if recorder.Code != http.StatusConflict || rate.refundCalls != 1 {
		t.Fatalf("status=%d refunds=%d body=%s", recorder.Code, rate.refundCalls, recorder.Body.String())
	}
	if rate.refundNet != "203.0.113.0/24" ||
		rate.refundEmail != registration.HashAbuseValue("player@example.com") ||
		rate.refundIntent != registration.HashAbuseValue("conflict-form-token") {
		t.Fatalf("refund binding net=%q email=%q intent=%q", rate.refundNet, rate.refundEmail, rate.refundIntent)
	}
	if strings.Contains(recorder.Body.String(), "player@example.com") || strings.Contains(recorder.Body.String(), "moonstone") {
		t.Fatalf("conflict response leaked submitted identifiers: %s", recorder.Body.String())
	}
}

func TestRegistrationConflictRefundFailureDoesNotReplaceConflictResponse(t *testing.T) {
	service := &registrationServiceStub{createErr: registration.ErrConflict}
	rate := &registrationRateStub{allowed: true, refundErr: errors.New("redis unavailable")}
	handler := newRegistrationHandlersForTest(service, rate, true)
	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"conflict-form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()

	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))

	if recorder.Code != http.StatusConflict || rate.refundCalls != 1 || !strings.Contains(recorder.Body.String(), `"code":"registration.conflict"`) {
		t.Fatalf("status=%d refunds=%d body=%s", recorder.Code, rate.refundCalls, recorder.Body.String())
	}
}

func TestRegistrationNonConflictFailureNeverRefundsEmailBudget(t *testing.T) {
	service := &registrationServiceStub{createErr: registration.ErrUnavailable}
	rate := &registrationRateStub{allowed: true}
	handler := newRegistrationHandlersForTest(service, rate, true)
	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"failed-form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()

	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))

	if recorder.Code != http.StatusBadGateway || rate.refundCalls != 0 {
		t.Fatalf("status=%d refunds=%d body=%s", recorder.Code, rate.refundCalls, recorder.Body.String())
	}
}

func TestRegistrationRateLimitConvertsMillisecondsToRetryAfterSeconds(t *testing.T) {
	service := &registrationServiceStub{}
	rate := &registrationRateStub{allowed: false, retryAfter: 30_000 * time.Millisecond}
	handler := newRegistrationHandlersForTest(service, rate, true)
	body := `{"username":"moonstone","displayName":"Moonstone","email":"player@example.com","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"formIntentToken":"limited-form-token","automationBrief":""}`
	recorder := httptest.NewRecorder()

	handler.Create(recorder, registrationRequest("/api/v1/registrations", body))

	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "30" {
		t.Fatalf("status=%d retry=%q body=%s", recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
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
	limitedBody := strings.Replace(createBody, `"formIntentToken":"form-token"`, `"formIntentToken":"fresh-limited-token"`, 1)
	handler.Create(recorder, registrationRequest("/api/v1/registrations", limitedBody))
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
