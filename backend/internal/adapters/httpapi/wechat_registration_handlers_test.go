package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

type fakeWeChatRegistrationService struct {
	mu    sync.Mutex
	input wechatregistration.CreateInput
	err   error
	calls int
}

func (s *fakeWeChatRegistrationService) Create(_ context.Context, input wechatregistration.CreateInput) (registration.CreateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.input = input
	s.calls++
	if s.err != nil {
		return registration.CreateResult{}, s.err
	}
	return registration.CreateResult{RegistrationToken: "opaque-registration-token", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (s *fakeWeChatRegistrationService) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type fakeRegistrationRate struct {
	mu         sync.Mutex
	allow      bool
	key        string
	proofErr   error
	loginHash  string
	phoneHash  string
	proofCalls int
	usedLogins map[string]struct{}
	usedPhones map[string]struct{}
}

func (r *fakeRegistrationRate) CheckRegistrationCreate(_ context.Context, _, _ string, key string, _ registration.CreateRatePolicy) (bool, time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.key = key
	return r.allow, time.Minute, nil
}
func (r *fakeRegistrationRate) CheckRegistrationVerify(context.Context, string, string, registration.Limit) (bool, time.Duration, error) {
	return true, 0, nil
}
func (r *fakeRegistrationRate) CheckRegistrationResend(context.Context, string, string, registration.Limit) (bool, time.Duration, error) {
	return true, 0, nil
}
func (r *fakeRegistrationRate) ConsumeWeChatRegistrationProofs(_ context.Context, loginHash, phoneHash string, _ time.Duration) (bool, time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loginHash, r.phoneHash = loginHash, phoneHash
	r.proofCalls++
	if r.proofErr != nil {
		return false, time.Minute, r.proofErr
	}
	if r.usedLogins == nil {
		r.usedLogins = make(map[string]struct{})
		r.usedPhones = make(map[string]struct{})
	}
	if _, exists := r.usedLogins[loginHash]; exists {
		return false, time.Minute, nil
	}
	if _, exists := r.usedPhones[phoneHash]; exists {
		return false, time.Minute, nil
	}
	r.usedLogins[loginHash] = struct{}{}
	r.usedPhones[phoneHash] = struct{}{}
	return true, 0, nil
}

func (r *fakeRegistrationRate) proofSnapshot() (loginHash, phoneHash string, calls int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loginHash, r.phoneHash, r.proofCalls
}

func (r *fakeRegistrationRate) registrationKey() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.key
}

func validWeChatRegistrationBody(email, loginCode, phoneCode string) string {
	return `{"username":"moonstone","displayName":"Moonstone","email":"` + email + `","password":"Correct-Horse-Battery-Staple9!","acceptedTerms":true,"loginCode":"` + loginCode + `","phoneCode":"` + phoneCode + `"}`
}

func wechatRegistrationTestPolicy(limit int) registration.CreateRatePolicy {
	bucket := registration.Limit{Max: limit, Window: time.Minute}
	return registration.CreateRatePolicy{
		ClientIP: bucket, ClientNet: bucket, Email: bucket, ClientEmail: bucket,
		IPv4NetBits: 24, IPv6NetBits: 64,
	}
}

func performWeChatRegistration(h *WeChatRegistrationHandlers, body, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registrations/wechat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	rr := httptest.NewRecorder()
	h.Create(rr, req)
	return rr
}

func TestWeChatRegistrationRequiresCodesAndDoesNotRateLimitOnRawProof(t *testing.T) {
	service, rate := &fakeWeChatRegistrationService{}, &fakeRegistrationRate{allow: true}
	h := NewWeChatRegistrationHandlers(service, rate, wechatRegistrationTestPolicy(5), testLogger())
	body := validWeChatRegistrationBody("player@example.com", "login-code", "phone-code")
	rr := performWeChatRegistration(h, body, "203.0.113.10:1234")
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if service.input.LoginCode != "login-code" || service.input.PhoneCode != "phone-code" {
		t.Fatalf("input=%#v", service.input)
	}
	registrationKey := rate.registrationKey()
	if registrationKey == "player@example.com" || registrationKey == "login-code" || registrationKey == "phone-code" || registrationKey == "" {
		t.Fatalf("unsafe rate key=%q", registrationKey)
	}
	loginHash, phoneHash, proofCalls := rate.proofSnapshot()
	if proofCalls != 1 || loginHash == "login-code" || phoneHash == "phone-code" || len(loginHash) != 64 || len(phoneHash) != 64 {
		t.Fatalf("unsafe proof consumption: login=%q phone=%q calls=%d", loginHash, phoneHash, proofCalls)
	}
	if strings.Contains(rr.Body.String(), "login-code") || strings.Contains(rr.Body.String(), "phone-code") {
		t.Fatalf("response leaked proof: %s", rr.Body.String())
	}
}

func TestWeChatRegistrationDoesNotCreateWhenProviderProofRejected(t *testing.T) {
	service, rate := &fakeWeChatRegistrationService{err: registration.ErrInvalidInput}, &fakeRegistrationRate{allow: true}
	h := NewWeChatRegistrationHandlers(service, rate, wechatRegistrationTestPolicy(5), testLogger())
	rr := performWeChatRegistration(h, validWeChatRegistrationBody("player@example.com", "login-code", "phone-code"), "203.0.113.11:1234")
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWeChatRegistrationProofReplayIsGlobalAcrossIPs(t *testing.T) {
	for _, test := range []struct {
		name       string
		secondPeer string
	}{
		{name: "same IP", secondPeer: "203.0.113.20:2002"},
		{name: "different IP", secondPeer: "198.51.100.21:2002"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, rate := &fakeWeChatRegistrationService{}, &fakeRegistrationRate{allow: true}
			h := NewWeChatRegistrationHandlers(service, rate, wechatRegistrationTestPolicy(5), testLogger())
			body := validWeChatRegistrationBody("player@example.com", "one-login-code", "one-phone-code")
			first := performWeChatRegistration(h, body, "203.0.113.20:2001")
			second := performWeChatRegistration(h, body, test.secondPeer)
			if first.Code != http.StatusCreated || second.Code != http.StatusTooManyRequests {
				t.Fatalf("first=%d second=%d secondBody=%s", first.Code, second.Code, second.Body.String())
			}
			if service.callCount() != 1 {
				t.Fatalf("service calls=%d; replay reached provider/account creation", service.callCount())
			}
		})
	}
}

func TestWeChatRegistrationConcurrentReplayReachesServiceOnce(t *testing.T) {
	service, rate := &fakeWeChatRegistrationService{}, &fakeRegistrationRate{allow: true}
	h := NewWeChatRegistrationHandlers(service, rate, wechatRegistrationTestPolicy(100), testLogger())
	body := validWeChatRegistrationBody("player@example.com", "concurrent-login-code", "concurrent-phone-code")
	const attempts = 24
	start := make(chan struct{})
	statuses := make(chan int, attempts)
	var group sync.WaitGroup
	for i := 0; i < attempts; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			rr := performWeChatRegistration(h, body, fmt.Sprintf("203.0.113.%d:%d", 30+index, 3000+index))
			statuses <- rr.Code
		}(i)
	}
	close(start)
	group.Wait()
	close(statuses)
	created, denied := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusTooManyRequests:
			denied++
		default:
			t.Fatalf("unexpected status=%d", status)
		}
	}
	if created != 1 || denied != attempts-1 || service.callCount() != 1 {
		t.Fatalf("created=%d denied=%d serviceCalls=%d", created, denied, service.callCount())
	}
}

func TestWeChatRegistrationRedisProofFailureIsFailClosed(t *testing.T) {
	service := &fakeWeChatRegistrationService{}
	rate := &fakeRegistrationRate{allow: true, proofErr: errors.New("redis unavailable")}
	h := NewWeChatRegistrationHandlers(service, rate, wechatRegistrationTestPolicy(5), testLogger())
	rr := performWeChatRegistration(h, validWeChatRegistrationBody("player@example.com", "login-code", "phone-code"), "203.0.113.40:1234")
	if rr.Code != http.StatusTooManyRequests || service.callCount() != 0 {
		t.Fatalf("status=%d serviceCalls=%d body=%s", rr.Code, service.callCount(), rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "请求过于频繁，请稍后再试。") {
		t.Fatalf("rate-limit wording drifted: %s", rr.Body.String())
	}
}

func TestWeChatRegistrationPreservesCreateRateLimitBeforeProofConsumption(t *testing.T) {
	service := &fakeWeChatRegistrationService{}
	rate := &fakeRegistrationRate{allow: false}
	h := NewWeChatRegistrationHandlers(service, rate, wechatRegistrationTestPolicy(5), testLogger())
	rr := performWeChatRegistration(h, validWeChatRegistrationBody("player@example.com", "login-code", "phone-code"), "203.0.113.50:1234")
	_, _, proofCalls := rate.proofSnapshot()
	if rr.Code != http.StatusTooManyRequests || proofCalls != 0 || service.callCount() != 0 {
		t.Fatalf("status=%d proofCalls=%d serviceCalls=%d", rr.Code, proofCalls, service.callCount())
	}
}

func TestWeChatRegistrationRejectsMalformedProofBeforeAnyRateOrServiceCall(t *testing.T) {
	for _, test := range []struct {
		name      string
		loginCode string
		phoneCode string
	}{
		{name: "surrounding whitespace", loginCode: " login-code", phoneCode: "phone-code"},
		{name: "oversized", loginCode: strings.Repeat("a", 2049), phoneCode: "phone-code"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeWeChatRegistrationService{}
			rate := &fakeRegistrationRate{allow: true}
			h := NewWeChatRegistrationHandlers(service, rate, wechatRegistrationTestPolicy(5), testLogger())
			rr := performWeChatRegistration(h, validWeChatRegistrationBody("player@example.com", test.loginCode, test.phoneCode), "203.0.113.51:1234")
			_, _, proofCalls := rate.proofSnapshot()
			if rr.Code != http.StatusUnprocessableEntity || rate.registrationKey() != "" || proofCalls != 0 || service.callCount() != 0 {
				t.Fatalf("status=%d registrationKey=%q proofCalls=%d serviceCalls=%d body=%s", rr.Code, rate.registrationKey(), proofCalls, service.callCount(), rr.Body.String())
			}
		})
	}
}

func TestWeChatRegistrationMountRequiresMiniProgramMarkerAndJSON(t *testing.T) {
	service, rate := &fakeWeChatRegistrationService{}, &fakeRegistrationRate{allow: true}
	h := NewWeChatRegistrationHandlers(service, rate, wechatRegistrationTestPolicy(5), testLogger())
	router := chi.NewRouter()
	h.Mount(router)
	body := validWeChatRegistrationBody("player@example.com", "login-code", "phone-code")

	request := func(marker, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/registrations/wechat", strings.NewReader(body))
		if marker != "" {
			req.Header.Set("X-UnitedPass-Client", marker)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	if rr := request("", "application/json"); rr.Code != http.StatusNotFound {
		t.Fatalf("missing Mini Program marker status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := request(session.ClientKindMiniProgram, "text/plain"); rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON mutation status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := request(session.ClientKindMiniProgram, "application/json"); rr.Code != http.StatusCreated {
		t.Fatalf("valid Mini Program registration status=%d body=%s", rr.Code, rr.Body.String())
	}
}
