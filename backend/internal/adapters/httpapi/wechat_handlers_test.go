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

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
)

type fakeWeChatService struct {
	user       identity.User
	resolveErr error
	bindErr    error
	loginCode  string
	phoneCode  string
}

func (s *fakeWeChatService) ResolveLogin(_ context.Context, code string) (identity.User, error) {
	s.loginCode = code
	if s.resolveErr != nil {
		return identity.User{}, s.resolveErr
	}
	return s.user, nil
}

func (s *fakeWeChatService) BindVerifiedPhone(_ context.Context, _ identity.UserID, loginCode, phoneCode string) error {
	s.loginCode, s.phoneCode = loginCode, phoneCode
	return s.bindErr
}

type fakeWeChatSessions struct {
	input        session.CreateSessionInput
	err          error
	deletedToken string
	deleteErr    error
}

func (s *fakeWeChatSessions) DeleteSession(_ context.Context, token string) error {
	s.deletedToken = token
	return s.deleteErr
}

const fakeWeChatSessionBearer = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func (s *fakeWeChatSessions) CreateSession(_ context.Context, input session.CreateSessionInput) (session.CreateSessionResult, error) {
	s.input = input
	if s.err != nil {
		return session.CreateSessionResult{}, s.err
	}
	return session.CreateSessionResult{
		SessionToken: fakeWeChatSessionBearer,
		CSRFToken:    "csrf-token",
		Record:       session.SessionRecord{ExpiresAt: time.Now().Add(time.Hour)},
	}, nil
}

type fakeWeChatRateChecker struct {
	allow bool
	keys  []string
}

func (r *fakeWeChatRateChecker) CheckWeChatLogin(_ context.Context, _ string, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	r.keys = append(r.keys, key)
	return r.allow, time.Minute, nil
}

func (r *fakeWeChatRateChecker) CheckWeChatPhone(_ context.Context, _ string, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	r.keys = append(r.keys, key)
	return r.allow, time.Minute, nil
}

func TestWeChatLoginReturnsNativeBearerWithoutCookies(t *testing.T) {
	service := &fakeWeChatService{user: testUser()}
	sessions := &fakeWeChatSessions{}
	rate := &fakeWeChatRateChecker{allow: true}
	h := NewWeChatHandlers(service, sessions, rate, 5, time.Minute, testLogger())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/wechat/sessions", strings.NewReader(`{"code":"wx-login-code"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if service.loginCode != "wx-login-code" {
		t.Fatalf("service code=%q", service.loginCode)
	}
	if sessions.input.Provider != wechat.ProviderName || sessions.input.UserID != service.user.ID || sessions.input.ClientKind != session.ClientKindMiniProgram || sessions.input.Remember {
		t.Fatalf("session input=%+v", sessions.input)
	}
	if len(rate.keys) != 1 || rate.keys[0] == "wx-login-code" {
		t.Fatalf("rate key should be a non-raw hash: %#v", rate.keys)
	}
	var body struct {
		Status        string    `json:"status"`
		SessionBearer string    `json:"sessionBearer"`
		ExpiresAt     time.Time `json:"expiresAt"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Status != "authenticated" || body.SessionBearer != fakeWeChatSessionBearer || body.ExpiresAt.IsZero() {
		t.Fatalf("body=%s err=%v", rr.Body.String(), err)
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Fatalf("native bearer login must not write cookies: %+v", rr.Result().Cookies())
	}
}

func TestWeChatLoginRejectsNonJSONAndDoesNotCallProvider(t *testing.T) {
	service := &fakeWeChatService{user: testUser()}
	h := NewWeChatHandlers(service, &fakeWeChatSessions{}, &fakeWeChatRateChecker{allow: true}, 5, time.Minute, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/wechat/sessions", strings.NewReader(`{"code":"wx-login-code"}`))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	h.Login(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType || service.loginCode != "" {
		t.Fatalf("status=%d providerCode=%q", rr.Code, service.loginCode)
	}
}

func TestWeChatLoginDoesNotRevealWhetherBindingExists(t *testing.T) {
	service := &fakeWeChatService{resolveErr: wechat.ErrNotRegistered}
	h := NewWeChatHandlers(service, &fakeWeChatSessions{}, &fakeWeChatRateChecker{allow: true}, 5, time.Minute, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/wechat/sessions", strings.NewReader(`{"code":"wx-login-code"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Login(rr, req)
	if rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), "registered") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWeChatBindPhoneRejectsMismatchedBinding(t *testing.T) {
	service := &fakeWeChatService{bindErr: wechat.ErrBindingMismatch}
	h := NewWeChatHandlers(service, nil, &fakeWeChatRateChecker{allow: true}, 5, time.Minute, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/wechat/phone", strings.NewReader(`{"loginCode":"login-code","phoneCode":"phone-code"}`))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithPrincipal(req.Context(), session.Principal{UserID: identity.UserID("user_01TEST001")})
	rr := httptest.NewRecorder()
	h.BindPhone(rr, req.WithContext(ctx))
	if rr.Code != http.StatusUnprocessableEntity || strings.Contains(rr.Body.String(), "mismatch") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWeChatLoginFailsClosedOnRateLimitFailure(t *testing.T) {
	service := &fakeWeChatService{user: testUser()}
	rate := &failingWeChatRateChecker{}
	h := NewWeChatHandlers(service, &fakeWeChatSessions{}, rate, 5, time.Minute, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/wechat/sessions", strings.NewReader(`{"code":"wx-login-code"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Login(rr, req)
	if rr.Code != http.StatusTooManyRequests || service.loginCode != "" {
		t.Fatalf("status=%d providerCode=%q", rr.Code, service.loginCode)
	}
}

type failingWeChatRateChecker struct{}

func (failingWeChatRateChecker) CheckWeChatLogin(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	return false, time.Minute, errors.New("redis unavailable")
}

func (failingWeChatRateChecker) CheckWeChatPhone(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	return false, time.Minute, errors.New("redis unavailable")
}
