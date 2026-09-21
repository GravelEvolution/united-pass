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

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
)

type onboardingServiceStub struct {
	beginInput    wechatonboarding.BeginInput
	completeInput wechatonboarding.CompleteInput
	mfaInput      wechatonboarding.MFAInput
	beginResult   wechatonboarding.BeginResult
	complete      wechatonboarding.CompleteResult
	mfa           wechatonboarding.CompleteResult
	beginErr      error
	completeErr   error
	mfaErr        error
}

type onboardingRevokerStub struct {
	reference string
}

type onboardingPromotionStub struct {
	completedToken string
	scheduledToken string
	completeErr    error
	scheduleErr    error
}

func (s *onboardingPromotionStub) CompleteProviderSessionPromotion(_ context.Context, token string) error {
	s.completedToken = token
	return s.completeErr
}

func (s *onboardingPromotionStub) ScheduleProviderSessionCleanup(_ context.Context, token string) error {
	s.scheduledToken = token
	return s.scheduleErr
}

func (s *onboardingRevokerStub) RevokeProviderSession(_ context.Context, reference string) error {
	s.reference = reference
	return nil
}

func (s *onboardingServiceStub) Begin(_ context.Context, input wechatonboarding.BeginInput) (wechatonboarding.BeginResult, error) {
	s.beginInput = input
	return s.beginResult, s.beginErr
}

func (s *onboardingServiceStub) Complete(_ context.Context, input wechatonboarding.CompleteInput) (wechatonboarding.CompleteResult, error) {
	s.completeInput = input
	return s.complete, s.completeErr
}

func (s *onboardingServiceStub) CompleteMFA(_ context.Context, input wechatonboarding.MFAInput) (wechatonboarding.CompleteResult, error) {
	s.mfaInput = input
	return s.mfa, s.mfaErr
}

func onboardingRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UnitedPass-Client", session.ClientKindMiniProgram)
	return req
}

func onboardingRouter(service *onboardingServiceStub, sessions *fakeWeChatSessions, rate WeChatOnboardingBeginRateChecker) http.Handler {
	return onboardingRouterWithDependencies(service, sessions, rate, &onboardingRevokerStub{}, &onboardingPromotionStub{})
}

func onboardingRouterWithRevoker(service *onboardingServiceStub, sessions *fakeWeChatSessions, rate WeChatOnboardingBeginRateChecker, revoker WeChatOnboardingProviderSessionRevoker) http.Handler {
	return onboardingRouterWithDependencies(service, sessions, rate, revoker, &onboardingPromotionStub{})
}

func onboardingRouterWithDependencies(service *onboardingServiceStub, sessions *fakeWeChatSessions, rate WeChatOnboardingBeginRateChecker, revoker WeChatOnboardingProviderSessionRevoker, promotion WeChatOnboardingProviderSessionPromotion) http.Handler {
	handlers := NewWeChatOnboardingHandlers(service, sessions, rate, revoker, promotion, wechatRegistrationTestPolicy(5), 5, time.Minute, testLogger())
	router := chi.NewRouter()
	handlers.Mount(router)
	return router
}

func TestWeChatOnboardingRevokesProviderSessionWhenNativeSessionCreationFails(t *testing.T) {
	service := &onboardingServiceStub{complete: wechatonboarding.CompleteResult{
		Status: wechatonboarding.StatusAuthenticated,
		Authentication: auth.AuthenticationResult{
			Status: auth.StatusAuthenticated, UserID: "user_existing", Provider: "zitadel",
			ProviderSessionReference: "provider-session", AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		},
	}}
	revoker := &onboardingRevokerStub{}
	router := onboardingRouterWithRevoker(service, &fakeWeChatSessions{err: errors.New("session store unavailable")}, &fakeWeChatRateChecker{allow: true}, revoker)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding/complete", `{"onboardingToken":"token","email":"existing@example.com","password":"password","acceptedTerms":true}`))
	if rr.Code != http.StatusInternalServerError || revoker.reference != "provider-session" {
		t.Fatalf("status=%d revoked=%q body=%s", rr.Code, revoker.reference, rr.Body.String())
	}
}

func TestWeChatOnboardingBeginReturnsOpaqueChallenge(t *testing.T) {
	expires := time.Now().UTC().Add(5 * time.Minute)
	service := &onboardingServiceStub{beginResult: wechatonboarding.BeginResult{Status: wechatonboarding.StatusOnboardingRequired, OnboardingToken: "opaque-onboarding-token", ExpiresAt: expires}}
	router := onboardingRouter(service, &fakeWeChatSessions{}, &fakeWeChatRateChecker{allow: true})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding", `{"loginCode":"login-code","phoneCode":"phone-code"}`))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if service.beginInput.LoginCode != "login-code" || service.beginInput.PhoneCode != "phone-code" {
		t.Fatalf("input = %#v", service.beginInput)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body["status"] != "onboarding_required" || body["onboardingToken"] != "opaque-onboarding-token" || body["expiresAt"] == nil {
		t.Fatalf("body=%s err=%v", rr.Body.String(), err)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q", rr.Header().Get("Cache-Control"))
	}
}

func TestWeChatOnboardingLinkedAccountSessionCarriesPhoneAssurance(t *testing.T) {
	service := &onboardingServiceStub{beginResult: wechatonboarding.BeginResult{
		Status: wechatonboarding.StatusAuthenticated, UserID: "user_existing",
	}}
	sessions := &fakeWeChatSessions{}
	router := onboardingRouter(service, sessions, &fakeWeChatRateChecker{allow: true})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding", `{"loginCode":"login-code","phoneCode":"phone-code"}`))
	if rr.Code != http.StatusOK || sessions.input.Provider != wechat.ProviderName || !hasAuthenticationMethod(sessions.input.AuthenticationMethods, auth.MethodFederated) || !hasAuthenticationMethod(sessions.input.AuthenticationMethods, auth.MethodWeChatPhoneVerified) {
		t.Fatalf("status=%d session=%+v body=%s", rr.Code, sessions.input, rr.Body.String())
	}
}

func TestWeChatOnboardingBeginRequiresPhoneCodeBeforeService(t *testing.T) {
	service := &onboardingServiceStub{}
	router := onboardingRouter(service, &fakeWeChatSessions{}, &fakeWeChatRateChecker{allow: true})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding", `{"loginCode":"login-code"}`))
	if rr.Code != http.StatusUnprocessableEntity || service.beginInput.LoginCode != "" {
		t.Fatalf("status=%d input=%#v body=%s", rr.Code, service.beginInput, rr.Body.String())
	}
	var response ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil || response.Error.Code != codeWeChatPhoneRequired {
		t.Fatalf("error=%#v decode=%v", response.Error, err)
	}
}

func TestWeChatOnboardingPhoneProofFailureAndConflictHaveStableErrors(t *testing.T) {
	for _, test := range []struct {
		name     string
		service  *onboardingServiceStub
		wantHTTP int
		wantCode string
	}{
		{name: "provider proof missing", service: &onboardingServiceStub{beginErr: wechatonboarding.ErrPhoneRequired}, wantHTTP: http.StatusUnprocessableEntity, wantCode: codeWeChatPhoneRequired},
		{name: "provider infrastructure unavailable", service: &onboardingServiceStub{beginErr: wechatonboarding.ErrUnavailable}, wantHTTP: http.StatusBadGateway, wantCode: CodeProviderUnavailable},
		{name: "authority conflict", service: &onboardingServiceStub{beginErr: wechatonboarding.ErrPhoneConflict}, wantHTTP: http.StatusConflict, wantCode: codeWeChatPhoneConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := onboardingRouter(test.service, &fakeWeChatSessions{}, &fakeWeChatRateChecker{allow: true})
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding", `{"loginCode":"login-code","phoneCode":"phone-code"}`))
			var response ErrorResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil || rr.Code != test.wantHTTP || response.Error.Code != test.wantCode {
				t.Fatalf("status=%d error=%#v decode=%v body=%s", rr.Code, response.Error, err, rr.Body.String())
			}
		})
	}
}

func TestWeChatOnboardingCompletePasswordMismatchUsesStableRequestedCode(t *testing.T) {
	service := &onboardingServiceStub{completeErr: wechatonboarding.ErrPasswordMismatch}
	router := onboardingRouter(service, &fakeWeChatSessions{}, &fakeWeChatRateChecker{allow: true})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding/complete", `{"onboardingToken":"token","email":"existing@example.com","password":"wrong","acceptedTerms":true}`))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != codeWeChatOnboardingPasswordMismatch || response.Error.Message != "此邮箱已存在账号，请设定原始密码以进行绑定" {
		t.Fatalf("error=%#v", response.Error)
	}
	if service.completeInput.ClientIP == "" || service.completeInput.OnboardingToken != "token" {
		t.Fatalf("complete input=%#v", service.completeInput)
	}
}

func TestWeChatOnboardingAuthenticatedCreatesNativeSessionWithBothMethods(t *testing.T) {
	userID := identity.UserID("user_existing")
	service := &onboardingServiceStub{complete: wechatonboarding.CompleteResult{
		Status: wechatonboarding.StatusAuthenticated,
		Authentication: auth.AuthenticationResult{
			Status: auth.StatusAuthenticated, UserID: userID, Provider: "zitadel",
			ProviderSessionReference: "provider-session", ProviderSessionToken: auth.NewProviderSessionToken("provider-secret"),
			AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		},
	}}
	sessions := &fakeWeChatSessions{}
	router := onboardingRouter(service, sessions, &fakeWeChatRateChecker{allow: true})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding/complete", `{"onboardingToken":"token","email":"existing@example.com","password":"password","acceptedTerms":true}`))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), fakeWeChatSessionBearer) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if sessions.input.UserID != userID || sessions.input.ClientKind != session.ClientKindMiniProgram || sessions.input.ProviderSessionReference != "provider-session" || sessions.input.ProviderSessionToken.Token() != "provider-secret" {
		t.Fatalf("session input=%+v", sessions.input)
	}
	if !hasAuthenticationMethod(sessions.input.AuthenticationMethods, auth.MethodPassword) || !hasAuthenticationMethod(sessions.input.AuthenticationMethods, auth.MethodFederated) || !hasAuthenticationMethod(sessions.input.AuthenticationMethods, auth.MethodWeChatPhoneVerified) {
		t.Fatalf("methods=%#v", sessions.input.AuthenticationMethods)
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Fatalf("native onboarding wrote cookies: %#v", rr.Result().Cookies())
	}
}

func TestWeChatOnboardingMFAContractUsesDedicatedToken(t *testing.T) {
	service := &onboardingServiceStub{mfa: wechatonboarding.CompleteResult{
		Status:         wechatonboarding.StatusAuthenticated,
		Authentication: auth.AuthenticationResult{Status: auth.StatusAuthenticated, UserID: "user_existing", ProviderSessionReference: "provider-session", AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword, auth.MethodTOTP}},
	}}
	router := onboardingRouter(service, &fakeWeChatSessions{}, &fakeWeChatRateChecker{allow: true})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding/mfa", `{"mfaToken":"mfa-token","method":"totp","code":"123456"}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if service.mfaInput.MFAToken != "mfa-token" || service.mfaInput.Method != auth.MFAMethodTOTP || service.mfaInput.Code != "123456" || service.mfaInput.ClientIP == "" {
		t.Fatalf("MFA input=%#v", service.mfaInput)
	}
}

func TestWeChatOnboardingMFAPromotesOnlyAfterNativeSessionCreation(t *testing.T) {
	service := &onboardingServiceStub{mfa: wechatonboarding.CompleteResult{
		Status: wechatonboarding.StatusAuthenticated,
		Authentication: auth.AuthenticationResult{
			Status: auth.StatusAuthenticated, UserID: "user_existing", Provider: "zitadel",
			ProviderSessionReference: "provider-session", AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword, auth.MethodTOTP},
		},
	}}
	sessions := &fakeWeChatSessions{}
	promotion := &onboardingPromotionStub{}
	router := onboardingRouterWithDependencies(service, sessions, &fakeWeChatRateChecker{allow: true}, &onboardingRevokerStub{}, promotion)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding/mfa", `{"mfaToken":"mfa-promotion-token","method":"totp","code":"123456"}`))

	if rr.Code != http.StatusOK || sessions.input.UserID == "" {
		t.Fatalf("status=%d session=%+v body=%s", rr.Code, sessions.input, rr.Body.String())
	}
	if promotion.completedToken != "mfa-promotion-token" || promotion.scheduledToken != "" {
		t.Fatalf("completed=%q scheduled=%q", promotion.completedToken, promotion.scheduledToken)
	}
}

func TestWeChatOnboardingMFASessionFailureSchedulesCleanup(t *testing.T) {
	service := &onboardingServiceStub{mfa: wechatonboarding.CompleteResult{
		Status: wechatonboarding.StatusAuthenticated,
		Authentication: auth.AuthenticationResult{
			Status: auth.StatusAuthenticated, UserID: "user_existing", Provider: "zitadel", ProviderSessionReference: "provider-session",
		},
	}}
	sessions := &fakeWeChatSessions{err: errors.New("session store unavailable")}
	promotion := &onboardingPromotionStub{}
	revoker := &onboardingRevokerStub{}
	router := onboardingRouterWithDependencies(service, sessions, &fakeWeChatRateChecker{allow: true}, revoker, promotion)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding/mfa", `{"mfaToken":"mfa-session-failure","method":"totp","code":"123456"}`))

	if rr.Code != http.StatusInternalServerError || promotion.scheduledToken != "mfa-session-failure" || promotion.completedToken != "" {
		t.Fatalf("status=%d completed=%q scheduled=%q body=%s", rr.Code, promotion.completedToken, promotion.scheduledToken, rr.Body.String())
	}
	if revoker.reference != "provider-session" {
		t.Fatalf("provider session revoked=%q", revoker.reference)
	}
}

func TestWeChatOnboardingMFAPromotionFailureDeletesUnreturnedSession(t *testing.T) {
	service := &onboardingServiceStub{mfa: wechatonboarding.CompleteResult{
		Status: wechatonboarding.StatusAuthenticated,
		Authentication: auth.AuthenticationResult{
			Status: auth.StatusAuthenticated, UserID: "user_existing", Provider: "zitadel", ProviderSessionReference: "provider-session",
		},
	}}
	sessions := &fakeWeChatSessions{}
	promotion := &onboardingPromotionStub{completeErr: errors.New("promotion lease expired")}
	revoker := &onboardingRevokerStub{}
	router := onboardingRouterWithDependencies(service, sessions, &fakeWeChatRateChecker{allow: true}, revoker, promotion)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding/mfa", `{"mfaToken":"mfa-expired-promotion","method":"totp","code":"123456"}`))

	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), fakeWeChatSessionBearer) {
		t.Fatalf("status=%d leakedBearer=%v body=%s", rr.Code, strings.Contains(rr.Body.String(), fakeWeChatSessionBearer), rr.Body.String())
	}
	if sessions.deletedToken != fakeWeChatSessionBearer {
		t.Fatalf("deleted session token=%q", sessions.deletedToken)
	}
	if promotion.scheduledToken != "mfa-expired-promotion" || revoker.reference != "provider-session" {
		t.Fatalf("scheduled=%q revoked=%q", promotion.scheduledToken, revoker.reference)
	}
}

func TestWeChatOnboardingMFAMissingProviderReferenceFailsBeforeSessionCreation(t *testing.T) {
	service := &onboardingServiceStub{mfa: wechatonboarding.CompleteResult{
		Status:         wechatonboarding.StatusAuthenticated,
		Authentication: auth.AuthenticationResult{Status: auth.StatusAuthenticated, UserID: "user_existing"},
	}}
	sessions := &fakeWeChatSessions{}
	promotion := &onboardingPromotionStub{}
	router := onboardingRouterWithDependencies(service, sessions, &fakeWeChatRateChecker{allow: true}, &onboardingRevokerStub{}, promotion)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding/mfa", `{"mfaToken":"mfa-missing-provider-reference","method":"totp","code":"123456"}`))

	if rr.Code != http.StatusInternalServerError || sessions.input.UserID != "" {
		t.Fatalf("status=%d session=%+v body=%s", rr.Code, sessions.input, rr.Body.String())
	}
	if promotion.scheduledToken != "mfa-missing-provider-reference" || promotion.completedToken != "" {
		t.Fatalf("completed=%q scheduled=%q", promotion.completedToken, promotion.scheduledToken)
	}
}

func TestWeChatOnboardingRoutesRequireNativeMarkerAndStrictJSON(t *testing.T) {
	service := &onboardingServiceStub{beginResult: wechatonboarding.BeginResult{Status: wechatonboarding.StatusOnboardingRequired, OnboardingToken: "token", ExpiresAt: time.Now().Add(time.Minute)}}
	router := onboardingRouter(service, &fakeWeChatSessions{}, &fakeWeChatRateChecker{allow: true})

	missingMarker := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/wechat/onboarding", strings.NewReader(`{"loginCode":"login-code"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(missingMarker, req)
	if missingMarker.Code != http.StatusNotFound {
		t.Fatalf("missing marker status=%d", missingMarker.Code)
	}

	unknown := httptest.NewRecorder()
	router.ServeHTTP(unknown, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding", `{"loginCode":"login-code","openid":"caller-controlled"}`))
	if unknown.Code != http.StatusBadRequest || service.beginInput.LoginCode != "" {
		t.Fatalf("unknown field status=%d input=%#v", unknown.Code, service.beginInput)
	}
}

func TestWeChatOnboardingBeginRateFailureStopsProviderFlow(t *testing.T) {
	service := &onboardingServiceStub{}
	router := onboardingRouter(service, &fakeWeChatSessions{}, failingWeChatRateChecker{})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, onboardingRequest(http.MethodPost, "/auth/wechat/onboarding", `{"loginCode":"login-code","phoneCode":"phone-code"}`))
	if rr.Code != http.StatusTooManyRequests || service.beginInput.LoginCode != "" {
		t.Fatalf("status=%d input=%#v", rr.Code, service.beginInput)
	}
}
