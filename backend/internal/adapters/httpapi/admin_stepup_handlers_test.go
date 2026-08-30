package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type fakeAdminStepUpService struct {
	challenge                                             adminstepup.ChallengeView
	enroll                                                adminstepup.Challenge
	verify                                                adminstepup.VerifyResult
	rotate                                                adminstepup.Challenge
	err                                                   error
	initialEnrollmentAllowed                              bool
	initialEnrollmentErr                                  error
	initialEnrollmentCalls                                int
	initialEnrollmentUserID                               identity.UserID
	initialEnrollmentEventID                              string
	challengeCalls, enrollCalls, verifyCalls, rotateCalls int
	lastEnroll                                            adminstepup.EnrollInput
	lastVerify                                            adminstepup.VerifyRequest
	lastRotate                                            adminstepup.RotateInput
}

func (f *fakeAdminStepUpService) InitialEnrollmentAllowed(_ context.Context, userID identity.UserID, eventID string) (bool, error) {
	f.initialEnrollmentCalls++
	f.initialEnrollmentUserID = userID
	f.initialEnrollmentEventID = eventID
	return f.initialEnrollmentAllowed, f.initialEnrollmentErr
}

func (f *fakeAdminStepUpService) Challenge(context.Context, identity.UserID, string) (adminstepup.ChallengeView, error) {
	f.challengeCalls++
	return f.challenge, f.err
}
func (f *fakeAdminStepUpService) Enroll(_ context.Context, input adminstepup.EnrollInput) (adminstepup.Challenge, error) {
	f.enrollCalls++
	f.lastEnroll = input
	return f.enroll, f.err
}
func (f *fakeAdminStepUpService) Verify(_ context.Context, input adminstepup.VerifyRequest) (adminstepup.VerifyResult, error) {
	f.verifyCalls++
	f.lastVerify = input
	return f.verify, f.err
}
func (f *fakeAdminStepUpService) Rotate(_ context.Context, input adminstepup.RotateInput) (adminstepup.Challenge, error) {
	f.rotateCalls++
	f.lastRotate = input
	return f.rotate, f.err
}

func adminStepUpRequest(method, target, body string, record *session.SessionRecord) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := request.WithID(req.Context(), "req_admin_stepup_1")
	if record != nil {
		principal := session.Principal{UserID: record.UserID, SessionID: record.SessionID, AuthenticationTime: record.AuthenticationTime, AuthenticationMethods: record.AuthenticationMethods}
		ctx = WithPrincipal(ctx, principal)
		ctx = WithSessionRecord(ctx, *record)
	}
	return req.WithContext(ctx)
}

func freshProviderMFASession(now time.Time) session.SessionRecord {
	return session.SessionRecord{
		SessionID: "sess_1", UserID: "user_1", Provider: "zitadel",
		ProviderSessionReference:  "provider-session-1",
		ProviderSessionCredential: session.EncryptedProviderSessionCredential("sealed-provider-session"),
		AuthenticationTime:        now.Add(-time.Minute),
		AuthenticationMethods:     []auth.AuthenticationMethod{auth.MethodPassword, auth.MethodTOTP},
	}
}

func TestAdminStepUpEnrollAllowsFreshProviderBootstrapWithoutExistingMFA(t *testing.T) {
	now := time.Date(2026, 8, 17, 19, 0, 0, 0, time.UTC)
	record := freshProviderMFASession(now)
	record.AuthenticationMethods = []auth.AuthenticationMethod{auth.MethodPassword}
	service := &fakeAdminStepUpService{
		initialEnrollmentAllowed: true,
		enroll: adminstepup.Challenge{
			UserID: "user_1", Status: adminstepup.ChallengeActive, Version: 1, CredentialVersion: 1, SecurityEpoch: 1,
		},
	}
	handler := NewAdminStepUpHandlers(service, 5*time.Minute, func() time.Time { return now })
	recorder := httptest.NewRecorder()
	handler.Enroll(recorder, adminStepUpRequest(http.MethodPost, "/api/v1/admin/step-up/enroll", `{"eventId":"evt_a","question":"你最想解决的问题是什么？","answer":"答案答案答案答案答案答案答案"}`, &record))

	if recorder.Code != http.StatusCreated || service.initialEnrollmentCalls != 1 || service.initialEnrollmentUserID != "user_1" || service.initialEnrollmentEventID != "evt_a" || service.enrollCalls != 1 {
		t.Fatalf("status=%d initial_calls=%d initial_user=%q initial_event=%q enroll_calls=%d body=%s", recorder.Code, service.initialEnrollmentCalls, service.initialEnrollmentUserID, service.initialEnrollmentEventID, service.enrollCalls, recorder.Body.String())
	}
}

func TestAdminStepUpEnrollRequiresProviderBackedFreshSessionAndMFAOrBootstrapException(t *testing.T) {
	now := time.Date(2026, 8, 17, 19, 0, 0, 0, time.UTC)
	body := `{"eventId":"evt_a","question":"你最想解决的问题是什么？","answer":"答案答案答案答案答案答案答案"}`
	cases := []struct {
		name     string
		record   *session.SessionRecord
		wantCode string
	}{
		{"anonymous", nil, CodeUnauthorized},
		{"stale login", func() *session.SessionRecord {
			value := freshProviderMFASession(now)
			value.AuthenticationTime = now.Add(-6 * time.Minute)
			return &value
		}(), CodeReauthenticationReq},
		{"missing MFA", func() *session.SessionRecord {
			value := freshProviderMFASession(now)
			value.AuthenticationMethods = []auth.AuthenticationMethod{auth.MethodPassword}
			return &value
		}(), CodeReauthenticationReq},
		{"missing provider session proof", func() *session.SessionRecord {
			value := freshProviderMFASession(now)
			value.Provider = "wechat"
			value.ProviderSessionReference = ""
			value.ProviderSessionCredential = ""
			return &value
		}(), CodeReauthenticationReq},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeAdminStepUpService{initialEnrollmentAllowed: tc.name == "stale login"}
			handler := NewAdminStepUpHandlers(service, 5*time.Minute, func() time.Time { return now })
			recorder := httptest.NewRecorder()
			handler.Enroll(recorder, adminStepUpRequest(http.MethodPost, "/api/v1/admin/step-up/enroll", body, tc.record))
			if recorder.Code == http.StatusOK || recorder.Code == http.StatusCreated {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.wantCode) {
				t.Fatalf("status=%d body=%s, want code %q", recorder.Code, recorder.Body.String(), tc.wantCode)
			}
			if service.enrollCalls != 0 {
				t.Fatal("enrollment dependency called before session prerequisites")
			}
			if tc.name == "stale login" && service.initialEnrollmentCalls != 0 {
				t.Fatal("stale login reached the bootstrap authorization check")
			}
		})
	}
}

func TestAdminStepUpEnrollFailsClosedWhenInitialEnrollmentCheckFails(t *testing.T) {
	now := time.Date(2026, 8, 17, 19, 0, 0, 0, time.UTC)
	record := freshProviderMFASession(now)
	record.AuthenticationMethods = []auth.AuthenticationMethod{auth.MethodPassword}
	body := `{"eventId":"evt_a","question":"你最想解决的问题是什么？","answer":"答案答案答案答案答案答案答案"}`
	for _, tc := range []struct {
		name    string
		allowed bool
		err     error
	}{
		{name: "not authorized"},
		{name: "authorization lookup unavailable", allowed: true, err: errors.New("binding lookup unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeAdminStepUpService{initialEnrollmentAllowed: tc.allowed, initialEnrollmentErr: tc.err}
			handler := NewAdminStepUpHandlers(service, 5*time.Minute, func() time.Time { return now })
			recorder := httptest.NewRecorder()
			handler.Enroll(recorder, adminStepUpRequest(http.MethodPost, "/api/v1/admin/step-up/enroll", body, &record))
			if recorder.Code != http.StatusForbidden || service.initialEnrollmentCalls != 1 || service.enrollCalls != 0 {
				t.Fatalf("status=%d initial_calls=%d enroll_calls=%d body=%s", recorder.Code, service.initialEnrollmentCalls, service.enrollCalls, recorder.Body.String())
			}
		})
	}
}

func TestAdminStepUpHandlersDoNotEchoChallengeSecrets(t *testing.T) {
	now := time.Date(2026, 8, 17, 19, 0, 0, 0, time.UTC)
	record := freshProviderMFASession(now)
	service := &fakeAdminStepUpService{enroll: adminstepup.Challenge{UserID: "user_1", Status: adminstepup.ChallengeActive, Version: 1, CredentialVersion: 1, SecurityEpoch: 1}}
	handler := NewAdminStepUpHandlers(service, 5*time.Minute, func() time.Time { return now })
	req := adminStepUpRequest(http.MethodPost, "/api/v1/admin/step-up/enroll", `{"eventId":"evt_a","question":"你最想解决的问题是什么？","answer":"绝密答案绝密答案绝密答案"}`, &record)
	req.Header.Set("Idempotency-Key", strings.Repeat("A", 32))
	recorder := httptest.NewRecorder()
	handler.Enroll(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.enrollCalls != 1 || service.lastEnroll.UserID != "user_1" || service.lastEnroll.IdempotencyKey == "" {
		t.Fatalf("enroll input=%+v", service.lastEnroll)
	}
	if service.initialEnrollmentCalls != 0 {
		t.Fatalf("existing MFA unexpectedly invoked initial-enrollment exception: calls=%d", service.initialEnrollmentCalls)
	}
	for _, secret := range []string{"最想解决", "绝密答案"} {
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("secret %q echoed in response: %s", secret, recorder.Body.String())
		}
	}
}

func TestAdminStepUpRotateRequiresIfMatchAndParsesExactVersion(t *testing.T) {
	now := time.Date(2026, 8, 17, 19, 0, 0, 0, time.UTC)
	record := freshProviderMFASession(now)
	service := &fakeAdminStepUpService{rotate: adminstepup.Challenge{UserID: "user_1", Status: adminstepup.ChallengeActive, Version: 2, CredentialVersion: 2, SecurityEpoch: 2}}
	handler := NewAdminStepUpHandlers(service, 5*time.Minute, func() time.Time { return now })
	body := `{"eventId":"evt_a","oldAnswer":"答案答案答案答案答案答案答案","question":"你下一阶段最想解决什么问题？","answer":"新答案新答案新答案新答案"}`
	req := adminStepUpRequest(http.MethodPost, "/api/v1/admin/step-up/rotate", body, &record)
	req.Header.Set("Idempotency-Key", strings.Repeat("A", 32))
	recorder := httptest.NewRecorder()
	handler.Rotate(recorder, req)
	if recorder.Code != http.StatusPreconditionRequired || service.rotateCalls != 0 {
		t.Fatalf("missing If-Match status=%d calls=%d", recorder.Code, service.rotateCalls)
	}

	req = adminStepUpRequest(http.MethodPost, "/api/v1/admin/step-up/rotate", body, &record)
	req.Header.Set("Idempotency-Key", strings.Repeat("B", 32))
	req.Header.Set("If-Match", `"1"`)
	recorder = httptest.NewRecorder()
	handler.Rotate(recorder, req)
	if recorder.Code != http.StatusOK || service.lastRotate.ExpectedVersion != 1 {
		t.Fatalf("status=%d input=%+v body=%s", recorder.Code, service.lastRotate, recorder.Body.String())
	}
}

func TestAdminStepUpIfMatchRequiresStrongQuotedVersion(t *testing.T) {
	for _, value := range []string{"", "1", `W/"1"`, `"0"`, `"01"`, `"1", "2"`, "*"} {
		if _, err := parseChallengeIfMatch(value); err == nil {
			t.Errorf("If-Match %q unexpectedly accepted", value)
		}
	}
	version, err := parseChallengeIfMatch(`"27"`)
	if err != nil || version != 27 {
		t.Fatalf("strong If-Match version=%d err=%v", version, err)
	}
}

func TestAdminStepUpVerifyMapsRotationAndLockStates(t *testing.T) {
	now := time.Date(2026, 8, 17, 19, 0, 0, 0, time.UTC)
	record := freshProviderMFASession(now)
	for _, tc := range []struct {
		err  error
		code int
		body string
	}{
		{adminstepup.ErrRotationRequired, http.StatusConflict, CodeAdminStepUpRotationRequired},
		{adminstepup.ErrLocked, http.StatusLocked, CodeAdminStepUpLocked},
		{adminstepup.ErrEnrollmentRequired, http.StatusConflict, CodeAdminStepUpEnrollmentRequired},
		{adminstepup.ErrRateLimited, http.StatusTooManyRequests, CodeRateLimited},
		{adminstepup.ErrUnsupportedAction, http.StatusUnprocessableEntity, CodeValidation},
		{adminstepup.ErrInvalidVerifyRequest, http.StatusUnprocessableEntity, CodeValidation},
	} {
		service := &fakeAdminStepUpService{err: tc.err}
		handler := NewAdminStepUpHandlers(service, 5*time.Minute, func() time.Time { return now })
		req := adminStepUpRequest(http.MethodPost, "/api/v1/admin/step-up/verify", `{"eventId":"evt_a","answer":"答案答案答案答案答案答案答案","action":"dreamup.admin.role.manage","target":"evt_a"}`, &record)
		req.Header.Set("Idempotency-Key", strings.Repeat("A", 32))
		recorder := httptest.NewRecorder()
		handler.Verify(recorder, req)
		if recorder.Code != tc.code || !strings.Contains(recorder.Body.String(), tc.body) {
			t.Fatalf("err=%v status=%d body=%s", tc.err, recorder.Code, recorder.Body.String())
		}
	}
}

func TestAdminStepUpVerifyRequiresFreshProviderLoginBeforeService(t *testing.T) {
	now := time.Date(2026, 8, 17, 19, 0, 0, 0, time.UTC)
	body := `{"eventId":"evt_a","answer":"答案答案答案答案答案答案答案","action":"dreamup.admin.role.manage","target":"evt_a"}`

	boundary := freshProviderMFASession(now)
	boundary.AuthenticationTime = now.Add(-dreamupdelegation.MaxAdministratorLoginAge)
	boundaryService := &fakeAdminStepUpService{}
	boundaryHandler := NewAdminStepUpHandlers(boundaryService, 5*time.Minute, func() time.Time { return now })
	boundaryRecorder := httptest.NewRecorder()
	boundaryHandler.Verify(boundaryRecorder, adminStepUpRequest(http.MethodPost, "/api/v1/admin/step-up/verify", body, &boundary))
	if boundaryRecorder.Code != http.StatusOK || boundaryService.verifyCalls != 1 {
		t.Fatalf("exact freshness boundary status=%d calls=%d body=%s", boundaryRecorder.Code, boundaryService.verifyCalls, boundaryRecorder.Body.String())
	}

	for _, tc := range []struct {
		name     string
		authTime time.Time
	}{
		{"stale by one second", now.Add(-dreamupdelegation.MaxAdministratorLoginAge - time.Second)},
		{"future beyond clock skew", now.Add(dreamupdelegation.MaxClockSkew + time.Second)},
		{"missing authentication time", time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := freshProviderMFASession(now)
			record.AuthenticationTime = tc.authTime
			service := &fakeAdminStepUpService{}
			handler := NewAdminStepUpHandlers(service, 5*time.Minute, func() time.Time { return now })
			recorder := httptest.NewRecorder()
			// The malformed body proves login freshness is checked before decoding
			// or invoking the security-answer verifier.
			handler.Verify(recorder, adminStepUpRequest(http.MethodPost, "/api/v1/admin/step-up/verify", `{`, &record))
			if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), CodeReauthenticationReq) || service.verifyCalls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", recorder.Code, service.verifyCalls, recorder.Body.String())
			}
		})
	}
}

func TestAdminStepUpChallengeUsesOwnerIdentityOnly(t *testing.T) {
	now := time.Date(2026, 8, 17, 19, 0, 0, 0, time.UTC)
	record := freshProviderMFASession(now)
	service := &fakeAdminStepUpService{challenge: adminstepup.ChallengeView{State: adminstepup.StateActive, Question: "只对本人返回的问题？", Version: 4, CredentialVersion: 2}}
	handler := NewAdminStepUpHandlers(service, 5*time.Minute, func() time.Time { return now })
	recorder := httptest.NewRecorder()
	handler.Challenge(recorder, adminStepUpRequest(http.MethodGet, "/api/v1/admin/step-up/challenge?eventId=evt_a&userId=user_other", "", &record))
	if recorder.Code != http.StatusOK || service.challengeCalls != 1 || !strings.Contains(recorder.Body.String(), "只对本人") {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, service.challengeCalls, recorder.Body.String())
	}
}

func TestAdminStepUpHandlerUnknownErrorIsRedacted(t *testing.T) {
	now := time.Now().UTC()
	record := freshProviderMFASession(now)
	service := &fakeAdminStepUpService{err: errors.New("database says answer=secret")}
	handler := NewAdminStepUpHandlers(service, 5*time.Minute, func() time.Time { return now })
	recorder := httptest.NewRecorder()
	handler.Challenge(recorder, adminStepUpRequest(http.MethodGet, "/api/v1/admin/step-up/challenge?eventId=evt_a", "", &record))
	if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
