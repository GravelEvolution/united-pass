package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/accountcontact"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type accountContactServiceStub struct {
	beginCalls   int
	verifyCalls  int
	verifyInput  accountcontact.VerifyInput
	verifyResult accountcontact.VerifyResult
}

func (s *accountContactServiceStub) Begin(_ context.Context, _ accountcontact.BeginInput) (accountcontact.BeginResult, error) {
	s.beginCalls++
	return accountcontact.BeginResult{RequestID: "email_change_0123456789abcdef0123456789abcdef"}, nil
}

func (s *accountContactServiceStub) Verify(_ context.Context, input accountcontact.VerifyInput) (accountcontact.VerifyResult, error) {
	s.verifyCalls++
	s.verifyInput = input
	if s.verifyResult.Email != "" {
		return s.verifyResult, nil
	}
	return accountcontact.VerifyResult{}, accountcontact.ErrVerificationFailed
}

type accountContactRateStub struct {
	beginKeys  []string
	verifyKeys []string
}

func (s *accountContactRateStub) CheckAccountEmailChangeBegin(_ context.Context, _, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	s.beginKeys = append(s.beginKeys, key)
	return true, 0, nil
}

func (s *accountContactRateStub) CheckAccountEmailChangeVerify(_ context.Context, _, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	s.verifyKeys = append(s.verifyKeys, key)
	return true, 0, nil
}

type accountContactReauthStub struct {
	err       error
	token     string
	action    string
	sessionID string
	calls     int
}

func (s *accountContactReauthStub) VerifyAndConsume(_ context.Context, token, action, sessionID, _ string, _ applications.ApplicationID, _ applications.OAuthClientID) error {
	s.calls++
	s.token, s.action, s.sessionID = token, action, sessionID
	return s.err
}

func accountContactRequest(t *testing.T, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Origin", "https://auth.example.test")
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:1234"
	ctx := WithPrincipal(req.Context(), session.Principal{UserID: identity.UserID("user_actor"), SessionID: session.SessionID("session_actor")})
	return req.WithContext(ctx)
}

func TestBeginEmailChangeRequiresSessionBoundStrongReauthentication(t *testing.T) {
	service := &accountContactServiceStub{}
	rate := &accountContactRateStub{}
	h := NewAccountContactHandlers(service, rate, nil, "https://auth.example.test", 5, time.Minute, testLogger())
	req := accountContactRequest(t, "/api/v1/me/email-change", `{"email":"new@example.com"}`)
	rr := httptest.NewRecorder()
	h.BeginEmailChange(rr, req)
	if rr.Code != http.StatusForbidden || service.beginCalls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", rr.Code, service.beginCalls, rr.Body.String())
	}
}

func TestBeginEmailChangeConsumesEmailChangeGrantAndUsesStableUserBudget(t *testing.T) {
	service := &accountContactServiceStub{}
	rate := &accountContactRateStub{}
	reauth := &accountContactReauthStub{}
	h := NewAccountContactHandlers(service, rate, reauth, "https://auth.example.test", 5, time.Minute, testLogger())
	req := accountContactRequest(t, "/api/v1/me/email-change", `{"email":"new@example.com"}`)
	req.Header.Set("X-Reauthentication-Token", "strong-grant")
	rr := httptest.NewRecorder()
	h.BeginEmailChange(rr, req)
	wantDigest := sha256.Sum256([]byte("user_actor"))
	wantKey := hex.EncodeToString(wantDigest[:])
	if rr.Code != http.StatusAccepted || service.beginCalls != 1 || reauth.calls != 1 || reauth.token != "strong-grant" || reauth.action != auth.ReauthActionEmailChange || reauth.sessionID != "session_actor" {
		t.Fatalf("status=%d service=%d reauth=%#v body=%s", rr.Code, service.beginCalls, reauth, rr.Body.String())
	}
	if len(rate.beginKeys) != 1 || rate.beginKeys[0] != wantKey {
		t.Fatalf("begin rate keys=%v want=%q", rate.beginKeys, wantKey)
	}
}

func TestVerifyEmailChangeRequestIDRotationDoesNotResetBudget(t *testing.T) {
	service := &accountContactServiceStub{}
	rate := &accountContactRateStub{}
	h := NewAccountContactHandlers(service, rate, &accountContactReauthStub{}, "https://auth.example.test", 5, time.Minute, testLogger())
	for _, requestID := range []string{"email_change_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "email_change_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"} {
		req := accountContactRequest(t, "/api/v1/me/email-change/verify", `{"requestId":"`+requestID+`","code":"bad"}`)
		rr := httptest.NewRecorder()
		h.VerifyEmailChange(rr, req)
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("request=%q status=%d body=%s", requestID, rr.Code, rr.Body.String())
		}
	}
	if len(rate.verifyKeys) != 2 || rate.verifyKeys[0] != rate.verifyKeys[1] {
		t.Fatalf("request IDs changed rate budget: %v", rate.verifyKeys)
	}
	wantDigest := sha256.Sum256([]byte("user_actor"))
	if rate.verifyKeys[0] != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("verify key=%q", rate.verifyKeys[0])
	}
}

func TestBeginEmailChangeRejectsInvalidReauthenticationGrant(t *testing.T) {
	service := &accountContactServiceStub{}
	reauth := &accountContactReauthStub{err: errors.New("stale grant")}
	h := NewAccountContactHandlers(service, &accountContactRateStub{}, reauth, "https://auth.example.test", 5, time.Minute, testLogger())
	req := accountContactRequest(t, "/api/v1/me/email-change", `{"email":"new@example.com"}`)
	req.Header.Set("X-Reauthentication-Token", "stale")
	rr := httptest.NewRecorder()
	h.BeginEmailChange(rr, req)
	if rr.Code != http.StatusForbidden || service.beginCalls != 0 {
		t.Fatalf("status=%d calls=%d", rr.Code, service.beginCalls)
	}
}

func TestVerifyEmailChangeAcceptsAlphanumericProviderCode(t *testing.T) {
	service := &accountContactServiceStub{verifyResult: accountcontact.VerifyResult{Email: "new@example.com"}}
	handler := NewAccountContactHandlers(service, &accountContactRateStub{}, &accountContactReauthStub{}, "https://auth.example.test", 5, time.Minute, testLogger())
	request := accountContactRequest(t, "/api/v1/me/email-change/verify", `{"requestId":"email_change_0123456789abcdef0123456789abcdef","code":"A1B2C3"}`)
	recorder := httptest.NewRecorder()
	handler.VerifyEmailChange(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if service.verifyInput.Code != "A1B2C3" {
		t.Fatalf("service code = %q, want A1B2C3", service.verifyInput.Code)
	}
}
