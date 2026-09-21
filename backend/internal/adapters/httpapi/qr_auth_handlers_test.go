package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/qrauth"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/go-chi/chi/v5"
)

type fakeQRAuthService struct {
	receiver          string
	user              identity.UserID
	consumeErr        error
	approvedChallenge string
	consumedChallenge string
}

type fakeQRAuthRateChecker struct {
	allowed bool
	err     error
}

type fakeQRAuthAuditor struct {
	events []QRAuthAuditEvent
	err    error
}

func (a *fakeQRAuthAuditor) RecordQRAuthEvent(_ context.Context, event QRAuthAuditEvent) error {
	a.events = append(a.events, event)
	return a.err
}

func (f fakeQRAuthRateChecker) CheckQRAuthBegin(context.Context, string, int, time.Duration) (bool, time.Duration, error) {
	return f.allowed, time.Second, f.err
}

func (s *fakeQRAuthService) Begin(context.Context) (string, string, error) {
	return "challenge-visible", s.receiver, nil
}
func (s *fakeQRAuthService) Approve(_ context.Context, challengeID string, user identity.UserID) error {
	s.approvedChallenge = challengeID
	s.user = user
	return nil
}
func (s *fakeQRAuthService) Consume(_ context.Context, challengeID string, receiver string) (identity.UserID, error) {
	s.consumedChallenge = challengeID
	if receiver != s.receiver {
		return "", qrauth.ErrDenied
	}
	if s.consumeErr != nil {
		return "", s.consumeErr
	}
	return s.user, nil
}

func TestQRAuthConsumeNeedsBrowserReceiverAndNeverExposesSessionToken(t *testing.T) {
	service := &fakeQRAuthService{receiver: "receiver-only", user: identity.UserID("user_01TEST001")}
	sessions := &fakeWeChatSessions{}
	auditor := &fakeQRAuthAuditor{}
	h := NewQRAuthHandlers(service, sessions, &fakeUserChecker{users: map[identity.UserID]identity.UserStatus{service.user: identity.UserStatusActive}}, fakeQRAuthRateChecker{allowed: true}, auditor, SessionCookieAttributes{}, time.Minute, 12, time.Minute, testLogger())
	router := chi.NewRouter()
	router.Post("/auth/qr/challenges/{challengeId}/consume", h.Consume)
	const challengeID = "challenge_12345678901234567890"
	req := httptest.NewRequest(http.MethodPost, "/auth/qr/challenges/"+challengeID+"/consume", nil)
	req.AddCookie(&http.Cookie{Name: qrReceiverCookieName, Value: "receiver-only", Path: "/api/v1/auth/qr"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() == "" || strings.Contains(rr.Body.String(), fakeWeChatSessionBearer) {
		t.Fatalf("body exposed token: %s", rr.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == SessionCookieName {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value != fakeWeChatSessionBearer {
		t.Fatal("session cookie was not set")
	}
	if sessions.input.Provider != currentQRAuthSessionProvider {
		t.Fatalf("QR session provider=%q, want cutover provider %q", sessions.input.Provider, currentQRAuthSessionProvider)
	}
	if hasAuthenticationMethod(sessions.input.AuthenticationMethods, auth.MethodWeChatPhoneVerified) {
		t.Fatalf("generic QR handoff falsely inherited phone assurance: %#v", sessions.input.AuthenticationMethods)
	}
	if len(auditor.events) != 1 || auditor.events[0].EventType != qrAuthEventReceiverVerified || auditor.events[0].ChallengeReference == challengeID {
		t.Fatalf("unexpected receiver-verification audit events: %#v", auditor.events)
	}
}

func TestQRAuthConsumePendingDoesNotCreateSession(t *testing.T) {
	service := &fakeQRAuthService{receiver: "receiver-only", consumeErr: qrauth.ErrPending}
	h := NewQRAuthHandlers(service, &fakeWeChatSessions{}, nil, fakeQRAuthRateChecker{allowed: true}, &fakeQRAuthAuditor{}, SessionCookieAttributes{}, time.Minute, 12, time.Minute, testLogger())
	router := chi.NewRouter()
	router.Post("/{challengeId}", h.Consume)
	req := httptest.NewRequest(http.MethodPost, "/challenge_12345678901234567890", nil)
	req.AddCookie(&http.Cookie{Name: qrReceiverCookieName, Value: "receiver-only"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted || rr.Result().Header.Get("Set-Cookie") != "" {
		t.Fatalf("status=%d cookies=%q", rr.Code, rr.Result().Header.Get("Set-Cookie"))
	}
}

func TestQRAuthBeginFailsClosedWhenRateLimited(t *testing.T) {
	h := NewQRAuthHandlers(&fakeQRAuthService{receiver: "receiver-only"}, nil, nil, fakeQRAuthRateChecker{allowed: false}, &fakeQRAuthAuditor{}, SessionCookieAttributes{}, time.Minute, 12, time.Minute, testLogger())
	router := chi.NewRouter()
	router.Post("/challenges", h.Begin)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/challenges", nil))
	if rr.Code != http.StatusTooManyRequests || rr.Result().Header.Get("Retry-After") == "" {
		t.Fatalf("status=%d retry-after=%q", rr.Code, rr.Result().Header.Get("Retry-After"))
	}
}

func TestQRAuthConsumeAuditFailureFailsClosedBeforeSessionCreation(t *testing.T) {
	service := &fakeQRAuthService{receiver: "receiver-only", user: identity.UserID("user_01TEST001")}
	sessions := &fakeWeChatSessions{}
	auditor := &fakeQRAuthAuditor{err: errors.New("postgres unavailable")}
	h := NewQRAuthHandlers(service, sessions, &fakeUserChecker{users: map[identity.UserID]identity.UserStatus{service.user: identity.UserStatusActive}}, fakeQRAuthRateChecker{allowed: true}, auditor, SessionCookieAttributes{}, time.Minute, 12, time.Minute, testLogger())
	router := chi.NewRouter()
	router.Post("/{challengeId}", h.Consume)
	req := httptest.NewRequest(http.MethodPost, "/challenge_12345678901234567890", nil)
	req.AddCookie(&http.Cookie{Name: qrReceiverCookieName, Value: "receiver-only"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if sessions.input.UserID != "" {
		t.Fatalf("audit failure created browser session for %q", sessions.input.UserID)
	}
	if len(auditor.events) != 1 || auditor.events[0].EventType != qrAuthEventReceiverVerified {
		t.Fatalf("audit event = %#v, want receiver verification", auditor.events)
	}
}

func TestQRAuthConsumeInactiveAccountIsAuditedWithoutCreatingSession(t *testing.T) {
	service := &fakeQRAuthService{receiver: "receiver-only", user: identity.UserID("user_01TEST001")}
	sessions := &fakeWeChatSessions{}
	auditor := &fakeQRAuthAuditor{}
	h := NewQRAuthHandlers(service, sessions, &fakeUserChecker{users: map[identity.UserID]identity.UserStatus{service.user: identity.UserStatusDisabled}}, fakeQRAuthRateChecker{allowed: true}, auditor, SessionCookieAttributes{}, time.Minute, 12, time.Minute, testLogger())
	router := chi.NewRouter()
	router.Post("/{challengeId}", h.Consume)
	req := httptest.NewRequest(http.MethodPost, "/challenge_12345678901234567890", nil)
	req.AddCookie(&http.Cookie{Name: qrReceiverCookieName, Value: "receiver-only"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if sessions.input.UserID != "" {
		t.Fatalf("inactive account created browser session for %q", sessions.input.UserID)
	}
	if len(auditor.events) != 1 || auditor.events[0].EventType != qrAuthEventReceiverRejected || auditor.events[0].FailureClass != "account_unavailable" {
		t.Fatalf("audit event = %#v, want account-unavailable rejection", auditor.events)
	}
}

func TestQRAuthRejectsMalformedChallengeIDsBeforeAuditOrStoreAccess(t *testing.T) {
	invalidIDs := []string{"short", "https://example.test/challenge", "challenge with spaces 1234567890", strings.Repeat("a", 256)}
	for index, challengeID := range invalidIDs {
		t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
			service := &fakeQRAuthService{receiver: "receiver-only"}
			auditor := &fakeQRAuthAuditor{}
			h := NewQRAuthHandlers(service, &fakeWeChatSessions{}, nil, fakeQRAuthRateChecker{allowed: true}, auditor, SessionCookieAttributes{}, time.Minute, 12, time.Minute, testLogger())
			router := chi.NewRouter()
			router.Post("/{challengeId}/approve", h.Approve)
			router.Post("/{challengeId}/consume", h.Consume)

			escapedChallengeID := url.PathEscape(challengeID)
			approve := httptest.NewRequest(http.MethodPost, "/"+escapedChallengeID+"/approve", nil)
			approve = approve.WithContext(WithPrincipal(approve.Context(), session.Principal{UserID: identity.UserID("user_01TEST001")}))
			approveRecorder := httptest.NewRecorder()
			router.ServeHTTP(approveRecorder, approve)
			if approveRecorder.Code != http.StatusNotFound || service.approvedChallenge != "" || len(auditor.events) != 0 {
				t.Fatalf("approve status=%d challenge=%q audit=%#v", approveRecorder.Code, service.approvedChallenge, auditor.events)
			}

			consume := httptest.NewRequest(http.MethodPost, "/"+escapedChallengeID+"/consume", nil)
			consume.AddCookie(&http.Cookie{Name: qrReceiverCookieName, Value: "receiver-only"})
			consumeRecorder := httptest.NewRecorder()
			router.ServeHTTP(consumeRecorder, consume)
			if consumeRecorder.Code != http.StatusNotFound || service.consumedChallenge != "" || len(auditor.events) != 0 {
				t.Fatalf("consume status=%d challenge=%q audit=%#v", consumeRecorder.Code, service.consumedChallenge, auditor.events)
			}
		})
	}
}
