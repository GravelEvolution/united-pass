package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	app "github.com/GravelEvolution/united-pass/backend/internal/dreamupadmin"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type nativeReauthIdentityStub struct {
	user  identity.User
	err   error
	calls int
}

func (s *nativeReauthIdentityStub) ResolveLogin(context.Context, string) (identity.User, error) {
	s.calls++
	return s.user, s.err
}

func (*nativeReauthIdentityStub) BindVerifiedPhone(context.Context, identity.UserID, string, string) error {
	return nil
}

type nativeReauthRateStub struct{ allow bool }

func (s nativeReauthRateStub) CheckWeChatLogin(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	return s.allow, time.Minute, nil
}

func (s nativeReauthRateStub) CheckWeChatPhone(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	return s.allow, time.Minute, nil
}

type nativeReauthServiceStub struct {
	result app.NativeReauthenticationAuthorization
	err    error
	actor  app.Actor
	input  app.NativeReauthenticationRequest
	calls  int
}

func (s *nativeReauthServiceStub) AuthorizeNativeReauthentication(_ context.Context, actor app.Actor, input app.NativeReauthenticationRequest) (app.NativeReauthenticationAuthorization, error) {
	s.calls++
	s.actor, s.input = actor, input
	return s.result, s.err
}

func nativeReauthRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/dreamup/reauthentication", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UnitedPass-Client", session.ClientKindMiniProgram)
	principal := session.Principal{UserID: "user_1", SessionID: "session_1"}
	record := session.SessionRecord{
		SessionID: "session_1", UserID: "user_1", ClientKind: session.ClientKindMiniProgram,
		AuthenticationTime: time.Now().UTC().Add(-time.Minute), SecurityEpoch: 7,
	}
	ctx := WithPrincipal(req.Context(), principal)
	ctx = WithSessionRecord(ctx, record)
	ctx = WithNativeBearerSession(ctx)
	return req.WithContext(ctx)
}

func TestDreamUPNativeReauthenticationMintsExactSingleUseGrant(t *testing.T) {
	target := `["dreamup-admin-target/v1","evt_shanghai","application","app_1"]`
	service := &nativeReauthServiceStub{result: app.NativeReauthenticationAuthorization{
		Action: permissions.ActionApplicationReview, Target: target, ChallengeVersion: 11, SecurityEpoch: 7,
	}}
	identities := &nativeReauthIdentityStub{user: identity.User{ID: "user_1"}}
	grants := newMemReauthGrants()
	handler, err := NewDreamUPNativeReauthHandlers(service, identities, grants, nativeReauthRateStub{allow: true}, &fakeReauthAuditor{}, time.Minute, 5, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"loginCode":"wx-code-1","eventId":"evt_shanghai","action":"event.application.review","target":"[\"dreamup-admin-target/v1\",\"evt_shanghai\",\"application\",\"app_1\"]"}`
	w := httptest.NewRecorder()
	handler.Request(w, nativeReauthRequest(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	token := decodeReauthToken(t, w)
	grant, err := grants.ConsumeGrant(context.Background(), session.HashToken(token))
	if err != nil {
		t.Fatal(err)
	}
	if grant.UserID != "user_1" || grant.SessionID != "session_1" || grant.Action != string(permissions.ActionApplicationReview) || grant.Target != target || grant.SecurityEpoch != securitystate.Epoch(7) || grant.ChallengeVersion != 11 || !strings.HasPrefix(grant.GrantID, "rgr_") {
		t.Fatalf("grant=%+v", grant)
	}
	if service.calls != 1 || service.actor.AuthenticationTransport != app.AuthenticationTransportNativeMiniProgramBearer || service.input.EventID != "evt_shanghai" || identities.calls != 1 {
		t.Fatalf("service=%+v identities=%d", service, identities.calls)
	}
}

func TestDreamUPNativeReauthenticationRejectsDifferentWeChatIdentity(t *testing.T) {
	service := &nativeReauthServiceStub{}
	identities := &nativeReauthIdentityStub{user: identity.User{ID: "user_other"}}
	grants := newMemReauthGrants()
	handler, err := NewDreamUPNativeReauthHandlers(service, identities, grants, nativeReauthRateStub{allow: true}, &fakeReauthAuditor{}, time.Minute, 5, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.Request(w, nativeReauthRequest(`{"loginCode":"wx-code-2","eventId":"evt_shanghai","action":"event.application.review","target":"[\"dreamup-admin-target/v1\",\"evt_shanghai\",\"application\",\"app_1\"]"}`))
	if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if service.calls != 0 || len(grants.data) != 0 {
		t.Fatalf("serviceCalls=%d grants=%d", service.calls, len(grants.data))
	}
}

func TestDreamUPNativeReauthenticationRejectsNonCanonicalTargetBeforeIdentityExchange(t *testing.T) {
	service := &nativeReauthServiceStub{}
	identities := &nativeReauthIdentityStub{user: identity.User{ID: "user_1"}}
	grants := newMemReauthGrants()
	handler, err := NewDreamUPNativeReauthHandlers(service, identities, grants, nativeReauthRateStub{allow: true}, &fakeReauthAuditor{}, time.Minute, 5, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.Request(w, nativeReauthRequest(`{"loginCode":"wx-code-3","eventId":"evt_shanghai","action":"event.application.review","target":"[ \"dreamup-admin-target/v1\", \"evt_shanghai\", \"application\", \"app_1\" ]"}`))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if identities.calls != 0 || service.calls != 0 || len(grants.data) != 0 {
		t.Fatalf("identityCalls=%d serviceCalls=%d grants=%d", identities.calls, service.calls, len(grants.data))
	}
}
