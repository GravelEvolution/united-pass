package dreamupadmin

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

func TestProxyRequestMatchesTheGlobalRequestIDContract(t *testing.T) {
	input := ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionDashboardRead, ResourceKind: "event", ResourceID: "evt_shanghai", Method: http.MethodGet, Path: "/internal/v1/events/evt_shanghai/dashboard", RequestID: strings.Repeat("a", 128)}
	if err := validateProxyRequest(input); err != nil {
		t.Fatalf("128-character request ID rejected: %v", err)
	}
	input.RequestID += "a"
	if err := validateProxyRequest(input); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("129-character request ID error=%v", err)
	}
}

type serviceAuthorizerStub struct {
	decision permissions.Decision
	seen     permissions.Resource
}

func (s *serviceAuthorizerStub) Check(_ context.Context, _ identity.UserID, _ permissions.Action, resource permissions.Resource) (permissions.Decision, error) {
	s.seen = resource
	return s.decision, nil
}

type serviceRegistryStub struct{ event adminroles.RegisteredEvent }

func (s serviceRegistryStub) GetExact(_ context.Context, id string) (adminroles.RegisteredEvent, error) {
	if id != s.event.EventID {
		return adminroles.RegisteredEvent{}, adminroles.ErrEventRegistryNotFound
	}
	return s.event, nil
}
func (s serviceRegistryStub) ListEnabled(context.Context, adminpagination.Query) (adminpagination.Page[adminroles.RegisteredEvent], error) {
	return adminpagination.Page[adminroles.RegisteredEvent]{Items: []adminroles.RegisteredEvent{s.event}}, nil
}

type eligibilityRegistryStub struct {
	pages   map[string]adminpagination.Page[adminroles.RegisteredEvent]
	queries []adminpagination.Query
}

func (s *eligibilityRegistryStub) GetExact(context.Context, string) (adminroles.RegisteredEvent, error) {
	panic("eligibility must not fetch event details")
}

func (s *eligibilityRegistryStub) ListEnabled(_ context.Context, query adminpagination.Query) (adminpagination.Page[adminroles.RegisteredEvent], error) {
	s.queries = append(s.queries, query)
	return s.pages[query.Cursor], nil
}

type eligibilityAuthorizerStub struct {
	decisions map[string]permissions.Decision
	actions   []permissions.Action
	resources []permissions.Resource
}

func (s *eligibilityAuthorizerStub) Check(_ context.Context, _ identity.UserID, action permissions.Action, resource permissions.Resource) (permissions.Decision, error) {
	s.actions = append(s.actions, action)
	s.resources = append(s.resources, resource)
	return s.decisions[resource.EventID], nil
}

type eligibilityStepUpPanic struct{}

func (eligibilityStepUpPanic) GetActiveForSession(context.Context, string, identity.UserID, time.Time) (adminstepup.StepUpState, error) {
	panic("eligibility must not require administrator step-up")
}

func registeredEligibilityEvent(id string) adminroles.RegisteredEvent {
	return adminroles.RegisteredEvent{EventID: id, Series: "dreamup", Slug: id, DisplayName: id, Enabled: true, Version: 1}
}

func TestServiceEligibilityRequiresAuthoritativeBindingWithoutStepUp(t *testing.T) {
	actor := Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)}
	tests := []struct {
		name     string
		decision permissions.Decision
		want     bool
	}{
		{name: "generic administrator persona is not authority", decision: permissions.Decision{Role: adminroles.RoleAdmin}, want: false},
		{name: "policy allow without binding evidence fails closed", decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin}, want: false},
		{name: "active event binding is eligible", decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 1}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := &eligibilityRegistryStub{pages: map[string]adminpagination.Page[adminroles.RegisteredEvent]{"": {Items: []adminroles.RegisteredEvent{registeredEligibilityEvent("evt_a")}}}}
			authorizer := &eligibilityAuthorizerStub{decisions: map[string]permissions.Decision{"evt_a": test.decision}}
			service, err := NewService(ServiceDependencies{Authorizer: authorizer, Registry: registry, StepUps: eligibilityStepUpPanic{}, Signer: &serviceSignerStub{}, Client: &serviceClientStub{}}, ServiceConfig{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := service.Eligible(context.Background(), actor)
			if err != nil || got != test.want {
				t.Fatalf("eligible=%v err=%v want=%v", got, err, test.want)
			}
			if len(authorizer.actions) != 1 || len(authorizer.resources) != 1 {
				t.Fatalf("actions=%v resources=%+v", authorizer.actions, authorizer.resources)
			}
			resource := authorizer.resources[0]
			if authorizer.actions[0] != permissions.ActionDashboardRead || resource.Kind != "event" || resource.ID != "evt_a" || resource.EventID != "evt_a" || resource.Attributes != nil {
				t.Fatalf("actions=%v resources=%+v", authorizer.actions, authorizer.resources)
			}
		})
	}
}

func TestServiceEligibilityTraversesRegistryPagesWithoutDisclosingThem(t *testing.T) {
	registry := &eligibilityRegistryStub{pages: map[string]adminpagination.Page[adminroles.RegisteredEvent]{
		"":         {Items: []adminroles.RegisteredEvent{registeredEligibilityEvent("evt_a")}, HasMore: true, NextCursor: "cursor_2"},
		"cursor_2": {Items: []adminroles.RegisteredEvent{registeredEligibilityEvent("evt_b")}},
	}}
	authorizer := &eligibilityAuthorizerStub{decisions: map[string]permissions.Decision{
		"evt_a": {},
		"evt_b": {Allowed: true, Role: adminroles.RoleSeniorAdmin, BindingID: "binding_2", BindingVersion: 4},
	}}
	service, err := NewService(ServiceDependencies{Authorizer: authorizer, Registry: registry, StepUps: eligibilityStepUpPanic{}, Signer: &serviceSignerStub{}, Client: &serviceClientStub{}}, ServiceConfig{})
	if err != nil {
		t.Fatal(err)
	}
	eligible, err := service.Eligible(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: time.Now().UTC()})
	if err != nil || !eligible {
		t.Fatalf("eligible=%v err=%v", eligible, err)
	}
	if len(registry.queries) != 2 || registry.queries[0].Cursor != "" || registry.queries[1].Cursor != "cursor_2" || registry.queries[0].Limit != adminpagination.MaxPageSize {
		t.Fatalf("queries=%+v", registry.queries)
	}
}

type serviceStepUpStub struct{ state adminstepup.StepUpState }

func (s serviceStepUpStub) GetActiveForSession(_ context.Context, sessionID string, userID identity.UserID, now time.Time) (adminstepup.StepUpState, error) {
	if s.state.SessionID != sessionID || s.state.UserID != userID || s.state.RevokedAt != nil || !now.Before(s.state.ExpiresAt) {
		return adminstepup.StepUpState{}, adminstepup.ErrNotFound
	}
	return s.state, nil
}

type serviceAccountSecurityStub struct {
	epoch securitystate.Epoch
	err   error
	seen  identity.UserID
	calls int
}

func (s *serviceAccountSecurityStub) CurrentEpoch(_ context.Context, userID identity.UserID) (securitystate.Epoch, error) {
	s.calls++
	s.seen = userID
	return s.epoch, s.err
}

type serviceReauthStub struct {
	data                             auth.ReauthGrantData
	err                              error
	token, action, sessionID, target string
	applicationID                    applications.ApplicationID
	clientID                         applications.OAuthClientID
	calls                            int
}

func (s *serviceReauthStub) VerifyAndConsumeData(_ context.Context, token, action, sessionID, target string, applicationID applications.ApplicationID, clientID applications.OAuthClientID) (auth.ReauthGrantData, error) {
	s.calls++
	s.token, s.action, s.sessionID, s.target, s.applicationID, s.clientID = token, action, sessionID, target, applicationID, clientID
	return s.data, s.err
}

func validServiceGrant(now time.Time, action, target string) auth.ReauthGrantData {
	return auth.ReauthGrantData{GrantID: "rgr_exact_1", UserID: "user_1", SessionID: "session_1", Action: action, Target: target, CreatedAt: now.Add(-time.Minute), SecurityEpoch: 1, ChallengeVersion: 4}
}

type serviceSignerStub struct {
	input dreamupdelegation.AdministratorAssertion
}

func (s *serviceSignerStub) SignAdministrator(input dreamupdelegation.AdministratorAssertion) (dreamupdelegation.SignedAssertion, error) {
	s.input = input
	return dreamupdelegation.SignedAssertion{Token: "signed", NotBefore: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(20 * time.Second)}, nil
}

type serviceClientStub struct {
	input    UpstreamRequest
	response UpstreamResponse
	err      error
}

func (s *serviceClientStub) Execute(_ context.Context, input UpstreamRequest) (UpstreamResponse, error) {
	s.input = input
	if s.err != nil {
		return UpstreamResponse{}, s.err
	}
	if s.response.StatusCode != 0 {
		return s.response, nil
	}
	return UpstreamResponse{StatusCode: http.StatusOK, Body: json.RawMessage(`{"review":{"version":2}}`), RequestID: input.RequestID, ETag: `"2"`}, nil
}

func TestServiceBindsExactEventRoleStepUpAndRequest(t *testing.T) {
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	authorizer := &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}}
	signer := &serviceSignerStub{}
	client := &serviceClientStub{}
	applicationTarget := dreamUPGrantTarget("evt_shanghai", "application", "app_1")
	reauth := &serviceReauthStub{data: validServiceGrant(now, string(permissions.ActionApplicationReview), applicationTarget)}
	service, err := NewService(ServiceDependencies{
		Authorizer:   authorizer,
		Registry:     serviceRegistryStub{event: adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai", DisplayName: "上海站", Enabled: true, Version: 1}},
		StepUps:      serviceStepUpStub{state: adminstepup.StepUpState{ID: "asu_review_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}},
		ReauthGrants: reauth,
		Signer:       signer, Client: client,
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	body := json.RawMessage(`{"recommendation":"accept","note":"clear"}`)
	result, err := service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute), AuthenticationTransport: AuthenticationTransportNativeMiniProgramBearer}, ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview,
		ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPut,
		Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: body,
		RequestID: "req_12345678", IdempotencyKey: "0123456789abcdef0123456789abcdef", IfMatch: `"1"`, ReauthenticationToken: strings.Repeat("R", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusOK || authorizer.seen.EventID != "evt_shanghai" || authorizer.seen.ID != "app_1" {
		t.Fatalf("result=%+v resource=%+v", result, authorizer.seen)
	}
	if signer.input.EventID != "evt_shanghai" || signer.input.RoleBindingID != "binding_1" || signer.input.RoleVersion != 3 || signer.input.ChallengeVersion != 4 || signer.input.IfMatch != `"1"` || signer.input.ReauthGrantID != "rgr_exact_1" || !signer.input.StepUpAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("signed input=%+v", signer.input)
	}
	if client.input.IdempotencyKey == "" || client.input.IfMatch != `"1"` || string(client.input.Body) != string(body) {
		t.Fatalf("upstream input=%+v", client.input)
	}
	if reauth.calls != 1 || reauth.token != strings.Repeat("R", 43) || reauth.action != string(permissions.ActionApplicationReview) || reauth.sessionID != "session_1" || reauth.target != applicationTarget || reauth.applicationID != "" || reauth.clientID != "" {
		t.Fatalf("reauth consumption binding calls=%d tokenMatch=%v action=%q session=%q target=%q app=%q client=%q", reauth.calls, reauth.token == strings.Repeat("R", 43), reauth.action, reauth.sessionID, reauth.target, reauth.applicationID, reauth.clientID)
	}
}

func TestServiceAllowsFreshDurableStepUpOnlyForLegacyCookieHighRiskRequest(t *testing.T) {
	now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	signer := &serviceSignerStub{}
	client := &serviceClientStub{}
	accountSecurity := &serviceAccountSecurityStub{epoch: 9}
	service, err := NewService(ServiceDependencies{
		Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
		Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
		AccountSecurity: accountSecurity,
		StepUps: serviceStepUpStub{state: adminstepup.StepUpState{
			ID: "asu_cookie_fresh_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, SecurityEpoch: 9,
			VerifiedAt: now.Add(-dreamupdelegation.MaxHighRiskStepUpAge), ExpiresAt: now.Add(20 * time.Minute),
		}},
		Signer: signer, Client: client,
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Proxy(context.Background(), Actor{
		UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-10 * time.Minute),
		AuthenticationTransport: AuthenticationTransportBrowserCookie,
	}, ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview, ResourceKind: "application", ResourceID: "app_1",
		Method: http.MethodPut, Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: json.RawMessage(`{"recommendation":"accept"}`),
		RequestID: "req_cookie_compat", IdempotencyKey: strings.Repeat("C", 32), IfMatch: `"1"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if signer.input.ReauthGrantID != "asu_cookie_fresh_1" || signer.input.ChallengeVersion != 4 || !signer.input.StepUpAt.Equal(now.Add(-dreamupdelegation.MaxHighRiskStepUpAge)) {
		t.Fatalf("legacy cookie assertion=%+v", signer.input)
	}
	if client.input.Path != "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me" {
		t.Fatalf("upstream input=%+v", client.input)
	}
	if accountSecurity.calls != 1 || accountSecurity.seen != "user_1" {
		t.Fatalf("account security calls=%d user=%q", accountSecurity.calls, accountSecurity.seen)
	}
}

func TestServiceLegacyCookieFallbackFailsClosedOutsideExactBoundary(t *testing.T) {
	now := time.Date(2026, 8, 29, 3, 15, 0, 0, time.UTC)
	tests := []struct {
		name                string
		transport           AuthenticationTransport
		authTime            time.Time
		state               adminstepup.StepUpState
		currentEpoch        securitystate.Epoch
		epochErr            error
		omitAccountSecurity bool
		wantEpochCalls      int
	}{
		{
			name: "unknown transport", authTime: now.Add(-10 * time.Minute),
			state:        adminstepup.StepUpState{ID: "asu_unknown_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, SecurityEpoch: 1, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
			currentEpoch: 1,
		},
		{
			name: "stale cookie proof", transport: AuthenticationTransportBrowserCookie, authTime: now.Add(-10 * time.Minute),
			state:        adminstepup.StepUpState{ID: "asu_stale_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, SecurityEpoch: 1, VerifiedAt: now.Add(-dreamupdelegation.MaxHighRiskStepUpAge - time.Second), ExpiresAt: now.Add(time.Minute)},
			currentEpoch: 1, wantEpochCalls: 1,
		},
		{
			name: "future cookie proof", transport: AuthenticationTransportBrowserCookie, authTime: now.Add(-10 * time.Minute),
			state:        adminstepup.StepUpState{ID: "asu_future_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, SecurityEpoch: 1, VerifiedAt: now.Add(dreamupdelegation.MaxClockSkew + time.Second), ExpiresAt: now.Add(time.Minute)},
			currentEpoch: 1, wantEpochCalls: 1,
		},
		{
			name: "proof predates current login", transport: AuthenticationTransportBrowserCookie, authTime: now.Add(-time.Minute),
			state:        adminstepup.StepUpState{ID: "asu_old_login_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, SecurityEpoch: 1, VerifiedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(time.Minute)},
			currentEpoch: 1, wantEpochCalls: 1,
		},
		{
			name: "missing security epoch", transport: AuthenticationTransportBrowserCookie, authTime: now.Add(-10 * time.Minute),
			state:        adminstepup.StepUpState{ID: "asu_epoch_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
			currentEpoch: 1, wantEpochCalls: 1,
		},
		{
			name: "account security epoch drift", transport: AuthenticationTransportBrowserCookie, authTime: now.Add(-10 * time.Minute),
			state:        adminstepup.StepUpState{ID: "asu_epoch_drift_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, SecurityEpoch: 9, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
			currentEpoch: 10, wantEpochCalls: 1,
		},
		{
			name: "account security epoch lookup failure", transport: AuthenticationTransportBrowserCookie, authTime: now.Add(-10 * time.Minute),
			state:        adminstepup.StepUpState{ID: "asu_epoch_error_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, SecurityEpoch: 9, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
			currentEpoch: 9, epochErr: errors.New("database unavailable"), wantEpochCalls: 1,
		},
		{
			name: "account security reader unavailable", transport: AuthenticationTransportBrowserCookie, authTime: now.Add(-10 * time.Minute),
			state:               adminstepup.StepUpState{ID: "asu_epoch_reader_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, SecurityEpoch: 9, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
			omitAccountSecurity: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := &serviceSignerStub{}
			accountSecurity := &serviceAccountSecurityStub{epoch: test.currentEpoch, err: test.epochErr}
			var accountSecurityReader AccountSecurityEpochReader = accountSecurity
			if test.omitAccountSecurity {
				accountSecurityReader = nil
			}
			service, err := NewService(ServiceDependencies{
				Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
				Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
				StepUps:         serviceStepUpStub{state: test.state},
				AccountSecurity: accountSecurityReader,
				Signer:          signer, Client: &serviceClientStub{},
			}, ServiceConfig{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: test.authTime, AuthenticationTransport: test.transport}, ProxyRequest{
				EventID: "evt_shanghai", Capability: permissions.ActionContentManage, ResourceKind: "event_content", ResourceID: "evt_shanghai",
				Method: http.MethodGet, Path: "/internal/v1/events/evt_shanghai/content", RequestID: "req_cookie_boundary",
			})
			if !errors.Is(err, ErrStepUpRequired) || signer.input.EventID != "" {
				t.Fatalf("error=%v signed=%+v", err, signer.input)
			}
			if accountSecurity.calls != test.wantEpochCalls {
				t.Fatalf("account security calls=%d want=%d", accountSecurity.calls, test.wantEpochCalls)
			}
		})
	}
}

func TestServiceNativeMiniProgramUsesEpochBoundSessionWithoutSecurityQuestion(t *testing.T) {
	now := time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	accountSecurity := &serviceAccountSecurityStub{epoch: 7}
	signer := &serviceSignerStub{}
	client := &serviceClientStub{}
	consumer := &serviceReauthStub{err: errors.New("must not consume a grant")}
	service, err := NewService(ServiceDependencies{
		Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_native_1", BindingVersion: 5}},
		Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
		StepUps:         serviceStepUpStub{},
		AccountSecurity: accountSecurity,
		ReauthGrants:    consumer,
		Signer:          signer,
		Client:          client,
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{
		UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-10 * time.Minute), SecurityEpoch: 7,
		AuthenticationTransport: AuthenticationTransportNativeMiniProgramBearer,
	}
	_, err = service.Proxy(context.Background(), actor, ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview, ResourceKind: "application", ResourceID: "app_1",
		Method: http.MethodPut, Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: json.RawMessage(`{"recommendation":"accept"}`),
		RequestID: "req_native_session", IdempotencyKey: strings.Repeat("N", 32), IfMatch: `"1"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if accountSecurity.calls != 1 || accountSecurity.seen != "user_1" || consumer.calls != 0 {
		t.Fatalf("epoch calls=%d user=%q grant consumer calls=%d", accountSecurity.calls, accountSecurity.seen, consumer.calls)
	}
	if signer.input.ChallengeVersion != 7 || !signer.input.StepUpAt.Equal(now) || !strings.HasPrefix(signer.input.ReauthGrantID, "nma_") || len(signer.input.ReauthGrantID) != 28 {
		t.Fatalf("native assertion=%+v", signer.input)
	}
	if signer.input.RoleBindingID != "binding_native_1" || signer.input.RoleVersion != 5 || client.input.Path == "" {
		t.Fatalf("native signed=%+v upstream=%+v", signer.input, client.input)
	}
}

func TestServiceNativeMiniProgramSessionProofFailsClosedOnEpochDrift(t *testing.T) {
	now := time.Date(2026, 8, 29, 4, 5, 0, 0, time.UTC)
	signer := &serviceSignerStub{}
	service, err := NewService(ServiceDependencies{
		Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_native_1", BindingVersion: 5}},
		Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
		StepUps:         serviceStepUpStub{},
		AccountSecurity: &serviceAccountSecurityStub{epoch: 8},
		Signer:          signer,
		Client:          &serviceClientStub{},
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{
		UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-time.Minute), SecurityEpoch: 7,
		AuthenticationTransport: AuthenticationTransportNativeMiniProgramBearer,
	}, ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionApplicationReadBasic, ResourceKind: "application", ResourceID: "app_1",
		Method: http.MethodGet, Path: "/internal/v1/events/evt_shanghai/applications/app_1", RequestID: "req_epoch_drift",
	})
	if !errors.Is(err, ErrStepUpRequired) || signer.input.EventID != "" {
		t.Fatalf("error=%v signed=%+v", err, signer.input)
	}
}

func TestServiceNativeMiniProgramOrdinaryReadUsesEpochBoundSession(t *testing.T) {
	now := time.Date(2026, 8, 29, 4, 10, 0, 0, time.UTC)
	authenticatedAt := now.Add(-3 * time.Minute)
	accountSecurity := &serviceAccountSecurityStub{epoch: 3}
	signer := &serviceSignerStub{}
	client := &serviceClientStub{}
	service, err := NewService(ServiceDependencies{
		Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_native_read", BindingVersion: 2}},
		Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
		StepUps:         serviceStepUpStub{},
		AccountSecurity: accountSecurity,
		Signer:          signer,
		Client:          client,
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{
		UserID: "user_1", SessionID: "session_1", AuthenticatedAt: authenticatedAt, SecurityEpoch: 3,
		AuthenticationTransport: AuthenticationTransportNativeMiniProgramBearer,
	}, ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionApplicationReadBasic, ResourceKind: "application", ResourceID: "app_1",
		Method: http.MethodGet, Path: "/internal/v1/events/evt_shanghai/applications/app_1", RequestID: "req_native_read",
	})
	if err != nil {
		t.Fatal(err)
	}
	if accountSecurity.calls != 1 || signer.input.ChallengeVersion != 3 || !signer.input.StepUpAt.Equal(authenticatedAt) || signer.input.ReauthGrantID != "" {
		t.Fatalf("epoch calls=%d assertion=%+v", accountSecurity.calls, signer.input)
	}
	if signer.input.Method != http.MethodGet || signer.input.PathAndQuery != "/internal/v1/events/evt_shanghai/applications/app_1" || client.input.RequestID != "req_native_read" {
		t.Fatalf("assertion=%+v upstream=%+v", signer.input, client.input)
	}
}

func TestServiceNativeMiniProgramListEventsUsesEpochBoundSession(t *testing.T) {
	now := time.Date(2026, 8, 29, 4, 15, 0, 0, time.UTC)
	accountSecurity := &serviceAccountSecurityStub{epoch: 3}
	signer := &serviceSignerStub{}
	client := &serviceClientStub{response: UpstreamResponse{StatusCode: http.StatusOK, Body: json.RawMessage(`{"applications":[]}`)}}
	service, err := NewService(ServiceDependencies{
		Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_native_list", BindingVersion: 2}},
		Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
		StepUps:         serviceStepUpStub{},
		AccountSecurity: accountSecurity,
		Signer:          signer,
		Client:          client,
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	events, err := service.ListEvents(context.Background(), Actor{
		UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-3 * time.Minute), SecurityEpoch: 3,
		AuthenticationTransport: AuthenticationTransportNativeMiniProgramBearer,
	})
	if err != nil || len(events) != 1 || events[0].EventID != "evt_shanghai" {
		t.Fatalf("events=%+v error=%v", events, err)
	}
	if accountSecurity.calls != 2 || signer.input.PathAndQuery != "/internal/v1/events/evt_shanghai/applications" || client.input.Path == "" {
		t.Fatalf("epoch calls=%d assertion=%+v upstream=%+v", accountSecurity.calls, signer.input, client.input)
	}
}

func TestServiceNativeMiniProgramOperationStatusFailsBeforeStorageOnEpochDrift(t *testing.T) {
	now := time.Date(2026, 8, 29, 4, 18, 0, 0, time.UTC)
	service, err := NewService(ServiceDependencies{
		Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_native_status", BindingVersion: 1}},
		Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
		StepUps:         serviceStepUpStub{},
		AccountSecurity: &serviceAccountSecurityStub{epoch: 2},
		Signer:          &serviceSignerStub{},
		Client:          &serviceClientStub{},
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.OperationStatus(context.Background(), Actor{
		UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-time.Minute), SecurityEpoch: 1,
		AuthenticationTransport: AuthenticationTransportNativeMiniProgramBearer,
	}, "evt_shanghai", "0123456789abcdef0123456789abcdef")
	if !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("error=%v", err)
	}
}

func TestServiceNativeMiniProgramSessionBoundaryFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 29, 4, 20, 0, 0, time.UTC)
	tests := []struct {
		name          string
		securityEpoch securitystate.Epoch
		authTime      time.Time
		reader        AccountSecurityEpochReader
		wantCalls     int
	}{
		{name: "unstamped session", authTime: now.Add(-time.Minute), reader: &serviceAccountSecurityStub{epoch: 1}},
		{name: "missing epoch reader", securityEpoch: 1, authTime: now.Add(-time.Minute)},
		{name: "epoch lookup failure", securityEpoch: 1, authTime: now.Add(-time.Minute), reader: &serviceAccountSecurityStub{epoch: 1, err: errors.New("database unavailable")}, wantCalls: 1},
		{name: "epoch drift", securityEpoch: 1, authTime: now.Add(-time.Minute), reader: &serviceAccountSecurityStub{epoch: 2}, wantCalls: 1},
		{name: "future authentication", securityEpoch: 1, authTime: now.Add(dreamupdelegation.MaxClockSkew + time.Second), reader: &serviceAccountSecurityStub{epoch: 1}},
		{name: "stale authentication", securityEpoch: 1, authTime: now.Add(-dreamupdelegation.MaxAdministratorLoginAge - time.Second), reader: &serviceAccountSecurityStub{epoch: 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := &serviceSignerStub{}
			client := &serviceClientStub{}
			service, err := NewService(ServiceDependencies{
				Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_native_1", BindingVersion: 1}},
				Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
				StepUps:         serviceStepUpStub{},
				AccountSecurity: test.reader,
				Signer:          signer,
				Client:          client,
			}, ServiceConfig{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Proxy(context.Background(), Actor{
				UserID: "user_1", SessionID: "session_1", AuthenticatedAt: test.authTime, SecurityEpoch: test.securityEpoch,
				AuthenticationTransport: AuthenticationTransportNativeMiniProgramBearer,
			}, ProxyRequest{
				EventID: "evt_shanghai", Capability: permissions.ActionApplicationReadBasic, ResourceKind: "application", ResourceID: "app_1",
				Method: http.MethodGet, Path: "/internal/v1/events/evt_shanghai/applications/app_1", RequestID: "req_native_boundary",
			})
			if !errors.Is(err, ErrStepUpRequired) || signer.input.EventID != "" || client.input.Path != "" {
				t.Fatalf("error=%v signed=%+v upstream=%+v", err, signer.input, client.input)
			}
			if stub, ok := test.reader.(*serviceAccountSecurityStub); ok && stub.calls != test.wantCalls {
				t.Fatalf("epoch calls=%d want=%d", stub.calls, test.wantCalls)
			}
		})
	}
}

func TestServiceNativeMiniProgramInvalidExplicitGrantCannotFallBackToSession(t *testing.T) {
	now := time.Date(2026, 8, 29, 4, 30, 0, 0, time.UTC)
	consumer := &serviceReauthStub{err: auth.ErrReauthGrantNotFound}
	accountSecurity := &serviceAccountSecurityStub{epoch: 4}
	signer := &serviceSignerStub{}
	service, err := NewService(ServiceDependencies{
		Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_native_1", BindingVersion: 1, ChallengeVersion: 2}},
		Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
		StepUps:         serviceStepUpStub{},
		AccountSecurity: accountSecurity,
		ReauthGrants:    consumer,
		Signer:          signer,
		Client:          &serviceClientStub{},
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{
		UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-time.Minute), SecurityEpoch: 4,
		AuthenticationTransport: AuthenticationTransportNativeMiniProgramBearer,
	}, ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview, ResourceKind: "application", ResourceID: "app_1",
		Method: http.MethodPut, Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: json.RawMessage(`{"recommendation":"accept"}`),
		RequestID: "req_native_bad_grant", IdempotencyKey: strings.Repeat("B", 32), IfMatch: `"1"`, ReauthenticationToken: strings.Repeat("X", 43),
	})
	if !errors.Is(err, ErrStepUpRequired) || consumer.calls != 1 || accountSecurity.calls != 0 || signer.input.EventID != "" {
		t.Fatalf("error=%v consumerCalls=%d epochCalls=%d signed=%+v", err, consumer.calls, accountSecurity.calls, signer.input)
	}
}

func TestServiceCookieRejectedOneShotTokenNeverDowngradesToDurableProof(t *testing.T) {
	now := time.Date(2026, 8, 29, 3, 30, 0, 0, time.UTC)
	consumer := &serviceReauthStub{err: auth.ErrReauthGrantNotFound}
	signer := &serviceSignerStub{}
	accountSecurity := &serviceAccountSecurityStub{epoch: 1}
	service, err := NewService(ServiceDependencies{
		Authorizer:      &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
		Registry:        serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
		AccountSecurity: accountSecurity,
		StepUps: serviceStepUpStub{state: adminstepup.StepUpState{
			ID: "asu_cookie_valid_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, SecurityEpoch: 1,
			VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		}},
		ReauthGrants: consumer, Signer: signer, Client: &serviceClientStub{},
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{
		UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute), AuthenticationTransport: AuthenticationTransportBrowserCookie,
	}, ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionContentManage, ResourceKind: "event_content", ResourceID: "evt_shanghai",
		Method: http.MethodGet, Path: "/internal/v1/events/evt_shanghai/content", RequestID: "req_cookie_bad_token", ReauthenticationToken: strings.Repeat("Z", 43),
	})
	if !errors.Is(err, ErrStepUpRequired) || consumer.calls != 1 || accountSecurity.calls != 0 || signer.input.EventID != "" {
		t.Fatalf("error=%v consumerCalls=%d epochCalls=%d signed=%+v", err, consumer.calls, accountSecurity.calls, signer.input)
	}
}

func TestServiceHighRiskGrantValidationFailsClosedBeforeSigning(t *testing.T) {
	now := time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)
	base := validServiceGrant(now, string(permissions.ActionApplicationReview), dreamUPGrantTarget("evt_shanghai", "application", "app_1"))
	tests := []struct {
		name   string
		mutate func(*auth.ReauthGrantData)
	}{
		{name: "wrong user", mutate: func(v *auth.ReauthGrantData) { v.UserID = "user_other" }},
		{name: "wrong session", mutate: func(v *auth.ReauthGrantData) { v.SessionID = "session_other" }},
		{name: "wrong action", mutate: func(v *auth.ReauthGrantData) { v.Action = string(permissions.ActionContentManage) }},
		{name: "wrong application target", mutate: func(v *auth.ReauthGrantData) { v.Target = "app_other" }},
		{name: "application binding injected", mutate: func(v *auth.ReauthGrantData) { v.ApplicationID = "oauth_app" }},
		{name: "client binding injected", mutate: func(v *auth.ReauthGrantData) { v.ClientID = "oauth_client" }},
		{name: "missing stable grant id", mutate: func(v *auth.ReauthGrantData) { v.GrantID = "" }},
		{name: "challenge generation drift", mutate: func(v *auth.ReauthGrantData) { v.ChallengeVersion++ }},
		{name: "missing security epoch", mutate: func(v *auth.ReauthGrantData) { v.SecurityEpoch = 0 }},
		{name: "stale grant", mutate: func(v *auth.ReauthGrantData) {
			v.CreatedAt = now.Add(-dreamupdelegation.MaxHighRiskStepUpAge - time.Second)
		}},
		{name: "future grant", mutate: func(v *auth.ReauthGrantData) { v.CreatedAt = now.Add(dreamupdelegation.MaxClockSkew + time.Second) }},
		{name: "predates current login", mutate: func(v *auth.ReauthGrantData) { v.CreatedAt = now.Add(-10 * time.Minute) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			grant := base
			test.mutate(&grant)
			signer := &serviceSignerStub{}
			service, err := NewService(ServiceDependencies{
				Authorizer:   &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
				Registry:     serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
				StepUps:      serviceStepUpStub{},
				ReauthGrants: &serviceReauthStub{data: grant},
				Signer:       signer,
				Client:       &serviceClientStub{},
			}, ServiceConfig{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{
				EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview, ResourceKind: "application", ResourceID: "app_1",
				Method: http.MethodPut, Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: json.RawMessage(`{"recommendation":"accept"}`),
				RequestID: "req_grant_matrix", IdempotencyKey: strings.Repeat("I", 32), IfMatch: `"1"`, ReauthenticationToken: strings.Repeat("T", 43),
			})
			if !errors.Is(err, ErrStepUpRequired) || signer.input.EventID != "" {
				t.Fatalf("error=%v signed=%+v", err, signer.input)
			}
		})
	}
}

func TestServiceMissingGrantAndVerifierFailureFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name  string
		token string
		stub  *serviceReauthStub
	}{
		{name: "missing token", stub: &serviceReauthStub{data: validServiceGrant(now, string(permissions.ActionContentManage), dreamUPGrantTarget("evt_shanghai", "event", "evt_shanghai"))}},
		{name: "atomic consumer rejected or reused token", token: strings.Repeat("U", 43), stub: &serviceReauthStub{err: auth.ErrReauthGrantNotFound}},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer := &serviceSignerStub{}
			service, err := NewService(ServiceDependencies{
				Authorizer: &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 1, ChallengeVersion: 4}},
				Registry:   serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")}, StepUps: serviceStepUpStub{}, ReauthGrants: test.stub,
				Signer: signer, Client: &serviceClientStub{},
			}, ServiceConfig{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{
				EventID: "evt_shanghai", Capability: permissions.ActionContentManage, ResourceKind: "event_content", ResourceID: "evt_shanghai", Method: http.MethodGet,
				Path: "/internal/v1/events/evt_shanghai/content", RequestID: "req_missing_grant", ReauthenticationToken: test.token,
			})
			if !errors.Is(err, ErrStepUpRequired) || signer.input.EventID != "" {
				t.Fatalf("error=%v signed=%+v", err, signer.input)
			}
			if test.token == "" && test.stub.calls != 0 {
				t.Fatalf("missing token called consumer %d times", test.stub.calls)
			}
		})
	}
}

func TestServiceOrdinaryActionRejectsGrantWithoutConsumption(t *testing.T) {
	now := time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)
	reauth := &serviceReauthStub{data: validServiceGrant(now, string(permissions.ActionApplicationReadBasic), "app_1")}
	service, err := NewService(ServiceDependencies{
		Authorizer:   &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 1, ChallengeVersion: 4}},
		Registry:     serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
		StepUps:      serviceStepUpStub{state: adminstepup.StepUpState{ID: "asu_general", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}},
		ReauthGrants: reauth, Signer: &serviceSignerStub{}, Client: &serviceClientStub{},
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionApplicationReadBasic, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodGet,
		Path: "/internal/v1/events/evt_shanghai/applications/app_1", RequestID: "req_ordinary_token", ReauthenticationToken: strings.Repeat("V", 43),
	})
	if !errors.Is(err, ErrInvalidRequest) || reauth.calls != 0 {
		t.Fatalf("error=%v consumer calls=%d", err, reauth.calls)
	}
}

func TestHighRiskGrantTargetIsStableAndServerDerived(t *testing.T) {
	tests := []struct {
		name  string
		input ProxyRequest
		want  string
	}{
		{name: "content document and announcement", input: ProxyRequest{EventID: "evt_a", Capability: permissions.ActionContentManage, ResourceKind: "event_content", ResourceID: "announcement_1"}, want: dreamUPGrantTarget("evt_a", "event", "evt_a")},
		{name: "contact list", input: ProxyRequest{EventID: "evt_a", Capability: permissions.ActionContactSubmissionManage, ResourceKind: "event", ResourceID: "evt_a"}, want: dreamUPGrantTarget("evt_a", "event", "evt_a")},
		{name: "contact detail and resolution", input: ProxyRequest{EventID: "evt_a", Capability: permissions.ActionContactSubmissionManage, ResourceKind: "contact_submission", ResourceID: "contact_1"}, want: dreamUPGrantTarget("evt_a", "contact_submission", "contact_1")},
		{name: "application mutation", input: ProxyRequest{EventID: "evt_a", Capability: permissions.ActionApplicationDecide, ResourceKind: "application", ResourceID: "app_1"}, want: dreamUPGrantTarget("evt_a", "application", "app_1")},
		{name: "check in", input: ProxyRequest{EventID: "evt_a", Capability: permissions.ActionCheckinScan, ResourceKind: "event", ResourceID: "evt_a"}, want: dreamUPGrantTarget("evt_a", "event", "evt_a")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := highRiskGrantTarget(test.input)
			if !ok || got != test.want {
				t.Fatalf("target=%q ok=%v want=%q", got, ok, test.want)
			}
		})
	}
}

func TestServiceObjectGrantCannotCrossEventsWhenResourceIDCollides(t *testing.T) {
	now := time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, kind, resourceID string
		action                 permissions.Action
		path                   string
	}{
		{name: "application", kind: "application", resourceID: "same_id", action: permissions.ActionApplicationReview, path: "/internal/v1/events/evt_b/applications/same_id/reviews/me"},
		{name: "contact submission", kind: "contact_submission", resourceID: "same_id", action: permissions.ActionContactSubmissionManage, path: "/internal/v1/events/evt_b/contact-submissions/same_id/resolution"},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := validServiceGrant(now, string(test.action), dreamUPGrantTarget("evt_a", test.kind, test.resourceID))
			consumer := &serviceReauthStub{data: proof}
			signer := &serviceSignerStub{}
			service, err := NewService(ServiceDependencies{
				Authorizer: &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_b", BindingVersion: 1, ChallengeVersion: 4}},
				Registry:   serviceRegistryStub{event: registeredEligibilityEvent("evt_b")}, ReauthGrants: consumer,
				StepUps: serviceStepUpStub{}, Signer: signer, Client: &serviceClientStub{},
			}, ServiceConfig{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{
				EventID: "evt_b", Capability: test.action, ResourceKind: test.kind, ResourceID: test.resourceID,
				Method: http.MethodPut, Path: test.path, Body: json.RawMessage(`{"value":"safe"}`), RequestID: "req_cross_event_object",
				IdempotencyKey: strings.Repeat("X", 32), IfMatch: `"1"`, ReauthenticationToken: strings.Repeat("T", 43),
			})
			if !errors.Is(err, ErrStepUpRequired) || signer.input.EventID != "" || consumer.calls != 1 {
				t.Fatalf("error=%v signed=%+v calls=%d", err, signer.input, consumer.calls)
			}
			wantTarget := dreamUPGrantTarget("evt_b", test.kind, test.resourceID)
			if consumer.target != wantTarget || consumer.target == proof.Target {
				t.Fatalf("consumer target=%q proof target=%q want=%q", consumer.target, proof.Target, wantTarget)
			}
		})
	}
}

func TestServiceRejectsCrossEventAndStaleChallengeBeforeSigning(t *testing.T) {
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	authorizer := &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 5}}
	signer := &serviceSignerStub{}
	service, err := NewService(ServiceDependencies{
		Authorizer: authorizer,
		Registry:   serviceRegistryStub{event: adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai", DisplayName: "上海站", Enabled: true}},
		StepUps:    serviceStepUpStub{state: adminstepup.StepUpState{ID: "asu_review_durable", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}},
		Signer:     signer, Client: &serviceClientStub{},
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-time.Minute)}, ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationReadBasic, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodGet, Path: "/internal/v1/events/evt_other/applications/app_1", RequestID: "req_12345678"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("cross-event error=%v", err)
	}
	_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-time.Minute)}, ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationReadBasic, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodGet, Path: "/internal/v1/events/evt_shanghai/applications/app_1", RequestID: "req_12345678"})
	if !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("challenge drift error=%v", err)
	}
	if signer.input.EventID != "" {
		t.Fatal("stale challenge was signed")
	}
}

func TestServiceNeverBypassesSessionBoundStepUpForPrivilegedRoles(t *testing.T) {
	now := time.Date(2026, 8, 27, 5, 0, 0, 0, time.UTC)
	tests := []struct {
		name             string
		role             adminroles.Role
		challengeVersion int64
	}{
		{name: "super admin without enrollment", role: adminroles.RoleSuperAdmin, challengeVersion: 0},
		{name: "top admin without enrollment", role: adminroles.RoleTopAdmin, challengeVersion: 0},
		{name: "super admin missing active session proof", role: adminroles.RoleSuperAdmin, challengeVersion: 7},
		{name: "top admin missing active session proof", role: adminroles.RoleTopAdmin, challengeVersion: 7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := &serviceSignerStub{}
			service, err := NewService(ServiceDependencies{
				Authorizer: &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: test.role, BindingID: "binding_1", BindingVersion: 1, ChallengeVersion: test.challengeVersion}},
				Registry:   serviceRegistryStub{event: adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai", DisplayName: "上海站", Enabled: true}},
				StepUps:    serviceStepUpStub{}, Signer: signer, Client: &serviceClientStub{},
			}, ServiceConfig{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-time.Minute)}, ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPut, Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: json.RawMessage(`{"recommendation":"accept"}`), RequestID: "req_12345678", IdempotencyKey: "0123456789abcdef0123456789abcdef", IfMatch: `"1"`})
			if !errors.Is(err, ErrStepUpRequired) {
				t.Fatalf("expected step-up required, got %v", err)
			}
			if signer.input.EventID != "" {
				t.Fatal("request was signed without real session-bound step-up")
			}
		})
	}
}

func TestServiceSignsContactManagementWithExactOneShotGrant(t *testing.T) {
	now := time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)
	signer := &serviceSignerStub{}
	service, err := NewService(ServiceDependencies{
		Authorizer:   &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
		Registry:     serviceRegistryStub{event: adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai", DisplayName: "上海站", Enabled: true}},
		StepUps:      serviceStepUpStub{state: adminstepup.StepUpState{ID: "asu_contact_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}},
		ReauthGrants: &serviceReauthStub{data: validServiceGrant(now, string(permissions.ActionContactSubmissionManage), dreamUPGrantTarget("evt_shanghai", "contact_submission", "contact_1"))},
		Signer:       signer, Client: &serviceClientStub{},
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{
		EventID: "evt_shanghai", Capability: permissions.ActionContactSubmissionManage,
		ResourceKind: "contact_submission", ResourceID: "contact_1", Method: http.MethodPatch,
		Path: "/internal/v1/events/evt_shanghai/contact-submissions/contact_1/resolution",
		Body: json.RawMessage(`{"status":"acknowledged"}`), RequestID: "req_contact_01",
		IdempotencyKey: "0123456789abcdef0123456789abcdef", IfMatch: `"0"`, ReauthenticationToken: strings.Repeat("C", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	if signer.input.Capability != dreamupdelegation.AdministratorCapabilityContactSubmissionManage || signer.input.ReauthGrantID != "rgr_exact_1" || !signer.input.StepUpAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("signed input=%+v", signer.input)
	}
}

func TestServiceRequiresFreshProofEvenForContentDraftRead(t *testing.T) {
	now := time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		age     time.Duration
		wantErr bool
	}{
		{name: "fresh content read", age: time.Minute},
		{name: "stale content read", age: dreamupdelegation.MaxHighRiskStepUpAge + time.Second, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer := &serviceSignerStub{}
			client := &serviceClientStub{}
			grant := validServiceGrant(now, string(permissions.ActionContentManage), dreamUPGrantTarget("evt_shanghai", "event", "evt_shanghai"))
			grant.CreatedAt = now.Add(-test.age)
			service, err := NewService(ServiceDependencies{
				Authorizer: &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
				Registry:   serviceRegistryStub{event: registeredEligibilityEvent("evt_shanghai")},
				StepUps: serviceStepUpStub{state: adminstepup.StepUpState{
					ID: "asu_content_1", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4,
					VerifiedAt: now.Add(-test.age), ExpiresAt: now.Add(10 * time.Minute),
				}},
				ReauthGrants: &serviceReauthStub{data: grant},
				Signer:       signer, Client: client,
			}, ServiceConfig{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{
				EventID: "evt_shanghai", Capability: permissions.ActionContentManage,
				ResourceKind: "event_content", ResourceID: "evt_shanghai", Method: http.MethodGet,
				Path: "/internal/v1/events/evt_shanghai/content", RequestID: "req_content_read", ReauthenticationToken: strings.Repeat("D", 43),
			})
			if test.wantErr {
				if !errors.Is(err, ErrStepUpRequired) || signer.input.EventID != "" {
					t.Fatalf("err=%v signed=%+v", err, signer.input)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if signer.input.Capability != dreamupdelegation.AdministratorCapabilityContentManage || signer.input.ReauthGrantID != "rgr_exact_1" || client.input.Path != "/internal/v1/events/evt_shanghai/content" {
				t.Fatalf("signed=%+v upstream=%+v", signer.input, client.input)
			}
		})
	}
}

func TestServiceRejectsMutationWithoutFreshExactGrant(t *testing.T) {
	now := time.Date(2026, 8, 27, 6, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		id   string
		age  time.Duration
	}{
		{name: "missing durable ID", age: time.Minute},
		{name: "stale proof", id: "asu_stale_1", age: dreamupdelegation.MaxHighRiskStepUpAge + time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer := &serviceSignerStub{}
			grant := validServiceGrant(now, string(permissions.ActionApplicationReview), dreamUPGrantTarget("evt_shanghai", "application", "app_1"))
			grant.GrantID, grant.CreatedAt = test.id, now.Add(-test.age)
			service, err := NewService(ServiceDependencies{
				Authorizer: &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
				Registry:   serviceRegistryStub{event: adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai", DisplayName: "上海站", Enabled: true}},
				StepUps: serviceStepUpStub{state: adminstepup.StepUpState{
					ID: test.id, SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4,
					VerifiedAt: now.Add(-test.age), ExpiresAt: now.Add(10 * time.Minute),
				}},
				ReauthGrants: &serviceReauthStub{data: grant},
				Signer:       signer, Client: &serviceClientStub{},
			}, ServiceConfig{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{
				EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview,
				ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPut,
				Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: json.RawMessage(`{"recommendation":"accept"}`),
				RequestID: "req_review_freshness", IdempotencyKey: "0123456789abcdef0123456789abcdef", IfMatch: `"1"`, ReauthenticationToken: strings.Repeat("E", 43),
			})
			if !errors.Is(err, ErrStepUpRequired) || signer.input.EventID != "" {
				t.Fatalf("err=%v signed=%+v", err, signer.input)
			}
		})
	}
}

type serviceOutboxStub struct {
	item     adminstore.OutboxItem
	phases   []adminstore.DeliveryPhase
	settled  bool
	failed   bool
	deferred bool
	result   adminstore.AllowlistedResult
	getErr   error
}

func (s *serviceOutboxStub) CreateOrReplay(_ context.Context, item adminstore.OutboxItem) (adminstore.OutboxItem, bool, error) {
	s.item = item
	return item, false, nil
}
func (s *serviceOutboxStub) GetByIdempotencyKey(context.Context, string) (adminstore.OutboxItem, error) {
	return adminstore.SanitizeOutboxReplay(s.item), s.getErr
}
func (s *serviceOutboxStub) ClaimExact(_ context.Context, id string, expected int64, now time.Time, lease time.Duration) (adminstore.OutboxItem, error) {
	s.item.State = "claimed"
	s.item.Version = expected + 1
	s.item.ClaimToken = "claim"
	until := now.Add(lease)
	s.item.ClaimLeaseUntil = &until
	return s.item, nil
}
func (s *serviceOutboxStub) MarkDeliveryPhase(_ context.Context, _ string, _ int64, _ string, phase adminstore.DeliveryPhase, _ time.Time) error {
	s.phases = append(s.phases, phase)
	return nil
}
func (s *serviceOutboxStub) Settle(_ context.Context, _ string, _ int64, _ string, result adminstore.AllowlistedResult, _ time.Time) error {
	s.settled = true
	s.result = result
	return nil
}
func (s *serviceOutboxStub) Fail(_ context.Context, _ string, _ int64, _ string, result adminstore.AllowlistedResult, _ time.Time) error {
	s.failed = true
	s.result = result
	return nil
}
func (*serviceOutboxStub) CompleteLocal(context.Context, string, int64, adminstore.AllowlistedResult, time.Time) error {
	panic("unexpected")
}
func (*serviceOutboxStub) ClaimDue(context.Context, time.Time, int) ([]adminstore.OutboxItem, error) {
	panic("unexpected")
}
func (*serviceOutboxStub) ClaimReceiptsDue(context.Context, time.Time, int, time.Duration) ([]adminstore.OutboxItem, error) {
	panic("unexpected")
}

func (s *serviceOutboxStub) DeferReceipt(context.Context, string, int64, string, time.Time, time.Time) error {
	s.deferred = true
	return nil
}
func (*serviceOutboxStub) MarkNeedsOperator(context.Context, string, int64, string, time.Time) error {
	panic("unexpected")
}
func (*serviceOutboxStub) MarkAuditReconciled(context.Context, string, int64, time.Time) error {
	panic("unexpected")
}
func (*serviceOutboxStub) ReleaseExpiredClaim(context.Context, string, int64, time.Time) error {
	panic("unexpected")
}
func (*serviceOutboxStub) PurgePayload(context.Context, string, int64, time.Time) error {
	panic("unexpected")
}

type serviceUOWStub struct{ outbox *serviceOutboxStub }

func (s serviceUOWStub) Within(ctx context.Context, fn func(adminstore.Repositories) error) error {
	return fn(adminstore.Repositories{Outbox: s.outbox})
}

type serviceFingerprinterStub struct {
	namespace string
	payload   []byte
}

func (s *serviceFingerprinterStub) Fingerprint(namespace string, payload []byte) (adminstore.Fingerprint, error) {
	s.namespace = namespace
	s.payload = append([]byte(nil), payload...)
	return adminstore.Fingerprint{Version: "hmac-sha256-v1", KeyID: "key_1", Digest: "digest_12345678"}, nil
}

func TestServicePersistsAndSettlesMutationIntentAroundOneUpstreamCall(t *testing.T) {
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	outbox := &serviceOutboxStub{}
	fingerprinter := &serviceFingerprinterStub{}
	service, err := NewService(ServiceDependencies{
		Authorizer:   &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
		Registry:     serviceRegistryStub{event: adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai", DisplayName: "上海站", Enabled: true}},
		StepUps:      serviceStepUpStub{state: adminstepup.StepUpState{ID: "asu_review_outbox", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}},
		ReauthGrants: &serviceReauthStub{data: validServiceGrant(now, string(permissions.ActionApplicationReview), dreamUPGrantTarget("evt_shanghai", "application", "app_1"))},
		Signer:       &serviceSignerStub{}, Client: &serviceClientStub{}, UnitOfWork: serviceUOWStub{outbox}, Fingerprinter: fingerprinter,
	}, ServiceConfig{Now: func() time.Time { return now }, RequireDurableMutations: true, MutationLease: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPut, Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: json.RawMessage(`{"recommendation":"accept","note":"clear"}`), RequestID: ":trace-admin_123", IdempotencyKey: "0123456789abcdef0123456789abcdef", IfMatch: `"1"`, ReauthenticationToken: strings.Repeat("F", 43)})
	if err != nil {
		t.Fatal(err)
	}
	if len(outbox.phases) != 2 || outbox.phases[0] != adminstore.DeliveryPhaseIndeterminate || outbox.phases[1] != adminstore.DeliveryPhaseSent || !outbox.settled {
		t.Fatalf("phases=%v settled=%v", outbox.phases, outbox.settled)
	}
	if outbox.item.Result.Payload["actor_id"] != "user_1" || outbox.item.Result.Payload["operation_request_id"] != ":trace-admin_123" ||
		outbox.item.Result.Payload["receipt_action"] != "application.review_saved" || outbox.item.Result.Payload["receipt_target_type"] != "application" || outbox.item.Result.Payload["receipt_target_id"] != "app_1" ||
		outbox.result.Digest != sha256Hex([]byte(`{"review":{"version":2}}`)) || outbox.result.Payload["response_status"] != "200" || outbox.result.Payload["result_version"] != "2" {
		t.Fatalf("pending=%+v settled=%+v", outbox.item.Result, outbox.result)
	}
	var durableBinding map[string]string
	if err := json.Unmarshal(fingerprinter.payload, &durableBinding); err != nil {
		t.Fatalf("decode durable fingerprint input: %v", err)
	}
	if fingerprinter.namespace != "dreamup-admin-bff-mutation" || durableBinding["Headers"] != dreamupdelegation.AdministratorHeadersSHA256(`"1"`, "0123456789abcdef0123456789abcdef") {
		t.Fatalf("durable request binding namespace=%q payload=%v", fingerprinter.namespace, durableBinding)
	}
}

func TestExpectedMutationReceiptBindsEveryExposedMutationFamily(t *testing.T) {
	base := "/internal/v1/events/evt_shanghai"
	tests := []struct {
		name  string
		input ProxyRequest
		want  mutationReceiptExpectation
	}{
		{name: "intro", input: ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionContentManage, ResourceKind: "event_content", ResourceID: "evt_shanghai", Method: http.MethodPut, Path: base + "/content/intro", Body: json.RawMessage(`{"action":"publish"}`)}, want: mutationReceiptExpectation{Action: "event_content.intro.publish", TargetType: "event_content"}},
		{name: "new announcement", input: ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionContentManage, ResourceKind: "event_content", ResourceID: "evt_shanghai", Method: http.MethodPost, Path: base + "/announcements", Body: json.RawMessage(`{"action":"save_draft"}`)}, want: mutationReceiptExpectation{Action: "event_content.announcement.save_draft", TargetType: "event_content"}},
		{name: "announcement", input: ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionContentManage, ResourceKind: "event_content", ResourceID: "announcement_1", Method: http.MethodPatch, Path: base + "/announcements/announcement_1", Body: json.RawMessage(`{"action":"archive"}`)}, want: mutationReceiptExpectation{Action: "event_content.announcement.archive", TargetType: "event_content", TargetID: "announcement_1"}},
		{name: "contact", input: ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionContactSubmissionManage, ResourceKind: "contact_submission", ResourceID: "contact_1", Method: http.MethodPatch, Path: base + "/contact-submissions/contact_1/resolution"}, want: mutationReceiptExpectation{Action: "contact_submission.resolved", TargetType: "contact_submission", TargetID: "contact_1"}},
		{name: "review", input: ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPut, Path: base + "/applications/app_1/reviews/me"}, want: mutationReceiptExpectation{Action: "application.review_saved", TargetType: "application", TargetID: "app_1"}},
		{name: "approve", input: ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationApproveAdmission, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPut, Path: base + "/applications/app_1/admission-consensus/approval"}, want: mutationReceiptExpectation{Action: "application.admission_approved", TargetType: "application", TargetID: "app_1"}},
		{name: "withdraw", input: ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationApproveAdmission, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodDelete, Path: base + "/applications/app_1/admission-consensus/approval"}, want: mutationReceiptExpectation{Action: "application.admission_approval_withdrawn", TargetType: "application", TargetID: "app_1"}},
		{name: "decision", input: ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationDecide, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPatch, Path: base + "/applications/app_1/decision", Body: json.RawMessage(`{"status":"waitlisted"}`)}, want: mutationReceiptExpectation{Action: "application.waitlisted", TargetType: "application", TargetID: "app_1"}},
		{name: "checkin", input: ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionCheckinScan, ResourceKind: "event", ResourceID: "evt_shanghai", Method: http.MethodPost, Path: base + "/checkins/scan"}, want: mutationReceiptExpectation{Action: "checkin.completed", TargetType: "application"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := expectedMutationReceipt(test.input)
			if err != nil || got != test.want {
				t.Fatalf("expectation=%+v want=%+v err=%v", got, test.want, err)
			}
		})
	}
	invalid := tests[4].input
	invalid.Path = base + "/applications/app_2/reviews/me"
	if _, err := expectedMutationReceipt(invalid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mismatched route binding error=%v", err)
	}
}

func TestPendingMutationReplayRequiresExactPersistedReceiptBinding(t *testing.T) {
	payload := map[string]string{
		"event_id": "evt_shanghai", "operation_request_id": "req_replay_1", "actor_id": "user_1",
		"receipt_action": "application.review_saved", "receipt_target_type": "application", "receipt_target_id": "app_1",
	}
	incoming := adminstore.OutboxItem{Kind: adminstore.OperationCrossSystem, State: "pending", DeliveryPhase: adminstore.DeliveryPhaseNotSent, Version: 1, Result: adminstore.AllowlistedResult{Code: "operation.pending", Payload: maps.Clone(payload)}}
	stored := incoming
	stored.Result.Payload = maps.Clone(payload)
	if !validPendingMutationReplay(stored, incoming) {
		t.Fatal("exact safe pending replay rejected")
	}
	delete(stored.Result.Payload, "receipt_action")
	if validPendingMutationReplay(stored, incoming) {
		t.Fatal("legacy replay without authoritative receipt binding accepted")
	}
}

func TestServicePersistsDeterministicUpstreamFailureWithoutReissuingMutation(t *testing.T) {
	now := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	outbox := &serviceOutboxStub{}
	service, err := NewService(ServiceDependencies{
		Authorizer:   &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
		Registry:     serviceRegistryStub{event: adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai", DisplayName: "上海站", Enabled: true}},
		StepUps:      serviceStepUpStub{state: adminstepup.StepUpState{ID: "asu_failure", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}},
		ReauthGrants: &serviceReauthStub{data: validServiceGrant(now, string(permissions.ActionApplicationReview), dreamUPGrantTarget("evt_shanghai", "application", "app_1"))},
		Signer:       &serviceSignerStub{}, Client: &serviceClientStub{err: ErrConflict}, UnitOfWork: serviceUOWStub{outbox}, Fingerprinter: &serviceFingerprinterStub{},
	}, ServiceConfig{Now: func() time.Time { return now }, RequireDurableMutations: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPut, Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: json.RawMessage(`{"recommendation":"accept"}`), RequestID: "req_failure_1", IdempotencyKey: "0123456789abcdef0123456789abcdef", IfMatch: `"1"`, ReauthenticationToken: strings.Repeat("G", 43)})
	if !errors.Is(err, ErrConflict) || !outbox.failed || outbox.settled || len(outbox.phases) != 2 || outbox.phases[1] != adminstore.DeliveryPhaseSent {
		t.Fatalf("err=%v failed=%v settled=%v phases=%v", err, outbox.failed, outbox.settled, outbox.phases)
	}
	if outbox.result.Code != "operation.failed" || outbox.result.Payload["response_status"] != "409" || outbox.result.Payload["actor_id"] != "user_1" {
		t.Fatalf("failure result=%+v", outbox.result)
	}
}

func TestServiceDefersAmbiguousUpstreamFailureToAuthoritativeReceipt(t *testing.T) {
	now := time.Date(2026, 8, 27, 9, 15, 0, 0, time.UTC)
	outbox := &serviceOutboxStub{}
	service, err := NewService(ServiceDependencies{
		Authorizer:   &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
		Registry:     serviceRegistryStub{event: adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai", DisplayName: "上海站", Enabled: true}},
		StepUps:      serviceStepUpStub{state: adminstepup.StepUpState{ID: "asu_ambiguous", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}},
		ReauthGrants: &serviceReauthStub{data: validServiceGrant(now, string(permissions.ActionApplicationReview), dreamUPGrantTarget("evt_shanghai", "application", "app_1"))},
		Signer:       &serviceSignerStub{}, Client: &serviceClientStub{err: ErrUpstream}, UnitOfWork: serviceUOWStub{outbox}, Fingerprinter: &serviceFingerprinterStub{},
	}, ServiceConfig{Now: func() time.Time { return now }, RequireDurableMutations: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Proxy(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, ProxyRequest{EventID: "evt_shanghai", Capability: permissions.ActionApplicationReview, ResourceKind: "application", ResourceID: "app_1", Method: http.MethodPut, Path: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", Body: json.RawMessage(`{"recommendation":"accept"}`), RequestID: "trace:ambiguous.1", IdempotencyKey: "fedcba9876543210fedcba9876543210", IfMatch: `"1"`, ReauthenticationToken: strings.Repeat("H", 43)})
	if !errors.Is(err, ErrUpstream) || !outbox.deferred || outbox.failed || outbox.settled || len(outbox.phases) != 1 || outbox.phases[0] != adminstore.DeliveryPhaseIndeterminate {
		t.Fatalf("err=%v deferred=%v failed=%v settled=%v phases=%v", err, outbox.deferred, outbox.failed, outbox.settled, outbox.phases)
	}
}

func TestServiceOperationStatusIsAuthoritativeActorBoundAndNoBodyReplay(t *testing.T) {
	now := time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC)
	terminal := now.Add(-time.Second)
	outbox := &serviceOutboxStub{item: adminstore.OutboxItem{
		ID: "aop_status_1", Kind: adminstore.OperationCrossSystem, State: "succeeded", DeliveryPhase: adminstore.DeliveryPhaseSent,
		Result:     adminstore.AllowlistedResult{Code: "operation.settled", Digest: strings.Repeat("a", 64), Payload: map[string]string{"event_id": "evt_shanghai", "operation_request_id": ":trace-admin_123", "actor_id": "user_1", "response_status": "200", "result_version": "7"}},
		TerminalAt: &terminal, UpdatedAt: terminal,
	}}
	service, err := NewService(ServiceDependencies{
		Authorizer: &serviceAuthorizerStub{decision: permissions.Decision{Allowed: true, Role: adminroles.RoleAdmin, BindingID: "binding_1", BindingVersion: 3, ChallengeVersion: 4}},
		Registry:   serviceRegistryStub{event: adminroles.RegisteredEvent{EventID: "evt_shanghai", Series: "dreamup", Slug: "shanghai", DisplayName: "上海站", Enabled: true}},
		StepUps:    serviceStepUpStub{state: adminstepup.StepUpState{ID: "asu_status", SessionID: "session_1", UserID: "user_1", ChallengeVersion: 4, VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}},
		Signer:     &serviceSignerStub{}, Client: &serviceClientStub{}, UnitOfWork: serviceUOWStub{outbox},
	}, ServiceConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.OperationStatus(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, "evt_shanghai", "0123456789abcdef0123456789abcdef")
	if err != nil || status.Status != "succeeded" || status.RequestID != ":trace-admin_123" || status.ResponseStatus == nil || *status.ResponseStatus != 200 || status.ResultVersion == nil || *status.ResultVersion != 7 || !status.UpdatedAt.Equal(terminal) {
		t.Fatalf("status=%+v err=%v", status, err)
	}

	outbox.item.Result.Payload["actor_id"] = "user_other"
	if _, err := service.OperationStatus(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, "evt_shanghai", "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-actor status error=%v", err)
	}
	outbox.item.Result.Payload["actor_id"] = "user_1"
	outbox.getErr = adminstore.ErrOperationNotFound
	if _, err := service.OperationStatus(context.Background(), Actor{UserID: "user_1", SessionID: "session_1", AuthenticatedAt: now.Add(-2 * time.Minute)}, "evt_shanghai", "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing status error=%v", err)
	}
}

func TestMutationFinalizeContextSurvivesCallerCancellation(t *testing.T) {
	caller, cancelCaller := context.WithCancel(context.Background())
	cancelCaller()
	ctx, cancel := mutationFinalizeContext(caller)
	defer cancel()
	if err := ctx.Err(); err != nil {
		t.Fatalf("finalization inherited caller cancellation: %v", err)
	}
}

func TestMutationStatusProjectionFailsClosedOnCorruptLedgerRows(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	terminal := now.Add(-time.Second)
	tests := []struct {
		name       string
		item       adminstore.OutboxItem
		wantStatus string
		wantErr    error
	}{
		{name: "pending", item: adminstore.OutboxItem{State: "pending", Result: adminstore.AllowlistedResult{Code: "operation.pending", Payload: map[string]string{"operation_request_id": "req_pending_1"}}, UpdatedAt: now}, wantStatus: "pending"},
		{name: "failed", item: adminstore.OutboxItem{State: "failed", DeliveryPhase: adminstore.DeliveryPhaseSent, Result: adminstore.AllowlistedResult{Code: "operation.failed", Payload: map[string]string{"operation_request_id": "req_failed_1", "response_status": "409"}}, TerminalAt: &terminal, UpdatedAt: now}, wantStatus: "failed"},
		{name: "operator", item: adminstore.OutboxItem{State: "needs_operator", DeliveryPhase: adminstore.DeliveryPhaseIndeterminate, Result: adminstore.AllowlistedResult{Code: "operation.pending", Payload: map[string]string{"operation_request_id": "req_operator_1"}}, TerminalAt: &terminal, UpdatedAt: now}, wantStatus: "needs_operator"},
		{name: "success missing digest", item: adminstore.OutboxItem{State: "succeeded", Result: adminstore.AllowlistedResult{Code: "operation.settled", Payload: map[string]string{"operation_request_id": "req_corrupt_1"}}, TerminalAt: &terminal, UpdatedAt: now}, wantErr: ErrUpstream},
		{name: "failure with ambiguous 5xx", item: adminstore.OutboxItem{State: "failed", DeliveryPhase: adminstore.DeliveryPhaseSent, Result: adminstore.AllowlistedResult{Code: "operation.failed", Payload: map[string]string{"operation_request_id": "req_corrupt_2", "response_status": "502"}}, TerminalAt: &terminal, UpdatedAt: now}, wantErr: ErrUpstream},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, err := mutationStatusFromItem(test.item)
			if !errors.Is(err, test.wantErr) || status.Status != test.wantStatus {
				t.Fatalf("status=%+v err=%v", status, err)
			}
		})
	}
}
