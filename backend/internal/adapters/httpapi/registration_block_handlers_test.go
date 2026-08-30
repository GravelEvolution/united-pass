package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type registrationBlockStoreStub struct {
	dimension registration.AbuseBlockDimension
	digest    string
	err       error
	calls     int
	before    func() bool
}

func (s *registrationBlockStoreStub) UnblockRegistrationHash(_ context.Context, dimension registration.AbuseBlockDimension, digest string) error {
	if s.before != nil && !s.before() {
		return errors.New("mutation reached before durable request audit")
	}
	s.calls++
	s.dimension, s.digest = dimension, digest
	return s.err
}

type registrationBlockRoleReaderStub struct {
	binding adminroles.Binding
	err     error
	scope   adminroles.Scope
	calls   int
}

func (r *registrationBlockRoleReaderStub) GetForScope(_ context.Context, _ identity.UserID, scope adminroles.Scope) (adminroles.Binding, error) {
	r.calls++
	r.scope = scope
	return r.binding, r.err
}

type registrationBlockAuditStub struct {
	events    []applications.SecurityEvent
	failEvent string
}

type registrationBlockPrincipalReaderStub struct {
	principal permissions.PrincipalContext
	err       error
}

type registrationBlockPermissionResolverStub struct {
	capabilities permissions.Capabilities
	err          error
}

type registrationBlockReauthStub struct {
	wantToken string
	err       error
	calls     int
	action    string
	sessionID string
	target    string
}

func (s *registrationBlockReauthStub) VerifyAndConsume(_ context.Context, token, action, sessionID, target string, _ applications.ApplicationID, _ applications.OAuthClientID) error {
	s.calls++
	s.action, s.sessionID, s.target = action, sessionID, target
	if s.err != nil {
		return s.err
	}
	if token == "" || token != s.wantToken {
		return errors.New("invalid reauthentication token")
	}
	return nil
}

type registrationBlockRateStub struct {
	allowed    bool
	retryAfter time.Duration
	err        error
	calls      int
	actorHash  string
}

func (s *registrationBlockRateStub) CheckRegistrationBlockRevoke(_ context.Context, actorHash string, _ int, _ time.Duration) (bool, time.Duration, error) {
	s.calls++
	s.actorHash = actorHash
	return s.allowed, s.retryAfter, s.err
}

func (r *registrationBlockPermissionResolverStub) Resolve(context.Context, identity.UserID) (permissions.Capabilities, error) {
	return r.capabilities, r.err
}

func (r *registrationBlockPrincipalReaderStub) GetPermissionPrincipal(context.Context, identity.UserID) (permissions.PrincipalContext, error) {
	return r.principal, r.err
}

func (a *registrationBlockAuditStub) Record(_ context.Context, event applications.SecurityEvent) error {
	if event.EventType == a.failEvent {
		return errors.New("audit unavailable")
	}
	a.events = append(a.events, event)
	return nil
}

func activeSystemAdmin(role adminroles.Role) adminroles.Binding {
	return adminroles.Binding{
		ID: "arb_operator", UserID: "user_operator", Role: role,
		Scope: adminroles.Scope{Kind: adminroles.ScopeSystem}, Enabled: true, Version: 1,
	}
}

func registrationBlockRequest(body string, principal bool) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/registration-defense/blocks/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := request.WithID(req.Context(), "req_registration_unblock")
	if principal {
		ctx = WithPrincipal(ctx, session.Principal{UserID: "user_operator", SessionID: "sess_operator"})
		req.Header.Set("X-Reauthentication-Token", "reauth-good")
	}
	return req.WithContext(ctx)
}

func newRegistrationBlockHandler(store *registrationBlockStoreStub, roles *registrationBlockRoleReaderStub, audit *registrationBlockAuditStub) *RegistrationBlockHandlers {
	people := &registrationBlockPrincipalReaderStub{principal: permissions.PrincipalContext{Attributes: map[string]any{"accountStatus": string(identity.UserStatusActive), "employeeStatus": "active"}}}
	access := &registrationBlockPermissionResolverStub{capabilities: permissions.Capabilities{PolicyManage: true, AuditRead: true}}
	auditTargets, err := NewRegistrationBlockAuditTargets(bytes.Repeat([]byte{0x42}, 32), "test-v1")
	if err != nil {
		panic(err)
	}
	handler := NewRegistrationBlockHandlers(store, roles, people, access, audit, RegistrationBlockControls{
		Reauth: &registrationBlockReauthStub{wantToken: "reauth-good"},
		Rates:  &registrationBlockRateStub{allowed: true}, AuditTargets: auditTargets,
		RateLimit: 12, RateWindow: 15 * time.Minute,
	}, nil)
	handler.now = func() time.Time { return time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC) }
	return handler
}

func TestRegistrationBlockRevokeRejectsUnauthenticatedAndNonSystemAdmin(t *testing.T) {
	t.Run("unauthenticated", func(t *testing.T) {
		store := &registrationBlockStoreStub{}
		roles := &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}
		audit := &registrationBlockAuditStub{}
		recorder := httptest.NewRecorder()
		newRegistrationBlockHandler(store, roles, audit).Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, false))
		if recorder.Code != http.StatusUnauthorized || store.calls != 0 || roles.calls != 0 {
			t.Fatalf("status=%d store=%d roles=%d", recorder.Code, store.calls, roles.calls)
		}
	})

	t.Run("event administrator cannot operate system block", func(t *testing.T) {
		store := &registrationBlockStoreStub{}
		roles := &registrationBlockRoleReaderStub{binding: adminroles.Binding{Role: adminroles.RoleAdmin, Enabled: true, Scope: adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_test"}}}
		audit := &registrationBlockAuditStub{}
		recorder := httptest.NewRecorder()
		newRegistrationBlockHandler(store, roles, audit).Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true))
		if recorder.Code != http.StatusForbidden || store.calls != 0 || roles.scope.Kind != adminroles.ScopeSystem {
			t.Fatalf("status=%d store=%d scope=%#v", recorder.Code, store.calls, roles.scope)
		}
		if len(audit.events) != 1 || audit.events[0].EventType != "authorization.denied" || audit.events[0].ActorUserID != "user_operator" {
			t.Fatalf("audit=%#v", audit.events)
		}
	})

	t.Run("binding for another user is rejected", func(t *testing.T) {
		store := &registrationBlockStoreStub{}
		binding := activeSystemAdmin(adminroles.RoleTopAdmin)
		binding.UserID = "user_other"
		audit := &registrationBlockAuditStub{}
		recorder := httptest.NewRecorder()
		newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: binding}, audit).Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true))
		if recorder.Code != http.StatusForbidden || store.calls != 0 {
			t.Fatalf("status=%d store=%d", recorder.Code, store.calls)
		}
	})

	t.Run("offboarding system administrator is rejected", func(t *testing.T) {
		store := &registrationBlockStoreStub{}
		audit := &registrationBlockAuditStub{}
		handler := newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, audit)
		handler.people = &registrationBlockPrincipalReaderStub{principal: permissions.PrincipalContext{Attributes: map[string]any{"accountStatus": string(identity.UserStatusActive), "employeeStatus": "offboarding"}}}
		recorder := httptest.NewRecorder()
		handler.Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true))
		if recorder.Code != http.StatusForbidden || store.calls != 0 {
			t.Fatalf("status=%d store=%d", recorder.Code, store.calls)
		}
	})

	t.Run("Cerbos-derived capability denial is authoritative", func(t *testing.T) {
		store := &registrationBlockStoreStub{}
		audit := &registrationBlockAuditStub{}
		handler := newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, audit)
		handler.access = &registrationBlockPermissionResolverStub{capabilities: permissions.Capabilities{AuditRead: true}}
		recorder := httptest.NewRecorder()
		handler.Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true))
		if recorder.Code != http.StatusForbidden || store.calls != 0 {
			t.Fatalf("status=%d store=%d", recorder.Code, store.calls)
		}
	})
}

func TestRegistrationBlockRevokeHashesAtBoundaryAndPersistsAudit(t *testing.T) {
	device, err := session.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	deviceDigest := registration.HashAbuseValue(device)
	tests := []struct {
		name, body, canonical, wantDigest, sourceTarget, auditTarget, encoding string
		dimension                                                              registration.AbuseBlockDimension
	}{
		{name: "canonical ip", body: `{"dimension":"ip","value":"::ffff:203.0.113.7","valueEncoding":"raw","reasonCode":"support_verified"}`, canonical: "203.0.113.7", sourceTarget: "client_ip_hash", auditTarget: "client_ip_hmac", encoding: "raw", dimension: registration.AbuseBlockIP},
		{name: "server device token", body: `{"dimension":"device","value":"` + device + `","valueEncoding":"raw","reasonCode":"false_positive"}`, canonical: device, sourceTarget: "device_id_hash", auditTarget: "device_id_hmac", encoding: "raw", dimension: registration.AbuseBlockDevice},
		{name: "audited device digest", body: `{"dimension":"device","value":"` + deviceDigest + `","valueEncoding":"sha256","reasonCode":"support_verified"}`, wantDigest: deviceDigest, sourceTarget: "device_id_hash", auditTarget: "device_id_hmac", encoding: "sha256", dimension: registration.AbuseBlockDevice},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &registrationBlockStoreStub{}
			roles := &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}
			audit := &registrationBlockAuditStub{}
			store.before = func() bool {
				return len(audit.events) == 1 && audit.events[0].EventType == "registration.abuse_unblock_requested"
			}
			recorder := httptest.NewRecorder()
			newRegistrationBlockHandler(store, roles, audit).Revoke(recorder, registrationBlockRequest(test.body, true))
			wantDigest := test.wantDigest
			if wantDigest == "" {
				wantDigest = registration.HashAbuseValue(test.canonical)
			}
			if recorder.Code != http.StatusNoContent || store.calls != 1 || store.dimension != test.dimension || store.digest != wantDigest {
				t.Fatalf("status=%d store=%#v wantDigest=%s", recorder.Code, store, wantDigest)
			}
			if len(audit.events) != 2 || audit.events[1].EventType != "registration.abuse_unblocked" {
				t.Fatalf("audit=%#v", audit.events)
			}
			for _, event := range audit.events {
				if event.ActorUserID != "user_operator" || event.RequestID != "req_registration_unblock" || event.TargetKey != test.auditTarget || event.TargetID == wantDigest || !validRegistrationBlockSHA256(event.TargetID) || event.Extra["fingerprint_dimension"] != string(test.dimension) || event.Extra["value_encoding"] != test.encoding || event.Extra["source_target_key"] != test.sourceTarget || event.Extra["audit_target_version"] != "hmac-sha256-v1" || event.Extra["audit_target_key_id"] != "test-v1" {
					t.Fatalf("event=%#v", event)
				}
				if test.canonical != "" && strings.Contains(event.TargetID, test.canonical) {
					t.Fatal("raw fingerprint leaked into audit target")
				}
			}
		})
	}
}

func TestRegistrationBlockRevokeRequiresTargetBoundReauthentication(t *testing.T) {
	store := &registrationBlockStoreStub{}
	audit := &registrationBlockAuditStub{}
	handler := newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, audit)
	reauth := &registrationBlockReauthStub{wantToken: "reauth-good"}
	handler.controls.Reauth = reauth
	req := registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true)
	req.Header.Del("X-Reauthentication-Token")
	recorder := httptest.NewRecorder()
	handler.Revoke(recorder, req)
	if recorder.Code != http.StatusForbidden || store.calls != 0 || reauth.calls != 0 {
		t.Fatalf("status=%d store=%d reauth=%d", recorder.Code, store.calls, reauth.calls)
	}
	if len(audit.events) != 1 || audit.events[0].EventType != "registration.abuse_unblock_denied" || audit.events[0].FailureClass != "reauthentication" || audit.events[0].TargetID == registration.HashAbuseValue("203.0.113.7") {
		t.Fatalf("audit=%#v", audit.events)
	}

	req = registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true)
	recorder = httptest.NewRecorder()
	handler.Revoke(recorder, req)
	wantDigest := registration.HashAbuseValue("203.0.113.7")
	if recorder.Code != http.StatusNoContent || reauth.action != auth.ReauthActionRegistrationAbuseUnblock || reauth.sessionID != "sess_operator" || reauth.target != "ip_"+wantDigest {
		t.Fatalf("status=%d reauth=%#v", recorder.Code, reauth)
	}

	store = &registrationBlockStoreStub{}
	handler = newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, &registrationBlockAuditStub{})
	handler.controls.Reauth = nil
	recorder = httptest.NewRecorder()
	handler.Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true))
	if recorder.Code != http.StatusForbidden || store.calls != 0 {
		t.Fatalf("nil verifier status=%d store=%d", recorder.Code, store.calls)
	}
}

func TestRegistrationBlockRevokeRateLimitFailsClosedBeforeReauthentication(t *testing.T) {
	for _, rate := range []*registrationBlockRateStub{
		{allowed: false, retryAfter: time.Minute},
		{err: errors.New("redis unavailable")},
	} {
		store := &registrationBlockStoreStub{}
		handler := newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, &registrationBlockAuditStub{})
		reauth := &registrationBlockReauthStub{wantToken: "reauth-good"}
		handler.controls.Rates = rate
		handler.controls.Reauth = reauth
		recorder := httptest.NewRecorder()
		handler.Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true))
		if recorder.Code != http.StatusTooManyRequests || store.calls != 0 || reauth.calls != 0 || rate.calls != 1 || rate.actorHash != registration.HashAbuseValue("user_operator") {
			t.Fatalf("status=%d store=%d reauth=%d rate=%#v", recorder.Code, store.calls, reauth.calls, rate)
		}
	}
}

func TestRegistrationBlockAuditTargetsUsePurposeSeparatedHMAC(t *testing.T) {
	root := bytes.Repeat([]byte{0x23}, 32)
	targets, err := NewRegistrationBlockAuditTargets(root, "audit-v1")
	if err != nil {
		t.Fatal(err)
	}
	digest := registration.HashAbuseValue("203.0.113.7")
	key, value, ok := targets.pseudonym(registration.AbuseBlockIP, digest)
	if !ok || key != "client_ip_hmac" || value == digest || !validRegistrationBlockSHA256(value) {
		t.Fatalf("key=%q value=%q ok=%v", key, value, ok)
	}
	_, deviceValue, ok := targets.pseudonym(registration.AbuseBlockDevice, digest)
	if !ok || deviceValue == value {
		t.Fatal("dimension was not included in the audit HMAC domain")
	}
	if _, err := NewRegistrationBlockAuditTargets(root[:31], "audit-v1"); err == nil {
		t.Fatal("short root key accepted")
	}
	defaultID, err := NewRegistrationBlockAuditTargets(root, "")
	if err != nil || defaultID.keyID != "v1" {
		t.Fatalf("empty session key ID did not inherit v1: keyID=%q err=%v", defaultID.keyID, err)
	}
	legacyID, err := NewRegistrationBlockAuditTargets(root, "legacy key/id")
	if err != nil || !strings.HasPrefix(legacyID.keyID, "sha256-") || !validRegistrationBlockKeyID(legacyID.keyID) {
		t.Fatalf("legacy session key ID was not safely aliased: keyID=%q err=%v", legacyID.keyID, err)
	}
}

func TestRegistrationBlockRevokeValidatesExplicitDimensionValueAndReason(t *testing.T) {
	validDigest := registration.HashAbuseValue("device")
	tests := []string{
		`{"dimension":"redis_key","value":"registration:block:ip:anything","valueEncoding":"raw","reasonCode":"false_positive"}`,
		`{"dimension":"ip","value":" 203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`,
		`{"dimension":"ip","value":"not-an-ip","valueEncoding":"raw","reasonCode":"false_positive"}`,
		`{"dimension":"ip","value":"fe80::1%eth0","valueEncoding":"raw","reasonCode":"false_positive"}`,
		`{"dimension":"device","value":"attacker-selected-value","valueEncoding":"raw","reasonCode":"false_positive"}`,
		`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"free form text"}`,
		`{"dimension":"ip","value":"203.0.113.7","reasonCode":"false_positive"}`,
		`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"unknown","reasonCode":"false_positive"}`,
		`{"dimension":"ip","value":"` + validDigest + `","valueEncoding":"sha256","reasonCode":"false_positive"}`,
		`{"dimension":"device","value":"` + strings.ToUpper(validDigest) + `","valueEncoding":"sha256","reasonCode":"false_positive"}`,
		`{"dimension":"device","value":"sha256:` + validDigest + `","valueEncoding":"sha256","reasonCode":"false_positive"}`,
		`{"dimension":"device","value":"` + validDigest + `00","valueEncoding":"sha256","reasonCode":"false_positive"}`,
	}
	for _, body := range tests {
		store := &registrationBlockStoreStub{}
		audit := &registrationBlockAuditStub{}
		recorder := httptest.NewRecorder()
		newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleSuperAdmin)}, audit).Revoke(recorder, registrationBlockRequest(body, true))
		if recorder.Code != http.StatusUnprocessableEntity || store.calls != 0 || len(audit.events) != 0 {
			t.Fatalf("body=%s status=%d store=%d audit=%d", body, recorder.Code, store.calls, len(audit.events))
		}
	}

	store := &registrationBlockStoreStub{}
	recorder := httptest.NewRecorder()
	newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, &registrationBlockAuditStub{}).Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive","redisKey":"arbitrary"}`, true))
	if recorder.Code != http.StatusBadRequest || store.calls != 0 {
		t.Fatalf("unknown field status=%d store=%d", recorder.Code, store.calls)
	}
}

func TestRegistrationBlockRevokeFailsClosedWhenAuditOrStoreUnavailable(t *testing.T) {
	t.Run("request audit before mutation", func(t *testing.T) {
		store := &registrationBlockStoreStub{}
		audit := &registrationBlockAuditStub{failEvent: "registration.abuse_unblock_requested"}
		recorder := httptest.NewRecorder()
		newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, audit).Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true))
		if recorder.Code != http.StatusInternalServerError || store.calls != 0 {
			t.Fatalf("status=%d store=%d", recorder.Code, store.calls)
		}
	})

	t.Run("store failure has durable requested and failed outcomes", func(t *testing.T) {
		store := &registrationBlockStoreStub{err: errors.New("redis unavailable")}
		audit := &registrationBlockAuditStub{}
		recorder := httptest.NewRecorder()
		newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, audit).Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true))
		if recorder.Code != http.StatusInternalServerError || store.calls != 1 || len(audit.events) != 2 || audit.events[1].EventType != "registration.abuse_unblock_failed" || audit.events[1].FailureClass != "state_store" {
			t.Fatalf("status=%d store=%d audit=%#v", recorder.Code, store.calls, audit.events)
		}
	})

	t.Run("terminal audit failure remains retryable with durable request", func(t *testing.T) {
		store := &registrationBlockStoreStub{}
		audit := &registrationBlockAuditStub{failEvent: "registration.abuse_unblocked"}
		recorder := httptest.NewRecorder()
		newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, audit).Revoke(recorder, registrationBlockRequest(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`, true))
		if recorder.Code != http.StatusInternalServerError || store.calls != 1 || len(audit.events) != 1 || audit.events[0].EventType != "registration.abuse_unblock_requested" {
			t.Fatalf("status=%d store=%d audit=%#v", recorder.Code, store.calls, audit.events)
		}
	})
}

func TestRegistrationBlockRouteRequiresCSRF(t *testing.T) {
	store := &registrationBlockStoreStub{}
	handler := newRegistrationBlockHandler(store, &registrationBlockRoleReaderStub{binding: activeSystemAdmin(adminroles.RoleTopAdmin)}, &registrationBlockAuditStub{})
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithPrincipal(r.Context(), session.Principal{UserID: "user_operator", SessionID: "sess_operator"})
			ctx = WithSessionRecord(ctx, session.SessionRecord{CSRFTokenHash: session.HashToken("csrf-token")})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	router.Use(RequireCSRF())
	router.Post("/api/v1/admin/registration-defense/blocks/revoke", handler.Revoke)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/admin/registration-defense/blocks/revoke", strings.NewReader(`{"dimension":"ip","value":"203.0.113.7","valueEncoding":"raw","reasonCode":"false_positive"}`)))
	if recorder.Code != http.StatusForbidden || store.calls != 0 {
		t.Fatalf("status=%d store=%d", recorder.Code, store.calls)
	}
}
