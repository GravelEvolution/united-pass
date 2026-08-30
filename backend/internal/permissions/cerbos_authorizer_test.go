package permissions

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

type scopedRoleRepository struct {
	bindings map[string]adminroles.Binding
	scopes   []adminroles.Scope
	err      error
}

func scopedBindingKey(userID identity.UserID, scope adminroles.Scope) string {
	key, _ := scope.Key()
	return string(userID) + ":" + string(scope.Kind) + ":" + key
}

func (r *scopedRoleRepository) GetForScope(_ context.Context, userID identity.UserID, scope adminroles.Scope) (adminroles.Binding, error) {
	r.scopes = append(r.scopes, scope)
	if r.err != nil {
		return adminroles.Binding{}, r.err
	}
	binding, ok := r.bindings[scopedBindingKey(userID, scope)]
	if !ok {
		return adminroles.Binding{}, adminroles.ErrBindingNotFound
	}
	return binding, nil
}

func (*scopedRoleRepository) ListForUser(context.Context, identity.UserID, adminpagination.Query) (adminpagination.Page[adminroles.Binding], error) {
	panic("unexpected list")
}
func (*scopedRoleRepository) ListForEvent(context.Context, string, adminpagination.Query) (adminpagination.Page[adminroles.Binding], error) {
	panic("unexpected list")
}
func (*scopedRoleRepository) Create(context.Context, adminroles.Binding, adminroles.MutationAudit) (adminroles.Binding, error) {
	panic("unexpected create")
}
func (*scopedRoleRepository) Update(context.Context, adminroles.Binding, int64, adminroles.MutationAudit) (adminroles.Binding, error) {
	panic("unexpected update")
}
func (*scopedRoleRepository) Disable(context.Context, string, int64, adminroles.MutationAudit) (adminroles.Binding, error) {
	panic("unexpected disable")
}

type scopedPrincipalReader struct {
	principal PrincipalContext
	err       error
}

func (r scopedPrincipalReader) GetPermissionPrincipal(context.Context, identity.UserID) (PrincipalContext, error) {
	return r.principal, r.err
}

type scopedPolicyReader struct {
	items    []policies.PublishedPolicy
	err      error
	action   string
	resource string
}

func (r *scopedPolicyReader) ListPublished(_ context.Context, action, resource string) ([]policies.PublishedPolicy, error) {
	r.action, r.resource = action, resource
	return r.items, r.err
}

type scopedDecisionClient struct {
	allowed         bool
	allowedByPolicy map[policies.PolicyID]bool
	err             error
	principal       cerbos.Principal
	checks          []cerbos.ResourceCheck
	calls           int
}

func (c *scopedDecisionClient) Check(_ context.Context, _ string, principal cerbos.Principal, checks []cerbos.ResourceCheck) ([]cerbos.Decision, error) {
	c.calls++
	c.principal = principal
	c.checks = append([]cerbos.ResourceCheck(nil), checks...)
	if c.err != nil {
		return nil, c.err
	}
	result := make([]cerbos.Decision, len(checks))
	for i, check := range checks {
		allowed := c.allowed
		if c.allowedByPolicy != nil {
			allowed = c.allowedByPolicy[check.PolicyID]
		}
		result[i] = cerbos.Decision{PolicyID: check.PolicyID, Allowed: allowed}
	}
	return result, nil
}

func TestScopedCerbosAuthorizerUsesOnlyExactEventBinding(t *testing.T) {
	userID := identity.UserID("user_1")
	repo := &scopedRoleRepository{bindings: map[string]adminroles.Binding{}}
	repo.bindings[scopedBindingKey(userID, adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_a"})] = adminroles.Binding{ID: "arb_a", UserID: userID, Role: adminroles.RoleSeniorAdmin, Scope: adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_a"}, Enabled: true, Version: 4}
	policy := &scopedPolicyReader{items: []policies.PublishedPolicy{{PolicyID: "pol_scoped_allow", Action: string(ActionIdentityAccessRequest), Resource: "application:app_1", Effect: policies.EffectAllow, Version: 1}}}
	client := &scopedDecisionClient{allowed: true}
	authorizer := NewCerbosAuthorizer(repo, scopedPrincipalReader{principal: PrincipalContext{Roles: []string{"authenticated"}, Attributes: map[string]any{"accountStatus": "active", "employeeStatus": "active"}, ChallengeVersion: 8}}, policy, client)

	decision, err := authorizer.Check(context.Background(), userID, ActionIdentityAccessRequest, Resource{Kind: "application", ID: "app_1", EventID: "evt_a"})
	if err != nil || !decision.Allowed {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if decision.Role != adminroles.RoleSeniorAdmin || decision.BindingID != "arb_a" || decision.BindingVersion != 4 || decision.ChallengeVersion != 8 {
		t.Fatalf("decision metadata=%+v", decision)
	}
	if policy.action != string(ActionIdentityAccessRequest) || policy.resource != "application:app_1" {
		t.Fatalf("policy lookup=%q %q", policy.action, policy.resource)
	}
	if client.principal.Attributes["eventId"] != "evt_a" || client.principal.Attributes["eventRole"] != string(adminroles.RoleSeniorAdmin) {
		t.Fatalf("principal attrs=%v", client.principal.Attributes)
	}
	if len(repo.scopes) != 2 || repo.scopes[0].Kind != adminroles.ScopeSystem || repo.scopes[1] != (adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_a"}) {
		t.Fatalf("loaded scopes=%+v", repo.scopes)
	}

	denied, err := authorizer.Check(context.Background(), userID, ActionIdentityAccessRequest, Resource{Kind: "application", ID: "app_1", EventID: "evt_b"})
	if err != nil || denied.Allowed {
		t.Fatalf("cross-event decision=%+v err=%v", denied, err)
	}
}

func TestScopedCerbosAuthorizerAcceptsPublishedWildcardResource(t *testing.T) {
	userID := identity.UserID("user_1")
	scope := adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_a"}
	repo := &scopedRoleRepository{bindings: map[string]adminroles.Binding{
		scopedBindingKey(userID, scope): {ID: "arb_a", UserID: userID, Role: adminroles.RoleAdmin, Scope: scope, Enabled: true, Version: 1},
	}}
	policy := &scopedPolicyReader{items: []policies.PublishedPolicy{{PolicyID: "pol_wildcard_allow", Action: string(ActionApplicationReview), Resource: "*", Effect: policies.EffectAllow, Version: 1}}}
	client := &scopedDecisionClient{allowed: true}
	authorizer := NewCerbosAuthorizer(repo, scopedPrincipalReader{principal: PrincipalContext{Attributes: map[string]any{"accountStatus": "active"}}}, policy, client)

	decision, err := authorizer.Check(context.Background(), userID, ActionApplicationReview, Resource{Kind: "application", ID: "app_1", EventID: "evt_a"})
	if err != nil || !decision.Allowed || client.calls != 1 {
		t.Fatalf("wildcard decision=%+v err=%v calls=%d", decision, err, client.calls)
	}
	if policy.resource != "application:app_1" {
		t.Fatalf("policy lookup resource=%q", policy.resource)
	}
}

func TestScopedCerbosAuthorizerFailsClosedForLifecyclePolicyAndPDPFailures(t *testing.T) {
	userID := identity.UserID("user_1")
	scope := adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_a"}
	binding := adminroles.Binding{ID: "arb_a", UserID: userID, Role: adminroles.RoleAdmin, Scope: scope, Enabled: true, Version: 1}
	resource := Resource{Kind: "application", ID: "app_1", EventID: "evt_a"}
	allow := []policies.PublishedPolicy{{PolicyID: "pol_scoped_allow", Action: string(ActionApplicationReview), Resource: "application:app_1", Effect: policies.EffectAllow, Version: 1}}

	for _, tc := range []struct {
		name       string
		attributes map[string]any
		policies   []policies.PublishedPolicy
		clientErr  error
		wantErr    bool
		wantCalls  int
	}{
		{name: "disabled", attributes: map[string]any{"accountStatus": "disabled", "employeeStatus": "active"}, policies: allow, wantCalls: 1},
		{name: "offboarding", attributes: map[string]any{"accountStatus": "active", "employeeStatus": "offboarding"}, policies: allow, wantCalls: 1},
		{name: "missing policy", attributes: map[string]any{"accountStatus": "active", "employeeStatus": "active"}, wantCalls: 0},
		{name: "PDP failure", attributes: map[string]any{"accountStatus": "active", "employeeStatus": "active"}, policies: allow, clientErr: errors.New("down"), wantErr: true, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &scopedRoleRepository{bindings: map[string]adminroles.Binding{scopedBindingKey(userID, scope): binding}}
			client := &scopedDecisionClient{allowed: true, err: tc.clientErr}
			authorizer := NewCerbosAuthorizer(repo, scopedPrincipalReader{principal: PrincipalContext{Attributes: tc.attributes}}, &scopedPolicyReader{items: tc.policies}, client)
			decision, err := authorizer.Check(context.Background(), userID, ActionApplicationReview, resource)
			if decision.Allowed || (err != nil) != tc.wantErr || client.calls != tc.wantCalls {
				t.Fatalf("decision=%+v err=%v calls=%d", decision, err, client.calls)
			}
		})
	}
}

func TestScopedCerbosAuthorizerCombinesAllowAndExplicitDeny(t *testing.T) {
	userID := identity.UserID("user_1")
	scope := adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_a"}
	repo := &scopedRoleRepository{bindings: map[string]adminroles.Binding{scopedBindingKey(userID, scope): {ID: "arb_a", UserID: userID, Role: adminroles.RoleAdmin, Scope: scope, Enabled: true, Version: 1}}}
	policy := &scopedPolicyReader{items: []policies.PublishedPolicy{{PolicyID: "pol_allow_123", Action: string(ActionApplicationReview), Resource: "application:app_1", Effect: policies.EffectAllow, Version: 1}, {PolicyID: "pol_deny_1234", Action: string(ActionApplicationReview), Resource: "application:app_1", Effect: policies.EffectDeny, Version: 1}}}
	client := &scopedDecisionClient{allowedByPolicy: map[policies.PolicyID]bool{"pol_allow_123": true, "pol_deny_1234": false}}
	authorizer := NewCerbosAuthorizer(repo, scopedPrincipalReader{principal: PrincipalContext{Attributes: map[string]any{"accountStatus": "active"}}}, policy, client)
	decision, err := authorizer.Check(context.Background(), userID, ActionApplicationReview, Resource{Kind: "application", ID: "app_1", EventID: "evt_a"})
	if err != nil || decision.Allowed {
		t.Fatalf("explicit deny decision=%+v err=%v", decision, err)
	}
}

func TestScopedCerbosAuthorizerRejectsMismatchedBindingAndPolicyTuple(t *testing.T) {
	userID := identity.UserID("user_1")
	requested := adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_a"}
	wrongScope := adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_b"}
	repo := &scopedRoleRepository{bindings: map[string]adminroles.Binding{
		scopedBindingKey(userID, requested): {ID: "arb_wrong", UserID: userID, Role: adminroles.RoleAdmin, Scope: wrongScope, Enabled: true, Version: 1},
	}}
	client := &scopedDecisionClient{allowed: true}
	authorizer := NewCerbosAuthorizer(repo, scopedPrincipalReader{principal: PrincipalContext{Attributes: map[string]any{"accountStatus": "active"}}}, &scopedPolicyReader{items: []policies.PublishedPolicy{{PolicyID: "pol_scoped_allow", Action: string(ActionApplicationReview), Resource: "application:app_1", Effect: policies.EffectAllow, Version: 1}}}, client)
	decision, err := authorizer.Check(context.Background(), userID, ActionApplicationReview, Resource{Kind: "application", ID: "app_1", EventID: "evt_a"})
	if err == nil || decision.Allowed || client.calls != 0 {
		t.Fatalf("mismatched binding decision=%+v err=%v calls=%d", decision, err, client.calls)
	}

	repo.bindings[scopedBindingKey(userID, requested)] = adminroles.Binding{ID: "arb_a", UserID: userID, Role: adminroles.RoleAdmin, Scope: requested, Enabled: true, Version: 1}
	authorizer = NewCerbosAuthorizer(repo, scopedPrincipalReader{principal: PrincipalContext{Attributes: map[string]any{"accountStatus": "active"}}}, &scopedPolicyReader{items: []policies.PublishedPolicy{{PolicyID: "pol_wrong_tuple", Action: string(ActionApplicationReview), Resource: "application:other", Effect: policies.EffectAllow, Version: 1}}}, client)
	decision, err = authorizer.Check(context.Background(), userID, ActionApplicationReview, Resource{Kind: "application", ID: "app_1", EventID: "evt_a"})
	if err != nil || decision.Allowed || client.calls != 0 {
		t.Fatalf("wrong policy tuple decision=%+v err=%v calls=%d", decision, err, client.calls)
	}
}

func TestScopedCerbosAuthorizerRequiresSystemSuperForSystemActions(t *testing.T) {
	userID := identity.UserID("user_1")
	system := adminroles.Scope{Kind: adminroles.ScopeSystem}
	repo := &scopedRoleRepository{bindings: map[string]adminroles.Binding{
		scopedBindingKey(userID, system): {ID: "arb_super", UserID: userID, Role: adminroles.RoleSuperAdmin, Scope: system, Enabled: true, Version: 2},
	}}
	policy := &scopedPolicyReader{items: []policies.PublishedPolicy{{PolicyID: "pol_system_allow", Action: string(ActionRoleMigrationRead), Resource: "role_migration:job_1", Effect: policies.EffectAllow, Version: 1}}}
	client := &scopedDecisionClient{allowed: true}
	authorizer := NewCerbosAuthorizer(repo, scopedPrincipalReader{principal: PrincipalContext{Attributes: map[string]any{"accountStatus": "active"}}}, policy, client)
	decision, err := authorizer.Check(context.Background(), userID, ActionRoleMigrationRead, Resource{Kind: "role_migration", ID: "job_1", EventID: "evt_a"})
	if err != nil || !decision.Allowed || decision.Role != adminroles.RoleSuperAdmin {
		t.Fatalf("system decision=%+v err=%v", decision, err)
	}
	decision, err = authorizer.Check(context.Background(), userID, ActionOperationReceiptRead, Resource{Kind: "operation_receipt", ID: "aop_1", EventID: "evt_a"})
	if err != nil || decision.Allowed || client.calls != 1 {
		t.Fatalf("browser receipt decision=%+v err=%v calls=%d", decision, err, client.calls)
	}
}
