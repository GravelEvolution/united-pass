package permissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

type CerbosAuthorizer struct {
	roles     adminroles.Repository
	principal PrincipalContextReader
	policies  PublishedPolicyReader
	client    CerbosDecisionClient
	requestID func(context.Context) string
}

var _ Authorizer = (*CerbosAuthorizer)(nil)

func NewCerbosAuthorizer(roles adminroles.Repository, principal PrincipalContextReader, policyReader PublishedPolicyReader, client CerbosDecisionClient, requestID ...func(context.Context) string) *CerbosAuthorizer {
	authorizer := &CerbosAuthorizer{roles: roles, principal: principal, policies: policyReader, client: client}
	if len(requestID) > 0 {
		authorizer.requestID = requestID[0]
	}
	return authorizer
}

func (a *CerbosAuthorizer) Check(ctx context.Context, userID identity.UserID, action Action, resource Resource) (Decision, error) {
	if err := validateScopedRequest(userID, action, resource); err != nil {
		return Decision{}, err
	}
	if a == nil || a.roles == nil || a.principal == nil || a.policies == nil || a.client == nil || action == ActionOperationReceiptRead {
		return Decision{}, nil
	}

	principal, err := a.principal.GetPermissionPrincipal(ctx, userID)
	if err != nil {
		return Decision{}, fmt.Errorf("scoped permission principal: %w", err)
	}
	systemBinding, err := loadOptionalBinding(ctx, a.roles, userID, adminroles.Scope{Kind: adminroles.ScopeSystem})
	if err != nil {
		return Decision{}, fmt.Errorf("scoped system binding: %w", err)
	}
	var eventBinding adminroles.Binding
	if resource.EventID != "" {
		eventBinding, err = loadOptionalBinding(ctx, a.roles, userID, adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: resource.EventID})
		if err != nil {
			return Decision{}, fmt.Errorf("scoped event binding: %w", err)
		}
	}

	binding := selectScopedBinding(action, systemBinding, eventBinding)
	if !activeBinding(binding) || !FixedRoleAllows(binding.Role, action) {
		return Decision{}, nil
	}

	selector := resource.Kind + ":" + resource.ID
	published, err := a.policies.ListPublished(ctx, string(action), selector)
	if err != nil {
		return Decision{}, fmt.Errorf("scoped permission policy list: %w", err)
	}
	if len(published) == 0 {
		return Decision{}, nil
	}
	for _, policy := range published {
		if policy.Action != string(action) || (policy.Resource != selector && policy.Resource != "*") || (policy.Effect != policies.EffectAllow && policy.Effect != policies.EffectDeny) {
			return Decision{}, nil
		}
	}

	attributes := cloneAttributes(principal.Attributes)
	attributes["eventId"] = resource.EventID
	attributes["eventRole"] = string(binding.Role)
	attributes["roleBindingId"] = binding.ID
	attributes["roleBindingVersion"] = binding.Version
	attributes["challengeVersion"] = principal.ChallengeVersion
	roles := appendRole(principal.Roles, string(binding.Role))
	checks := make([]cerbos.ResourceCheck, 0, len(published))
	for _, policy := range published {
		resourceAttributes := cloneAttributes(resource.Attributes)
		resourceAttributes["kind"] = resource.Kind
		resourceAttributes["id"] = resource.ID
		resourceAttributes["eventId"] = resource.EventID
		resourceAttributes["action"] = string(action)
		resourceAttributes["selector"] = selector
		checks = append(checks, cerbos.ResourceCheck{PolicyID: policy.PolicyID, Version: policy.Version, Attributes: resourceAttributes})
	}
	correlationID := ""
	if a.requestID != nil {
		correlationID = a.requestID(ctx)
	}
	cerbosPrincipal := cerbos.Principal{ID: string(userID), Roles: roles, Attributes: attributes}
	decisions := make([]cerbos.Decision, 0, len(checks))
	for start := 0; start < len(checks); start += maxCerbosChecksPerRequest {
		end := min(start+maxCerbosChecksPerRequest, len(checks))
		batch, err := a.client.Check(ctx, correlationID, cerbosPrincipal, checks[start:end])
		if err != nil {
			return Decision{}, fmt.Errorf("scoped Cerbos decision: %w", err)
		}
		decisions = append(decisions, batch...)
	}
	allowed, err := combineScopedPolicyDecisions(published, decisions)
	if err != nil {
		return Decision{}, err
	}
	// Lifecycle state is authoritative backend data. It deliberately guards
	// after the PDP decision so a policy can never re-enable a disabled or
	// offboarding principal.
	if principal.Attributes["accountStatus"] != string(identity.UserStatusActive) || principal.Attributes["employeeStatus"] == "offboarding" {
		allowed = false
	}
	if !allowed {
		return Decision{}, nil
	}
	return Decision{Allowed: true, Role: binding.Role, BindingID: binding.ID, BindingVersion: binding.Version, ChallengeVersion: principal.ChallengeVersion}, nil
}

func loadOptionalBinding(ctx context.Context, repository adminroles.Repository, userID identity.UserID, scope adminroles.Scope) (adminroles.Binding, error) {
	binding, err := repository.GetForScope(ctx, userID, scope)
	if errors.Is(err, adminroles.ErrBindingNotFound) {
		return adminroles.Binding{}, nil
	}
	if err != nil {
		return adminroles.Binding{}, err
	}
	if binding.UserID != userID || binding.Scope != scope || adminroles.ValidateRoleScope(binding.Role, binding.Scope) != nil {
		return adminroles.Binding{}, ErrInvalidScopedAuthorization
	}
	return binding, nil
}

func selectScopedBinding(action Action, system, event adminroles.Binding) adminroles.Binding {
	if activeBinding(system) && (system.Role == adminroles.RoleSuperAdmin || system.Role == adminroles.RoleTopAdmin) {
		return system
	}
	if _, ok := eventActions[action]; ok {
		return event
	}
	return adminroles.Binding{}
}

func activeBinding(binding adminroles.Binding) bool {
	return binding.ID != "" && binding.Enabled && binding.DisabledAt == nil && binding.Version > 0
}

func appendRole(roles []string, role string) []string {
	result := append([]string(nil), roles...)
	for _, existing := range result {
		if existing == role {
			return result
		}
	}
	return append(result, role)
}

func cloneAttributes(attributes map[string]any) map[string]any {
	result := make(map[string]any, len(attributes)+6)
	for key, value := range attributes {
		result[key] = value
	}
	return result
}

func combineScopedPolicyDecisions(published []policies.PublishedPolicy, decisions []cerbos.Decision) (bool, error) {
	if len(decisions) != len(published) {
		return false, fmt.Errorf("scoped Cerbos decision count mismatch")
	}
	matchedAllow, matchedDeny := false, false
	for index, decision := range decisions {
		policy := published[index]
		if decision.PolicyID != policy.PolicyID {
			return false, fmt.Errorf("scoped Cerbos decision correlation mismatch")
		}
		if policy.Effect == policies.EffectAllow && decision.Allowed {
			matchedAllow = true
		}
		if policy.Effect == policies.EffectDeny && !decision.Allowed {
			matchedDeny = true
		}
	}
	return matchedAllow && !matchedDeny, nil
}
