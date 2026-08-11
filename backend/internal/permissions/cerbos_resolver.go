//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Cerbos-backed authoritative permission resolver
//

package permissions

import (
	"context"
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

// Cerbos defaults to at most 50 resources per CheckResources request. Keep
// every outbound call within that public limit while retaining fail-closed
// aggregation across the complete policy set.
const maxCerbosChecksPerRequest = 50

type PrincipalContext struct {
	Roles      []string
	Attributes map[string]any
}

type PrincipalContextReader interface {
	GetPermissionPrincipal(context.Context, identity.UserID) (PrincipalContext, error)
}

type PublishedPolicyReader interface {
	ListPublished(context.Context, string, string) ([]policies.PublishedPolicy, error)
}

type CerbosDecisionClient interface {
	Check(context.Context, string, cerbos.Principal, []cerbos.ResourceCheck) ([]cerbos.Decision, error)
}

type CerbosResolver struct {
	principal PrincipalContextReader
	policies  PublishedPolicyReader
	client    CerbosDecisionClient
	requestID func(context.Context) string
}

func NewCerbosResolver(principal PrincipalContextReader, policyReader PublishedPolicyReader, client CerbosDecisionClient, requestID ...func(context.Context) string) *CerbosResolver {
	resolver := &CerbosResolver{principal: principal, policies: policyReader, client: client}
	if len(requestID) > 0 {
		resolver.requestID = requestID[0]
	}
	return resolver
}

type capabilitySpec struct {
	action   string
	resource string
	set      func(*Capabilities, bool)
}

var capabilitySpecs = []capabilitySpec{
	{"user.read", "user:*", func(c *Capabilities, v bool) { c.UserRead = v }},
	{"user.disable", "user:*", func(c *Capabilities, v bool) { c.UserDisable = v }},
	{"employee.manage", "employee:*", func(c *Capabilities, v bool) { c.EmployeeManage = v }},
	{"employee.offboard", "employee:*", func(c *Capabilities, v bool) { c.EmployeeOffboard = v }},
	{"department.manage", "department:*", func(c *Capabilities, v bool) { c.DepartmentManage = v }},
	{"application.read", "application:*", func(c *Capabilities, v bool) { c.ApplicationRead = v }},
	{"application.manage", "application:*", func(c *Capabilities, v bool) { c.ApplicationManage = v }},
	{"application.secret.rotate", "application:*", func(c *Capabilities, v bool) { c.ApplicationSecretRotate = v }},
	{"policy.read", "policy:*", func(c *Capabilities, v bool) { c.PolicyRead = v }},
	{"policy.manage", "policy:*", func(c *Capabilities, v bool) { c.PolicyManage = v }},
	{"policy.publish", "policy:*", func(c *Capabilities, v bool) { c.PolicyPublish = v }},
	{"audit.read", "audit:*", func(c *Capabilities, v bool) { c.AuditRead = v }},
	{"audit.export", "audit:*", func(c *Capabilities, v bool) { c.AuditExport = v }},
	{"provider.read", "provider:*", func(c *Capabilities, v bool) { c.ProviderRead = v }},
	{"provider.manage", "provider:*", func(c *Capabilities, v bool) { c.ProviderManage = v }},
}

type pendingPolicy struct {
	policy policies.PublishedPolicy
	spec   int
}

func (r *CerbosResolver) Resolve(ctx context.Context, userID identity.UserID) (Capabilities, error) {
	if r.principal == nil || r.policies == nil || r.client == nil || userID == "" {
		return NoCapabilities(), nil
	}
	principal, err := r.principal.GetPermissionPrincipal(ctx, userID)
	if err != nil {
		return NoCapabilities(), fmt.Errorf("permission principal context: %w", err)
	}
	pending := make([]pendingPolicy, 0)
	checks := make([]cerbos.ResourceCheck, 0)
	for index, spec := range capabilitySpecs {
		published, err := r.policies.ListPublished(ctx, spec.action, spec.resource)
		if err != nil {
			return NoCapabilities(), fmt.Errorf("permission policy list: %w", err)
		}
		for _, policy := range published {
			pending = append(pending, pendingPolicy{policy: policy, spec: index})
			checks = append(checks, cerbos.ResourceCheck{PolicyID: policy.PolicyID, Version: policy.Version, Attributes: map[string]any{"selector": spec.resource, "action": spec.action}})
		}
	}
	if len(checks) == 0 {
		return NoCapabilities(), nil
	}
	correlationID := ""
	if r.requestID != nil {
		correlationID = r.requestID(ctx)
	}
	cerbosPrincipal := cerbos.Principal{ID: string(userID), Roles: principal.Roles, Attributes: principal.Attributes}
	decisions := make([]cerbos.Decision, 0, len(checks))
	for start := 0; start < len(checks); start += maxCerbosChecksPerRequest {
		end := min(start+maxCerbosChecksPerRequest, len(checks))
		batch, err := r.client.Check(ctx, correlationID, cerbosPrincipal, checks[start:end])
		if err != nil {
			return NoCapabilities(), fmt.Errorf("permission Cerbos decision: %w", err)
		}
		decisions = append(decisions, batch...)
	}
	if len(decisions) != len(pending) {
		return NoCapabilities(), fmt.Errorf("permission Cerbos decision count mismatch")
	}
	matchedAllow := make([]bool, len(capabilitySpecs))
	matchedDeny := make([]bool, len(capabilitySpecs))
	for index, decision := range decisions {
		item := pending[index]
		if decision.PolicyID != item.policy.PolicyID {
			return NoCapabilities(), fmt.Errorf("permission Cerbos decision correlation mismatch")
		}
		if item.policy.Effect == policies.EffectAllow && decision.Allowed {
			matchedAllow[item.spec] = true
		}
		if item.policy.Effect == policies.EffectDeny && !decision.Allowed {
			matchedDeny[item.spec] = true
		}
	}
	capabilities := NoCapabilities()
	for index, spec := range capabilitySpecs {
		spec.set(&capabilities, matchedAllow[index] && !matchedDeny[index])
	}
	return capabilities, nil
}
