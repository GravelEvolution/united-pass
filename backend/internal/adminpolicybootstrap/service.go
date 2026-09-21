// Package adminpolicybootstrap installs the reviewed, fixed administrator
// policy matrix required before a system super-administrator can be granted.
package adminpolicybootstrap

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/cerbos"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

var (
	ErrUnavailable  = errors.New("administrator policy bootstrap unavailable")
	ErrInvalidInput = errors.New("administrator policy bootstrap input invalid")
	ErrPolicyDrift  = errors.New("administrator policy bootstrap drift")
	ErrReadback     = errors.New("administrator policy bootstrap readback failed")
)

type Service struct {
	repository policies.Repository
	publisher  policies.Publisher
	pdp        permissions.CerbosDecisionClient
	catalog    []fixedPolicySpec
}

func NewService(repository policies.Repository, publisher policies.Publisher, pdp permissions.CerbosDecisionClient) *Service {
	return &Service{repository: repository, publisher: publisher, pdp: pdp, catalog: fixedPolicyCatalog()}
}

func (s *Service) Ensure(ctx context.Context, actor identity.UserID, requestID string) error {
	if s == nil || s.repository == nil || s.publisher == nil || s.pdp == nil {
		return ErrUnavailable
	}
	if actor == "" || strings.TrimSpace(requestID) == "" {
		return ErrInvalidInput
	}
	for _, spec := range s.catalog {
		if err := policies.ValidateDraft(spec.input); err != nil {
			return errors.Join(ErrPolicyDrift, err)
		}
		if err := s.ensurePolicy(ctx, actor, requestID, spec); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ensurePolicy(ctx context.Context, actor identity.UserID, requestID string, spec fixedPolicySpec) error {
	detail, found, err := s.findByName(ctx, spec.input.Name)
	if err != nil {
		return fmt.Errorf("%w: find %s: %v", ErrUnavailable, spec.input.Action, err)
	}
	if !found {
		id, version, err := s.repository.Create(ctx, actor, spec.input)
		if err != nil {
			if !errors.Is(err, policies.ErrDuplicateName) {
				return fmt.Errorf("%w: create %s: %v", ErrUnavailable, spec.input.Action, err)
			}
			// Another bootstrap process may have won the unique-name insert.
			// Adopt it only after an exact immutable-state readback.
			detail, found, err = s.findByName(ctx, spec.input.Name)
			if err != nil || !found {
				return fmt.Errorf("%w: concurrent create readback for %s: %v", ErrReadback, spec.input.Action, err)
			}
		} else {
			detail = detailFromDraft(id, version, policies.StatusDraft, spec.input)
		}
	}
	if !detailMatches(detail, spec.input) {
		return fmt.Errorf("%w: %s", ErrPolicyDrift, spec.input.Action)
	}
	switch detail.Status {
	case policies.StatusDraft:
		if err := s.publish(ctx, actor, requestID, detail, spec.input); err != nil {
			return err
		}
	case policies.StatusPublished:
		// An already-published exact policy is never overwritten. Its database
		// and PDP state are proven again below.
	default:
		return fmt.Errorf("%w: %s has status %q", ErrPolicyDrift, spec.input.Action, detail.Status)
	}
	policy, err := s.readBackPublished(ctx, detail.PolicyID, detail.Version, spec.input)
	if err != nil {
		return err
	}
	return s.readBackPDP(ctx, requestID, spec, policy)
}

func (s *Service) findByName(ctx context.Context, name string) (policies.Detail, bool, error) {
	cursor := ""
	var id policies.PolicyID
	for pageNumber := 0; pageNumber < 10; pageNumber++ {
		page, err := s.repository.List(ctx, policies.ListQuery{Cursor: cursor, Limit: 100, Query: name})
		if err != nil {
			return policies.Detail{}, false, err
		}
		for _, summary := range page.Items {
			if !strings.EqualFold(summary.Name, name) {
				continue
			}
			if id != "" && id != summary.PolicyID {
				return policies.Detail{}, false, ErrPolicyDrift
			}
			id = summary.PolicyID
		}
		if !page.HasMore {
			if id == "" {
				return policies.Detail{}, false, nil
			}
			detail, err := s.repository.Get(ctx, id)
			return detail, err == nil, err
		}
		if page.NextCursor == "" || page.NextCursor == cursor {
			return policies.Detail{}, false, ErrPolicyDrift
		}
		cursor = page.NextCursor
	}
	return policies.Detail{}, false, ErrPolicyDrift
}

func (s *Service) publish(ctx context.Context, actor identity.UserID, requestID string, detail policies.Detail, input policies.DraftInput) error {
	job, err := s.repository.BeginPublication(ctx, actor, detail.PolicyID, detail.Version, requestID)
	if err != nil {
		return fmt.Errorf("%w: begin publication for %s: %v", ErrUnavailable, input.Action, err)
	}
	if !publishedMatches(job.Policy, detail.PolicyID, detail.Version, input) {
		_ = s.repository.FailPublication(context.WithoutCancel(ctx), job.JobID, "bootstrap_drift")
		return fmt.Errorf("%w: publication job for %s", ErrPolicyDrift, input.Action)
	}
	if err := s.publisher.Publish(ctx, job.Policy); err != nil {
		_ = s.repository.FailPublication(context.WithoutCancel(ctx), job.JobID, "provider")
		return fmt.Errorf("%w: publish %s: %v", ErrUnavailable, input.Action, err)
	}
	if err := s.repository.CompletePublication(ctx, job.JobID); err != nil {
		return fmt.Errorf("%w: complete publication for %s: %v", ErrUnavailable, input.Action, err)
	}
	return nil
}

func (s *Service) readBackPublished(ctx context.Context, id policies.PolicyID, version int, input policies.DraftInput) (policies.PublishedPolicy, error) {
	items, err := s.repository.ListPublished(ctx, input.Action, input.Resource)
	if err != nil {
		return policies.PublishedPolicy{}, fmt.Errorf("%w: list %s: %v", ErrReadback, input.Action, err)
	}
	if len(items) != 1 {
		return policies.PublishedPolicy{}, fmt.Errorf("%w: expected one fixed policy for %s, got %d", ErrReadback, input.Action, len(items))
	}
	var matched *policies.PublishedPolicy
	for index := range items {
		if items[index].PolicyID != id {
			continue
		}
		if matched != nil || !publishedMatches(items[index], id, version, input) {
			return policies.PublishedPolicy{}, fmt.Errorf("%w: database drift for %s", ErrReadback, input.Action)
		}
		copy := items[index]
		matched = &copy
	}
	if matched == nil {
		return policies.PublishedPolicy{}, fmt.Errorf("%w: missing %s", ErrReadback, input.Action)
	}
	return *matched, nil
}

func (s *Service) readBackPDP(ctx context.Context, requestID string, spec fixedPolicySpec, policy policies.PublishedPolicy) error {
	roles := []adminroles.Role{adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin}
	for _, role := range roles {
		if err := s.checkPDP(ctx, requestID, policy, string(role), slices.Contains(spec.roles, role)); err != nil {
			return err
		}
	}
	return s.checkPDP(ctx, requestID, policy, "contestant", false)
}

func (s *Service) checkPDP(ctx context.Context, requestID string, policy policies.PublishedPolicy, role string, expected bool) error {
	principal := cerbos.Principal{
		ID:         "admin-policy-bootstrap-readback-" + role,
		Roles:      []string{role},
		Attributes: map[string]any{"eventRole": role, "accountStatus": "active"},
	}
	checks := []cerbos.ResourceCheck{{
		PolicyID: policy.PolicyID,
		Version:  policy.Version,
		Attributes: map[string]any{
			"selector": "*",
			"action":   policy.Action,
		},
	}}
	decisions, err := s.pdp.Check(ctx, requestID, principal, checks)
	if err != nil {
		return fmt.Errorf("%w: PDP error for %s: %v", ErrReadback, policy.Action, err)
	}
	if len(decisions) != 1 || decisions[0].PolicyID != policy.PolicyID || decisions[0].Allowed != expected {
		return fmt.Errorf("%w: PDP decision for %s role %s", ErrReadback, policy.Action, role)
	}
	return nil
}

func detailFromDraft(id policies.PolicyID, version int, status policies.Status, input policies.DraftInput) policies.Detail {
	return policies.Detail{
		PolicyID: id, Name: input.Name, Description: input.Description, Resource: input.Resource,
		Action: input.Action, Effect: input.Effect, Version: version, Status: status,
		Principals: append([]policies.Clause(nil), input.Principals...),
		Conditions: append([]policies.Clause(nil), input.Conditions...),
	}
}

func detailMatches(detail policies.Detail, input policies.DraftInput) bool {
	return detail.PolicyID != "" && detail.Version > 0 && detail.Name == input.Name && detail.Description == input.Description &&
		detail.Resource == input.Resource && detail.Action == input.Action && detail.Effect == input.Effect &&
		slices.Equal(detail.Principals, input.Principals) && slices.Equal(detail.Conditions, input.Conditions)
}

func publishedMatches(policy policies.PublishedPolicy, id policies.PolicyID, version int, input policies.DraftInput) bool {
	return policy.PolicyID == id && policy.Version == version && policy.Name == input.Name && policy.Resource == input.Resource &&
		policy.Action == input.Action && policy.Effect == input.Effect && slices.Equal(policy.Principals, input.Principals) &&
		slices.Equal(policy.Conditions, input.Conditions)
}

type policyKind string

const (
	policyKindCapability policyKind = "capability"
	policyKindDreamUP    policyKind = "dreamup"
)

type fixedPolicySpec struct {
	kind  policyKind
	input policies.DraftInput
	roles []adminroles.Role
}

// fixedPolicyCatalog is deliberately literal. Adding an administrator
// capability or DreamUP action must be accompanied by a conscious review and
// an edit to this list; it must never be derived from AllCapabilities at
// runtime.
func fixedPolicyCatalog() []fixedPolicySpec {
	return []fixedPolicySpec{
		capabilityPolicy("user.read"),
		capabilityPolicy("user.disable"),
		capabilityPolicy("employee.manage"),
		capabilityPolicy("employee.offboard"),
		capabilityPolicy("department.manage"),
		capabilityPolicy("application.read"),
		capabilityPolicy("application.manage"),
		capabilityPolicy("application.secret.rotate"),
		capabilityPolicy("policy.read"),
		capabilityPolicy("policy.manage"),
		capabilityPolicy("policy.publish"),
		capabilityPolicy("audit.read"),
		capabilityPolicy("audit.export"),
		capabilityPolicy("provider.read"),
		capabilityPolicy("provider.manage"),

		dreamUPPolicy(permissions.ActionDashboardRead, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionApplicationReadBasic, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionApplicationReview, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionApplicationApproveAdmission, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionApplicationDecide, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionRegistrationManage, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionCheckinScan, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionCheckinManageWindow, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionIdentityAccessRequest, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionIdentityAccessApprove, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionIdentityTargetValidate, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionIdentityGrantConsume, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionIdentityReadRestricted, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionLegalRead, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionApplicationExport, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionRoleManage, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionAuditRead, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionContactSubmissionManage, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionContentManage, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionInspectionPointRead, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionInspectionPointManage, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionInspectionPerform, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionInspectionReview, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionAssetRead, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionAssetManage, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionAssetReservationManage, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionAssetCustodyTransfer, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionAssetInventoryAdjust, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionPersonalAssetAssignment, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionAssetCodeRotate, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionQRPrintSingle, adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionQRPrintBulk, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionRoleMigrationRead, adminroles.RoleSuperAdmin),
		dreamUPPolicy(permissions.ActionEventRegistryManage, adminroles.RoleSuperAdmin),
	}
}

func capabilityPolicy(action string) fixedPolicySpec {
	return fixedPolicySpec{kind: policyKindCapability, roles: []adminroles.Role{adminroles.RoleSuperAdmin}, input: policies.DraftInput{
		Name:        "Administrator bootstrap: " + action,
		Description: "Fixed bootstrap allow for active system super administrators.",
		Resource:    "*",
		Action:      action,
		Effect:      policies.EffectAllow,
		Principals: []policies.Clause{{
			Attribute: "eventRole",
			Operator:  policies.OperatorEqual,
			Value:     string(adminroles.RoleSuperAdmin),
		}},
		Conditions: []policies.Clause{},
	}}
}

func dreamUPPolicy(action permissions.Action, roles ...adminroles.Role) fixedPolicySpec {
	value := ""
	for index, role := range roles {
		if index > 0 {
			value += ","
		}
		value += string(role)
	}
	operator := policies.OperatorIn
	if len(roles) == 1 {
		operator = policies.OperatorEqual
	}
	return fixedPolicySpec{kind: policyKindDreamUP, roles: append([]adminroles.Role(nil), roles...), input: policies.DraftInput{
		Name:        "DreamUP administrator bootstrap: " + string(action),
		Description: "Fixed event-role allow bounded by the United Pass role matrix.",
		Resource:    "*",
		Action:      string(action),
		Effect:      policies.EffectAllow,
		Principals: []policies.Clause{{
			Attribute: "eventRole",
			Operator:  operator,
			Value:     value,
		}},
		Conditions: []policies.Clause{},
	}}
}
