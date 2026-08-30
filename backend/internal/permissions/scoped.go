package permissions

import (
	"context"
	"errors"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type Action string

const (
	ActionDashboardRead               Action = "event.dashboard.read"
	ActionApplicationReadBasic        Action = "event.application.read_basic"
	ActionApplicationReview           Action = "event.application.review"
	ActionApplicationApproveAdmission Action = "event.application.approve_admission"
	ActionApplicationDecide           Action = "event.application.decide"
	ActionRegistrationManage          Action = "event.registration.manage"
	ActionCheckinScan                 Action = "event.checkin.scan"
	ActionCheckinManageWindow         Action = "event.checkin.manage_window"
	ActionIdentityAccessRequest       Action = "event.identity_access.request"
	ActionIdentityAccessApprove       Action = "event.identity_access.approve"
	ActionIdentityTargetValidate      Action = "event.identity_access.validate_target"
	ActionIdentityGrantConsume        Action = "event.identity_access.consume"
	ActionIdentityReadRestricted      Action = "event.identity.read_restricted"
	ActionLegalRead                   Action = "event.legal.read"
	ActionApplicationExport           Action = "event.application.export"
	ActionRoleManage                  Action = "event.role.manage"
	ActionAuditRead                   Action = "event.audit.read"
	ActionContactSubmissionManage     Action = "event.contact_submission.manage"
	ActionContentManage               Action = "event.content.manage"
	ActionRoleMigrationRead           Action = "system.role_migration.read"
	ActionEventRegistryManage         Action = "system.event_registry.manage"
	ActionOperationReceiptRead        Action = "system.operation_receipt.read"
)

var ErrInvalidScopedAuthorization = errors.New("permissions: invalid scoped authorization request")

type Resource struct {
	Kind       string
	ID         string
	EventID    string
	Attributes map[string]any
}

type Decision struct {
	Allowed          bool
	Role             adminroles.Role
	BindingID        string
	BindingVersion   int64
	ChallengeVersion int64
}

type Authorizer interface {
	Check(context.Context, identity.UserID, Action, Resource) (Decision, error)
}

var eventActions = map[Action]struct{}{
	ActionDashboardRead: {}, ActionApplicationReadBasic: {}, ActionApplicationReview: {},
	ActionApplicationApproveAdmission: {}, ActionApplicationDecide: {}, ActionRegistrationManage: {}, ActionCheckinScan: {},
	ActionCheckinManageWindow: {}, ActionIdentityAccessRequest: {}, ActionIdentityAccessApprove: {},
	ActionIdentityTargetValidate: {}, ActionIdentityGrantConsume: {}, ActionIdentityReadRestricted: {},
	ActionLegalRead: {}, ActionApplicationExport: {}, ActionRoleManage: {}, ActionAuditRead: {}, ActionContactSubmissionManage: {}, ActionContentManage: {},
}

var systemActions = map[Action]struct{}{
	ActionRoleMigrationRead: {}, ActionEventRegistryManage: {},
	ActionOperationReceiptRead: {},
}

// dreamUPDelegatedAdministratorActions is the single capability/action
// allowlist shared by administrator assertion signing and administrator
// step-up. Keeping the transport proof gate on this same set prevents a BFF
// capability from being signable but impossible to mint a native one-shot
// grant for (or vice versa).
var dreamUPDelegatedAdministratorActions = map[Action]struct{}{
	ActionDashboardRead: {}, ActionApplicationReadBasic: {}, ActionApplicationReview: {},
	ActionApplicationApproveAdmission: {}, ActionApplicationDecide: {}, ActionRegistrationManage: {},
	ActionCheckinScan: {}, ActionCheckinManageWindow: {}, ActionIdentityTargetValidate: {},
	ActionIdentityGrantConsume: {}, ActionIdentityReadRestricted: {}, ActionLegalRead: {},
	ActionApplicationExport: {}, ActionAuditRead: {}, ActionContactSubmissionManage: {},
	ActionContentManage: {}, ActionRoleMigrationRead: {},
}

var dreamUPHighRiskDelegatedAdministratorActions = map[Action]struct{}{
	ActionApplicationReview: {}, ActionApplicationApproveAdmission: {}, ActionApplicationDecide: {},
	ActionRegistrationManage: {}, ActionCheckinScan: {}, ActionCheckinManageWindow: {},
	ActionIdentityGrantConsume: {}, ActionIdentityReadRestricted: {}, ActionLegalRead: {},
	ActionApplicationExport: {}, ActionAuditRead: {}, ActionContactSubmissionManage: {},
	ActionContentManage: {}, ActionRoleMigrationRead: {},
}

// IsDreamUPDelegatedAdministratorAction reports whether action is an exact
// capability understood by the private DreamUP administrator assertion
// contract. It deliberately excludes legacy dreamup.admin.* reauthentication
// names, which remain supported only by their original direct consumers.
func IsDreamUPDelegatedAdministratorAction(action Action) bool {
	_, ok := dreamUPDelegatedAdministratorActions[action]
	return ok
}

// IsDreamUPHighRiskDelegatedAdministratorAction reports whether native
// Mini Program use of action requires an action-and-target-bound one-shot
// grant. This is the authoritative high-risk subset for both minting and
// downstream administrator assertion validation.
func IsDreamUPHighRiskDelegatedAdministratorAction(action Action) bool {
	_, ok := dreamUPHighRiskDelegatedAdministratorActions[action]
	return ok
}

var adminEventActions = map[Action]struct{}{
	ActionDashboardRead: {}, ActionApplicationReadBasic: {}, ActionApplicationReview: {}, ActionApplicationApproveAdmission: {},
	ActionCheckinScan: {}, ActionAuditRead: {}, ActionContactSubmissionManage: {}, ActionContentManage: {},
}

var seniorEventActions = map[Action]struct{}{
	ActionIdentityAccessRequest: {}, ActionIdentityTargetValidate: {}, ActionIdentityGrantConsume: {},
}

// FixedRoleAllows is a hard upper bound. Cerbos can further restrict this
// matrix, but a published policy cannot broaden it or grant receipt access to
// a browser principal.
func FixedRoleAllows(role adminroles.Role, action Action) bool {
	if action == ActionOperationReceiptRead {
		return false
	}
	switch role {
	case adminroles.RoleSuperAdmin, adminroles.RoleTopAdmin:
		_, event := eventActions[action]
		_, system := systemActions[action]
		return event || system
	case adminroles.RoleSeniorAdmin:
		if _, ok := adminEventActions[action]; ok {
			return true
		}
		_, ok := seniorEventActions[action]
		return ok
	case adminroles.RoleAdmin:
		_, ok := adminEventActions[action]
		return ok
	default:
		return false
	}
}

func validateScopedRequest(userID identity.UserID, action Action, resource Resource) error {
	if userID == "" || strings.TrimSpace(resource.Kind) == "" || strings.TrimSpace(resource.ID) == "" || strings.Contains(resource.Kind, ":") || strings.Contains(resource.ID, ":") {
		return ErrInvalidScopedAuthorization
	}
	if _, ok := eventActions[action]; ok {
		if strings.TrimSpace(resource.EventID) == "" {
			return ErrInvalidScopedAuthorization
		}
		return nil
	}
	if _, ok := systemActions[action]; ok {
		if (action == ActionRoleMigrationRead || action == ActionOperationReceiptRead) && strings.TrimSpace(resource.EventID) == "" {
			return ErrInvalidScopedAuthorization
		}
		return nil
	}
	return ErrInvalidScopedAuthorization
}

type roleManagementGate struct{ authorizer Authorizer }

var _ adminroles.RoleManagementAuthorizer = (*roleManagementGate)(nil)

func NewRoleManagementGate(authorizer Authorizer) *roleManagementGate {
	return &roleManagementGate{authorizer: authorizer}
}

func (g *roleManagementGate) CheckRoleManagement(ctx context.Context, actor identity.UserID, eventID string) (adminroles.RoleManagementDecision, error) {
	if g == nil || g.authorizer == nil || strings.TrimSpace(eventID) == "" {
		return adminroles.RoleManagementDecision{}, nil
	}
	decision, err := g.authorizer.Check(ctx, actor, ActionRoleManage, Resource{Kind: "role_binding", ID: eventID, EventID: eventID})
	if err != nil || !decision.Allowed {
		return adminroles.RoleManagementDecision{}, err
	}
	scope := adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: eventID}
	if decision.Role == adminroles.RoleSuperAdmin || decision.Role == adminroles.RoleTopAdmin {
		scope = adminroles.Scope{Kind: adminroles.ScopeSystem}
	}
	return adminroles.RoleManagementDecision{Allowed: true, Role: decision.Role, BindingID: decision.BindingID, BindingVersion: decision.BindingVersion, Scope: scope}, nil
}
