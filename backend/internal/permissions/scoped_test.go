package permissions

import (
	"context"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestFixedDreamUPRoleMatrix(t *testing.T) {
	cases := []struct {
		role   adminroles.Role
		action Action
		allow  bool
	}{
		{adminroles.RoleAdmin, ActionApplicationReview, true},
		{adminroles.RoleAdmin, ActionApplicationApproveAdmission, true},
		{adminroles.RoleAdmin, ActionContactSubmissionManage, true},
		{adminroles.RoleAdmin, ActionContentManage, true},
		{adminroles.RoleAdmin, ActionIdentityAccessRequest, false},
		{adminroles.RoleSeniorAdmin, ActionIdentityAccessRequest, true},
		{adminroles.RoleSeniorAdmin, ActionApplicationApproveAdmission, true},
		{adminroles.RoleSeniorAdmin, ActionContactSubmissionManage, true},
		{adminroles.RoleSeniorAdmin, ActionContentManage, true},
		{adminroles.RoleSeniorAdmin, ActionApplicationDecide, false},
		{adminroles.RoleSuperAdmin, ActionApplicationDecide, true},
		{adminroles.RoleSuperAdmin, ActionLegalRead, true},
		{adminroles.RoleSuperAdmin, ActionContentManage, true},
		{adminroles.RoleSuperAdmin, ActionOperationReceiptRead, false},
	}
	for _, tc := range cases {
		if got := FixedRoleAllows(tc.role, tc.action); got != tc.allow {
			t.Fatalf("role=%s action=%s got=%v want=%v", tc.role, tc.action, got, tc.allow)
		}
	}
}

func TestDreamUPDelegationActionSetsAreExact(t *testing.T) {
	delegated := []Action{
		ActionDashboardRead, ActionApplicationReadBasic, ActionApplicationReview,
		ActionApplicationApproveAdmission, ActionApplicationDecide, ActionRegistrationManage,
		ActionCheckinScan, ActionCheckinManageWindow, ActionIdentityTargetValidate,
		ActionIdentityGrantConsume, ActionIdentityReadRestricted, ActionLegalRead,
		ActionApplicationExport, ActionAuditRead, ActionContactSubmissionManage,
		ActionContentManage, ActionRoleMigrationRead,
	}
	highRisk := map[Action]bool{
		ActionApplicationReview: true, ActionApplicationApproveAdmission: true, ActionApplicationDecide: true,
		ActionRegistrationManage: true, ActionCheckinScan: true, ActionCheckinManageWindow: true,
		ActionIdentityGrantConsume: true, ActionIdentityReadRestricted: true, ActionLegalRead: true,
		ActionApplicationExport: true, ActionAuditRead: true, ActionContactSubmissionManage: true,
		ActionContentManage: true, ActionRoleMigrationRead: true,
	}
	if len(dreamUPDelegatedAdministratorActions) != len(delegated) || len(dreamUPHighRiskDelegatedAdministratorActions) != len(highRisk) {
		t.Fatalf("delegated=%d/%d highRisk=%d/%d", len(dreamUPDelegatedAdministratorActions), len(delegated), len(dreamUPHighRiskDelegatedAdministratorActions), len(highRisk))
	}
	for _, action := range delegated {
		if !IsDreamUPDelegatedAdministratorAction(action) {
			t.Errorf("delegated action %q missing", action)
		}
		if got := IsDreamUPHighRiskDelegatedAdministratorAction(action); got != highRisk[action] {
			t.Errorf("action %q highRisk=%v want=%v", action, got, highRisk[action])
		}
	}
	for _, unsupported := range []Action{ActionIdentityAccessRequest, ActionIdentityAccessApprove, ActionRoleManage, ActionEventRegistryManage, "dreamup.admin.export", "event.unknown"} {
		if IsDreamUPDelegatedAdministratorAction(unsupported) || IsDreamUPHighRiskDelegatedAdministratorAction(unsupported) {
			t.Errorf("unsupported action %q entered delegation contract", unsupported)
		}
	}
}

type roleManagementAuthorizerStub struct {
	action   Action
	resource Resource
	decision Decision
}

func (s *roleManagementAuthorizerStub) Check(_ context.Context, _ identity.UserID, action Action, resource Resource) (Decision, error) {
	s.action, s.resource = action, resource
	return s.decision, nil
}

func TestScopedRoleManagementGateUsesExactEventAction(t *testing.T) {
	base := &roleManagementAuthorizerStub{}
	gate := NewRoleManagementGate(base)
	base.decision = Decision{Allowed: true, Role: adminroles.RoleSuperAdmin, BindingID: "arb_super", BindingVersion: 2}
	decision, err := gate.CheckRoleManagement(context.Background(), "user_actor", "evt_shanghai")
	if err != nil || !decision.Allowed {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if base.action != ActionRoleManage || base.resource.Kind != "role_binding" || base.resource.ID != "evt_shanghai" || base.resource.EventID != "evt_shanghai" {
		t.Fatalf("action=%s resource=%+v", base.action, base.resource)
	}
	if decision.BindingID != "arb_super" || decision.BindingVersion != 2 || decision.Scope.Kind != adminroles.ScopeSystem {
		t.Fatalf("role management evidence=%+v", decision)
	}
}

func TestScopedGlobalPrincipalRolesOnlyAddActiveSystemSuper(t *testing.T) {
	base := []string{"authenticated", "employee"}
	if got := GlobalPrincipalRoles(base, false); containsRole(got, string(adminroles.RoleSuperAdmin)) {
		t.Fatalf("event/non-super context leaked global super role: %v", got)
	}
	got := GlobalPrincipalRoles(base, true)
	if !containsRole(got, string(adminroles.RoleSuperAdmin)) {
		t.Fatalf("active system super missing: %v", got)
	}
	got[0] = "mutated"
	if base[0] != "authenticated" {
		t.Fatal("helper mutated caller-owned roles")
	}
}

func containsRole(roles []string, want string) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}
