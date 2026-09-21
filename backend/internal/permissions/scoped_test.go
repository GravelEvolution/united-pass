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
		{adminroles.RoleAdmin, ActionInspectionPerform, true},
		{adminroles.RoleAdmin, ActionAssetCustodyTransfer, true},
		{adminroles.RoleAdmin, ActionAssetReservationManage, false},
		{adminroles.RoleAdmin, ActionAssetManage, false},
		{adminroles.RoleAdmin, ActionQRPrintSingle, true},
		{adminroles.RoleAdmin, ActionQRPrintBulk, false},
		{adminroles.RoleSeniorAdmin, ActionIdentityAccessRequest, true},
		{adminroles.RoleSeniorAdmin, ActionApplicationApproveAdmission, true},
		{adminroles.RoleSeniorAdmin, ActionContactSubmissionManage, true},
		{adminroles.RoleSeniorAdmin, ActionContentManage, true},
		{adminroles.RoleSeniorAdmin, ActionApplicationDecide, false},
		{adminroles.RoleSeniorAdmin, ActionInspectionReview, true},
		{adminroles.RoleSeniorAdmin, ActionAssetReservationManage, true},
		{adminroles.RoleSeniorAdmin, ActionAssetInventoryAdjust, false},
		{adminroles.RoleSuperAdmin, ActionApplicationDecide, true},
		{adminroles.RoleSuperAdmin, ActionLegalRead, true},
		{adminroles.RoleSuperAdmin, ActionContentManage, true},
		{adminroles.RoleSuperAdmin, ActionOperationReceiptRead, false},
		{adminroles.RoleSuperAdmin, ActionInspectionPointManage, true},
		{adminroles.RoleSuperAdmin, ActionAssetManage, true},
		{adminroles.RoleSuperAdmin, ActionAssetInventoryAdjust, true},
		{adminroles.RoleSuperAdmin, ActionPersonalAssetAssignment, true},
		{adminroles.RoleSuperAdmin, ActionAssetCodeRotate, true},
		{adminroles.RoleSuperAdmin, ActionQRPrintBulk, true},
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
		ActionInspectionPointRead, ActionInspectionPointManage, ActionInspectionPerform, ActionInspectionReview,
		ActionAssetRead, ActionAssetManage, ActionAssetReservationManage, ActionAssetCustodyTransfer,
		ActionAssetInventoryAdjust, ActionPersonalAssetAssignment, ActionAssetCodeRotate,
		ActionQRPrintSingle, ActionQRPrintBulk,
	}
	highRisk := map[Action]bool{
		ActionApplicationReview: true, ActionApplicationApproveAdmission: true, ActionApplicationDecide: true,
		ActionRegistrationManage: true, ActionCheckinScan: true, ActionCheckinManageWindow: true,
		ActionIdentityGrantConsume: true, ActionIdentityReadRestricted: true, ActionLegalRead: true,
		ActionApplicationExport: true, ActionAuditRead: true, ActionContactSubmissionManage: true,
		ActionContentManage: true, ActionRoleMigrationRead: true,
		ActionInspectionPointManage: true, ActionInspectionPerform: true, ActionInspectionReview: true,
		ActionAssetManage: true, ActionAssetReservationManage: true, ActionAssetCustodyTransfer: true,
		ActionAssetInventoryAdjust: true, ActionPersonalAssetAssignment: true, ActionAssetCodeRotate: true,
		ActionQRPrintSingle: true, ActionQRPrintBulk: true,
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

func TestParseDreamUPReauthenticationTarget(t *testing.T) {
	canonical := func(kind, id string) string {
		return `["dreamup-admin-target/v1","evt_shanghai","` + kind + `","` + id + `"]`
	}
	tests := []struct {
		name   string
		action Action
		target string
		kind   string
		id     string
		ok     bool
	}{
		{name: "event content", action: ActionContentManage, target: canonical("event", "evt_shanghai"), kind: "event", id: "evt_shanghai", ok: true},
		{name: "application review", action: ActionApplicationReview, target: canonical("application", "app_1"), kind: "application", id: "app_1", ok: true},
		{name: "bulk print result", action: ActionQRPrintBulk, target: canonical("qr_print_job", "print_1"), kind: "qr_print_job", id: "print_1", ok: true},
		{name: "bulk print event", action: ActionQRPrintBulk, target: canonical("event", "evt_shanghai"), kind: "event", id: "evt_shanghai", ok: true},
		{name: "inspection perform rejects broad event", action: ActionInspectionPerform, target: canonical("event", "evt_shanghai")},
		{name: "wrong resource kind", action: ActionApplicationReview, target: canonical("asset_unit", "unit_1")},
		{name: "wrong event", action: ActionContentManage, target: `["dreamup-admin-target/v1","evt_other","event","evt_other"]`},
		{name: "non canonical JSON", action: ActionContentManage, target: `[ "dreamup-admin-target/v1", "evt_shanghai", "event", "evt_shanghai" ]`},
		{name: "ordinary action", action: ActionDashboardRead, target: canonical("event", "evt_shanghai")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource, ok := ParseDreamUPReauthenticationTarget("evt_shanghai", test.action, test.target)
			if ok != test.ok {
				t.Fatalf("ok=%v want=%v resource=%+v", ok, test.ok, resource)
			}
			if ok && (resource.Kind != test.kind || resource.ID != test.id || resource.EventID != "evt_shanghai") {
				t.Fatalf("resource=%+v", resource)
			}
		})
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
