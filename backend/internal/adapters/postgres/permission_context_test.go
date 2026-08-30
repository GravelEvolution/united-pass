package postgres

import (
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestPermissionContextNeverFlattensSystemSuperForDisabledOrOffboardingUser(t *testing.T) {
	tests := []struct {
		name           string
		accountStatus  string
		employeeStatus string
		wantSuper      bool
	}{
		{name: "active", accountStatus: string(identity.UserStatusActive), employeeStatus: "active", wantSuper: true},
		{name: "disabled", accountStatus: "disabled", employeeStatus: "active", wantSuper: false},
		{name: "offboarding", accountStatus: string(identity.UserStatusActive), employeeStatus: "offboarding", wantSuper: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			roles := permissionContextRoles([]string{"employee"}, test.accountStatus, test.employeeStatus, true)
			systemRole := permissionContextSystemRole(test.accountStatus, test.employeeStatus, true)
			gotSuper := false
			for _, role := range roles {
				gotSuper = gotSuper || role == string(adminroles.RoleSuperAdmin)
			}
			if gotSuper != test.wantSuper {
				t.Fatalf("roles=%v wantSuper=%v", roles, test.wantSuper)
			}
			if (systemRole == string(adminroles.RoleSuperAdmin)) != test.wantSuper {
				t.Fatalf("systemRole=%q wantSuper=%v", systemRole, test.wantSuper)
			}
		})
	}
}
