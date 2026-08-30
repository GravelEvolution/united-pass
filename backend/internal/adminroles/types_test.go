package adminroles_test

import (
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
)

func TestRoleScopeValidation(t *testing.T) {
	tests := []struct {
		name  string
		role  adminroles.Role
		scope adminroles.Scope
		ok    bool
	}{
		{"system super", adminroles.RoleSuperAdmin, adminroles.Scope{Kind: adminroles.ScopeSystem}, true},
		{"event senior", adminroles.RoleSeniorAdmin, adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_shanghai"}, true},
		{"event admin", adminroles.RoleAdmin, adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_shanghai"}, true},
		{"event super rejected", adminroles.RoleSuperAdmin, adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_shanghai"}, false},
		{"system admin rejected", adminroles.RoleAdmin, adminroles.Scope{Kind: adminroles.ScopeSystem}, false},
		{"system event id rejected", adminroles.RoleSuperAdmin, adminroles.Scope{Kind: adminroles.ScopeSystem, EventID: "evt_shanghai"}, false},
		{"empty event rejected", adminroles.RoleAdmin, adminroles.Scope{Kind: adminroles.ScopeEvent}, false},
		{"unknown role rejected", adminroles.Role("owner"), adminroles.Scope{Kind: adminroles.ScopeSystem}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := adminroles.ValidateRoleScope(tt.role, tt.scope); (got == nil) != tt.ok {
				t.Fatalf("role=%s scope=%+v err=%v", tt.role, tt.scope, got)
			}
		})
	}
}

func TestEventRoleListRequiresMatchingEventScope(t *testing.T) {
	valid := adminpagination.Query{ScopeKind: "event", EventID: "evt_a", ListKind: adminroles.ListKindEventBindings}
	if err := adminroles.ValidateEventListQuery("evt_a", valid); err != nil {
		t.Fatalf("valid event list rejected: %v", err)
	}
	for _, query := range []adminpagination.Query{
		{ScopeKind: "event", EventID: "evt_b", ListKind: adminroles.ListKindEventBindings},
		{ScopeKind: "system", EventID: "evt_a", ListKind: adminroles.ListKindEventBindings},
		{ScopeKind: "event", EventID: "evt_a", ListKind: "applications"},
	} {
		if err := adminroles.ValidateEventListQuery("evt_a", query); err == nil {
			t.Fatalf("mismatched event query accepted: %+v", query)
		}
	}
}

func TestUserRoleListHasDistinctSystemCursorContext(t *testing.T) {
	valid := adminpagination.Query{ScopeKind: "system", ListKind: adminroles.ListKindUserBindings}
	if err := adminroles.ValidateUserListQuery(valid); err != nil {
		t.Fatalf("valid user list rejected: %v", err)
	}
	for _, query := range []adminpagination.Query{
		{ScopeKind: "event", EventID: "evt_a", ListKind: adminroles.ListKindUserBindings},
		{ScopeKind: "system", ListKind: adminroles.ListKindEventBindings},
	} {
		if err := adminroles.ValidateUserListQuery(query); err == nil {
			t.Fatalf("mismatched user-list query accepted: %+v", query)
		}
	}
}

func TestRegistryListRequiresSystemScope(t *testing.T) {
	if err := adminroles.ValidateRegistryListQuery(adminpagination.Query{ScopeKind: "system", ListKind: "event_registry"}); err != nil {
		t.Fatalf("system registry query rejected: %v", err)
	}
	if err := adminroles.ValidateRegistryListQuery(adminpagination.Query{ScopeKind: "event", EventID: "evt_a", ListKind: "event_registry"}); err == nil {
		t.Fatal("event-scoped registry list accepted")
	}
}

func TestScopeKeyUsesFixedSystemSentinel(t *testing.T) {
	tests := []struct {
		scope adminroles.Scope
		want  string
	}{
		{adminroles.Scope{Kind: adminroles.ScopeSystem}, "system"},
		{adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_shanghai"}, "evt_shanghai"},
	}
	for _, tt := range tests {
		got, err := tt.scope.Key()
		if err != nil {
			t.Fatalf("Key(%+v): %v", tt.scope, err)
		}
		if got != tt.want {
			t.Fatalf("Key(%+v)=%q, want %q", tt.scope, got, tt.want)
		}
	}
}

func TestBindingReplacementKeepsIdentityAndScopeImmutable(t *testing.T) {
	current := adminroles.Binding{ID: "arb_1", UserID: "user_1", Role: adminroles.RoleAdmin, Scope: adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: "evt_a"}, Version: 3, Enabled: true}
	next := current
	next.Role = adminroles.RoleSeniorAdmin
	if err := adminroles.ValidateBindingReplacement(current, next); err != nil {
		t.Fatalf("admin to senior update rejected: %v", err)
	}
	tests := []func(*adminroles.Binding){
		func(b *adminroles.Binding) { b.ID = "arb_2" },
		func(b *adminroles.Binding) { b.UserID = "user_2" },
		func(b *adminroles.Binding) { b.Scope.EventID = "evt_b" },
		func(b *adminroles.Binding) { b.Role = adminroles.RoleSuperAdmin },
	}
	for i, edit := range tests {
		candidate := next
		edit(&candidate)
		if err := adminroles.ValidateBindingReplacement(current, candidate); err == nil {
			t.Fatalf("immutable mutation %d accepted", i)
		}
	}
}
