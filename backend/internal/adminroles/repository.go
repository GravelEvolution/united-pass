package adminroles

import (
	"context"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type Repository interface {
	GetForScope(context.Context, identity.UserID, Scope) (Binding, error)
	ListForUser(context.Context, identity.UserID, adminpagination.Query) (adminpagination.Page[Binding], error)
	ListForEvent(context.Context, string, adminpagination.Query) (adminpagination.Page[Binding], error)
	Create(context.Context, Binding, MutationAudit) (Binding, error)
	Update(context.Context, Binding, int64, MutationAudit) (Binding, error)
	Disable(context.Context, string, int64, MutationAudit) (Binding, error)
}

const (
	ListKindUserBindings  = "role_bindings_user"
	ListKindEventBindings = "role_bindings_event"
)

func ValidateUserListQuery(query adminpagination.Query) error {
	if query.ScopeKind != string(ScopeSystem) || query.EventID != "" || query.ListKind != ListKindUserBindings {
		return ErrInvalidRoleScope
	}
	return nil
}

func ValidateEventListQuery(eventID string, query adminpagination.Query) error {
	if eventID == "" || query.ScopeKind != string(ScopeEvent) || query.EventID != eventID || query.ListKind != ListKindEventBindings {
		return ErrInvalidRoleScope
	}
	return nil
}

func ValidateRegistryListQuery(query adminpagination.Query) error {
	if query.ScopeKind != string(ScopeSystem) || query.EventID != "" || query.ListKind != "event_registry" {
		return ErrInvalidRoleScope
	}
	return nil
}
