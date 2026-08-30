// Package adminroles defines event-scoped administrative role contracts.
package adminroles

import (
	"errors"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type Role string

const (
	RoleSuperAdmin  Role = "super_admin"
	RoleTopAdmin    Role = "top_admin"
	RoleSeniorAdmin Role = "senior_admin"
	RoleAdmin       Role = "admin"
)

type ScopeKind string

const (
	ScopeSystem ScopeKind = "system"
	ScopeEvent  ScopeKind = "event"
)

var (
	ErrInvalidRoleScope       = errors.New("adminroles: invalid role scope")
	ErrBindingNotFound        = errors.New("adminroles: binding not found")
	ErrBindingConflict        = errors.New("adminroles: binding conflict")
	ErrEventRegistryNotFound  = errors.New("adminroles: event registry row not found")
	ErrEventRegistryDisabled  = errors.New("adminroles: event registry row disabled")
	ErrEventRegistryConflict  = errors.New("adminroles: event registry conflict")
	ErrInvalidRegisteredEvent = errors.New("adminroles: invalid registered event")
)

type Scope struct {
	Kind    ScopeKind
	EventID string
}

func (s Scope) Key() (string, error) {
	switch s.Kind {
	case ScopeSystem:
		if s.EventID != "" {
			return "", ErrInvalidRoleScope
		}
		return "system", nil
	case ScopeEvent:
		if strings.TrimSpace(s.EventID) == "" {
			return "", ErrInvalidRoleScope
		}
		return s.EventID, nil
	default:
		return "", ErrInvalidRoleScope
	}
}

func ValidateRoleScope(role Role, scope Scope) error {
	if _, err := scope.Key(); err != nil {
		return err
	}
	switch role {
	case RoleSuperAdmin, RoleTopAdmin:
		if scope.Kind != ScopeSystem {
			return ErrInvalidRoleScope
		}
	case RoleSeniorAdmin, RoleAdmin:
		if scope.Kind != ScopeEvent {
			return ErrInvalidRoleScope
		}
	default:
		return ErrInvalidRoleScope
	}
	return nil
}

func ValidateBindingReplacement(current, next Binding) error {
	if current.ID == "" || current.ID != next.ID || current.UserID != next.UserID || current.Scope != next.Scope || !current.Enabled || current.DisabledAt != nil {
		return ErrBindingConflict
	}
	if err := ValidateRoleScope(next.Role, next.Scope); err != nil {
		return ErrBindingConflict
	}
	return nil
}

type Binding struct {
	ID         string
	UserID     identity.UserID
	Role       Role
	Scope      Scope
	Enabled    bool
	Version    int64
	GrantedBy  identity.UserID
	ReasonID   string
	DisabledAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type MutationAudit struct {
	ActorID   identity.UserID
	ReasonID  string
	RequestID string
	Action    string
}

type RegisteredEvent struct {
	EventID             string
	Series              string
	Slug                string
	DisplayName         string
	SourceVersion       string
	AuthoritativeReadAt time.Time
	Enabled             bool
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
