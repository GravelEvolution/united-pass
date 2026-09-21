package adminbootstrap

import (
	"context"
	"errors"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

var (
	ErrIdentityMismatch = errors.New("adminbootstrap: immutable identity mismatch")
	ErrBootstrapDrift   = errors.New("adminbootstrap: existing state drift")
	ErrInvalidApproval  = errors.New("adminbootstrap: invalid operator approval")
	ErrApprovalReplay   = errors.New("adminbootstrap: operator approval replay")
)

type LocalIdentity struct {
	UserID           identity.UserID
	Status           identity.UserStatus
	Provider         string
	ProviderTenantID string
	ProviderSubject  string
}

type ProviderIdentity struct {
	Subject   string
	LoginName string
	Enabled   bool
}

type LocalIdentityReadback interface {
	ReadExact(context.Context, identity.UserID, string, string, string) (LocalIdentity, error)
}

type ProviderIdentityReadback interface {
	ReadExact(context.Context, string, string) (ProviderIdentity, error)
}
