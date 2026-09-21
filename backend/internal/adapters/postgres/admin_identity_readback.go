package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/adminbootstrap"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type AdminLocalIdentityReadback struct{ users *UserRepository }

func NewAdminLocalIdentityReadback(pool *pgxpool.Pool) *AdminLocalIdentityReadback {
	return &AdminLocalIdentityReadback{users: NewUserRepository(pool)}
}

func (r *AdminLocalIdentityReadback) ReadExact(ctx context.Context, userID identity.UserID, provider, tenant, subject string) (adminbootstrap.LocalIdentity, error) {
	if r == nil || r.users == nil {
		return adminbootstrap.LocalIdentity{}, adminbootstrap.ErrIdentityMismatch
	}
	user, err := r.users.GetByID(ctx, userID)
	if err != nil {
		return adminbootstrap.LocalIdentity{}, adminbootstrap.ErrIdentityMismatch
	}
	link, err := r.users.GetIdentityLink(ctx, provider, tenant, subject)
	if err != nil || link.UserID != userID {
		return adminbootstrap.LocalIdentity{}, adminbootstrap.ErrIdentityMismatch
	}
	byUser, err := r.users.GetIdentityLinkByUserID(ctx, provider, tenant, userID)
	if err != nil || byUser.ID != link.ID || byUser.ProviderSubject != subject {
		return adminbootstrap.LocalIdentity{}, adminbootstrap.ErrIdentityMismatch
	}
	return adminbootstrap.LocalIdentity{UserID: user.ID, Status: user.Status, Provider: link.Provider, ProviderTenantID: link.ProviderTenantID, ProviderSubject: link.ProviderSubject}, nil
}

var _ adminbootstrap.LocalIdentityReadback = (*AdminLocalIdentityReadback)(nil)
