package dreamupadmin

import (
	"context"
	"errors"
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// ReviewIdentityReader is the minimum authority-plane surface needed to turn
// DreamUP's provider subject back into the stable United Pass user ID.
type ReviewIdentityReader interface {
	GetByID(context.Context, identity.UserID) (identity.User, error)
	GetIdentityLink(context.Context, string, string, string) (identity.IdentityLink, error)
	GetIdentityLinkByUserID(context.Context, string, string, identity.UserID) (identity.IdentityLink, error)
}

// ReviewIdentityResolver performs a bidirectional identity-link check before
// a stable user ID is returned to an authorized DreamUP reviewer.
type ReviewIdentityResolver interface {
	ResolveReviewIdentityUser(context.Context, string) (identity.UserID, error)
}

type reviewIdentityResolver struct {
	reader   ReviewIdentityReader
	provider string
	tenantID string
}

func NewReviewIdentityResolver(reader ReviewIdentityReader, provider, tenantID string) (ReviewIdentityResolver, error) {
	if reader == nil || !validPersonalAssetIdentityComponent(provider, 120) || !validPersonalAssetIdentityComponent(tenantID, 255) {
		return nil, ErrInvalidRequest
	}
	return &reviewIdentityResolver{reader: reader, provider: provider, tenantID: tenantID}, nil
}

func (r *reviewIdentityResolver) ResolveReviewIdentityUser(ctx context.Context, providerSubject string) (identity.UserID, error) {
	if r == nil || r.reader == nil || !validPersonalAssetIdentityComponent(providerSubject, 255) {
		return "", ErrInvalidRequest
	}
	link, err := r.reader.GetIdentityLink(ctx, r.provider, r.tenantID, providerSubject)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) || errors.Is(err, identity.ErrIdentityLinkConflict) {
			return "", ErrInvalidRequest
		}
		return "", fmt.Errorf("dreamupadmin: resolve review provider subject: %w", err)
	}
	if !personalAssetOwnerUserIDPattern.MatchString(string(link.UserID)) || link.Provider != r.provider ||
		link.ProviderTenantID != r.tenantID || link.ProviderSubject != providerSubject {
		return "", ErrInvalidRequest
	}
	user, err := r.reader.GetByID(ctx, link.UserID)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return "", ErrInvalidRequest
		}
		return "", fmt.Errorf("dreamupadmin: read review identity user: %w", err)
	}
	// Account status controls authentication, not the historical identity of a
	// submitted application. Preserve the stable UID for pending and disabled
	// accounts while still rejecting unknown/corrupt status values.
	if user.ID != link.UserID || !user.Status.IsValid() {
		return "", ErrInvalidRequest
	}
	reverse, err := r.reader.GetIdentityLinkByUserID(ctx, r.provider, r.tenantID, link.UserID)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) || errors.Is(err, identity.ErrIdentityLinkConflict) {
			return "", ErrInvalidRequest
		}
		return "", fmt.Errorf("dreamupadmin: reverse-check review identity: %w", err)
	}
	if reverse.ID == "" || reverse.ID != link.ID || reverse.UserID != link.UserID || reverse.Provider != link.Provider ||
		reverse.ProviderTenantID != link.ProviderTenantID || reverse.ProviderSubject != providerSubject {
		return "", ErrInvalidRequest
	}
	return link.UserID, nil
}
