package dreamupadmin

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

var personalAssetOwnerUserIDPattern = regexp.MustCompile(`^user_[A-Za-z0-9._:-]{1,123}$`)

// PersonalAssetIdentityReader is the minimum authority-database surface needed
// to bind a DreamUP personal asset to a canonical provider identity.
type PersonalAssetIdentityReader interface {
	GetByID(context.Context, identity.UserID) (identity.User, error)
	GetIdentityLinkByUserID(context.Context, string, string, identity.UserID) (identity.IdentityLink, error)
}

// PersonalAssetOwnerIdentity contains both sides of the verified identity
// binding. UserID remains the stable United Pass identifier used by the admin
// UI; ProviderSubject is the only subject DreamUP may use for participant
// ownership checks.
type PersonalAssetOwnerIdentity struct {
	UserID          identity.UserID
	ProviderSubject string
}

// PersonalAssetOwnerResolver resolves a caller-supplied stable United Pass
// user ID to the configured provider/tenant subject. Implementations must fail
// closed for inactive users and missing or ambiguous links.
type PersonalAssetOwnerResolver interface {
	ResolvePersonalAssetOwner(context.Context, string) (PersonalAssetOwnerIdentity, error)
}

type personalAssetOwnerResolver struct {
	reader   PersonalAssetIdentityReader
	provider string
	tenantID string
}

func NewPersonalAssetOwnerResolver(reader PersonalAssetIdentityReader, provider, tenantID string) (PersonalAssetOwnerResolver, error) {
	if reader == nil || !validPersonalAssetIdentityComponent(provider, 120) || !validPersonalAssetIdentityComponent(tenantID, 255) {
		return nil, ErrInvalidRequest
	}
	return &personalAssetOwnerResolver{reader: reader, provider: provider, tenantID: tenantID}, nil
}

func (r *personalAssetOwnerResolver) ResolvePersonalAssetOwner(ctx context.Context, rawUserID string) (PersonalAssetOwnerIdentity, error) {
	if r == nil || r.reader == nil || !personalAssetOwnerUserIDPattern.MatchString(rawUserID) {
		return PersonalAssetOwnerIdentity{}, ErrInvalidRequest
	}
	userID := identity.UserID(rawUserID)
	user, err := r.reader.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return PersonalAssetOwnerIdentity{}, ErrInvalidRequest
		}
		return PersonalAssetOwnerIdentity{}, fmt.Errorf("dreamupadmin: read personal asset owner: %w", err)
	}
	if user.ID != userID || user.Status != identity.UserStatusActive {
		return PersonalAssetOwnerIdentity{}, ErrInvalidRequest
	}
	link, err := r.reader.GetIdentityLinkByUserID(ctx, r.provider, r.tenantID, userID)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) || errors.Is(err, identity.ErrIdentityLinkConflict) {
			return PersonalAssetOwnerIdentity{}, ErrInvalidRequest
		}
		return PersonalAssetOwnerIdentity{}, fmt.Errorf("dreamupadmin: read personal asset owner identity link: %w", err)
	}
	if link.UserID != userID || link.Provider != r.provider || link.ProviderTenantID != r.tenantID ||
		!validPersonalAssetIdentityComponent(link.ProviderSubject, 255) {
		return PersonalAssetOwnerIdentity{}, ErrInvalidRequest
	}
	return PersonalAssetOwnerIdentity{UserID: userID, ProviderSubject: link.ProviderSubject}, nil
}

func validPersonalAssetIdentityComponent(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
