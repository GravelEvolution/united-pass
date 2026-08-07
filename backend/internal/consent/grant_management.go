package consent

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// ScopeOfflineAccess is the OIDC offline-access scope token. Its presence
// in a grant's consented scope set drives the hasOfflineAccess display
// fact (contract: AuthorizedApplication).
const ScopeOfflineAccess = "offline_access"

// AuthorizedApplication is one row of the current user's authorized
// application list (contract §7, ADR-0005 §6): the grant aggregated per
// OAuth client together with the client/application display facts.
//
// The list only ever contains grants whose client AND parent application
// are live, provisioned and effectively active: soft-deleted or disabled
// records are filtered out instead of being shown as active apps.
// LastUsedAt has no true signal on provider v2.71 and is therefore not
// carried here at all; the HTTP boundary serializes it as null
// (ADR-0005 §6).
type AuthorizedApplication struct {
	GrantID          GrantID
	ApplicationID    applications.ApplicationID
	ApplicationName  string
	ApplicationOwner string
	ClientType       applications.ClientType
	GrantedAt        time.Time
	Scopes           []string
	HasOfflineAccess bool
}

// AuthorizedGrantStore is the narrow grant-store port grant management
// needs: listing the user's active grants and the owner-bound idempotent
// revocation (ADR-0005 §6).
type AuthorizedGrantStore interface {
	// ListActiveGrantsByUser returns the user's active grants with their
	// consented scope sets, newest first.
	ListActiveGrantsByUser(ctx context.Context, userID identity.UserID) ([]Grant, error)

	// RevokeGrant revokes the grant identified by grantID if and only if
	// it belongs to userID. The transition and the canonical audit event
	// commit in one transaction. Revoking an already-revoked grant is a
	// no-op with the same stable outcome (idempotent, ADR-0005 §6).
	// Returns ErrGrantNotFound when no grant with this ID belongs to the
	// user (foreign and unknown grants are indistinguishable).
	RevokeGrant(ctx context.Context, userID identity.UserID, grantID GrantID) error
}

// AuthorizedClientFactsReader maps a local client ID to the client +
// application records for the authorized-application display. It returns
// ErrClientUnknown when no live, provisioned record matches (unknown,
// soft-deleted or not fully provisioned), so callers filter such grants
// out of the list without leaking which condition failed.
type AuthorizedClientFactsReader interface {
	GetAuthorizedClientFacts(ctx context.Context, clientID applications.OAuthClientID) (ConsentClientFacts, error)
}

// GrantManagementService serves the authorized-application listing and
// the owner-bound grant revocation (ADR-0005 §6). Revocation is a purely
// local consent action: it never calls the provider and it never claims
// to invalidate provider-issued tokens (already-issued access tokens run
// to their own expiry; refresh tokens remain usable at the provider
// token endpoint until provider-side expiry). A revoked grant never
// enables consent reuse (§7), so the next authorization request shows
// the consent screen again.
type GrantManagementService struct {
	grants  AuthorizedGrantStore
	clients AuthorizedClientFactsReader
}

// NewGrantManagementService builds the grant management service. All
// dependencies are required. Revocation timestamps are taken by the
// store inside the revoking transaction (NOW()), so the service needs
// no clock of its own.
func NewGrantManagementService(
	grants AuthorizedGrantStore,
	clients AuthorizedClientFactsReader,
) (*GrantManagementService, error) {
	if grants == nil {
		return nil, errors.New("consent: grant management requires a grant store")
	}
	if clients == nil {
		return nil, errors.New("consent: grant management requires a client facts reader")
	}
	return &GrantManagementService{grants: grants, clients: clients}, nil
}

// ListAuthorizedApplications returns the current user's authorized
// applications: active local grants joined with live, effectively active
// client/application display facts. Grants whose client or application
// was soft-deleted, de-provisioned or disabled disappear from the list —
// they must never be presented as normal active apps (ADR-0005 §6; P3.3
// review remainder). The result is deterministic: newest grant first,
// grant ID as the stable tie-breaker.
func (s *GrantManagementService) ListAuthorizedApplications(
	ctx context.Context,
	userID identity.UserID,
) ([]AuthorizedApplication, error) {
	if userID == "" {
		return nil, errors.New("consent: authorized application listing requires a user")
	}
	grants, err := s.grants.ListActiveGrantsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]AuthorizedApplication, 0, len(grants))
	for _, grant := range grants {
		facts, err := s.clients.GetAuthorizedClientFacts(ctx, grant.ClientID)
		if err != nil {
			if errors.Is(err, ErrClientUnknown) {
				// Soft-deleted / unprovisioned client or application: the
				// grant row survives revocation-until, but the list never
				// surfaces it as an active app.
				continue
			}
			return nil, err
		}
		if !applications.EffectiveClientActive(facts.Application.Status, facts.Client.Status) {
			// Disabled client or application: same display rule — no
			// active-app presentation while the kill switch is down.
			continue
		}
		result = append(result, AuthorizedApplication{
			GrantID:          grant.ID,
			ApplicationID:    facts.Application.ID,
			ApplicationName:  facts.Application.Name,
			ApplicationOwner: facts.Application.OwnerName,
			ClientType:       facts.Client.ClientType,
			GrantedAt:        grant.GrantedAt,
			Scopes:           append([]string(nil), grant.Scopes...),
			HasOfflineAccess: containsScope(grant.Scopes, ScopeOfflineAccess),
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if !result[i].GrantedAt.Equal(result[j].GrantedAt) {
			return result[i].GrantedAt.After(result[j].GrantedAt)
		}
		return result[i].GrantID < result[j].GrantID
	})
	return result, nil
}

// RevokeGrant revokes one of the current user's grants (ADR-0005 §6).
// Local consent revocation only: no provider call happens, issued tokens
// are not invalidated by United Pass, and the honest effect is that the
// next authorization request for this client requires fresh consent.
// Idempotent: revoking an already-revoked grant returns the same stable
// success. Foreign or unknown grants fail closed as ErrGrantNotFound.
func (s *GrantManagementService) RevokeGrant(
	ctx context.Context,
	userID identity.UserID,
	grantID GrantID,
) error {
	if userID == "" {
		return errors.New("consent: grant revocation requires a user")
	}
	if !HasGrantIDPrefix(string(grantID)) {
		return ErrGrantNotFound
	}
	return s.grants.RevokeGrant(ctx, userID, grantID)
}

func containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
