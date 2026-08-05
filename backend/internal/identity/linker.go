package identity

import "context"

// ProviderUserInfo carries the provider-side identity facts used to create
// (or update) the local United Pass user on first login. The Subject is the
// provider's stable user identifier; it becomes the provider_subject of the
// identity link. Passwords and MFA secrets never flow through this type.
type ProviderUserInfo struct {
	// Subject is the provider's stable user ID (e.g. the ZITADEL user ID).
	Subject string
	// DisplayName is the user's display name from the provider.
	DisplayName string
	// Email is the user's primary email address from the provider.
	Email string
	// EmailVerified reports whether the provider verified the email.
	EmailVerified bool
	// Phone is the user's phone number from the provider (E.164).
	Phone string
}

// UserLinker resolves a provider identity to a stable United Pass user,
// creating the user and its identity link on first login. It is the bridge
// between the authentication provider adapter and the local identity store.
type UserLinker interface {
	// GetOrCreateUserByProviderSubject returns the United Pass user bound to
	// the given provider subject, creating it on first login. The same
	// provider subject must always resolve to the same user.
	GetOrCreateUserByProviderSubject(
		ctx context.Context,
		provider string,
		providerTenantID string,
		info ProviderUserInfo,
	) (User, error)

	// GetIdentityLinkByUserID returns the identity link binding a United Pass
	// user to a provider subject. Reauthentication resolves the provider-side
	// user from the stable user ID — never from a caller-supplied identifier
	// (ADR-0004 §7). Returns ErrUserNotFound when no link exists.
	GetIdentityLinkByUserID(
		ctx context.Context,
		provider string,
		providerTenantID string,
		userID UserID,
	) (IdentityLink, error)
}
