//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Enumerated domain values (audience, status, client type, consent mode)
//

package applications

// ApplicationAudience describes who the application serves.
type ApplicationAudience string

const (
	AudienceInternal ApplicationAudience = "internal"
	AudienceExternal ApplicationAudience = "external"
	AudienceHybrid   ApplicationAudience = "hybrid"
)

// IsValid reports whether the audience is a recognized value.
func (a ApplicationAudience) IsValid() bool {
	switch a {
	case AudienceInternal, AudienceExternal, AudienceHybrid:
		return true
	}
	return false
}

// Status is the public lifecycle status shared by applications and clients.
// A resource only ever reports active or disabled; provisioning internals
// are tracked separately by ProvisioningStatus and never exposed.
type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

// IsValid reports whether the status is a recognized value.
func (s Status) IsValid() bool {
	return s == StatusActive || s == StatusDisabled
}

// ProvisioningStatus is the internal cross-store consistency state
// (ADR-0004 §2). Rows that are not Provisioned are hidden from listings
// and never reported as active.
type ProvisioningStatus string

const (
	ProvisioningStatusProvisioning       ProvisioningStatus = "provisioning"
	ProvisioningStatusProvisioned        ProvisioningStatus = "provisioned"
	ProvisioningStatusProvisioningFailed ProvisioningStatus = "provisioning_failed"
	ProvisioningStatusDeleting           ProvisioningStatus = "deleting"
	ProvisioningStatusDeleteFailed       ProvisioningStatus = "delete_failed"
)

// ClientProfile bundles the security-relevant OAuth client configuration.
// The profile is immutable after creation and is the stored authority; the
// frontend profile config is advisory only (ADR-0004 §3).
type ClientProfile string

const (
	ClientProfileWebServer ClientProfile = "web_server"
	ClientProfileSPAMobile ClientProfile = "spa_mobile"
	// ClientProfileServerToServer is kept for forward compatibility and
	// existing records only; creation is rejected by ValidateClientInput
	// because ZITADEL v2.71 serves client_credentials tokens only for
	// machine users, so a provisioned OIDC app could never execute the
	// grant the profile declares.
	ClientProfileServerToServer ClientProfile = "server_to_server"
)

// ClientType describes whether the client can keep a secret.
type ClientType string

const (
	ClientTypePublic       ClientType = "public"
	ClientTypeConfidential ClientType = "confidential"
)

// OAuthGrantType is a registered OAuth grant type.
type OAuthGrantType string

const (
	GrantTypeAuthorizationCode OAuthGrantType = "authorization_code"
	GrantTypeRefreshToken      OAuthGrantType = "refresh_token"
	GrantTypeClientCredentials OAuthGrantType = "client_credentials"
)

// TokenEndpointAuthMethod is the client authentication method at the token
// endpoint. Only values with verified provider support and a reviewed
// security model exist in Phase 2; client_secret_post and private_key_jwt
// are rejected with field errors.
type TokenEndpointAuthMethod string

const (
	TokenAuthClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	TokenAuthNone              TokenEndpointAuthMethod = "none"
)

// ConsentMode controls user consent behavior. For server_to_server clients
// only ConsentModeAlways is accepted and it is recorded as not-applicable
// metadata (ADR-0004 G4).
type ConsentMode string

const (
	ConsentModeAlways             ConsentMode = "always"
	ConsentModeFirstAuthorization ConsentMode = "first_authorization"
)

// ProfileRules is the derived, authoritative configuration for a client
// profile. All validation and provider mapping consume these rules.
type ProfileRules struct {
	ClientType          ClientType
	GrantTypes          []OAuthGrantType
	TokenEndpointAuth   TokenEndpointAuthMethod
	RedirectURIRequired bool
	SupportsSecret      bool
	OpenIDAllowed       bool
	ConsentApplicable   bool
}

// Rules returns the profile's authoritative rules. The boolean result is
// false for unknown profiles; callers must reject unknown profiles with a
// field error rather than fall back to defaults.
func (p ClientProfile) Rules() (ProfileRules, bool) {
	switch p {
	case ClientProfileWebServer:
		return ProfileRules{
			ClientType:          ClientTypeConfidential,
			GrantTypes:          []OAuthGrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken},
			TokenEndpointAuth:   TokenAuthClientSecretBasic,
			RedirectURIRequired: true,
			SupportsSecret:      true,
			OpenIDAllowed:       true,
			ConsentApplicable:   true,
		}, true
	case ClientProfileSPAMobile:
		return ProfileRules{
			ClientType:          ClientTypePublic,
			GrantTypes:          []OAuthGrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken},
			TokenEndpointAuth:   TokenAuthNone,
			RedirectURIRequired: true,
			SupportsSecret:      false,
			OpenIDAllowed:       true,
			ConsentApplicable:   true,
		}, true
	case ClientProfileServerToServer:
		return ProfileRules{
			ClientType:          ClientTypeConfidential,
			GrantTypes:          []OAuthGrantType{GrantTypeClientCredentials},
			TokenEndpointAuth:   TokenAuthClientSecretBasic,
			RedirectURIRequired: false,
			SupportsSecret:      true,
			OpenIDAllowed:       false,
			ConsentApplicable:   false,
		}, true
	}
	return ProfileRules{}, false
}

// IsValid reports whether the profile is recognized.
func (p ClientProfile) IsValid() bool {
	_, ok := p.Rules()
	return ok
}

// HasGrantType reports whether rules include the given grant type.
func (r ProfileRules) HasGrantType(g OAuthGrantType) bool {
	for _, gt := range r.GrantTypes {
		if gt == g {
			return true
		}
	}
	return false
}
