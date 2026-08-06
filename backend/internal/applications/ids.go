// Package applications defines the Phase 2 domain model for the OAuth
// application and client management plane. It is infrastructure-free: no
// HTTP, SQL, Redis or provider SDK dependencies. See docs/adr-0004.md.
package applications

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Typed identifiers keep local United Pass IDs, provider IDs and secret
// metadata IDs distinct at compile time. Provider identifiers are never
// United Pass identities (ADR-0004 §1).

// ApplicationID is a stable United Pass application identifier ("app_…").
type ApplicationID string

// OAuthClientID is a stable United Pass OAuth client identifier ("clt_…").
type OAuthClientID string

// ClientSecretID identifies secret metadata ("sec_…"). The raw secret value
// is never stored or represented anywhere in this package.
type ClientSecretID string

// ProviderOperationID identifies a recorded provider provisioning operation.
type ProviderOperationID string

// SecurityEventID identifies a durable audit event ("evt_…").
type SecurityEventID string

const (
	applicationIDPrefix       = "app_"
	oauthClientIDPrefix       = "clt_"
	clientSecretIDPrefix      = "sec_"
	providerOperationIDPrefix = "op_"
	securityEventIDPrefix     = "evt_"
	idRandomByteLength        = 16 // 128 bits of entropy, matches P1 user IDs
)

// NewApplicationID generates a fresh application ID.
func NewApplicationID() ApplicationID {
	return ApplicationID(applicationIDPrefix + randomHex(idRandomByteLength))
}

// NewOAuthClientID generates a fresh OAuth client ID.
func NewOAuthClientID() OAuthClientID {
	return OAuthClientID(oauthClientIDPrefix + randomHex(idRandomByteLength))
}

// NewClientSecretID generates a fresh secret metadata ID.
func NewClientSecretID() ClientSecretID {
	return ClientSecretID(clientSecretIDPrefix + randomHex(idRandomByteLength))
}

// NewProviderOperationID generates a fresh provider operation ID.
func NewProviderOperationID() ProviderOperationID {
	return ProviderOperationID(providerOperationIDPrefix + randomHex(idRandomByteLength))
}

// NewSecurityEventID generates a fresh audit event ID.
func NewSecurityEventID() SecurityEventID {
	return SecurityEventID(securityEventIDPrefix + randomHex(idRandomByteLength))
}

// HasApplicationIDPrefix reports whether s looks like a United Pass
// application ID. Used to fail closed on malformed path parameters.
func HasApplicationIDPrefix(s string) bool {
	return len(s) > len(applicationIDPrefix) && s[:len(applicationIDPrefix)] == applicationIDPrefix
}

// HasOAuthClientIDPrefix reports whether s looks like a United Pass client ID.
func HasOAuthClientIDPrefix(s string) bool {
	return len(s) > len(oauthClientIDPrefix) && s[:len(oauthClientIDPrefix)] == oauthClientIDPrefix
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is fatal for identity generation.
		panic(fmt.Sprintf("applications: generate random id: %v", err))
	}
	return hex.EncodeToString(buf)
}

// ProviderDisplayName builds the provider-side display name for a client:
// "{applicationName} · {clientName} · {shortClientId}". Local client names
// are only unique within one application, but every United Pass client
// shares a single provider project, so the provider identity must embed the
// globally unique client ID suffix. The deterministic suffix is what makes
// idempotent recovery possible after an ambiguous create (ADR-0004 §1).
func ProviderDisplayName(applicationName, clientName string, clientID OAuthClientID) string {
	return applicationName + " · " + clientName + " · " + shortIDSuffix(string(clientID))
}

// shortIDSuffix returns the trailing 8 characters of an ID; the full ID for
// shorter values.
func shortIDSuffix(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[len(id)-8:]
}
