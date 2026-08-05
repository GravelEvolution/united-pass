// Reauthentication challenge and grant records for high-risk operations
// (ADR-0004 §7). Like MFA challenges, raw tokens are never stored — only
// their SHA-256 hashes are used as Redis keys. Challenges and grants are
// short-lived (5 minutes by default); challenges carry an attempt budget and
// grants are strictly single-use, bound to user + session + action + target
// resource. Redis loss only invalidates them (fail closed).
package auth

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// Reauthentication actions recognized by the management plane. The grant is
// bound to exactly one action and can never be replayed for another.
const (
	ReauthActionApplicationDelete  = "application.delete"
	ReauthActionClientDelete       = "client.delete"
	ReauthActionClientSecretRotate = "client.secret.rotate"
)

// ReauthChallengeData is the reauthentication challenge record stored in
// Redis while a second factor is pending. It binds the in-progress
// verification to the user, the browser session, the declared action and the
// target resource, so a challenge can never complete for a different context
// than the one that requested it.
type ReauthChallengeData struct {
	// UserID is the stable United Pass user ID of the session user.
	UserID identity.UserID `json:"userId"`
	// SessionID is the United Pass session the challenge is bound to. A
	// challenge issued for one session can never be completed from another.
	SessionID string `json:"sessionId"`
	// Action is the high-risk action the eventual grant will authorize.
	Action string `json:"action"`
	// ApplicationID is the target application the grant is bound to.
	ApplicationID string `json:"applicationId"`
	// ClientID is the target client the grant is bound to (client actions).
	ClientID string `json:"clientId,omitempty"`
	// ProviderSessionID references the provider-side authentication session
	// that must be completed with the second factor. It is server-side only
	// and never exposed to the browser.
	ProviderSessionID string `json:"providerSessionId,omitempty"`
	// AvailableMethods lists the MFA methods the user may use.
	AvailableMethods []MFAMethod `json:"availableMethods"`
	// PasskeyRequestOptions carries the WebAuthn PublicKeyCredentialRequestOptions
	// (JSON object) when passkey is among the available methods.
	PasskeyRequestOptions json.RawMessage `json:"passkeyRequestOptions,omitempty"`
	// Attempts is the initial attempt count (always 0 at creation).
	Attempts int `json:"attempts"`
	// CreatedAt is when the challenge was issued.
	CreatedAt time.Time `json:"createdAt"`
}

// ReauthGrantData is the single-use reauthentication grant stored in Redis.
// The target operation consumes it atomically before executing; any binding
// mismatch or reuse fails closed.
type ReauthGrantData struct {
	// UserID is the stable United Pass user ID that reauthenticated.
	UserID identity.UserID `json:"userId"`
	// SessionID is the session the grant is bound to; a grant can never be
	// redeemed from a different session.
	SessionID string `json:"sessionId"`
	// Action is the high-risk action the grant authorizes.
	Action string `json:"action"`
	// ApplicationID is the target application the grant is bound to.
	ApplicationID string `json:"applicationId"`
	// ClientID is the target client the grant is bound to (client actions).
	ClientID string `json:"clientId,omitempty"`
	// CreatedAt is when the grant was issued.
	CreatedAt time.Time `json:"createdAt"`
}

// ErrReauthChallengeNotFound is returned when a reauthentication challenge
// token hash has no record: expired, already consumed, or never created.
var ErrReauthChallengeNotFound = errors.New("reauth challenge not found")

// ErrReauthChallengeClaimed is returned when a claim is attempted on a
// challenge whose lock is already held by another verification request.
var ErrReauthChallengeClaimed = errors.New("reauth challenge already claimed")

// ErrReauthChallengeNotHeld is returned when an operation references a claim
// ID that does not hold the challenge's lock.
var ErrReauthChallengeNotHeld = errors.New("reauth challenge claim not held")

// ErrReauthMaxAttemptsExceeded is returned when the challenge has been
// attempted more than the configured maximum.
var ErrReauthMaxAttemptsExceeded = errors.New("reauth max attempts exceeded")

// ErrReauthGrantNotFound is returned when a grant token hash has no record:
// expired, already consumed, or never created. A consumed grant can never be
// reused.
var ErrReauthGrantNotFound = errors.New("reauth grant not found")
