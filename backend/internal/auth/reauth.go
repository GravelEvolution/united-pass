//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Re-authentication challenge and grant records for sensitive operations
//

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
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

// Reauthentication actions recognized by the management plane. The grant is
// bound to exactly one action and can never be replayed for another.
const (
	ReauthActionApplicationDelete  = "application.delete"
	ReauthActionClientDelete       = "client.delete"
	ReauthActionClientSecretRotate = "client.secret.rotate"

	// Account security-factor actions (ADR-0006 §4). Account actions bind
	// user + session + action only; ApplicationID/ClientID must stay empty.
	ReauthActionPasswordChange = "account.password.change"
	ReauthActionTOTPEnroll     = "account.totp.enroll"
	ReauthActionTOTPRemove     = "account.totp.remove"
	ReauthActionPasskeyEnroll  = "account.passkey.enroll"
	ReauthActionPasskeyRemove  = "account.passkey.remove"

	// Phase 5 management actions bind the grant to the exact stable target
	// user ID through Target. They never carry application/client IDs.
	ReauthActionUserDisable        = "user.disable"
	ReauthActionUserSessionsRevoke = "user.sessions.revoke"
	ReauthActionEmployeeOffboard   = "employee.offboard"
)

// ReauthActionSessionsRevokeOthers is reserved but never accepted: session
// revocation needs no step-up (ADR-0006 §2/§4), so the reauth endpoint must
// refuse to mint a grant for it and no code path may consume it.
const ReauthActionSessionsRevokeOthers = "account.sessions.revoke_others"

// IsAccountReauthAction reports whether the action targets the caller's own
// account security factors (ADR-0006 §4) rather than an OAuth application or
// client. Account actions forbid application/client bindings and use the
// generic Target field instead.
func IsAccountReauthAction(action string) bool {
	switch action {
	case ReauthActionPasswordChange,
		ReauthActionTOTPEnroll,
		ReauthActionTOTPRemove,
		ReauthActionPasskeyEnroll,
		ReauthActionPasskeyRemove:
		return true
	default:
		return false
	}
}

// IsTargetReauthAction reports whether the action is a Phase 5 management
// mutation bound to a stable target user ID.
func IsTargetReauthAction(action string) bool {
	switch action {
	case ReauthActionUserDisable,
		ReauthActionUserSessionsRevoke,
		ReauthActionEmployeeOffboard:
		return true
	default:
		return false
	}
}

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
	// Target is the generic action-specific binding. It is the passkeyId for
	// account.passkey.remove and the stable target userId for Phase 5
	// user/employee management actions.
	Target string `json:"target,omitempty"`
	// Attempts is the initial attempt count (always 0 at creation).
	Attempts int `json:"attempts"`
	// CreatedAt is when the challenge was issued.
	CreatedAt time.Time `json:"createdAt"`
	// SecurityEpoch stamps the challenge with the issuing session's
	// security generation (ADR-0007 Decision 1). Legacy records decode
	// as 0 and are normalized to 1 at the adapter decode boundary (F2).
	SecurityEpoch securitystate.Epoch `json:"securityEpoch,omitempty"`
}

// ExpiredReauthChallenge identifies an abandoned or expired reauthentication
// challenge whose temporary provider session must still be revoked. The full
// challenge record may already be gone from Redis (TTL expiry or user
// abandonment), so the cleanup index carries only the fields needed to revoke
// the provider session and attribute a failure audit event.
type ExpiredReauthChallenge struct {
	// TokenHash is the SHA-256 hex hash of the challenge token.
	TokenHash string `json:"tokenHash"`
	// ProviderSessionID references the temporary provider session to revoke.
	// It may be empty when the provider never reported one.
	ProviderSessionID string `json:"providerSessionId,omitempty"`
	// UserID is the session user the challenge was issued to.
	UserID identity.UserID `json:"userId"`
	// ApplicationID is the target application the challenge was bound to.
	ApplicationID string `json:"applicationId"`
	// ClientID is the target client the challenge was bound to (client actions).
	ClientID string `json:"clientId,omitempty"`
	// Action is the high-risk action the challenge declared.
	Action string `json:"action"`
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
	// Target is the generic action-specific binding. A grant minted for one
	// passkey or one managed user can never mutate another target.
	Target string `json:"target,omitempty"`
	// CreatedAt is when the grant was issued.
	CreatedAt time.Time `json:"createdAt"`
	// SecurityEpoch stamps the grant with the issuing session's security
	// generation (ADR-0007 Decision 1). Consumption must additionally
	// verify the user's authoritative state against this stamp. Legacy
	// records decode as 0 and are normalized to 1 (F2).
	SecurityEpoch securitystate.Epoch `json:"securityEpoch,omitempty"`
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
