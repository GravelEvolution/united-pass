//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Security factor management port contracts (TOTP and passkeys)
//

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// Sentinel errors returned by FactorManager implementations. The HTTP layer
// maps them to stable response codes (ADR-0006 §7/§8): every failure is fail
// closed and never leaks provider detail.
var (
	// ErrFactorAlreadySet means the factor (or a pending enrollment) already
	// exists on the provider side. Maps to a stable 409.
	ErrFactorAlreadySet = errors.New("auth: factor already set up")
	// ErrFactorNotSet means the factor or passkey does not exist on the
	// provider side. Maps to the stable non-enumeration 404.
	ErrFactorNotSet = errors.New("auth: factor not set up")
	// ErrInvalidFactorCode means the provider rejected the confirmation
	// input: a wrong TOTP code or an invalid WebAuthn attestation. Maps to
	// 400.
	ErrInvalidFactorCode = errors.New("auth: invalid factor confirmation")
	// ErrProviderUnavailable means the provider could not be reached or the
	// service account lacks permission (provider.forbidden, §10). Maps to
	// 502. No local side effects may have occurred.
	ErrProviderUnavailable = errors.New("auth: factor provider unavailable")
)

// PasskeyState is the lifecycle state of a registered passkey as reported by
// the provider.
type PasskeyState string

const (
	// PasskeyStateActive means the passkey is verified and usable.
	PasskeyStateActive PasskeyState = "active"
	// PasskeyStatePending means the registration was begun but never
	// confirmed (the provider may still list it).
	PasskeyStatePending PasskeyState = "pending"
)

// PasskeyInfo describes one registered passkey for the factor summary.
// CreatedAt is nil when the provider does not report a per-key creation
// time; the HTTP layer renders it as null.
type PasskeyInfo struct {
	ID        string
	Name      string
	State     PasskeyState
	CreatedAt *time.Time
}

// TOTPEnrollment carries the provider-issued TOTP secret material returned
// by the enrollment begin step. SECURITY: both fields are secret-bearing
// (the otpauth URI embeds the secret); they appear only in the begin
// response, are never logged, audited or persisted locally, and are never
// returned again (ADR-0006 §7).
type TOTPEnrollment struct {
	Secret     string
	OTPAuthURI string
}

// PasskeyEnrollment carries the provider-issued passkey registration
// challenge returned by the enrollment begin step. CreationOptions is the
// WebAuthn PublicKeyCredentialCreationOptions as a JSON object, passed
// through verbatim to navigator.credentials.create (ADR-0006 §8).
type PasskeyEnrollment struct {
	PasskeyID       string
	CreationOptions json.RawMessage
}

// FactorSummary is the provider-derived account factor state served by
// GET /api/v1/me/security (ADR-0006 §8). Recovery codes are intentionally
// absent: they are deferred by architecture (§9) and rendered by the HTTP
// layer as a fixed available=false payload.
type FactorSummary struct {
	PasswordSet bool
	TOTPEnabled bool
	Passkeys    []PasskeyInfo
}

// FactorManager abstracts the security factor lifecycle of the
// authentication provider. All methods take the stable United Pass user ID;
// implementations resolve the provider-side user from the identity link and
// never accept a caller-supplied provider identifier. Implementations must
// not leak provider SDK types through this interface and must return only
// the sentinel errors above (plus unexpected internal errors).
type FactorManager interface {
	// BeginTOTPEnrollment registers a pending TOTP factor on the provider
	// and returns the secret material for the enroll UI. Already set up ⇒
	// ErrFactorAlreadySet.
	BeginTOTPEnrollment(ctx context.Context, userID identity.UserID) (TOTPEnrollment, error)
	// ConfirmTOTPEnrollment verifies a TOTP code against the pending
	// enrollment, activating the factor. Wrong code ⇒ ErrInvalidFactorCode;
	// no pending enrollment ⇒ ErrFactorNotSet.
	ConfirmTOTPEnrollment(ctx context.Context, userID identity.UserID, code string) error
	// RemoveTOTP removes the TOTP factor. Not enrolled ⇒ ErrFactorNotSet.
	RemoveTOTP(ctx context.Context, userID identity.UserID) error

	// BeginPasskeyEnrollment starts a passkey registration on the provider
	// and returns the WebAuthn creation options for the browser ceremony.
	BeginPasskeyEnrollment(ctx context.Context, userID identity.UserID) (PasskeyEnrollment, error)
	// ConfirmPasskeyEnrollment verifies the browser attestation for the
	// pending registration identified by passkeyID. Invalid attestation ⇒
	// ErrInvalidFactorCode; unknown passkeyID ⇒ ErrFactorNotSet.
	ConfirmPasskeyEnrollment(ctx context.Context, userID identity.UserID, passkeyID, name string, publicKeyCredential json.RawMessage) error
	// RemovePasskey deletes one registered passkey. Unknown passkeyID ⇒
	// ErrFactorNotSet (stable 404, non-enumeration).
	RemovePasskey(ctx context.Context, userID identity.UserID, passkeyID string) error

	// ListPasskeys returns the user's registered passkeys from the provider
	// (readback only; never inferred from local state).
	ListPasskeys(ctx context.Context, userID identity.UserID) ([]PasskeyInfo, error)
	// FactorSummary returns the combined factor state for GET /me/security.
	FactorSummary(ctx context.Context, userID identity.UserID) (FactorSummary, error)
}
