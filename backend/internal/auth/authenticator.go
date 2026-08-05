// Package auth defines the authentication domain interface and types.
// The Authenticator interface abstracts the authentication provider so that
// domain and HTTP code never depend on a specific provider SDK.
package auth

import (
	"context"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// AuthenticationStatus represents the outcome of an authentication attempt.
type AuthenticationStatus string

const (
	// StatusAuthenticated means the user has fully authenticated.
	StatusAuthenticated AuthenticationStatus = "authenticated"
	// StatusMFARequired means the user must complete an MFA challenge.
	StatusMFARequired AuthenticationStatus = "mfa_required"
	// StatusInvalidCredentials means the credentials were rejected.
	StatusInvalidCredentials AuthenticationStatus = "invalid_credentials"
	// StatusLocked means the account is locked.
	StatusLocked AuthenticationStatus = "locked"
	// StatusExpired means the credentials or challenge have expired.
	StatusExpired AuthenticationStatus = "expired"
	// StatusProviderUnavailable means the authentication provider could not
	// be reached. This is a server-side failure, not a user error.
	StatusProviderUnavailable AuthenticationStatus = "provider_unavailable"
)

// AuthenticationMethod records how the user authenticated.
type AuthenticationMethod string

const (
	MethodPassword AuthenticationMethod = "password"
	MethodTOTP     AuthenticationMethod = "totp"
	MethodPasskey  AuthenticationMethod = "passkey"
	MethodRecovery AuthenticationMethod = "recovery_code"
)

// MFAMethod is a method available for MFA challenge.
type MFAMethod string

const (
	MFAMethodTOTP     MFAMethod = "totp"
	MFAMethodPasskey  MFAMethod = "passkey"
	MFAMethodRecovery MFAMethod = "recovery_code"
)

// PasswordAuthenticationInput carries credentials for the initial
// authentication step. The password is never logged.
type PasswordAuthenticationInput struct {
	Identifier      string
	Password        string
	ResumeRequestID string
}

// MFAChallengeInput carries the MFA token and verification code.
type MFAChallengeInput struct {
	MFAToken string
	Method   MFAMethod
	Code     string
	// PasskeyAssertion is used for WebAuthn-based MFA. It is separate from
	// Code to avoid cramming a WebAuthn assertion into a string field.
	PasskeyAssertion string
}

// AuthenticationResult is the outcome of an authentication attempt. When
// Status is Authenticated, UserID and ProviderSessionReference are set.
// When Status is MFARequired, MFAToken and AvailableMethods are set.
type AuthenticationResult struct {
	Status                   AuthenticationStatus
	UserID                   identity.UserID
	Provider                 string
	ProviderSessionReference string
	AuthenticationMethods    []AuthenticationMethod
	MFAToken                 string
	AvailableMethods         []MFAMethod
}

// Authenticator abstracts the authentication provider. Implementations must
// not leak provider SDK types through this interface.
type Authenticator interface {
	// BeginPasswordAuthentication starts the authentication flow with
	// username/password credentials.
	BeginPasswordAuthentication(
		ctx context.Context,
		input PasswordAuthenticationInput,
	) (AuthenticationResult, error)

	// CompleteMFA completes an MFA challenge using the provided method.
	CompleteMFA(
		ctx context.Context,
		input MFAChallengeInput,
	) (AuthenticationResult, error)

	// RevokeProviderSession revokes the provider-side session. This is a
	// best-effort operation: local session invalidation must not depend on
	// this succeeding.
	RevokeProviderSession(
		ctx context.Context,
		sessionReference string,
	) error
}

// AuthenticationTime returns the current time as the authentication time.
// This is a separate function so tests can control it.
type Clock interface {
	Now() time.Time
}
