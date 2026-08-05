// Package auth also defines MFA challenge types that are shared between the
// Redis adapter (storage) and the HTTP handlers (consumer).
package auth

import (
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// MFAChallengeData is the MFA challenge record stored in Redis. The raw MFA
// token is never stored — only its SHA-256 hash is used as the Redis key.
// The challenge is short-lived (default 5 minutes) and single-use.
type MFAChallengeData struct {
	// UserID is the stable United Pass user ID of the authenticating user.
	UserID identity.UserID `json:"userId"`
	// Provider is the authentication provider name.
	Provider string `json:"provider"`
	// ProviderSessionReference is the provider-side session reference used
	// to resume the authentication flow after MFA completion.
	ProviderSessionReference string `json:"providerSessionReference,omitempty"`
	// AuthenticationMethods records how the user authenticated in the first
	// step (typically just "password").
	AuthenticationMethods []AuthenticationMethod `json:"authenticationMethods"`
	// AvailableMethods lists the MFA methods the user may use.
	AvailableMethods []MFAMethod `json:"availableMethods"`
	// Attempts is the initial attempt count (always 0 at creation).
	Attempts int `json:"attempts"`
	// CreatedAt is when the challenge was issued.
	CreatedAt time.Time `json:"createdAt"`
}

// ErrMFAChallengeNotFound is returned when an MFA challenge token hash has no
// record. This may mean the challenge expired, was already consumed, or was
// never created.
var ErrMFAChallengeNotFound = errors.New("mfa challenge not found")

// ErrMFAMaxAttemptsExceeded is returned when the MFA challenge has been
// attempted more than the configured maximum.
var ErrMFAMaxAttemptsExceeded = errors.New("mfa max attempts exceeded")
