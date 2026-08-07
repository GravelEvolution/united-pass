//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: MFA challenge types shared by the Redis store and the HTTP handlers
//

// Package auth also defines MFA challenge types that are shared between the
// Redis adapter (storage) and the HTTP handlers (consumer).
package auth

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// MFAChallengeData is the MFA challenge record stored in Redis. The raw MFA
// token is never stored — only its SHA-256 hash is used as the Redis key.
// The challenge is short-lived (default 5 minutes) and single-use.
//
// Challenge TTL is authoritative and immutable: claim/release operations use a
// separate short-lived lock key (mfa:claim:{hash}) and never modify the
// challenge's own TTL. This guarantees an expiring challenge cannot be
// extended by a verification attempt.
type MFAChallengeData struct {
	// UserID is the stable United Pass user ID of the authenticating user.
	UserID identity.UserID `json:"userId"`
	// Provider is the authentication provider name.
	Provider string `json:"provider"`
	// ProviderSessionReference is the provider-side session reference used
	// to resume the authentication flow after MFA completion. It is only
	// populated after successful verification (the challenge is consumed
	// at that point), so it is omitted here in practice.
	ProviderSessionReference string `json:"providerSessionReference,omitempty"`
	// AuthenticationMethods records how the user authenticated in the first
	// step (typically just "password").
	AuthenticationMethods []AuthenticationMethod `json:"authenticationMethods"`
	// AvailableMethods lists the MFA methods the user may use.
	AvailableMethods []MFAMethod `json:"availableMethods"`
	// ProviderSessionID references the provider-side authentication session
	// that must be completed with the second factor. It is populated only
	// after the password step and consumed together with the challenge; the
	// provider session token is never persisted.
	ProviderSessionID string `json:"providerSessionId,omitempty"`
	// PasskeyRequestOptions carries the WebAuthn PublicKeyCredentialRequestOptions
	// (JSON object) when passkey is among the available methods.
	PasskeyRequestOptions json.RawMessage `json:"passkeyRequestOptions,omitempty"`
	// Attempts is the initial attempt count (always 0 at creation).
	Attempts int `json:"attempts"`
	// CreatedAt is when the challenge was issued.
	CreatedAt time.Time `json:"createdAt"`
}

// ErrMFAChallengeNotFound is returned when an MFA challenge token hash has no
// record. This may mean the challenge expired, was already consumed, or was
// never created.
var ErrMFAChallengeNotFound = errors.New("mfa challenge not found")

// ErrMFAChallengeClaimed is returned when a claim is attempted on a challenge
// whose lock key is already held by another verification request. The
// challenge remains valid until the owner consumes or releases the lock.
var ErrMFAChallengeClaimed = errors.New("mfa challenge already claimed")

// ErrMFAChallengeNotHeld is returned when an operation (release or consume)
// references a claim ID that does not hold the challenge's lock. This can
// happen when the lock expired or was taken over after a timeout.
var ErrMFAChallengeNotHeld = errors.New("mfa challenge claim not held")

// ErrMFAMaxAttemptsExceeded is returned when the MFA challenge has been
// attempted more than the configured maximum.
var ErrMFAMaxAttemptsExceeded = errors.New("mfa max attempts exceeded")
