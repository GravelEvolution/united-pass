//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Server-side session domain types and opaque token generation
//

// Package session defines the server-side session domain types and token
// generation utilities. Session tokens are opaque, cryptographically random
// values stored in a Cookie. Only the SHA-256 hash of the token reaches Redis.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// SessionID is an internal identifier for a session record.
type SessionID string

// TokenBytes is the number of random bytes in a session token (256 bits).
const TokenBytes = 32

// CSRFTokenBytes is the number of random bytes in a CSRF token (256 bits).
const CSRFTokenBytes = 32

// MFATokenBytes is the number of random bytes in an MFA challenge token.
const MFATokenBytes = 32

// SessionRecord is the full session record stored in Redis. It is JSON-encoded
// with a TTL. The raw session token and CSRF token are never stored here —
// only their hashes.
type SessionRecord struct {
	Version                  int             `json:"version"`
	SessionID                SessionID       `json:"sessionId"`
	UserID                   identity.UserID `json:"userId"`
	Provider                 string          `json:"provider"`
	ProviderSessionReference string          `json:"providerSessionReference,omitempty"`
	// ProviderSessionCredential is the sealed (AES-256-GCM) versioned
	// provider session handle (ADR-0005 §3). Sessions created before the
	// ADR-0003 revision carry none — they cannot finalize OAuth
	// authorization requests and must re-login. Bearer material: never
	// log, audit, persist elsewhere or expose to HTTP.
	ProviderSessionCredential EncryptedProviderSessionCredential `json:"providerSessionCredential,omitempty"`
	CreatedAt                 time.Time                          `json:"createdAt"`
	LastSeenAt                time.Time                          `json:"lastSeenAt"`
	ExpiresAt                 time.Time                          `json:"expiresAt"`
	AuthenticationTime        time.Time                          `json:"authenticationTime"`
	AuthenticationMethods     []auth.AuthenticationMethod        `json:"authenticationMethods"`
	ReauthenticatedUntil      *time.Time                         `json:"reauthenticatedUntil,omitempty"`
	CSRFTokenHash             string                             `json:"csrfTokenHash"`
	UserAgentHash             string                             `json:"userAgentHash,omitempty"`
	Remember                  bool                               `json:"remember"`
}

// Principal is the minimal authenticated identity placed into the request
// context by session middleware. Handlers never read cookies or Redis directly.
type Principal struct {
	UserID                identity.UserID
	SessionID             SessionID
	AuthenticationTime    time.Time
	AuthenticationMethods []auth.AuthenticationMethod
	ReauthenticatedUntil  *time.Time
}

// ErrSessionNotFound is returned when a session token hash has no Redis record.
var ErrSessionNotFound = errors.New("session not found")

// ErrSessionExpired is returned when the session record exists but has passed
// its absolute or idle expiry.
var ErrSessionExpired = errors.New("session expired")

// ErrSessionRevoked is returned when the session has been explicitly revoked.
var ErrSessionRevoked = errors.New("session revoked")

// GenerateToken generates a cryptographically random session token and returns
// its base64url-encoded representation. The token is 256 bits of entropy.
func GenerateToken() (string, error) {
	buf := make([]byte, TokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateCSRFToken generates a cryptographically random CSRF token.
func GenerateCSRFToken() (string, error) {
	buf := make([]byte, CSRFTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateMFAToken generates a cryptographically random MFA challenge token.
func GenerateMFAToken() (string, error) {
	buf := make([]byte, MFATokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken returns the hex-encoded SHA-256 hash of a token. This hash is used
// as the Redis key — the raw token never touches Redis.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// HashUserAgent returns the hex-encoded SHA-256 hash of a User-Agent string.
func HashUserAgent(ua string) string {
	h := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(h[:])
}

// ConstantTimeEqual compares two strings in constant time.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// IsExpired checks whether a session record has passed its absolute or idle
// expiry relative to the given current time.
func (r SessionRecord) IsExpired(now time.Time, idleTTL time.Duration) bool {
	if now.After(r.ExpiresAt) {
		return true
	}
	if idleTTL > 0 && now.Sub(r.LastSeenAt) > idleTTL {
		return true
	}
	return false
}

// NeedsTouch reports whether the session's LastSeenAt should be refreshed,
// based on the configured touch interval.
func (r SessionRecord) NeedsTouch(now time.Time, touchInterval time.Duration) bool {
	return now.Sub(r.LastSeenAt) >= touchInterval
}
