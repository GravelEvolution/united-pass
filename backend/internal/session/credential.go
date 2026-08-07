package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
)

// Provider session credential (ADR-0005 §3, amending ADR-0003). ZITADEL
// CreateCallback requires session_id AND session_token to finalize an
// OAuth authorization request, so the authenticated provider session
// handle is sealed into a versioned, strongly typed credential
// immediately after authentication completes. Only the ciphertext is
// stored (in the Redis session record); the plaintext token is dropped
// as soon as encryption succeeds. The credential never enters
// PostgreSQL, the HTTP Principal, browser responses, logs, audit events
// or error messages, and it is decryptable only through the narrow
// reader seam consumed by the consent decision orchestration.
//
// The runtime type keeps every field unexported and implements the
// fmt and slog redaction interfaces, so no %v/%+v/%#v rendering, panic
// dump, structured log line or json.Marshal of the value itself can
// ever surface the bearer token — the guarantee is mechanical, not a
// calling convention. Serialization happens exclusively through the
// private wire DTO inside Seal/Decrypt.

// Provider session credential versions.
const (
	// ProviderSessionCredentialVersion1 is the legacy session-ID-only
	// credential of sessions created before the ADR-0003 revision. Such
	// sessions cannot finalize an OAuth authorization request; the consent
	// flow fails closed and routes the user agent into interactive
	// re-login, which upgrades the credential to Version 2. No background
	// migration of live credentials is performed.
	ProviderSessionCredentialVersion1 = 1
	// ProviderSessionCredentialVersion2 carries the full provider session
	// handle (ID + token) required by CreateCallback.
	ProviderSessionCredentialVersion2 = 2
)

// providerSessionFieldMaxLen mirrors the provider proto limits enforced
// again downstream by the consent SessionHandle (1..200 bytes).
const providerSessionFieldMaxLen = 200

// ProviderSessionCredential is the versioned, strongly typed wrapper
// around the provider-side session handle. Bearer material: its fields
// are unexported and every rendering path is redacted; its only at-rest
// form is EncryptedProviderSessionCredential.
type ProviderSessionCredential struct {
	version      int
	provider     string
	sessionID    string
	sessionToken string
}

// NewProviderSessionCredential builds the runtime credential. Validation
// happens through Validate (seal and decrypt both enforce it); the
// constructor never rejects so callers can surface domain errors.
func NewProviderSessionCredential(version int, provider, sessionID, sessionToken string) ProviderSessionCredential {
	return ProviderSessionCredential{
		version:      version,
		provider:     provider,
		sessionID:    sessionID,
		sessionToken: sessionToken,
	}
}

// Version returns the credential version discriminator.
func (c ProviderSessionCredential) Version() int { return c.version }

// Provider returns the issuing provider name.
func (c ProviderSessionCredential) Provider() string { return c.provider }

// SessionID returns the provider session id (narrow seam access).
func (c ProviderSessionCredential) SessionID() string { return c.sessionID }

// SessionToken returns the provider session token (narrow seam access
// for building the consent SessionHandle; never log the returned value).
func (c ProviderSessionCredential) SessionToken() string { return c.sessionToken }

// Validate enforces the per-version binding rules (fail closed), the
// provider requirement and the provider field length bounds.
func (c ProviderSessionCredential) Validate() error {
	if c.provider == "" {
		return errors.New("session: provider session credential requires a provider")
	}
	if len(c.sessionID) < 1 || len(c.sessionID) > providerSessionFieldMaxLen {
		return errors.New("session: invalid provider session id in credential")
	}
	switch c.version {
	case ProviderSessionCredentialVersion1:
		if c.sessionToken != "" {
			return errors.New("session: version 1 credential must not carry a session token")
		}
	case ProviderSessionCredentialVersion2:
		if len(c.sessionToken) < 1 || len(c.sessionToken) > providerSessionFieldMaxLen {
			return errors.New("session: invalid provider session token in credential")
		}
	default:
		return fmt.Errorf("session: unknown provider session credential version %d", c.version)
	}
	return nil
}

// CanFinalizeAuthorization reports whether the credential can complete a
// provider auth request (CreateCallback needs the session token). Legacy
// Version-1 credentials fail closed here and require re-login (ADR-0005
// §3 legacy compatibility).
func (c ProviderSessionCredential) CanFinalizeAuthorization() bool {
	return c.version == ProviderSessionCredentialVersion2 && c.sessionID != "" && c.sessionToken != ""
}

// Redaction: every rendering path a log line, panic dump or debugger
// could take stays redacted — including reflection-based %#v and slog.
func (ProviderSessionCredential) String() string { return "[redacted provider session credential]" }

func (ProviderSessionCredential) GoString() string { return "[redacted provider session credential]" }

func (ProviderSessionCredential) LogValue() slog.Value {
	return slog.StringValue("[redacted provider session credential]")
}

// providerSessionCredentialWire is the private serialization form used
// exclusively by Seal/Decrypt. Keeping the wire type distinct from the
// runtime type means json.Marshal of a runtime credential can never
// produce the bearer token (unexported fields marshal to "{}").
type providerSessionCredentialWire struct {
	Version      int    `json:"version"`
	Provider     string `json:"provider"`
	SessionID    string `json:"sessionId"`
	SessionToken string `json:"sessionToken,omitempty"`
}

// EncryptedProviderSessionCredential is the at-rest form of a sealed
// provider session credential: AES-256-GCM ciphertext of the canonical
// JSON of ProviderSessionCredential. It is a distinct storage type — not
// the old plain "provider session reference" — because its content
// includes bearer material (the session token).
type EncryptedProviderSessionCredential string

// ErrProviderSessionCredentialMissing: the session carries no sealed
// credential (legacy Version-1 sessions created before the ADR-0003
// revision, or sessions of providers that never issued one). Consent
// finalization fails closed and the user agent must re-login.
var ErrProviderSessionCredentialMissing = errors.New("session: no provider session credential")

// SealProviderSessionCredential validates the credential and seals it
// into its at-rest ciphertext form with the configured AES-256-GCM
// encryptor. The plaintext credential is dropped by the caller as soon
// as sealing succeeds. An encryptor is mandatory for non-empty
// credentials — the service refuses to downgrade to plaintext.
func (s *Service) SealProviderSessionCredential(cred ProviderSessionCredential) (EncryptedProviderSessionCredential, error) {
	if err := cred.Validate(); err != nil {
		return "", err
	}
	if s.encryptor == nil {
		return "", fmt.Errorf("session: %w", ErrMissingEncryptionKey)
	}
	payload, err := json.Marshal(providerSessionCredentialWire{
		Version:      cred.version,
		Provider:     cred.provider,
		SessionID:    cred.sessionID,
		SessionToken: cred.sessionToken,
	})
	if err != nil {
		return "", fmt.Errorf("session: encode provider session credential: %w", err)
	}
	encrypted, err := s.encryptor.Encrypt(string(payload))
	if err != nil {
		return "", fmt.Errorf("session: encrypt provider session credential: %w", err)
	}
	return EncryptedProviderSessionCredential(encrypted), nil
}

// DecryptProviderSessionCredential opens a sealed credential. It is the
// narrow server-side read seam: only the consent decision orchestration
// receives an implementation (ADR-0005 §3). Missing ciphertext maps to
// ErrProviderSessionCredentialMissing so legacy sessions fail closed.
func (s *Service) DecryptProviderSessionCredential(_ context.Context, encrypted EncryptedProviderSessionCredential) (ProviderSessionCredential, error) {
	if encrypted == "" {
		return ProviderSessionCredential{}, ErrProviderSessionCredentialMissing
	}
	if s.encryptor == nil {
		return ProviderSessionCredential{}, fmt.Errorf("session: %w", ErrMissingEncryptionKey)
	}
	plaintext, err := s.encryptor.Decrypt(string(encrypted))
	if err != nil {
		return ProviderSessionCredential{}, fmt.Errorf("session: decrypt provider session credential: %w", err)
	}
	var wire providerSessionCredentialWire
	if err := json.Unmarshal([]byte(plaintext), &wire); err != nil {
		return ProviderSessionCredential{}, fmt.Errorf("session: decode provider session credential: %w", err)
	}
	cred := NewProviderSessionCredential(wire.Version, wire.Provider, wire.SessionID, wire.SessionToken)
	if err := cred.Validate(); err != nil {
		return ProviderSessionCredential{}, err
	}
	return cred, nil
}
