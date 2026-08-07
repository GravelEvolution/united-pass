package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// ProviderSessionCredential is the versioned, strongly typed wrapper
// around the provider-side session handle. It is never serialized to
// HTTP, PostgreSQL, logs, audit or error values; its only at-rest form
// is EncryptedProviderSessionCredential.
type ProviderSessionCredential struct {
	Version      int    `json:"version"`
	Provider     string `json:"provider"`
	SessionID    string `json:"sessionId"`
	SessionToken string `json:"sessionToken,omitempty"`
}

// Validate enforces the per-version binding rules (fail closed).
func (c ProviderSessionCredential) Validate() error {
	switch c.Version {
	case ProviderSessionCredentialVersion1:
		if c.SessionID == "" {
			return errors.New("session: version 1 credential requires a session id")
		}
		if c.SessionToken != "" {
			return errors.New("session: version 1 credential must not carry a session token")
		}
	case ProviderSessionCredentialVersion2:
		if c.SessionID == "" {
			return errors.New("session: version 2 credential requires a session id")
		}
		if c.SessionToken == "" {
			return errors.New("session: version 2 credential requires a session token")
		}
	default:
		return fmt.Errorf("session: unknown provider session credential version %d", c.Version)
	}
	return nil
}

// CanFinalizeAuthorization reports whether the credential can complete a
// provider auth request (CreateCallback needs the session token). Legacy
// Version-1 credentials fail closed here and require re-login (ADR-0005
// §3 legacy compatibility).
func (c ProviderSessionCredential) CanFinalizeAuthorization() bool {
	return c.Version == ProviderSessionCredentialVersion2 && c.SessionID != "" && c.SessionToken != ""
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
	payload, err := json.Marshal(cred)
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
	var cred ProviderSessionCredential
	if err := json.Unmarshal([]byte(plaintext), &cred); err != nil {
		return ProviderSessionCredential{}, fmt.Errorf("session: decode provider session credential: %w", err)
	}
	if err := cred.Validate(); err != nil {
		return ProviderSessionCredential{}, err
	}
	return cred, nil
}
