//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Session store port contracts and session record types
//

// Package session also defines the Store interface and Service that
// orchestrates session lifecycle. The Store interface is satisfied by the
// Redis adapter; the Service wraps it with token generation, expiry checks,
// and CSRF binding.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// Store abstracts session persistence. The Redis adapter satisfies this
// interface; tests can use an in-memory fake.
type Store interface {
	Create(ctx context.Context, tokenHash string, record SessionRecord, ttl time.Duration) error
	Get(ctx context.Context, tokenHash string) (SessionRecord, error)
	Delete(ctx context.Context, tokenHash string) error
	Touch(ctx context.Context, tokenHash string, lastSeenAt time.Time, ttl time.Duration) error
	Rotate(ctx context.Context, oldTokenHash, newTokenHash string, newRecord SessionRecord, newTTL time.Duration) error
}

// Clock abstracts time so tests can control it.
type Clock interface {
	Now() time.Time
}

// SystemClock returns the real time.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

// Service orchestrates session lifecycle: creation, validation, touching,
// rotation, and deletion. It wraps a Store with token generation, expiry
// checks, CSRF binding, and at-rest encryption of provider session
// references. Handlers and middleware use the Service, not the Store
// directly.
type Service struct {
	store         Store
	clock         Clock
	encryptor     Encryptor
	ttl           time.Duration
	rememberTTL   time.Duration
	idleTTL       time.Duration
	touchInterval time.Duration
}

// NewService creates a session Service from the given store and configuration.
// encryptor is used to encrypt provider session references at rest (ADR-0002
// section 13); it may be nil only when the caller guarantees no provider
// session references will be stored (e.g. tests without provider references).
func NewService(store Store, clock Clock, ttl, rememberTTL, idleTTL, touchInterval time.Duration, encryptor Encryptor) *Service {
	if clock == nil {
		clock = SystemClock{}
	}
	return &Service{
		store:         store,
		clock:         clock,
		encryptor:     encryptor,
		ttl:           ttl,
		rememberTTL:   rememberTTL,
		idleTTL:       idleTTL,
		touchInterval: touchInterval,
	}
}

// CreateSessionInput carries the data needed to create a new session.
type CreateSessionInput struct {
	UserID                   identity.UserID
	Provider                 string
	ProviderSessionReference string
	// ProviderSessionToken is the provider session token returned by the
	// authenticating provider call, wrapped in the redacted auth type.
	// When present it is sealed immediately into a Version-2
	// ProviderSessionCredential (ADR-0005 §3); the plaintext is never
	// stored and must be dropped by the caller once session creation
	// succeeds. In-memory only — never log or render.
	ProviderSessionToken  auth.ProviderSessionToken
	AuthenticationMethods []auth.AuthenticationMethod
	Remember              bool
	UserAgent             string
}

// CreateSessionResult contains the newly created session's raw tokens and
// the session record. The raw tokens are returned to the caller so it can
// set cookies. They are never stored in Redis.
type CreateSessionResult struct {
	SessionToken string
	CSRFToken    string
	TokenHash    string
	Record       SessionRecord
}

// CreateSession generates a new session token and CSRF token, creates a session
// record, and stores it in Redis with the appropriate TTL.
func (s *Service) CreateSession(ctx context.Context, input CreateSessionInput) (CreateSessionResult, error) {
	token, err := GenerateToken()
	if err != nil {
		return CreateSessionResult{}, fmt.Errorf("session: generate token: %w", err)
	}

	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		return CreateSessionResult{}, fmt.Errorf("session: generate CSRF token: %w", err)
	}

	now := s.clock.Now()
	ttl := s.ttl
	if input.Remember {
		ttl = s.rememberTTL
	}

	// Encrypt the provider session reference before it reaches Redis.
	// Plaintext provider credentials must never be stored at rest (ADR-0002
	// section 13). If a reference is present but no encryptor is configured,
	// refuse to create the session rather than silently downgrading to
	// plaintext.
	providerRef, err := s.encryptProviderSessionReference(ctx, input.ProviderSessionReference)
	if err != nil {
		return CreateSessionResult{}, err
	}

	// Seal the provider session handle into the versioned credential
	// (ADR-0005 §3): a token-bearing Version-2 credential for providers
	// that returned one, no credential at all otherwise (legacy
	// Version-1 sessions cannot finalize OAuth authorization requests and
	// fail closed into re-login).
	var sealedCredential EncryptedProviderSessionCredential
	if !input.ProviderSessionToken.Empty() {
		if input.ProviderSessionReference == "" {
			return CreateSessionResult{}, errors.New("session: provider session token without a session reference")
		}
		sealed, err := s.SealProviderSessionCredential(NewProviderSessionCredential(
			ProviderSessionCredentialVersion2,
			input.Provider,
			input.ProviderSessionReference,
			input.ProviderSessionToken.Token(),
		))
		if err != nil {
			return CreateSessionResult{}, err
		}
		sealedCredential = sealed
	}

	record := SessionRecord{
		Version:                   1,
		SessionID:                 generateSessionID(),
		UserID:                    input.UserID,
		Provider:                  input.Provider,
		ProviderSessionReference:  providerRef,
		ProviderSessionCredential: sealedCredential,
		CreatedAt:                 now,
		LastSeenAt:                now,
		ExpiresAt:                 now.Add(ttl),
		AuthenticationTime:        now,
		AuthenticationMethods:     input.AuthenticationMethods,
		CSRFTokenHash:             HashToken(csrfToken),
		UserAgentHash:             HashUserAgent(input.UserAgent),
		Remember:                  input.Remember,
	}

	tokenHash := HashToken(token)
	if err := s.store.Create(ctx, tokenHash, record, ttl); err != nil {
		return CreateSessionResult{}, fmt.Errorf("session: store create: %w", err)
	}

	return CreateSessionResult{
		SessionToken: token,
		CSRFToken:    csrfToken,
		TokenHash:    tokenHash,
		Record:       record,
	}, nil
}

// encryptProviderSessionReference encrypts a provider session reference for
// at-rest storage. Empty references pass through unchanged; non-empty
// references require a configured Encryptor.
func (s *Service) encryptProviderSessionReference(ctx context.Context, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if s.encryptor == nil {
		return "", fmt.Errorf("session: %w", ErrMissingEncryptionKey)
	}
	encrypted, err := s.encryptor.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("session: encrypt provider reference: %w", err)
	}
	return encrypted, nil
}

// DecryptProviderSessionReference decrypts an at-rest provider session
// reference (AES-GCM ciphertext). Logout uses it to revoke the provider
// session; the plaintext reference never touches Redis or logs.
func (s *Service) DecryptProviderSessionReference(ctx context.Context, encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	if s.encryptor == nil {
		return "", fmt.Errorf("session: %w", ErrMissingEncryptionKey)
	}
	plaintext, err := s.encryptor.Decrypt(encrypted)
	if err != nil {
		return "", fmt.Errorf("session: decrypt provider reference: %w", err)
	}
	return plaintext, nil
}

// ValidateSession looks up a session by its raw token, checks absolute and
// idle expiry, and returns the Principal and record. If the session is
// expired or not found, an error is returned.
func (s *Service) ValidateSession(ctx context.Context, token string) (Principal, SessionRecord, error) {
	if token == "" {
		return Principal{}, SessionRecord{}, ErrSessionNotFound
	}

	tokenHash := HashToken(token)
	record, err := s.store.Get(ctx, tokenHash)
	if err != nil {
		return Principal{}, SessionRecord{}, err
	}

	now := s.clock.Now()
	if record.IsExpired(now, s.idleTTL) {
		// Best-effort cleanup of expired session.
		_ = s.store.Delete(ctx, tokenHash)
		return Principal{}, SessionRecord{}, ErrSessionExpired
	}

	principal := Principal{
		UserID:                record.UserID,
		SessionID:             record.SessionID,
		AuthenticationTime:    record.AuthenticationTime,
		AuthenticationMethods: record.AuthenticationMethods,
		ReauthenticatedUntil:  record.ReauthenticatedUntil,
	}

	return principal, record, nil
}

// TouchSession refreshes the session's LastSeenAt if enough time has passed
// since the last touch. This reduces Redis write load while still enforcing
// idle timeout.
func (s *Service) TouchSession(ctx context.Context, token string) error {
	if token == "" {
		return ErrSessionNotFound
	}

	tokenHash := HashToken(token)
	record, err := s.store.Get(ctx, tokenHash)
	if err != nil {
		return err
	}

	now := s.clock.Now()
	if !record.NeedsTouch(now, s.touchInterval) {
		return nil
	}

	ttl := s.ttl
	if record.Remember {
		ttl = s.rememberTTL
	}
	return s.store.Touch(ctx, tokenHash, now, ttl)
}

// DeleteSession removes a session from Redis by its raw token. It is idempotent.
func (s *Service) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	tokenHash := HashToken(token)
	return s.store.Delete(ctx, tokenHash)
}

// ValidateCSRF checks that the CSRF cookie value and header value match each
// other and match the hash stored in the session record. All comparisons use
// constant time.
func ValidateCSRF(cookieValue, headerValue string, record SessionRecord) bool {
	if cookieValue == "" || headerValue == "" {
		return false
	}
	if !ConstantTimeEqual(cookieValue, headerValue) {
		return false
	}
	expectedHash := HashToken(cookieValue)
	return ConstantTimeEqual(expectedHash, record.CSRFTokenHash)
}

// generateSessionID creates a random session ID for internal tracking.
func generateSessionID() SessionID {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails.
		return SessionID(hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405"))))
	}
	return SessionID(hex.EncodeToString(buf))
}
