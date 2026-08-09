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
	"log/slog"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

// Store abstracts session persistence. The Redis adapter satisfies this
// interface; tests can use an in-memory fake.
//
// Multi-key operations (Create, Delete, Rotate, Touch) must be atomic per
// ADR-0006 §1: record, user index entry and locator are written together in
// one MULTI/EXEC transaction or one Lua script. Implementations must never
// use a bare pipeline for them. Every implementation computes the session
// index score with SessionRecord.EffectiveExpiry — the single frozen
// definition; implementations must not re-derive the formula.
type Store interface {
	// Create writes the record, the user-index entry (score = the record's
	// effective expiry) and the SessionID→tokenHash locator atomically.
	Create(ctx context.Context, tokenHash string, record SessionRecord, ttl, idleTTL time.Duration) error
	Get(ctx context.Context, tokenHash string) (SessionRecord, error)
	// Delete removes record, index entry and locator atomically (idempotent).
	Delete(ctx context.Context, tokenHash string) error
	// Touch persists the updated record (new LastSeenAt), re-expires the
	// locator and refreshes the index member score atomically.
	Touch(ctx context.Context, tokenHash string, record SessionRecord, ttl, idleTTL time.Duration) error
	// Rotate replaces the record under oldTokenHash with newRecord under
	// newTokenHash, re-points the locator and refreshes the index score
	// atomically. The SessionID stays stable across rotation.
	Rotate(ctx context.Context, oldTokenHash, newTokenHash string, newRecord SessionRecord, newTTL, idleTTL time.Duration) error

	// GetBySessionID resolves a browser-supplied SessionID through the
	// locator and returns the record only when it belongs to userID.
	// Unknown, foreign, idle/absolute-expired or vanished sessions all yield
	// ErrSessionNotFound (non-enumerating, ADR-0006 §1.4/§2). Infrastructure
	// failures are propagated as-is: they must never be mistaken for a
	// not-found outcome (fail closed).
	GetBySessionID(ctx context.Context, userID identity.UserID, sessionID SessionID, now time.Time, idleTTL time.Duration) (SessionRecord, error)
	// DeleteBySessionID resolves like GetBySessionID and removes the session
	// atomically. Same non-enumerating error contract; the expiry replay
	// honours the frozen idle semantics (now + idleTTL).
	DeleteBySessionID(ctx context.Context, userID identity.UserID, sessionID SessionID, now time.Time, idleTTL time.Duration) error
	// ListUserSessions returns the caller's active sessions (never expired
	// ones) with stale index entries self-healed (ADR-0006 §1 rule 7).
	ListUserSessions(ctx context.Context, userID identity.UserID, now time.Time, idleTTL time.Duration) ([]SessionRecord, error)
	// RevokeAllOtherSessions removes every session of userID except
	// currentSessionID and returns the removed records (for best-effort
	// provider revocation) plus the revoked count. The expiry replay honours
	// the frozen idle semantics; infrastructure failures abort the walk and
	// are propagated so the caller never reports success while a revocation
	// may have been skipped (fail closed).
	RevokeAllOtherSessions(ctx context.Context, userID identity.UserID, currentSessionID SessionID, now time.Time, idleTTL time.Duration) ([]SessionRecord, int, error)
	// RevokeSessionsBeforeEpoch removes every session of userID whose
	// stamped security epoch is lower than newEpoch (ADR-0007 F4, the only
	// permitted post-password-change bulk revocation: generation-scoped,
	// never the generation-unaware RevokeAllOtherSessions). It returns the
	// removed records (for best-effort provider revocation) plus the revoked
	// count. Sessions already stamped with newEpoch (e.g. the freshly
	// rotated current session) are never touched. Same fail-closed error
	// contract as RevokeAllOtherSessions.
	RevokeSessionsBeforeEpoch(ctx context.Context, userID identity.UserID, newEpoch securitystate.Epoch, now time.Time, idleTTL time.Duration) ([]SessionRecord, int, error)
}

// ErrSessionIsCurrent is returned when a targeted revoke references the
// caller's current session. Handlers map it to the stable 409
// session.current conflict (ADR-0006 §2).
var ErrSessionIsCurrent = errors.New("session is the current session")

// Durable session security audit (ADR-0004 §8 / ADR-0006 §2): log-based
// audit is not a substitute, so successful session revocations are recorded
// through SecurityAuditor in addition to the structured log event. Payloads
// never contain tokens, provider references or raw IPs.
const (
	// EventSessionRevoked audits the revocation of the caller's own session
	// (self/current, ADR-0006 §2).
	EventSessionRevoked = "session.revoked"
	// EventSessionRevokedOther audits one targeted revocation of another
	// session owned by the caller (ADR-0006 §2).
	EventSessionRevokedOther = "session.revoked_other"
	// EventSessionsRevokedOthers audits a bulk revocation of the caller's
	// other sessions.
	EventSessionsRevokedOthers = "session.revoked_others"
	// EventSessionsRevokedEpoch audits the generation-scoped settlement
	// cleanup after a password mutation advanced the security epoch
	// (ADR-0007 F4). Unlike the user-initiated events above it is emitted
	// as a structured log only; the durable settlement audit row (with
	// provider/settlement outcomes) is written by the mutation handler.
	EventSessionsRevokedEpoch = "session.revoked_epoch"

	// AuditOutcomeSuccess / AuditOutcomeDenied are the stable audit result
	// values persisted for session events.
	AuditOutcomeSuccess = "success"
	AuditOutcomeDenied  = "denied"
)

// SecurityAuditEvent is one durable session security audit row.
type SecurityAuditEvent struct {
	EventType    string
	ActorUserID  identity.UserID
	SessionID    SessionID
	RequestID    string
	Operation    string
	Result       string
	FailureClass string
	OccurredAt   time.Time

	// ADR-0007 Decision 5 additive settlement fields (closes B5, F5): the
	// two orthogonal outcome facts of a provider-committed password change
	// and their forensic context. They never overload Result or
	// FailureClass — the frozen P4.1 result model stays untouched. Zero
	// values are omitted at the persistence boundary.
	ProviderOutcome   string
	SettlementOutcome string
	IntentID          int64
	FromEpoch         int64
	ToEpoch           int64
}

// SecurityAuditor persists durable session security audit rows. The
// composition root satisfies it with the canonical security event store;
// tests can use an in-memory fake.
type SecurityAuditor interface {
	RecordSessionEvent(ctx context.Context, ev SecurityAuditEvent) error
}

// ProviderSessionRevoker terminates a provider-side session. It is a narrow
// view of auth.Authenticator so the session inventory never depends on the
// full authentication seam. Revocation is best-effort: local session
// invalidation must never depend on it succeeding.
type ProviderSessionRevoker interface {
	RevokeProviderSession(ctx context.Context, sessionReference string) error
}

// EpochStamper returns a user's authoritative security epoch from the
// durable store (ADR-0007 Decision 1). It is satisfied by the
// security-state service; session creation stamps every new record with it
// and fails closed when the lookup fails.
type EpochStamper interface {
	CurrentEpoch(ctx context.Context, userID identity.UserID) (securitystate.Epoch, error)
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
	revoker       ProviderSessionRevoker
	auditor       SecurityAuditor
	epochStamper  EpochStamper
	logger        *slog.Logger
}

// ServiceOption customizes optional Service collaborators without changing
// the frozen NewService signature (ADR-0006 §1 session inventory).
type ServiceOption func(*Service)

// WithProviderRevoker wires the best-effort provider session revocation used
// by the session inventory revoke paths.
func WithProviderRevoker(r ProviderSessionRevoker) ServiceOption {
	return func(s *Service) { s.revoker = r }
}

// WithLogger wires the structured logger used for session security events.
func WithLogger(l *slog.Logger) ServiceOption {
	return func(s *Service) { s.logger = l }
}

// WithSecurityAuditor wires the durable audit recorder used for session
// revocation events (ADR-0004 §8). A nil auditor keeps log-only audit.
func WithSecurityAuditor(a SecurityAuditor) ServiceOption {
	return func(s *Service) { s.auditor = a }
}

// WithEpochStamper wires the authoritative epoch lookup used to stamp newly
// created sessions (ADR-0007 Decision 1). Production wiring always provides
// it; a nil stamper stamps generation 1 and exists for tests only.
func WithEpochStamper(e EpochStamper) ServiceOption {
	return func(s *Service) { s.epochStamper = e }
}

// NewService creates a session Service from the given store and configuration.
// encryptor is used to encrypt provider session references at rest (ADR-0002
// section 13); it may be nil only when the caller guarantees no provider
// session references will be stored (e.g. tests without provider references).
func NewService(store Store, clock Clock, ttl, rememberTTL, idleTTL, touchInterval time.Duration, encryptor Encryptor, opts ...ServiceOption) *Service {
	if clock == nil {
		clock = SystemClock{}
	}
	s := &Service{
		store:         store,
		clock:         clock,
		encryptor:     encryptor,
		ttl:           ttl,
		rememberTTL:   rememberTTL,
		idleTTL:       idleTTL,
		touchInterval: touchInterval,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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
	// ClientIP is the caller's remote address; only its masked form is
	// persisted (ADR-0006 §3).
	ClientIP string
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

	// SessionID randomness is mandatory: a crypto/rand failure fails session
	// creation closed — no timestamp fallback exists (ADR-0006 §1.4).
	sessionID, err := generateSessionID()
	if err != nil {
		return CreateSessionResult{}, fmt.Errorf("session: generate session id: %w", err)
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

	deviceDisplay, clientDisplay := NormalizeUserAgent(input.UserAgent)

	// Stamp the authoritative security epoch (ADR-0007 Decision 1): every
	// new session belongs to the user's current generation; the lookup
	// fails closed so no session is ever minted unstamped against a live
	// durable store.
	epoch := securitystate.Epoch(1)
	if s.epochStamper != nil {
		stamped, err := s.epochStamper.CurrentEpoch(ctx, input.UserID)
		if err != nil {
			return CreateSessionResult{}, fmt.Errorf("session: stamp security epoch: %w", err)
		}
		epoch = stamped
	}

	record := SessionRecord{
		Version:                   1,
		SessionID:                 sessionID,
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
		DeviceDisplay:             clampDisplay(deviceDisplay),
		ClientDisplay:             clampDisplay(clientDisplay),
		IPAddressMasked:           MaskIP(input.ClientIP),
		Remember:                  input.Remember,
		SecurityEpoch:             epoch,
	}

	tokenHash := HashToken(token)
	if err := s.store.Create(ctx, tokenHash, record, ttl, s.idleTTL); err != nil {
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

	// ADR-0006 §1 rule 6: Touch refreshes LastSeenAt and re-expires the
	// record/locator keys. The absolute deadline ExpiresAt is fixed at
	// creation (P1 semantics, unchanged): the key TTL is the remaining
	// absolute lifetime, and the index score becomes the record's new
	// effective expiry min(ExpiresAt, now + idleTTL).
	ttl := record.ExpiresAt.Sub(now)
	if ttl <= 0 {
		// Past its absolute deadline: treat as expired, clean up.
		_ = s.store.Delete(ctx, tokenHash)
		return ErrSessionExpired
	}
	record.LastSeenAt = now
	return s.store.Touch(ctx, tokenHash, record, ttl, s.idleTTL)
}

// DeleteSession removes a session from Redis by its raw token. It is idempotent.
func (s *Service) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	tokenHash := HashToken(token)
	return s.store.Delete(ctx, tokenHash)
}

// RotateSessionResult carries the rotated session's fresh raw tokens, the
// preserved record and the remaining absolute lifetime for cookie re-issue.
// The raw tokens are returned to the caller so it can set cookies; they are
// never stored in Redis.
type RotateSessionResult struct {
	SessionToken string
	CSRFToken    string
	TokenHash    string
	Record       SessionRecord
	// RemainingTTL is the session's remaining absolute lifetime
	// (ExpiresAt - now) after rotation; callers derive the cookie MaxAge
	// from it. Rotation never extends a session's absolute deadline.
	RemainingTTL time.Duration
}

// RotateSession replaces the session token and CSRF token of an existing
// session while keeping its identity stable (ADR-0006 §6 step 4): the
// SessionID, CreatedAt, ExpiresAt, Remember flag, provider reference and
// sealed provider credential all survive; LastSeenAt is refreshed and a
// fresh CSRF token hash is bound. Rotation never extends the absolute
// expiry — the key TTL becomes the remaining lifetime.
//
// newEpoch re-stamps the record (ADR-0007 Decision 1): password-mutation
// settlement rotates the current session under the advanced epoch so it
// survives the generation-scoped cleanup; the stamp must be the epoch
// returned by the outcome-record transaction (>= 1, fail closed).
//
// The vanished-session guard is a production invariant here: if the record
// disappears between validation and the atomic store rotation (a concurrent
// logout or revocation won the race), rotation fails closed with
// ErrSessionNotFound and never resurrects the session. An expired record is
// cleaned up and reported as ErrSessionExpired.
func (s *Service) RotateSession(ctx context.Context, oldToken string, newEpoch securitystate.Epoch) (RotateSessionResult, error) {
	if oldToken == "" {
		return RotateSessionResult{}, ErrSessionNotFound
	}
	if newEpoch < 1 {
		return RotateSessionResult{}, errors.New("session: rotation requires a security epoch stamp")
	}
	oldHash := HashToken(oldToken)
	record, err := s.store.Get(ctx, oldHash)
	if err != nil {
		return RotateSessionResult{}, err
	}

	now := s.clock.Now()
	if record.IsExpired(now, s.idleTTL) {
		// Best-effort cleanup of the expired record (mirrors ValidateSession).
		_ = s.store.Delete(ctx, oldHash)
		return RotateSessionResult{}, ErrSessionExpired
	}

	token, err := GenerateToken()
	if err != nil {
		return RotateSessionResult{}, fmt.Errorf("session: generate token: %w", err)
	}
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		return RotateSessionResult{}, fmt.Errorf("session: generate CSRF token: %w", err)
	}

	remaining := record.ExpiresAt.Sub(now)
	if remaining <= 0 {
		// Past its absolute deadline between the expiry check and now:
		// clean up and treat as expired.
		_ = s.store.Delete(ctx, oldHash)
		return RotateSessionResult{}, ErrSessionExpired
	}

	record.LastSeenAt = now
	record.CSRFTokenHash = HashToken(csrfToken)
	record.SecurityEpoch = newEpoch

	newHash := HashToken(token)
	if err := s.store.Rotate(ctx, oldHash, newHash, record, remaining, s.idleTTL); err != nil {
		return RotateSessionResult{}, err
	}

	return RotateSessionResult{
		SessionToken: token,
		CSRFToken:    csrfToken,
		TokenHash:    newHash,
		Record:       record,
		RemainingTTL: remaining,
	}, nil
}

// ListUserSessions returns the caller's live sessions (the current session
// included; handlers mark it via the Principal). Expired entries are
// filtered by the authoritative IsExpired replay inside the store, with the
// index self-healed (ADR-0006 §1 rule 7).
func (s *Service) ListUserSessions(ctx context.Context, userID identity.UserID) ([]SessionRecord, error) {
	records, err := s.store.ListUserSessions(ctx, userID, s.clock.Now(), s.idleTTL)
	if err != nil {
		return nil, fmt.Errorf("session: list sessions: %w", err)
	}
	return records, nil
}

// RevokeSession revokes one of the caller's sessions by its browser-visible
// SessionID. Revoking the current session is refused with ErrSessionIsCurrent
// (handlers map it to the stable 409 session.current conflict); unknown,
// foreign or already-expired targets yield ErrSessionNotFound (404) without
// distinguishing the cases (non-enumeration, ADR-0006 §2). The provider
// session is revoked best-effort afterwards, and the outcome is emitted as a
// structured security event.
func (s *Service) RevokeSession(ctx context.Context, userID identity.UserID, currentSessionID, targetSessionID SessionID) error {
	if targetSessionID == currentSessionID {
		return ErrSessionIsCurrent
	}

	record, err := s.store.GetBySessionID(ctx, userID, targetSessionID, s.clock.Now(), s.idleTTL)
	if err != nil {
		return err
	}
	if err := s.store.DeleteBySessionID(ctx, userID, targetSessionID, s.clock.Now(), s.idleTTL); err != nil {
		return fmt.Errorf("session: revoke session: %w", err)
	}

	failureClass := s.revokeProviderSession(ctx, record)
	s.logSecurityEvent(EventSessionRevokedOther, userID, targetSessionID, nil)
	s.recordAudit(ctx, EventSessionRevokedOther, userID, targetSessionID, "session.revoke", failureClass)
	return nil
}

// RevokeAllOtherSessions revokes every session of the caller except the
// current one and returns the number of sessions revoked. Provider sessions
// are revoked best-effort per victim; a provider failure never fails the
// operation but its stable failure class is recorded in the durable audit
// payload (ADR-0006 §2). When the store walk fails part-way, the provider
// cleanup of every already-removed victim still runs before the error is
// returned: a later victim's infrastructure failure must never erase an
// earlier victim's cleanup.
func (s *Service) RevokeAllOtherSessions(ctx context.Context, userID identity.UserID, currentSessionID SessionID) (int, error) {
	victims, count, err := s.store.RevokeAllOtherSessions(ctx, userID, currentSessionID, s.clock.Now(), s.idleTTL)
	var failureClass string
	for i := range victims {
		if fc := s.revokeProviderSession(ctx, victims[i]); fc != "" && failureClass == "" {
			failureClass = fc
		}
	}
	if err != nil {
		s.logSecurityEvent(EventSessionsRevokedOthers, userID, currentSessionID, err)
		return 0, fmt.Errorf("session: revoke all other sessions: %w", err)
	}
	s.logSecurityEvent(EventSessionsRevokedOthers, userID, currentSessionID, nil)
	s.recordAudit(ctx, EventSessionsRevokedOthers, userID, currentSessionID, "session.revoke_all_others", failureClass)
	return count, nil
}

// RevokeSessionsBeforeEpoch is the generation-scoped settlement cleanup
// (ADR-0007 F4): it physically removes only sessions stamped before
// newEpoch and never touches one already stamped with it. It satisfies
// securitystate.SettlementCleaner. Provider sessions of the victims are
// revoked best-effort afterwards (stable failure classes logged); a store
// walk failure propagates so settlement degrades instead of reporting a
// false success.
func (s *Service) RevokeSessionsBeforeEpoch(ctx context.Context, userID identity.UserID, newEpoch securitystate.Epoch) (int, error) {
	victims, count, err := s.store.RevokeSessionsBeforeEpoch(ctx, userID, newEpoch, s.clock.Now(), s.idleTTL)
	var failureClass string
	for i := range victims {
		if fc := s.revokeProviderSession(ctx, victims[i]); fc != "" && failureClass == "" {
			failureClass = fc
		}
	}
	if err != nil {
		s.lg().Warn(EventSessionsRevokedEpoch,
			"userId", string(userID),
			"newEpoch", int64(newEpoch),
			"revoked", count,
			"outcome", "failed",
			"errorClass", observability.ClassifyError(err),
		)
		return count, fmt.Errorf("session: revoke sessions before epoch: %w", err)
	}
	s.lg().Info(EventSessionsRevokedEpoch,
		"userId", string(userID),
		"newEpoch", int64(newEpoch),
		"revoked", count,
		"providerFailureClass", failureClass,
		"outcome", "success",
	)
	return count, nil
}

// revokeProviderSession terminates the provider-side session referenced by a
// revoked record. Best-effort: decrypt or provider failures never fail the
// local revocation — but they are surfaced as a stable failure class
// (never a raw error) so the durable audit row records the degraded
// provider outcome (ADR-0006 §2). An empty result means the cleanup either
// succeeded or had nothing to do.
func (s *Service) revokeProviderSession(ctx context.Context, record SessionRecord) string {
	if record.ProviderSessionReference == "" || s.revoker == nil {
		return ""
	}
	ref, err := s.DecryptProviderSessionReference(ctx, record.ProviderSessionReference)
	if err != nil {
		s.lg().Warn("provider session reference decrypt failed during session revocation",
			"sessionId", string(record.SessionID),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		return string(observability.ClassifyError(err))
	}
	if ref == "" {
		return ""
	}
	if err := s.revoker.RevokeProviderSession(ctx, ref); err != nil {
		s.lg().Warn("provider session revocation failed during session revocation",
			"sessionId", string(record.SessionID),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		return string(observability.ClassifyError(err))
	}
	return ""
}

// recordAudit persists one durable session security audit row. failureClass
// carries the stable provider-cleanup failure class when the local
// revocation succeeded but the provider-side cleanup degraded (ADR-0006
// §2); it is empty on a fully clean outcome. Audit is best-effort at the
// call site: the local revocation already succeeded, so a recorder failure
// is logged as an operational/security defect (making the audit gap visible)
// but never masks the revocation outcome.
func (s *Service) recordAudit(ctx context.Context, eventType string, userID identity.UserID, sessionID SessionID, operation, failureClass string) {
	if s.auditor == nil {
		return
	}
	err := s.auditor.RecordSessionEvent(ctx, SecurityAuditEvent{
		EventType:    eventType,
		ActorUserID:  userID,
		SessionID:    sessionID,
		Operation:    operation,
		Result:       AuditOutcomeSuccess,
		FailureClass: failureClass,
		OccurredAt:   s.clock.Now(),
	})
	if err != nil {
		s.lg().Warn("session security audit record failed",
			"event", eventType,
			"userId", string(userID),
			"sessionId", string(sessionID),
			"errorClass", observability.ClassifyError(err),
		)
	}
}

// logSecurityEvent emits a structured session security event. Payloads stay
// minimal: user and session identifiers plus the outcome — never tokens,
// provider references or raw IPs.
func (s *Service) logSecurityEvent(event string, userID identity.UserID, sessionID SessionID, err error) {
	logger := s.lg()
	if err != nil {
		logger.Warn(event,
			"userId", string(userID),
			"sessionId", string(sessionID),
			"outcome", "failed",
			"errorClass", observability.ClassifyError(err),
		)
		return
	}
	logger.Info(event,
		"userId", string(userID),
		"sessionId", string(sessionID),
		"outcome", "success",
	)
}

// lg returns the configured logger or the slog default so nil-wired
// services (tests) never panic.
func (s *Service) lg() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
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

// generateSessionID creates a random session ID for the browser-visible
// inventory (ADR-0006 §1.4): 128 bits from crypto/rand, hex-encoded. A
// random-read failure fails session creation closed — the previous
// timestamp-based fallback is removed because a predictable SessionID would
// weaken the revoke path's non-enumeration guarantees.
func generateSessionID() (SessionID, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("session: crypto/rand unavailable")
	}
	return SessionID(hex.EncodeToString(buf)), nil
}
