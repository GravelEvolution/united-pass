package applications

import (
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// SecurityEventResult distinguishes successful operations from denied ones.
type SecurityEventResult string

const (
	SecurityEventSuccess SecurityEventResult = "success"
	SecurityEventDenied  SecurityEventResult = "denied"
)

// Security event types recorded by the Phase 2 management plane (ADR-0004
// §8). Payloads never contain secrets, tokens, cookies, passwords or raw
// provider errors.
const (
	EventApplicationCreated  = "application.created"
	EventApplicationUpdated  = "application.updated"
	EventApplicationEnabled  = "application.enabled"
	EventApplicationDisabled = "application.disabled"
	EventApplicationDeleted  = "application.deleted"

	EventOAuthClientCreated  = "oauth_client.created"
	EventOAuthClientUpdated  = "oauth_client.updated"
	EventOAuthClientEnabled  = "oauth_client.enabled"
	EventOAuthClientDisabled = "oauth_client.disabled"
	EventOAuthClientDeleted  = "oauth_client.deleted"

	EventSecretRotated              = "oauth_client.secret_rotated"
	EventSecretRotationFailed       = "oauth_client.secret_rotation_failed"
	EventProviderReconciliationNeed = "oauth_client.provider_reconciliation_required"

	EventReauthenticationRequested = "reauthentication.requested"
	EventReauthenticationSucceeded = "reauthentication.succeeded"
	EventReauthenticationFailed    = "reauthentication.failed"

	// EventProviderSessionRevokeFailed marks a best-effort revocation of a
	// temporary provider session that failed at a reauthentication terminal
	// state (ADR-0004 §7). The session then relies on provider-side expiry.
	EventProviderSessionRevokeFailed = "provider_session.revoke_failed"

	// Phase 3 consent completion events (ADR-0005 §5). Exactly one of these
	// is written per terminal commit, constructed by the grant store from
	// the locked decision-operation row alone — callers never supply audit
	// facts.
	EventConsentGrantAllowed   = "consent.grant_allowed"
	EventConsentAccessDenied   = "consent.access_denied"
	EventConsentErrorCompleted = "consent.error_completion"
)

// SecurityEvent is one durable audit row. This is a real persistence
// boundary — log-based audit is not a substitute (ADR-0004 §8).
type SecurityEvent struct {
	EventID       SecurityEventID
	EventType     string
	ActorUserID   identity.UserID
	ApplicationID ApplicationID
	ClientID      OAuthClientID
	RequestID     string
	Operation     string
	Result        SecurityEventResult
	// FailureClass is a safe, stable failure category (e.g. "validation",
	// "authorization", "provider"). Never a raw provider error.
	FailureClass string
	OccurredAt   time.Time
}
