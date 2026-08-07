package consent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// Grant and decision-operation domain model (ADR-0005 §2, §4, §5). The
// provider auth request is authoritative for protocol facts; the local
// grant is the United Pass user-consent view — it implies consent, not
// live tokens, and is never presented as token state.

// GrantID is a stable United Pass authorization grant identifier ("grt_…").
type GrantID string

// DecisionOperationID identifies a consent decision operation ("dop_…").
type DecisionOperationID string

const (
	grantIDPrefix             = "grt_"
	decisionOperationIDPrefix = "dop_"
	consentIDRandomByteLength = 16 // 128 bits of entropy, matches P1/P2 IDs
)

// NewGrantID generates a fresh grant ID.
func NewGrantID() GrantID {
	return GrantID(grantIDPrefix + consentRandomHex(consentIDRandomByteLength))
}

// NewDecisionOperationID generates a fresh decision operation ID.
func NewDecisionOperationID() DecisionOperationID {
	return DecisionOperationID(decisionOperationIDPrefix + consentRandomHex(consentIDRandomByteLength))
}

func consentRandomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is fatal for identity generation.
		panic(fmt.Sprintf("consent: generate random id: %v", err))
	}
	return hex.EncodeToString(buf)
}

// Decision is the user's consent decision for one auth request.
type Decision string

// Decision values. The decision kind is part of the provider_succeeded
// proof record (ADR-0005 §5).
const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// Valid reports whether the decision is a known value.
func (d Decision) Valid() bool {
	return d == DecisionAllow || d == DecisionDeny
}

// DecisionOperationStatus is the durable state of a decision operation
// (ADR-0005 §2 lifecycle, §5 ordering). Transitions are compare-and-set.
type DecisionOperationStatus string

// Decision operation states.
const (
	// DecisionOperationPending: claimed locally; the provider call is in
	// flight or has not run yet.
	DecisionOperationPending DecisionOperationStatus = "pending"
	// DecisionOperationProviderSucceeded: CreateCallback returned and the
	// proof (decision kind + time, never the callback URL) is persisted;
	// the local commit is pending. Only rows in this state may ever be
	// repaired forward by reconciliation (ADR-0005 §4).
	DecisionOperationProviderSucceeded DecisionOperationStatus = "provider_succeeded"
	// DecisionOperationSucceeded: grant + audit + terminal state committed.
	DecisionOperationSucceeded DecisionOperationStatus = "succeeded"
	// DecisionOperationFailed: terminal failure without provider success
	// proof; fail-closed, never repaired into a grant.
	DecisionOperationFailed DecisionOperationStatus = "failed"
)

// InFlight reports whether the operation still needs reconciliation
// attention (pending without proof, or proof persisted without the local
// commit).
func (s DecisionOperationStatus) InFlight() bool {
	return s == DecisionOperationPending || s == DecisionOperationProviderSucceeded
}

// DecisionOperation is the global single-winner claim for one provider
// auth request (ADR-0005 §5). Exactly one row exists per (Provider,
// ProviderTenantID, AuthRequestID); LocalUserID is written by the winner
// as a binding and is never part of the unique key. The callback URL is
// never stored here.
type DecisionOperation struct {
	ID                  DecisionOperationID
	Provider            string
	ProviderTenantID    string
	AuthRequestID       string
	Decision            Decision
	Status              DecisionOperationStatus
	LocalUserID         identity.UserID
	ClientID            applications.OAuthClientID
	ErrorClass          ErrorClass
	ProviderSucceededAt time.Time // zero until the proof is persisted
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Key identifies the global single-winner claim of a decision operation.
type DecisionOperationKey struct {
	Provider         string
	ProviderTenantID string
	AuthRequestID    string
}

// Validate enforces the claim key input limits: provider required, auth
// request ID within the opaque-ID bounds (ADR-0005 §2).
func (k DecisionOperationKey) Validate() error {
	if k.Provider == "" {
		return errors.New("consent: empty provider")
	}
	return ValidateAuthRequestID(k.AuthRequestID)
}

// GrantStatus is the lifecycle state of a local grant.
type GrantStatus string

// Grant states. A revoked grant never enables consent reuse; re-consent
// reactivates the same (user, client) row with the new scope set.
const (
	GrantActive  GrantStatus = "active"
	GrantRevoked GrantStatus = "revoked"
)

// Grant is one (user × client) consent record. Scopes are the consented
// set at the last Allow; the row is upserted, never duplicated.
type Grant struct {
	ID        GrantID
	UserID    identity.UserID
	ClientID  applications.OAuthClientID
	Status    GrantStatus
	Scopes    []string
	GrantedAt time.Time
	// RevokedAt is zero while the grant has never been revoked.
	RevokedAt time.Time
	UpdatedAt time.Time
}

// HasScope reports whether the scope was consented on this grant.
func (g *Grant) HasScope(scope string) bool {
	for _, s := range g.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ScopesContain reports whether every requested scope is contained in the
// granted set (reuse precondition, ADR-0005 §7).
func (g *Grant) ScopesContain(requested []string) bool {
	for _, want := range requested {
		if !g.HasScope(want) {
			return false
		}
	}
	return true
}

// Sentinel errors returned by the grant store. Callers classify them into
// stable API outcomes; they never leak SQL detail.
var (
	// ErrDecisionConflict: the auth request was already claimed by another
	// decision. The loser receives a stable conflict result and must never
	// call the provider (ADR-0005 §5).
	ErrDecisionConflict = errors.New("consent: authorization request already claimed")
	// ErrDecisionStateConflict: a compare-and-set transition was attempted
	// from an unexpected state (e.g. committing without the
	// provider_succeeded proof).
	ErrDecisionStateConflict = errors.New("consent: decision operation state conflict")
	// ErrDecisionNotFound: no decision operation exists for the key.
	ErrDecisionNotFound = errors.New("consent: decision operation not found")
	// ErrGrantNotFound: no grant row exists for the (user, client) pair.
	ErrGrantNotFound = errors.New("consent: grant not found")
)

// AllowCommit carries the winner's Allow-side local commit inputs (ADR-0005
// §5 step 5): the grant upsert data and the durable audit events committed
// atomically with the terminal operation state.
type AllowCommit struct {
	OperationID DecisionOperationID
	UserID      identity.UserID
	ClientID    applications.OAuthClientID
	Scopes      []string
	Audit       []applications.SecurityEvent
}

// DenyCommit carries the winner's Deny-side local commit inputs. Deny
// creates no grant row (ADR-0005 §5).
type DenyCommit struct {
	OperationID DecisionOperationID
	UserID      identity.UserID
	Audit       []applications.SecurityEvent
}

// GrantStore persists consent decisions and grants (ADR-0005 §4, §5). The
// PostgreSQL repository implements it; higher layers never speak SQL. The
// provider call itself never runs inside a store transaction — callers
// follow the §5 ordering: claim → provider call → proof → commit.
type GrantStore interface {
	// ClaimDecisionOperation claims the global single-winner row for the
	// operation's (provider, provider_tenant_id, auth_request_id) key with
	// status pending. It returns the stored operation and won=true. When
	// the key is already claimed it returns the existing row, won=false and
	// ErrDecisionConflict; the caller must not call the provider.
	ClaimDecisionOperation(ctx context.Context, op DecisionOperation) (DecisionOperation, bool, error)

	// GetDecisionOperation reads the operation row by its global key.
	GetDecisionOperation(ctx context.Context, key DecisionOperationKey) (DecisionOperation, error)

	// RecordProviderSucceeded persists the provider success proof
	// (decision kind + time; never the callback URL) via a pending →
	// provider_succeeded compare-and-set. It fails with
	// ErrDecisionStateConflict from any other state.
	RecordProviderSucceeded(ctx context.Context, opID DecisionOperationID, at time.Time) error

	// CommitAllowDecision runs the Allow-side local commit in one
	// transaction: grant upsert + scope-set replacement + audit events +
	// provider_succeeded → succeeded terminal transition with the winner
	// user binding. A re-consent reactivates a revoked row and refreshes
	// granted_at; the (user, client) unique key forbids duplicates.
	CommitAllowDecision(ctx context.Context, commit AllowCommit) error

	// CommitDenyDecision runs the Deny-side local commit in one
	// transaction: audit events + provider_succeeded → succeeded terminal
	// transition with the winner user binding. It creates no grant row.
	CommitDenyDecision(ctx context.Context, commit DenyCommit) error

	// FailDecisionOperation terminates an operation without provider
	// success proof (pending → failed, recording the stable error class).
	// Rows carrying the provider_succeeded proof are never failed through
	// this path — reconciliation repairs them forward instead (ADR-0005
	// §4).
	FailDecisionOperation(ctx context.Context, opID DecisionOperationID, class ErrorClass) error

	// GetGrant reads the (user, client) grant with its consented scopes.
	// Returns ErrGrantNotFound when no row exists.
	GetGrant(ctx context.Context, userID identity.UserID, clientID applications.OAuthClientID) (Grant, error)
}
