package consent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	// MaxProviderNameLen bounds the provider identifier stored on decision
	// operations. United Pass currently runs a single provider.
	MaxProviderNameLen = 64
	// MaxScopeTokenLen bounds one scope token. OIDC scopes are short opaque
	// identifiers; anything longer is malformed input, not a scope.
	MaxScopeTokenLen = 128
	// MaxScopeCount bounds the scope set of one completion plan. Real OIDC
	// requests carry a handful of scopes; unbounded sets are abuse surface.
	MaxScopeCount = 32
)

// NormalizeScopes returns the canonical form of a scope set: every token
// validated, duplicates removed and the result deterministically sorted.
// This is the ONLY place scope facts are canonicalized — the claim
// snapshot and the provider call must consume the same normalized result,
// never compute their own.
func NormalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) > MaxScopeCount {
		return nil, fmt.Errorf("consent: more than %d scopes", MaxScopeCount)
	}
	seen := make(map[string]bool, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope == "" {
			return nil, errors.New("consent: empty scope token")
		}
		if strings.ContainsAny(scope, " \t\n\r\v\f") {
			return nil, fmt.Errorf("consent: scope token %q contains whitespace", scope)
		}
		if len(scope) > MaxScopeTokenLen {
			return nil, fmt.Errorf("consent: scope token exceeds %d bytes", MaxScopeTokenLen)
		}
		if seen[scope] {
			continue
		}
		seen[scope] = true
		out = append(out, scope)
	}
	sort.Strings(out)
	return out, nil
}

// ScopesAreCanonical reports whether a persisted scope set is already in
// canonical form: re-normalizing it yields exactly the stored sequence
// (every token valid, no duplicates, deterministically sorted). Commits
// and reconciliation re-check persisted snapshots with this predicate so
// a row corrupted after claim time (empty token, whitespace, oversize
// token, duplicates or unordered entries inserted out-of-band) fails
// closed instead of completing an inconsistent grant (ADR-0005 §5).
func ScopesAreCanonical(scopes []string) bool {
	normalized, err := NormalizeScopes(scopes)
	if err != nil {
		return false
	}
	if len(normalized) != len(scopes) {
		return false
	}
	for i, scope := range normalized {
		if scope != scopes[i] {
			return false
		}
	}
	return true
}

// NewGrantID generates a fresh grant ID.
func NewGrantID() GrantID {
	return GrantID(grantIDPrefix + consentRandomHex(consentIDRandomByteLength))
}

// HasGrantIDPrefix reports whether s looks like a grant ID. Grant
// lookups by URL-supplied identifiers fail closed on anything else.
func HasGrantIDPrefix(s string) bool {
	return len(s) > len(grantIDPrefix) && s[:len(grantIDPrefix)] == grantIDPrefix
}

// NewDecisionOperationID generates a fresh decision operation ID.
func NewDecisionOperationID() DecisionOperationID {
	return DecisionOperationID(decisionOperationIDPrefix + consentRandomHex(consentIDRandomByteLength))
}

// HasDecisionOperationIDPrefix reports whether s looks like a decision
// operation ID. Claims fail closed on anything else.
func HasDecisionOperationIDPrefix(s string) bool {
	return len(s) > len(decisionOperationIDPrefix) && s[:len(decisionOperationIDPrefix)] == decisionOperationIDPrefix
}

func consentRandomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is fatal for identity generation.
		panic(fmt.Sprintf("consent: generate random id: %v", err))
	}
	return hex.EncodeToString(buf)
}

// CompletionKind is the durable semantics of how an auth request is
// completed through the provider's one-shot CreateCallback. The two user
// decisions (allow, access_denied) and the gateway/provider error
// callbacks are all completion kinds: every one-shot completion needs the
// same global single-winner claim, success proof, lost-response handling
// and audit trail (ADR-0005 §5, §9, §12).
type CompletionKind string

// Completion kinds. The string values are the stored and audited values;
// the error-callback kinds match the OIDC error names delivered to the RP.
const (
	CompletionAllow                  CompletionKind = "allow"
	CompletionAccessDenied           CompletionKind = "access_denied"
	CompletionLoginRequired          CompletionKind = "login_required"
	CompletionConsentRequired        CompletionKind = "consent_required"
	CompletionAccountSelectionNeeded CompletionKind = "account_selection_required"
	CompletionRequestNotSupported    CompletionKind = "request_not_supported"
	CompletionServerError            CompletionKind = "server_error"
	CompletionTemporarilyUnavailable CompletionKind = "temporarily_unavailable"
)

// Valid reports whether the completion kind is a known value.
func (k CompletionKind) Valid() bool {
	switch k {
	case CompletionAllow, CompletionAccessDenied,
		CompletionLoginRequired, CompletionConsentRequired,
		CompletionAccountSelectionNeeded, CompletionRequestNotSupported,
		CompletionServerError, CompletionTemporarilyUnavailable:
		return true
	default:
		return false
	}
}

// IsUserDecision reports whether the kind is an interactive user decision
// (allow / access_denied) as opposed to a gateway or provider error
// callback completion.
func (k CompletionKind) IsUserDecision() bool {
	return k == CompletionAllow || k == CompletionAccessDenied
}

// CreatesGrant reports whether the kind produces a local grant row on
// success. Only Allow does.
func (k CompletionKind) CreatesGrant() bool {
	return k == CompletionAllow
}

// CallbackReason maps user-decision kinds to their provider error-callback
// reason; Allow has none (it completes with a session).
func (k CompletionKind) CallbackReason() (CallbackErrorReason, bool) {
	switch k {
	case CompletionAccessDenied:
		return ReasonAccessDenied, true
	case CompletionLoginRequired:
		return ReasonLoginRequired, true
	case CompletionConsentRequired:
		return ReasonConsentRequired, true
	case CompletionAccountSelectionNeeded:
		return ReasonAccountSelectionRequired, true
	case CompletionRequestNotSupported:
		return ReasonRequestNotSupported, true
	case CompletionServerError:
		return ReasonServerError, true
	case CompletionTemporarilyUnavailable:
		return ReasonTemporarilyUnavailable, true
	default:
		return 0, false
	}
}

// AuditEventType is the canonical audit event type of a committed
// completion. The audit row is constructed from the operation row alone
// after it is locked, so reconciliation never needs a second audit fact
// source (ADR-0005 §5).
func (k CompletionKind) AuditEventType() string {
	switch k {
	case CompletionAllow:
		return applications.EventConsentGrantAllowed
	case CompletionAccessDenied:
		return applications.EventConsentAccessDenied
	default:
		return applications.EventConsentErrorCompleted
	}
}

// AuditOperation is the canonical audit operation name of the kind.
func (k CompletionKind) AuditOperation() string {
	switch k {
	case CompletionAllow:
		return "consent_allow"
	case CompletionAccessDenied:
		return "consent_deny"
	default:
		return "consent_error_completion"
	}
}

// AuditResult is the canonical audit outcome of the kind: only Allow is a
// success; every denial and error-callback completion is recorded denied.
func (k CompletionKind) AuditResult() applications.SecurityEventResult {
	if k == CompletionAllow {
		return applications.SecurityEventSuccess
	}
	return applications.SecurityEventDenied
}

// AuditFailureClass distinguishes error-callback completions inside the
// audit payload (login_required vs server_error vs …). User decisions
// carry no failure class.
func (k CompletionKind) AuditFailureClass() string {
	if k.IsUserDecision() {
		return ""
	}
	return string(k)
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
	// proof (completion kind + time, never the callback URL) is persisted;
	// the local commit is pending. Only rows in this state may ever be
	// repaired forward by reconciliation (ADR-0005 §4) — and the row alone
	// carries the whole immutable completion plan needed for the repair.
	DecisionOperationProviderSucceeded DecisionOperationStatus = "provider_succeeded"
	// DecisionOperationSucceeded: the local terminal state is committed.
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
// ProviderTenantID, AuthRequestID).
//
// The completion plan — CompletionKind, LocalUserID, ClientID and the
// Scopes snapshot — is immutable from claim time: it is persisted BEFORE
// the provider CreateCallback runs, so forward reconciliation after a
// crash between provider success and local commit can complete the grant
// and audit from the row alone, without a browser and without the
// already-consumed provider request. The callback URL is never stored.
type DecisionOperation struct {
	ID                  DecisionOperationID
	Provider            string
	ProviderTenantID    string
	AuthRequestID       string
	CompletionKind      CompletionKind
	Status              DecisionOperationStatus
	LocalUserID         identity.UserID
	ClientID            applications.OAuthClientID
	Scopes              []string // consented scope snapshot (allow only)
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

// Validate enforces the claim key input limits: provider required and
// bounded, auth request ID within the opaque-ID bounds (ADR-0005 §2).
func (k DecisionOperationKey) Validate() error {
	if k.Provider == "" {
		return errors.New("consent: empty provider")
	}
	if len(k.Provider) > MaxProviderNameLen {
		return fmt.Errorf("consent: provider name exceeds %d bytes", MaxProviderNameLen)
	}
	return ValidateAuthRequestID(k.AuthRequestID)
}

// ValidateForClaim enforces the completion-plan invariants before the
// operation row is written (fail closed): a well-formed operation ID, a
// valid key, a known completion kind, and the per-kind bindings —
// user decisions bind the acting user AND the client (so the canonical
// audit always carries a client association), Allow additionally binds a
// non-empty NORMALIZED scope snapshot, deny and error callbacks never
// carry scopes. Scope validation runs on the normalized set, so a set
// that normalizes to nothing (e.g. []string{""}) can never be claimed.
func (op DecisionOperation) ValidateForClaim() error {
	if !HasDecisionOperationIDPrefix(string(op.ID)) {
		return errors.New("consent: invalid decision operation id")
	}
	if err := (DecisionOperationKey{
		Provider:         op.Provider,
		ProviderTenantID: op.ProviderTenantID,
		AuthRequestID:    op.AuthRequestID,
	}).Validate(); err != nil {
		return err
	}
	if !op.CompletionKind.Valid() {
		return fmt.Errorf("consent: invalid completion kind %q", op.CompletionKind)
	}
	switch {
	case op.CompletionKind == CompletionAllow:
		if op.LocalUserID == "" {
			return errors.New("consent: allow completion requires a bound user")
		}
		if op.ClientID == "" {
			return errors.New("consent: allow completion requires a bound client")
		}
		normalized, err := NormalizeScopes(op.Scopes)
		if err != nil {
			return err
		}
		if len(normalized) == 0 {
			return errors.New("consent: allow completion requires a non-empty scope snapshot")
		}
	case op.CompletionKind.IsUserDecision(): // access_denied
		if op.LocalUserID == "" {
			return errors.New("consent: deny completion requires a bound user")
		}
		if op.ClientID == "" {
			return errors.New("consent: deny completion requires a bound client")
		}
		if len(op.Scopes) > 0 {
			return errors.New("consent: deny completion must not carry scopes")
		}
	default: // error callbacks: user optional (none without a session)
		if len(op.Scopes) > 0 {
			return errors.New("consent: error callback completion must not carry scopes")
		}
	}
	return nil
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
	// completion. The loser receives a stable conflict result and must
	// never call the provider (ADR-0005 §5).
	ErrDecisionConflict = errors.New("consent: authorization request already claimed")
	// ErrDecisionStateConflict: a compare-and-set transition was attempted
	// from an unexpected state or against a mismatched completion plan
	// (e.g. committing an allow without the provider_succeeded proof, or
	// committing a deny operation through the allow path).
	ErrDecisionStateConflict = errors.New("consent: decision operation state conflict")
	// ErrDecisionNotFound: no decision operation exists for the key.
	ErrDecisionNotFound = errors.New("consent: decision operation not found")
	// ErrGrantNotFound: no grant row exists for the (user, client) pair.
	ErrGrantNotFound = errors.New("consent: grant not found")
)

// AllowCommit carries the winner's Allow-side local commit inputs (ADR-0005
// §5 step 5). It deliberately carries NOTHING but the operation ID: user,
// client, scopes and the audit event are all read from / constructed from
// the immutable plan bound on the operation row at claim time, so the
// commit can never drift from what the provider completed and a
// reconciler needs only the operation ID.
type AllowCommit struct {
	OperationID DecisionOperationID
}

// DenyCommit carries the winner's Deny-side local commit inputs. Deny
// creates no grant row (ADR-0005 §5); like AllowCommit it carries only
// the operation ID — the canonical audit is built from the row.
type DenyCommit struct {
	OperationID DecisionOperationID
}

// ErrorCompletionCommit carries the local terminal commit of a gateway or
// provider error-callback completion (login_required, consent_required,
// account_selection_required, request_not_supported, server_error,
// temporarily_unavailable). No grant is ever involved; only the operation
// ID travels with the commit.
type ErrorCompletionCommit struct {
	OperationID DecisionOperationID
}

// GrantStore persists consent decisions and grants (ADR-0005 §4, §5). The
// PostgreSQL repository implements it; higher layers never speak SQL. The
// provider call itself never runs inside a store transaction — callers
// follow the §5 ordering: claim (persisting the immutable completion
// plan) → provider call → proof → commit.
type GrantStore interface {
	// ClaimDecisionOperation claims the global single-winner row for the
	// operation's (provider, provider_tenant_id, auth_request_id) key,
	// persisting the full immutable completion plan (kind, user, client,
	// scope snapshot) with status pending. It returns the row exactly as
	// stored (status, timestamps and bindings read back from the database)
	// and won=true. When the key is already claimed it returns the
	// existing row, won=false and ErrDecisionConflict; the caller must not
	// call the provider.
	ClaimDecisionOperation(ctx context.Context, op DecisionOperation) (DecisionOperation, bool, error)

	// GetDecisionOperation reads the operation row (including its scope
	// snapshot) by its global key.
	GetDecisionOperation(ctx context.Context, key DecisionOperationKey) (DecisionOperation, error)

	// RecordProviderSucceeded persists the provider success proof
	// (completion kind is already on the row; this records the time —
	// never the callback URL) via a pending → provider_succeeded
	// compare-and-set. It fails with ErrDecisionStateConflict from any
	// other state.
	RecordProviderSucceeded(ctx context.Context, opID DecisionOperationID, at time.Time) error

	// CommitAllowDecision runs the Allow-side local commit in one
	// transaction: the operation is locked and verified against its bound
	// plan (status provider_succeeded, kind allow, complete user/client/
	// scope bindings), then the grant upsert, scope-set replacement, the
	// single canonical audit event (constructed from the locked row) and
	// the terminal transition commit. A re-consent reactivates a revoked
	// row and refreshes granted_at; the (user, client) unique key forbids
	// duplicates. The caller supplies no user, client, scope or audit
	// facts of its own.
	CommitAllowDecision(ctx context.Context, commit AllowCommit) error

	// CommitDenyDecision runs the Deny-side local commit in one
	// transaction: the locked operation must be provider_succeeded with
	// kind access_denied and a complete binding (non-empty user); the
	// canonical audit + terminal transition commit. It creates no grant
	// row.
	CommitDenyDecision(ctx context.Context, commit DenyCommit) error

	// CommitErrorCompletion terminates an error-callback completion
	// (login_required, consent_required, account_selection_required,
	// request_not_supported, server_error, temporarily_unavailable): the
	// locked operation must be provider_succeeded with a matching
	// non-decision kind and no scope snapshot; the canonical audit +
	// terminal transition commit, no grant.
	CommitErrorCompletion(ctx context.Context, commit ErrorCompletionCommit) error

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
