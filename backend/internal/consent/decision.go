//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Consent decision orchestration service (allow/deny completion flows)
//

package consent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// Authorization decision orchestration (ADR-0005 §3, §5, §12): the ONLY
// interactive execution entry for user decisions. Unlike the resolution GET
// (derived on read, advisory), Decide re-enforces every condition
// server-side, runs the §5 ordering — full re-validation → immutable
// completion plan → global claim → provider CreateCallback →
// provider_succeeded proof → canonical local commit — and returns the
// provider callback URL as the frozen redirectUrl field. An
// already_authorized resolution observed earlier by the user agent is
// advisory only and never short-circuits this flow.

// DecisionKind is the interactive user decision (frozen contract body
// values).
type DecisionKind string

// Decision kinds.
const (
	DecisionAllow DecisionKind = "allow"
	DecisionDeny  DecisionKind = "deny"
)

// Valid reports whether the kind is one of the frozen contract values.
func (k DecisionKind) Valid() bool {
	return k == DecisionAllow || k == DecisionDeny
}

// CompletionKind maps the user decision onto its completion kind.
func (k DecisionKind) CompletionKind() CompletionKind {
	if k == DecisionAllow {
		return CompletionAllow
	}
	return CompletionAccessDenied
}

// Sentinel decision errors. The HTTP layer maps them onto stable error
// codes; only stable classes ever reach responses or logs (ADR-0005 §8).
var (
	// ErrDecisionRequestExpired: the provider request can no longer be
	// re-read (not found, expired, already completed), or a re-validation
	// invariant no longer holds. NotFound is externally indistinguishable
	// from "consumed by a successful CreateCallback" and is never evidence
	// of success (ADR-0005 §4).
	ErrDecisionRequestExpired = errors.New("consent: authorization request can no longer be decided")
	// ErrDecisionAlreadyDecided: the global single-winner claim resolved
	// elsewhere — another completion won, the provider success proof is
	// being (or was) repaired forward, or the provider rejected a replay.
	// The caller receives a stable conflict outcome and never a callback
	// URL (ADR-0005 §5).
	ErrDecisionAlreadyDecided = errors.New("consent: authorization request already decided")
	// ErrDecisionCredentialRequired: the session carries no finalizing
	// Version-2 provider session credential (legacy V1 sessions, absent or
	// unusable credentials). The flow fails closed into interactive
	// re-login, which upgrades the credential (ADR-0005 §3).
	ErrDecisionCredentialRequired = errors.New("consent: session credential required to finalize authorization")
)

// ProviderSessionCredentialReader decrypts the sealed Version-2 provider
// session credential of the CURRENTLY VALID session of the request
// (ADR-0005 §3). Implementations must bind the credential to the session
// actually authenticated on the request; the consent domain never touches
// session storage or crypto directly. Missing, legacy or unusable
// credentials surface as errors — never as a downgrade.
type ProviderSessionCredentialReader interface {
	ReadProviderSessionCredential(ctx context.Context, sessionID session.SessionID) (session.ProviderSessionCredential, error)
}

// DecisionSession is the session state a decision executes under: the
// acting user, the authentication instant (freshness predicate input) and
// the United Pass session identifier used to locate the sealed provider
// session credential.
type DecisionSession struct {
	UserID             identity.UserID
	AuthenticationTime time.Time
	SessionID          session.SessionID
}

// DecisionInput is one interactive decision: the opaque auth request ID,
// the decision kind and the acting session.
type DecisionInput struct {
	AuthRequestID string
	Decision      DecisionKind
	Session       *DecisionSession
}

// DecisionOutcome is the successful decision result. The provider
// callback URL stays wrapped in the redacted CallbackResult until the
// HTTP serialization boundary unwraps it via RedirectURL() — the domain
// layer never hands out a bare, freely loggable string (ADR-0005 §3,
// §11). Rendering the outcome itself (%v/%#v/slog/json) is always
// redacted.
type DecisionOutcome struct {
	callback CallbackResult
}

// NewDecisionOutcome wraps the provider callback into the redacted
// decision result.
func NewDecisionOutcome(callback CallbackResult) DecisionOutcome {
	return DecisionOutcome{callback: callback}
}

// RedirectURL unwraps the provider callback URL. Only the HTTP response
// serialization point may call it; the returned value is credential-grade
// and must never be logged, persisted or parsed (ADR-0005 §11).
func (o DecisionOutcome) RedirectURL() string { return o.callback.Raw() }

func (DecisionOutcome) String() string { return "[redacted authorization decision outcome]" }

func (DecisionOutcome) GoString() string { return "[redacted authorization decision outcome]" }

func (DecisionOutcome) LogValue() slog.Value {
	return slog.StringValue("[redacted authorization decision outcome]")
}

// DecisionService executes interactive user decisions under the §5
// ordering. It is safe for concurrent use; every dependency is immutable
// after construction. The session credential reader is NOT a service
// dependency: decryption is keyed by the currently valid session of each
// request and released after use, so Decide receives the per-request
// reader directly (ADR-0005 §3). DecideSilently and
// CompleteWithErrorCallback additionally serve the interaction gateway
// (§12) through the exact same claim → provider → proof → commit model.
type DecisionService struct {
	provider         AuthRequestProvider
	clients          ConsentClientResolver
	grants           GrantStore
	providerName     string
	providerTenantID string
	now              func() time.Time
}

// NewDecisionService builds the decision orchestration service. Every
// dependency is required (fail closed): a decision service missing any
// seam would silently mis-complete authorization requests.
func NewDecisionService(
	provider AuthRequestProvider,
	clients ConsentClientResolver,
	grants GrantStore,
	providerName string,
	providerTenantID string,
	now func() time.Time,
) (*DecisionService, error) {
	if provider == nil {
		return nil, errors.New("consent: decision service requires an auth request provider")
	}
	if clients == nil {
		return nil, errors.New("consent: decision service requires a client resolver")
	}
	if grants == nil {
		return nil, errors.New("consent: decision service requires a grant store")
	}
	if providerName == "" {
		return nil, errors.New("consent: decision service requires a provider name")
	}
	if now == nil {
		return nil, errors.New("consent: decision service requires a clock")
	}
	return &DecisionService{
		provider:         provider,
		clients:          clients,
		grants:           grants,
		providerName:     providerName,
		providerTenantID: providerTenantID,
		now:              now,
	}, nil
}

// Decide executes one user decision end to end. Execution order (ADR-0005
// §5, plus the P3.4 pre-hardening): re-read the provider auth request →
// re-validate prompts, client, redirect and scopes (shared resolution
// helpers) → re-check session freshness through the SAME
// authenticationSatisfied predicate resolution uses → build the immutable
// completion plan → global claim → provider CreateCallback →
// provider_succeeded proof → canonical local commit → redirectUrl.
func (s *DecisionService) Decide(
	ctx context.Context,
	input DecisionInput,
	credentials ProviderSessionCredentialReader,
) (DecisionOutcome, error) {
	if err := ValidateAuthRequestID(input.AuthRequestID); err != nil {
		return DecisionOutcome{}, err
	}
	if !input.Decision.Valid() {
		return DecisionOutcome{}, fmt.Errorf("consent: unknown decision kind %q", input.Decision)
	}
	if input.Session == nil || input.Session.UserID == "" {
		// The interactive entry point always runs behind an authenticated
		// session; anything else is a wiring failure, never an anonymous
		// decision.
		return DecisionOutcome{}, errors.New("consent: decision requires an authenticated session")
	}
	if credentials == nil {
		return DecisionOutcome{}, errors.New("consent: decision requires a session credential reader")
	}

	// 1. Provider re-read. A vanished or already-finalized request can
	// only ever terminate as expired (ADR-0005 §4).
	view, err := s.provider.GetAuthRequest(ctx, input.AuthRequestID)
	if err != nil {
		if IsClass(err, ClassNotFound) || IsClass(err, ClassExpired) || IsClass(err, ClassAlreadyCompleted) {
			return DecisionOutcome{}, ErrDecisionRequestExpired
		}
		return DecisionOutcome{}, err
	}

	// 2. Full re-validation with the exact helpers resolution uses —
	// prompt whitelist, client mapping, redirect exact match, scope
	// canonicalization + catalog subset. A GET that once rendered
	// "valid" gives no exemption: every fact is re-derived from the
	// provider view and the local records.
	facts, requestedScopes, err := s.validateInteractiveRequest(ctx, view)
	if err != nil {
		return DecisionOutcome{}, err
	}

	// 3. prompt=none is executed exclusively by the interaction gateway;
	// the interactive decision entry never serves it (ADR-0005 §9, §12).
	// Authentication freshness shares the single resolution predicate —
	// never a second copy of the prompt/max_age judgment.
	if view.HasPrompt(PromptNone) {
		return DecisionOutcome{}, ErrResolutionNotInteractive
	}
	sess := &ResolutionSession{
		UserID:             input.Session.UserID,
		AuthenticationTime: input.Session.AuthenticationTime,
	}
	if !authenticationSatisfied(view, sess, s.now()) {
		return DecisionOutcome{}, ErrDecisionRequestExpired
	}

	// 4. Allow additionally needs the sealed Version-2 provider session
	// credential. It is read BEFORE the claim so an unusable credential
	// fails closed without leaving a pending operation row behind
	// (ADR-0005 §3).
	var handle SessionHandle
	if input.Decision == DecisionAllow {
		handle, err = s.readAllowCredential(ctx, credentials, input.Session)
		if err != nil {
			return DecisionOutcome{}, err
		}
	}

	// 5. Global single-winner claim with the immutable completion plan.
	// Deny binds the acting user AND the client so the canonical audit
	// always carries a client association; Allow binds the normalized
	// scope snapshot validated above.
	op := DecisionOperation{
		ID:               NewDecisionOperationID(),
		Provider:         s.providerName,
		ProviderTenantID: s.providerTenantID,
		AuthRequestID:    input.AuthRequestID,
		CompletionKind:   input.Decision.CompletionKind(),
		Status:           DecisionOperationPending,
		LocalUserID:      input.Session.UserID,
		ClientID:         facts.Client.ID,
	}
	if input.Decision == DecisionAllow {
		op.Scopes = requestedScopes
	}
	var complete func(context.Context) (CallbackResult, error)
	if input.Decision == DecisionAllow {
		complete = func(ctx context.Context) (CallbackResult, error) {
			return s.provider.CompleteWithSession(ctx, input.AuthRequestID, handle)
		}
	} else {
		complete = func(ctx context.Context) (CallbackResult, error) {
			return s.provider.CompleteWithError(ctx, input.AuthRequestID, ReasonAccessDenied)
		}
	}
	return s.claimCompleteAndCommit(ctx, op, complete)
}

// ErrSilentReuseUnavailable: the authoritative grant re-check inside
// DecideSilently found the consent no longer silently reusable (revoked,
// scope-reduced, consent-mode change or prompt=consent). The gateway maps
// it onto the consent_required error callback; nothing was claimed
// (ADR-0005 §7, §12).
var ErrSilentReuseUnavailable = errors.New("consent: grant no longer silently reusable")

// DecideSilently executes the prompt=none silent Allow under the exact §5
// ordering — re-read the provider request, re-validate every fact,
// freshness through the shared predicate, an AUTHORITATIVE grant re-check
// before anything is claimed, the sealed credential, the global claim,
// provider completion, proof and canonical commit. The re-check closes the
// revocation window between the gateway pre-check and the claim: a grant
// revoked in between can never be silently reused, and the failure leaves
// no operation row behind (ADR-0005 §12).
func (s *DecisionService) DecideSilently(
	ctx context.Context,
	input DecisionInput,
	credentials ProviderSessionCredentialReader,
) (DecisionOutcome, error) {
	if err := ValidateAuthRequestID(input.AuthRequestID); err != nil {
		return DecisionOutcome{}, err
	}
	if input.Decision != DecisionAllow {
		return DecisionOutcome{}, fmt.Errorf("consent: silent execution supports only the allow decision, got %q", input.Decision)
	}
	if input.Session == nil || input.Session.UserID == "" {
		return DecisionOutcome{}, errors.New("consent: silent decision requires an authenticated session")
	}
	if credentials == nil {
		return DecisionOutcome{}, errors.New("consent: silent decision requires a session credential reader")
	}

	// 1. Provider re-read.
	view, err := s.provider.GetAuthRequest(ctx, input.AuthRequestID)
	if err != nil {
		if IsClass(err, ClassNotFound) || IsClass(err, ClassExpired) || IsClass(err, ClassAlreadyCompleted) {
			return DecisionOutcome{}, ErrDecisionRequestExpired
		}
		return DecisionOutcome{}, err
	}

	// 2. Silent execution belongs exclusively to exactly prompt=none; any
	// other value or combination is neither downgraded nor reinterpreted
	// (ADR-0005 §9). The gateway performs the same structural check
	// before routing here; this re-check keeps the seam fail-closed.
	if len(view.Prompts) != 1 || !view.HasPrompt(PromptNone) {
		return DecisionOutcome{}, ErrResolutionNotInteractive
	}

	// 3. Full business re-validation with the exact helpers resolution
	// uses.
	facts, requestedScopes, err := validateBusinessFacts(ctx, s.clients, s.providerName, view)
	if err != nil {
		if errors.Is(err, ErrClientUnknown) {
			return DecisionOutcome{}, ErrDecisionRequestExpired
		}
		return DecisionOutcome{}, err
	}

	// 4. Freshness through the single shared predicate.
	sess := &ResolutionSession{
		UserID:             input.Session.UserID,
		AuthenticationTime: input.Session.AuthenticationTime,
	}
	if !authenticationSatisfied(view, sess, s.now()) {
		return DecisionOutcome{}, ErrDecisionRequestExpired
	}

	// 5. Authoritative grant re-check BEFORE the credential read and the
	// claim: the gateway pre-check only selected this branch, it never
	// constituted the authorization fact (ADR-0005 §7, §12).
	reusable, err := grantReusable(ctx, s.grants, sess, view, facts.Client, requestedScopes)
	if err != nil {
		return DecisionOutcome{}, err
	}
	if !reusable {
		return DecisionOutcome{}, ErrSilentReuseUnavailable
	}

	// 6. Credential (before the claim; unusable fails closed with no
	// pending row).
	handle, err := s.readAllowCredential(ctx, credentials, input.Session)
	if err != nil {
		return DecisionOutcome{}, err
	}

	// 7. Claim → provider completion → proof → canonical commit, exactly
	// as the interactive Allow.
	op := DecisionOperation{
		ID:               NewDecisionOperationID(),
		Provider:         s.providerName,
		ProviderTenantID: s.providerTenantID,
		AuthRequestID:    input.AuthRequestID,
		CompletionKind:   CompletionAllow,
		Status:           DecisionOperationPending,
		LocalUserID:      input.Session.UserID,
		ClientID:         facts.Client.ID,
		Scopes:           requestedScopes,
	}
	return s.claimCompleteAndCommit(ctx, op, func(ctx context.Context) (CallbackResult, error) {
		return s.provider.CompleteWithSession(ctx, input.AuthRequestID, handle)
	})
}

// CompleteWithErrorCallback executes a NON-user-decision error-callback
// completion (login_required, consent_required, account_selection_required,
// request_not_supported, server_error, temporarily_unavailable) under the
// same §5 model: provider re-read → global claim → provider error callback
// → success proof → canonical error commit. User decisions (allow /
// access_denied) are rejected at the seam. The optional bindings (acting
// user, validated client) enrich the canonical audit whenever the gateway
// has already established them; no grant row is ever created (ADR-0005
// §5, §12).
func (s *DecisionService) CompleteWithErrorCallback(
	ctx context.Context,
	authRequestID string,
	kind CompletionKind,
	sess *DecisionSession,
	clientID applications.OAuthClientID,
) (DecisionOutcome, error) {
	if !kind.Valid() || kind.IsUserDecision() {
		return DecisionOutcome{}, fmt.Errorf("consent: %q is not an error-callback completion kind", kind)
	}
	reason, ok := kind.CallbackReason()
	if !ok {
		return DecisionOutcome{}, fmt.Errorf("consent: completion kind %q has no callback reason", kind)
	}
	if err := ValidateAuthRequestID(authRequestID); err != nil {
		return DecisionOutcome{}, err
	}

	// A vanished or already-finalized request can receive no callback
	// either; terminate the completion as expired.
	if _, err := s.provider.GetAuthRequest(ctx, authRequestID); err != nil {
		if IsClass(err, ClassNotFound) || IsClass(err, ClassExpired) || IsClass(err, ClassAlreadyCompleted) {
			return DecisionOutcome{}, ErrDecisionRequestExpired
		}
		return DecisionOutcome{}, err
	}

	op := DecisionOperation{
		ID:               NewDecisionOperationID(),
		Provider:         s.providerName,
		ProviderTenantID: s.providerTenantID,
		AuthRequestID:    authRequestID,
		CompletionKind:   kind,
		Status:           DecisionOperationPending,
		ClientID:         clientID,
	}
	if sess != nil {
		op.LocalUserID = sess.UserID
	}
	return s.claimCompleteAndCommit(ctx, op, func(ctx context.Context) (CallbackResult, error) {
		return s.provider.CompleteWithError(ctx, authRequestID, reason)
	})
}

// readAllowCredential reads and validates the sealed Version-2 provider
// session credential for an Allow completion. It runs before the claim so
// an unusable credential fails closed without leaving a pending operation
// row behind (ADR-0005 §3).
func (s *DecisionService) readAllowCredential(
	ctx context.Context,
	credentials ProviderSessionCredentialReader,
	sess *DecisionSession,
) (SessionHandle, error) {
	cred, err := credentials.ReadProviderSessionCredential(ctx, sess.SessionID)
	if err != nil {
		if errors.Is(err, session.ErrProviderSessionCredentialMissing) {
			return SessionHandle{}, ErrDecisionCredentialRequired
		}
		return SessionHandle{}, err
	}
	if !cred.CanFinalizeAuthorization() || cred.Provider() != s.providerName {
		return SessionHandle{}, ErrDecisionCredentialRequired
	}
	handle, err := NewSessionHandle(cred.SessionID(), cred.SessionToken())
	if err != nil {
		return SessionHandle{}, ErrDecisionCredentialRequired
	}
	return handle, nil
}

// claimCompleteAndCommit runs the global single-winner claim, the one-shot
// provider completion (outside any store transaction), the provider
// success proof and the canonical local commit dispatched from the locked
// plan's completion kind. Every completion — interactive decisions, silent
// allows and gateway error callbacks — flows through this single sequence,
// so the §5 consistency model has exactly one implementation (ADR-0005
// §5, §12). A commit failure does not swallow the redirect: forward
// reconciliation repairs the local state from the persisted proof.
func (s *DecisionService) claimCompleteAndCommit(
	ctx context.Context,
	op DecisionOperation,
	complete func(context.Context) (CallbackResult, error),
) (DecisionOutcome, error) {
	stored, won, err := s.grants.ClaimDecisionOperation(ctx, op)
	if err != nil {
		if errors.Is(err, ErrDecisionConflict) {
			return DecisionOutcome{}, s.resolveClaimConflict(ctx, stored)
		}
		return DecisionOutcome{}, err
	}
	if !won {
		// Defensive mirror of the conflict path.
		return DecisionOutcome{}, s.resolveClaimConflict(ctx, stored)
	}

	callback, err := complete(ctx)
	if err != nil {
		return DecisionOutcome{}, s.handleProviderFailure(ctx, stored.ID, err)
	}

	// Persist the provider success proof (kind + time, never the callback
	// URL). A CAS conflict here means the row was terminated or committed
	// out from under us — the provider outcome can no longer be surfaced
	// as this caller's win.
	if err := s.grants.RecordProviderSucceeded(ctx, stored.ID, s.now()); err != nil {
		return DecisionOutcome{}, ErrDecisionAlreadyDecided
	}

	// Canonical local commit from the locked plan. The provider
	// completion already happened and the callback URL is unrecoverable
	// (one-shot API), so a commit failure must NOT swallow the redirect
	// (ADR-0005 §4, §5).
	_ = repairCompletionForward(ctx, s.grants, stored)

	return NewDecisionOutcome(callback), nil
}

// validateBusinessFacts re-derives every business precondition from the
// provider view and the local records, consuming the exact helpers
// resolution uses. Any failure terminates the decision as expired: the
// request can no longer be served through this entry point, and the
// precise reason is never surfaced (client anti-enumeration, ADR-0005
// §7) — only logged by the HTTP layer through the stable classes.
func validateBusinessFacts(
	ctx context.Context,
	clients ConsentClientResolver,
	providerName string,
	view *AuthRequestView,
) (ConsentClientFacts, []string, error) {
	facts, err := clients.ResolveConsentClient(ctx, providerName, view.ClientID)
	if err != nil {
		return ConsentClientFacts{}, nil, err
	}
	if !applications.EffectiveClientActive(facts.Application.Status, facts.Client.Status) {
		return ConsentClientFacts{}, nil, ErrClientUnknown
	}
	if !hasExactRedirectURI(facts.Client.RedirectURIs, view.RedirectURI) {
		return ConsentClientFacts{}, nil, ErrClientUnknown
	}
	requestedScopes, err := NormalizeScopes(view.Scopes)
	if err != nil || len(requestedScopes) == 0 {
		return ConsentClientFacts{}, nil, ErrClientUnknown
	}
	if len(disallowedScopes(requestedScopes, facts.Client.Scopes)) > 0 {
		return ConsentClientFacts{}, nil, ErrClientUnknown
	}
	return facts, requestedScopes, nil
}

// validateInteractiveRequest re-derives every business precondition from
// the provider view and the local records, consuming the exact helpers
// resolution uses. Any failure terminates the decision as expired: the
// request can no longer be served through this entry point, and the
// precise reason is never surfaced (client anti-enumeration, ADR-0005
// §7) — only logged by the HTTP layer through the stable classes.
func (s *DecisionService) validateInteractiveRequest(ctx context.Context, view *AuthRequestView) (ConsentClientFacts, []string, error) {
	if err := validateInteractivePrompts(view); err != nil {
		return ConsentClientFacts{}, nil, ErrDecisionRequestExpired
	}
	facts, requestedScopes, err := validateBusinessFacts(ctx, s.clients, s.providerName, view)
	if err != nil {
		if errors.Is(err, ErrClientUnknown) {
			return ConsentClientFacts{}, nil, ErrDecisionRequestExpired
		}
		return ConsentClientFacts{}, nil, err
	}
	return facts, requestedScopes, nil
}

// resolveClaimConflict maps a lost global claim onto the stable outcome:
// a row already carrying the provider success proof is repaired forward
// (its local commit may have been lost mid-flight); every other state is
// a plain conflict. The loser never calls the provider (ADR-0005 §5).
func (s *DecisionService) resolveClaimConflict(ctx context.Context, existing DecisionOperation) error {
	if existing.Status == DecisionOperationProviderSucceeded {
		_ = repairCompletionForward(ctx, s.grants, existing)
	}
	return ErrDecisionAlreadyDecided
}

// handleProviderFailure terminates the claimed operation fail-closed and
// maps the provider error onto the stable decision errors. The one-shot
// replay classification surfaces as the stable already-decided conflict;
// every other class (including the deterministic user-admission failure)
// keeps its classified error so the HTTP layer can apply the §8
// mapping. The operation is failed through the store's pending-only CAS —
// rows carrying the provider success proof are never failed here
// (ADR-0005 §4, §5, §8).
func (s *DecisionService) handleProviderFailure(ctx context.Context, opID DecisionOperationID, err error) error {
	class, ok := ErrorClassOf(err)
	if !ok {
		return err
	}
	_ = s.grants.FailDecisionOperation(ctx, opID, class)
	if class == ClassAlreadyCompleted {
		return ErrDecisionAlreadyDecided
	}
	return err
}

// repairCompletionForward completes the local terminal state of an
// operation that already carries the provider success proof, dispatching
// on the bound completion kind. Used both by the decision conflict path
// and by the background reconciler; commit inputs carry only the
// operation ID, so the repair can never drift from the immutable plan
// (ADR-0005 §4, §5).
func repairCompletionForward(ctx context.Context, grants GrantStore, op DecisionOperation) error {
	switch {
	case op.CompletionKind == CompletionAllow:
		return grants.CommitAllowDecision(ctx, AllowCommit{OperationID: op.ID})
	case op.CompletionKind == CompletionAccessDenied:
		return grants.CommitDenyDecision(ctx, DenyCommit{OperationID: op.ID})
	case op.CompletionKind.Valid():
		return grants.CommitErrorCompletion(ctx, ErrorCompletionCommit{OperationID: op.ID})
	default:
		return fmt.Errorf("consent: operation %s carries unknown completion kind %q", op.ID, op.CompletionKind)
	}
}
