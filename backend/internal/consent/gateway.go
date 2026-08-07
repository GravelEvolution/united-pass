//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Authorization Interaction Gateway domain service: prompt routing, silent execution and error callbacks
//

package consent

import (
	"context"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
)

// GatewayActionKind enumerates the outcomes of one interaction gateway
// routing decision (ADR-0005 §12). The gateway never renders UI: every
// outcome is either a 302 (provider callback URL, /login or /authorize) or
// a stable local failure page.
type GatewayActionKind int

// Gateway action kinds.
const (
	// ActionRedirectLogin sends the user agent to the Next.js login page
	// with requestId; (re-)authentication is required.
	ActionRedirectLogin GatewayActionKind = iota
	// ActionRedirectAuthorize sends the user agent to the Next.js consent
	// page with requestId. Interactive already_authorized requests also go
	// here: the frontend owns the no-form continuation into the decision
	// endpoint (ADR-0005 §7); the gateway never silent-completes an
	// interactive request.
	ActionRedirectAuthorize
	// ActionProviderCallback 302s to the provider-verified callback URL
	// carried in Outcome: silent Allow (code callback) or an error
	// callback (*_required / request_not_supported).
	ActionProviderCallback
	// ActionLocalFailure renders the stable local error page; no provider
	// callback exists for these outcomes.
	ActionLocalFailure
)

// LocalFailureKind classifies stable gateway failures for the HTTP status
// selection; the rendered page is fixed text in every case (no request
// input is ever reflected).
type LocalFailureKind int

// Local failure kinds.
const (
	// LocalFailureBadRequest: invalid parameters, invalid prompt
	// combinations, or terminal request states (client/redirect/scope).
	LocalFailureBadRequest LocalFailureKind = iota
	// LocalFailureExpired: the provider request is gone or finalized.
	LocalFailureExpired
	// LocalFailureInternal: an unclassified fault.
	LocalFailureInternal
)

// GatewayAction is one routing outcome. Outcome stays redacted end to end;
// only the HTTP serialization point unwraps it into the Location header
// (ADR-0005 §3, §11).
type GatewayAction struct {
	Kind    GatewayActionKind
	Outcome DecisionOutcome
	Failure LocalFailureKind
}

// InteractionGatewayService is the server-side execution entry for the
// non-interactive authorization branches (ADR-0005 §12). It alone sees the
// provider auth request, the United Pass session and the sealed provider
// session credential. Routing reuses the single resolution predicate
// (authenticationSatisfied), the single reuse judgment (grantReusable) and
// the single §5 completion model (DecisionService) — it introduces no
// second consistency model and no duplicated authorization judgment. It is
// safe for concurrent use; every dependency is immutable after
// construction.
type InteractionGatewayService struct {
	provider     AuthRequestProvider
	clients      ConsentClientResolver
	grants       GrantReader
	resolution   *ResolutionService
	decisions    *DecisionService
	providerName string
	now          func() time.Time
}

// NewInteractionGatewayService builds the gateway. Every dependency is
// required (fail closed): a gateway missing any seam could not execute
// prompt=none safely.
func NewInteractionGatewayService(
	provider AuthRequestProvider,
	clients ConsentClientResolver,
	grants GrantReader,
	resolution *ResolutionService,
	decisions *DecisionService,
	providerName string,
	now func() time.Time,
) (*InteractionGatewayService, error) {
	if provider == nil {
		return nil, errors.New("consent: interaction gateway requires an auth request provider")
	}
	if clients == nil {
		return nil, errors.New("consent: interaction gateway requires a client resolver")
	}
	if grants == nil {
		return nil, errors.New("consent: interaction gateway requires a grant reader")
	}
	if resolution == nil {
		return nil, errors.New("consent: interaction gateway requires the resolution service")
	}
	if decisions == nil {
		return nil, errors.New("consent: interaction gateway requires the decision service")
	}
	if providerName == "" {
		return nil, errors.New("consent: interaction gateway requires a provider name")
	}
	if now == nil {
		return nil, errors.New("consent: interaction gateway requires a clock")
	}
	return &InteractionGatewayService{
		provider:     provider,
		clients:      clients,
		grants:       grants,
		resolution:   resolution,
		decisions:    decisions,
		providerName: providerName,
		now:          now,
	}, nil
}

// Route executes one gateway arrival (ADR-0005 §12). The sess/credentials
// pair describes the United Pass session of THIS request (nil when absent);
// credentials are only ever consumed by the silent Allow path. Errors
// returned from Route are unclassified faults the HTTP layer renders as the
// internal local failure page — never with the callback URL.
func (g *InteractionGatewayService) Route(
	ctx context.Context,
	authRequestID string,
	sess *DecisionSession,
	credentials ProviderSessionCredentialReader,
) (GatewayAction, error) {
	if err := ValidateAuthRequestID(authRequestID); err != nil {
		return GatewayAction{Kind: ActionLocalFailure, Failure: LocalFailureBadRequest}, nil
	}

	// 1. Provider read. A vanished or finalized request has no callback
	// path left: stable local failure (ADR-0005 §4).
	view, err := g.provider.GetAuthRequest(ctx, authRequestID)
	if err != nil {
		if IsClass(err, ClassNotFound) || IsClass(err, ClassExpired) || IsClass(err, ClassAlreadyCompleted) {
			return GatewayAction{Kind: ActionLocalFailure, Failure: LocalFailureExpired}, nil
		}
		return GatewayAction{}, err
	}

	// 2. Structural prompt validation BEFORE any semantic short-circuit,
	// through the single shared rule (validatePromptStructure): unknown
	// values and invalid combinations are neither downgraded nor
	// reinterpreted (ADR-0005 §9) — they fail locally, never through a
	// *_required callback that would assign them a meaning. Structure only:
	// create/select_account stay semantically routable below.
	if err := validatePromptStructure(view); err != nil {
		return GatewayAction{Kind: ActionLocalFailure, Failure: LocalFailureBadRequest}, nil
	}
	hasNone := view.HasPrompt(PromptNone)

	// 3. Semantic routing.
	switch {
	case hasNone:
		return g.executeNone(ctx, authRequestID, view, sess, credentials)
	case view.HasPrompt(PromptCreate):
		// Registration is a Phase 3 non-goal: fail through the provider
		// error callback regardless of the session state; never silently
		// ignored, never routed to a nonexistent registration page.
		return g.completeError(ctx, authRequestID, CompletionRequestNotSupported, sess, "")
	case view.HasPrompt(PromptSelectAccount):
		// Single account per session: fail through the provider error
		// callback; the flow never stalls on a United Pass page.
		return g.completeError(ctx, authRequestID, CompletionAccountSelectionNeeded, sess, "")
	default:
		return g.routeInteractive(ctx, authRequestID, sess)
	}
}

// executeNone runs the prompt=none branch entirely at the gateway: no
// login or consent UI is ever rendered (ADR-0005 §9). The pre-checks below
// only decide which completion to attempt — the authorization fact is
// re-established inside DecideSilently (freshness + authoritative grant
// re-check) before anything is claimed.
func (g *InteractionGatewayService) executeNone(
	ctx context.Context,
	authRequestID string,
	view *AuthRequestView,
	sess *DecisionSession,
	credentials ProviderSessionCredentialReader,
) (GatewayAction, error) {
	resSession := resolutionSessionOf(sess)

	// No session, or one that does not satisfy the request's freshness
	// requirements ⇒ login_required.
	if sess == nil || sess.UserID == "" || !authenticationSatisfied(view, resSession, g.now()) {
		return g.completeError(ctx, authRequestID, CompletionLoginRequired, sess, "")
	}

	// Business facts for the reuse pre-check. Terminal facts failures have
	// no error-callback semantics — stable local failure.
	facts, requestedScopes, err := validateBusinessFacts(ctx, g.clients, g.providerName, view)
	if err != nil {
		if errors.Is(err, ErrClientUnknown) {
			return GatewayAction{Kind: ActionLocalFailure, Failure: LocalFailureBadRequest}, nil
		}
		return GatewayAction{}, err
	}

	// Session present but consent not silently reusable ⇒
	// consent_required.
	reusable, err := grantReusable(ctx, g.grants, resSession, view, facts.Client, requestedScopes)
	if err != nil {
		return GatewayAction{}, err
	}
	if !reusable {
		return g.completeError(ctx, authRequestID, CompletionConsentRequired, sess, facts.Client.ID)
	}

	// Silent Allow: an ordinary decision under §5, re-checking every fact
	// including grant reuse before the claim.
	outcome, err := g.decisions.DecideSilently(ctx, DecisionInput{
		AuthRequestID: authRequestID,
		Decision:      DecisionAllow,
		Session:       sess,
	}, credentials)
	if err != nil {
		switch {
		case errors.Is(err, ErrSilentReuseUnavailable):
			// Revocation (or another reuse precondition) landed between
			// the pre-check and the authoritative re-check: the request
			// can no longer complete silently.
			return g.completeError(ctx, authRequestID, CompletionConsentRequired, sess, facts.Client.ID)
		case errors.Is(err, ErrDecisionCredentialRequired):
			// Legacy session without a sealed Version-2 credential: only
			// a fresh login can produce one (ADR-0005 §3).
			return g.completeError(ctx, authRequestID, CompletionLoginRequired, sess, "")
		case errors.Is(err, ErrDecisionRequestExpired),
			errors.Is(err, ErrDecisionAlreadyDecided),
			errors.Is(err, ErrResolutionNotInteractive):
			return GatewayAction{Kind: ActionLocalFailure, Failure: LocalFailureExpired}, nil
		}
		return GatewayAction{}, err
	}
	return GatewayAction{Kind: ActionProviderCallback, Outcome: outcome}, nil
}

// routeInteractive sends interactive requests into Next.js through the
// single resolution judgment: (re-)authentication needed ⇒ /login, consent
// display (including the already_authorized no-form continuation) ⇒
// /authorize, terminal states ⇒ stable local failure. The gateway renders
// no UI and never silent-completes an interactive request (ADR-0005 §7,
// §12).
func (g *InteractionGatewayService) routeInteractive(
	ctx context.Context,
	authRequestID string,
	sess *DecisionSession,
) (GatewayAction, error) {
	resolved, err := g.resolution.Resolve(ctx, ResolutionInput{
		AuthRequestID: authRequestID,
		Session:       resolutionSessionOf(sess),
	})
	if err != nil {
		if errors.Is(err, ErrResolutionNotInteractive) {
			// Defensive: none/create/select_account/invalid combinations
			// are short-circuited before this point.
			return GatewayAction{Kind: ActionLocalFailure, Failure: LocalFailureBadRequest}, nil
		}
		return GatewayAction{}, err
	}
	switch resolved.Status {
	case ResolutionValid, ResolutionAlreadyAuthorized:
		return GatewayAction{Kind: ActionRedirectAuthorize}, nil
	case ResolutionUnauthenticated:
		return GatewayAction{Kind: ActionRedirectLogin}, nil
	case ResolutionExpired:
		return GatewayAction{Kind: ActionLocalFailure, Failure: LocalFailureExpired}, nil
	default:
		// client_not_found / redirect_mismatch / scope_not_allowed: no
		// provider callback exists for these outcomes.
		return GatewayAction{Kind: ActionLocalFailure, Failure: LocalFailureBadRequest}, nil
	}
}

// completeError runs one error-callback completion through the §5 model
// and maps the terminal failures onto the local page (a request that is
// already gone or decided cannot receive a callback either).
func (g *InteractionGatewayService) completeError(
	ctx context.Context,
	authRequestID string,
	kind CompletionKind,
	sess *DecisionSession,
	clientID applications.OAuthClientID,
) (GatewayAction, error) {
	outcome, err := g.decisions.CompleteWithErrorCallback(ctx, authRequestID, kind, sess, clientID)
	if err != nil {
		switch {
		case errors.Is(err, ErrDecisionRequestExpired), errors.Is(err, ErrDecisionAlreadyDecided):
			return GatewayAction{Kind: ActionLocalFailure, Failure: LocalFailureExpired}, nil
		}
		return GatewayAction{}, err
	}
	return GatewayAction{Kind: ActionProviderCallback, Outcome: outcome}, nil
}

// resolutionSessionOf narrows the decision session onto the resolution
// session view (nil stays nil).
func resolutionSessionOf(sess *DecisionSession) *ResolutionSession {
	if sess == nil {
		return nil
	}
	return &ResolutionSession{
		UserID:             sess.UserID,
		AuthenticationTime: sess.AuthenticationTime,
	}
}
