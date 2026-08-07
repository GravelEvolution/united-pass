package consent

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// Authorization-request resolution (ADR-0005 §2, §4, §7, §9, §12): the
// authorization-side-effect free derivation of the ConsentResolution union
// served by GET /api/v1/authorization/requests/{requestId}. Resolution
// states are derived on read — no request table, no operation claim, no
// provider completion, no grant write and no audit write ever happens
// here. (Transport-level session bookkeeping such as the OptionalSession
// touch is outside this guarantee.) The interaction gateway (P3.6) is the
// only execution entry for the non-interactive prompt branches.

// AuthRequestReader is the narrow provider port resolution needs: reading
// the auth request only. Resolution must never complete or mutate the
// request (ADR-0005 §12), so it deliberately does not receive the full
// AuthRequestProvider.
type AuthRequestReader interface {
	GetAuthRequest(ctx context.Context, authRequestID string) (*AuthRequestView, error)
}

// ConsentClientFacts bundles the local records authoritative for display
// data and business validity (ADR-0005 §4): the OAuth client plus its
// parent application.
type ConsentClientFacts struct {
	Client      applications.OAuthClient
	Application applications.Application
}

// ErrClientUnknown: no local client matches the provider identity, or the
// match is not a live provisioned record. Resolution reports it as
// client_not_found without leaking which validity condition failed
// (ADR-0005 §7).
var ErrClientUnknown = errors.New("consent: no live local client for provider identity")

// ConsentClientResolver maps a provider client identity to the local
// client + application records. The PostgreSQL application repository
// implements it.
type ConsentClientResolver interface {
	// ResolveConsentClient returns the live, provisioned client registered
	// for (provider, providerClientID) together with its parent
	// application. It returns ErrClientUnknown when no such record exists
	// (unknown, soft-deleted or not fully provisioned). Effective status
	// (application × client) is validated by the resolution service, not
	// here, so the precise reason stays available to audit in later
	// milestones.
	ResolveConsentClient(ctx context.Context, provider, providerClientID string) (ConsentClientFacts, error)
}

// GrantReader is the narrow grant-store port resolution needs: reading the
// (user, client) grant for reuse evaluation only (ADR-0005 §7).
type GrantReader interface {
	GetGrant(ctx context.Context, userID identity.UserID, clientID applications.OAuthClientID) (Grant, error)
}

// ErrResolutionNotInteractive: the auth request cannot proceed through the
// interactive consent UI — prompt=create, prompt=select_account, an
// unknown/unspecified prompt value, an invalid prompt combination, or
// prompt=none without a silently reusable grant (ADR-0005 §9). Such
// requests are executed exclusively by the interaction gateway; the
// resolution GET never renders UI for them and never downgrades or
// reinterprets them. HTTP adapters map it to a stable 400 outcome.
var ErrResolutionNotInteractive = errors.New("consent: request cannot proceed interactively")

// ResolutionStatus is the ConsentResolution union discriminator frozen by
// the frontend contract. No new members may be introduced (ADR-0005 §12).
type ResolutionStatus string

// Resolution statuses (frozen frontend union).
const (
	ResolutionValid             ResolutionStatus = "valid"
	ResolutionExpired           ResolutionStatus = "expired"
	ResolutionClientNotFound    ResolutionStatus = "client_not_found"
	ResolutionRedirectMismatch  ResolutionStatus = "redirect_mismatch"
	ResolutionUnauthenticated   ResolutionStatus = "unauthenticated"
	ResolutionScopeNotAllowed   ResolutionStatus = "scope_not_allowed"
	ResolutionAlreadyAuthorized ResolutionStatus = "already_authorized"
)

// unparseableRedirectHost is the fixed placeholder returned as the
// attempted redirect when the attacker-controlled URI does not parse to a
// host. The raw value is never surfaced (ADR-0005 §10).
const unparseableRedirectHost = "(invalid)"

// ResolutionScope is one requested scope with its catalog display data.
type ResolutionScope struct {
	Scope       string
	Label       string
	Description string
}

// ResolutionSession is the session state resolution evaluates: nil input
// session means unauthenticated. AuthenticationTime feeds the max_age
// check (ADR-0005 §9).
type ResolutionSession struct {
	UserID             identity.UserID
	AuthenticationTime time.Time
}

// ResolutionInput is everything the resolution GET contributes: the opaque
// auth request ID and the (possibly absent) United Pass session. All other
// facts are read from the provider and the local records.
type ResolutionInput struct {
	AuthRequestID string
	Session       *ResolutionSession
}

// Resolution is the derived consent resolution outcome. Only the fields
// relevant to Status are populated; it mirrors the frozen frontend
// ConsentResolution union exactly.
type Resolution struct {
	Status        ResolutionStatus
	AuthRequestID string

	// valid
	ApplicationName        string
	ApplicationDescription string
	ApplicationOwner       string
	RedirectHost           string
	Scopes                 []ResolutionScope

	// expired: the moment the request was determined to be no longer
	// retrievable. The provider never reports the original expiry instant
	// on the read path, so this is the determination time.
	ExpiredAt time.Time

	// redirect_mismatch: parsed host of the attempted URI only, never the
	// raw attacker-controlled value (ADR-0005 §10).
	AttemptedRedirectHost string

	// scope_not_allowed
	DisallowedScopes []string
}

// ResolutionService derives ConsentResolution outcomes side-effect free.
// It is safe for concurrent use; every dependency is read-only.
type ResolutionService struct {
	provider     AuthRequestReader
	clients      ConsentClientResolver
	grants       GrantReader
	providerName string
	now          func() time.Time
}

// NewResolutionService builds the resolution service. All dependencies are
// required (fail closed): a resolution service missing any seam would
// silently mis-resolve requests.
func NewResolutionService(
	provider AuthRequestReader,
	clients ConsentClientResolver,
	grants GrantReader,
	providerName string,
	now func() time.Time,
) (*ResolutionService, error) {
	if provider == nil {
		return nil, errors.New("consent: resolution service requires an auth request reader")
	}
	if clients == nil {
		return nil, errors.New("consent: resolution service requires a client resolver")
	}
	if grants == nil {
		return nil, errors.New("consent: resolution service requires a grant reader")
	}
	if providerName == "" {
		return nil, errors.New("consent: resolution service requires a provider name")
	}
	if now == nil {
		return nil, errors.New("consent: resolution service requires a clock")
	}
	return &ResolutionService{
		provider:     provider,
		clients:      clients,
		grants:       grants,
		providerName: providerName,
		now:          now,
	}, nil
}

// Resolve derives the ConsentResolution for one auth request. It performs
// no authorization writes of any kind: no operation claim, no provider
// completion, no grant mutation and no audit record (ADR-0005 §12).
// Evaluation order is fixed: provider read → prompt validation →
// client/application mapping → redirect exact match → scope
// canonicalization + validation → session state (including authentication
// freshness) → grant reuse.
func (s *ResolutionService) Resolve(ctx context.Context, input ResolutionInput) (Resolution, error) {
	if err := ValidateAuthRequestID(input.AuthRequestID); err != nil {
		return Resolution{}, err
	}

	// 1. Provider read. A vanished or already-finalized request can only
	// ever be reported as expired: NotFound is externally
	// indistinguishable from "consumed by a successful CreateCallback" and
	// is never evidence of success (ADR-0005 §4).
	view, err := s.provider.GetAuthRequest(ctx, input.AuthRequestID)
	if err != nil {
		if IsClass(err, ClassNotFound) || IsClass(err, ClassExpired) || IsClass(err, ClassAlreadyCompleted) {
			return Resolution{
				Status:        ResolutionExpired,
				AuthRequestID: input.AuthRequestID,
				ExpiredAt:     s.now().UTC(),
			}, nil
		}
		return Resolution{}, err
	}

	// 2. Prompt combinations that can never proceed through the consent UI
	// (ADR-0005 §9). They are rejected before any local facts are
	// revealed; the interaction gateway owns their execution.
	if err := validateInteractivePrompts(view); err != nil {
		return Resolution{}, err
	}

	// 3. Local client/application mapping. Unknown, soft-deleted,
	// not-fully-provisioned or disabled records all resolve to
	// client_not_found without leaking the precise reason (ADR-0005 §7).
	facts, err := s.clients.ResolveConsentClient(ctx, s.providerName, view.ClientID)
	if err != nil {
		if errors.Is(err, ErrClientUnknown) {
			return Resolution{
				Status:        ResolutionClientNotFound,
				AuthRequestID: input.AuthRequestID,
			}, nil
		}
		return Resolution{}, err
	}
	if !applications.EffectiveClientActive(facts.Application.Status, facts.Client.Status) {
		return Resolution{
			Status:        ResolutionClientNotFound,
			AuthRequestID: input.AuthRequestID,
		}, nil
	}

	// 4. Redirect exact match: registered URIs are compared verbatim, no
	// normalization is ever applied (ADR-0004 §4).
	if !hasExactRedirectURI(facts.Client.RedirectURIs, view.RedirectURI) {
		return Resolution{
			Status:                ResolutionRedirectMismatch,
			AuthRequestID:         input.AuthRequestID,
			AttemptedRedirectHost: attemptedRedirectHost(view.RedirectURI),
		}, nil
	}

	// 5. Scope canonicalization: the requested scopes are normalized
	// through the single P3.2 canonicalization boundary before any further
	// use, so the GET and the decision execution (P3.4) share one scope
	// fact — a request that cannot survive NormalizeScopes there can never
	// be advertised as continuable here. Structurally invalid or empty
	// results are reported as not allowed; the raw tokens are never echoed.
	requestedScopes, err := NormalizeScopes(view.Scopes)
	if err != nil || len(requestedScopes) == 0 {
		return Resolution{
			Status:           ResolutionScopeNotAllowed,
			AuthRequestID:    input.AuthRequestID,
			DisallowedScopes: []string{},
		}, nil
	}

	// 6. Catalog validation: every normalized scope must be registered on
	// the client.
	disallowed := disallowedScopes(requestedScopes, facts.Client.Scopes)
	if len(disallowed) > 0 {
		return Resolution{
			Status:           ResolutionScopeNotAllowed,
			AuthRequestID:    input.AuthRequestID,
			DisallowedScopes: disallowed,
		}, nil
	}

	// 7. prompt=none can only ever be represented by silent reuse on this
	// entry point: it must never render login or consent UI (ADR-0005
	// §9). The session must additionally satisfy the request's
	// authentication requirements (max_age); without both, the request
	// cannot proceed here and the gateway is the execution entry.
	if view.HasPrompt(PromptNone) {
		if input.Session == nil || input.Session.UserID == "" ||
			!authenticationSatisfied(view, input.Session, s.now()) {
			return Resolution{}, ErrResolutionNotInteractive
		}
		reusable, err := s.grantReusable(ctx, input.Session, view, facts.Client, requestedScopes)
		if err != nil {
			return Resolution{}, err
		}
		if reusable {
			return alreadyAuthorizedResolution(input.AuthRequestID, view, facts), nil
		}
		return Resolution{}, ErrResolutionNotInteractive
	}

	// 8. Session state. A missing session, or one that does not satisfy
	// the request's authentication freshness requirements (prompt=login,
	// max_age=0, exceeded max_age), requires (re-)login; the frozen union
	// has no reauthentication member, so they surface as unauthenticated.
	// The gateway routes the real flow through /login, and after a genuine
	// re-authentication the same request resolves past this check instead
	// of looping (ADR-0005 §9).
	if input.Session == nil || input.Session.UserID == "" ||
		!authenticationSatisfied(view, input.Session, s.now()) {
		return Resolution{
			Status:        ResolutionUnauthenticated,
			AuthRequestID: input.AuthRequestID,
		}, nil
	}

	// 9. Grant reuse evaluation (ADR-0005 §7). The GET is advisory: the
	// decision endpoint re-enforces every condition server-side.
	reusable, err := s.grantReusable(ctx, input.Session, view, facts.Client, requestedScopes)
	if err != nil {
		return Resolution{}, err
	}
	if reusable {
		return alreadyAuthorizedResolution(input.AuthRequestID, view, facts), nil
	}

	return Resolution{
		Status:                 ResolutionValid,
		AuthRequestID:          input.AuthRequestID,
		ApplicationName:        facts.Application.Name,
		ApplicationDescription: facts.Application.Description,
		ApplicationOwner:       facts.Application.OwnerName,
		RedirectHost:           verifiedRedirectHost(view.RedirectURI),
		Scopes:                 resolutionScopes(requestedScopes),
	}, nil
}

// grantReusable evaluates all ADR-0005 §7 reuse preconditions: an active
// grant for (user, client), the normalized requested scopes ⊆ granted
// scopes (which also guarantees offline_access is present only when it was
// explicitly consented before), a consent mode permitting reuse and no
// prompt=consent. Client/application validity and authentication freshness
// are already established by the caller.
func (s *ResolutionService) grantReusable(
	ctx context.Context,
	sess *ResolutionSession,
	view *AuthRequestView,
	client applications.OAuthClient,
	requestedScopes []string,
) (bool, error) {
	if sess == nil || sess.UserID == "" {
		return false, nil
	}
	if view.HasPrompt(PromptConsent) {
		return false, nil
	}
	if client.ConsentMode != applications.ConsentModeFirstAuthorization {
		return false, nil
	}
	grant, err := s.grants.GetGrant(ctx, sess.UserID, client.ID)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return false, nil
		}
		return false, err
	}
	if grant.Status != GrantActive {
		return false, nil
	}
	return grant.ScopesContain(requestedScopes), nil
}

// authenticationSatisfied is the single authentication-freshness predicate
// shared by every resolution path (ADR-0005 §9, OIDC Core). The
// interaction gateway (P3.6) must reuse exactly this judgment:
//
//   - prompt=login or max_age<=0 force re-authentication: they are
//     satisfied only by an authentication that happened AFTER this auth
//     request was created (session authentication time > view.CreatedAt).
//     That lets a completed re-login resume at /authorize instead of
//     looping, while the pre-request session never satisfies the force
//     flag. A missing creation time fails closed — the proof cannot be
//     established without it. P3.9 calibrates provider/local clock skew
//     on the real deployment.
//   - max_age > 0 bounds the elapsed time since authentication.
//   - no requirement: any session satisfies.
func authenticationSatisfied(view *AuthRequestView, sess *ResolutionSession, now time.Time) bool {
	if sess == nil || sess.UserID == "" {
		return false
	}
	if view.HasPrompt(PromptLogin) || (view.MaxAge != nil && *view.MaxAge <= 0) {
		if view.CreatedAt.IsZero() {
			return false
		}
		return sess.AuthenticationTime.After(view.CreatedAt)
	}
	if view.MaxAge != nil {
		return now.Sub(sess.AuthenticationTime) <= *view.MaxAge
	}
	return true
}

// validateInteractivePrompts rejects prompt values and combinations that
// can never proceed through the interactive consent UI (ADR-0005 §9):
// unknown values (which the adapters map to PromptUnspecified, plus any
// out-of-range value) fail closed instead of being silently ignored,
// create and select_account are unsupported in Phase 3, and none combined
// with any other prompt is an invalid combination that is neither
// downgraded nor reinterpreted.
func validateInteractivePrompts(view *AuthRequestView) error {
	for _, p := range view.Prompts {
		switch p {
		case PromptNone, PromptLogin, PromptConsent, PromptSelectAccount, PromptCreate:
		default:
			return ErrResolutionNotInteractive
		}
	}
	if view.HasPrompt(PromptNone) && len(view.Prompts) > 1 {
		return ErrResolutionNotInteractive
	}
	if view.HasPrompt(PromptCreate) || view.HasPrompt(PromptSelectAccount) {
		return ErrResolutionNotInteractive
	}
	return nil
}

// hasExactRedirectURI reports whether the provider redirect URI matches a
// registered URI byte-for-byte. No normalization is ever applied
// (ADR-0004 §4).
func hasExactRedirectURI(registered []applications.RedirectURI, requested string) bool {
	for _, uri := range registered {
		if uri.URI == requested {
			return true
		}
	}
	return false
}

// disallowedScopes returns the requested scopes absent from the client's
// registered catalog, deduplicated and deterministically sorted.
func disallowedScopes(requested, allowed []string) []string {
	catalog := make(map[string]bool, len(allowed))
	for _, scope := range allowed {
		catalog[scope] = true
	}
	seen := make(map[string]bool, len(requested))
	out := []string{}
	for _, scope := range requested {
		if catalog[scope] || seen[scope] {
			continue
		}
		seen[scope] = true
		out = append(out, scope)
	}
	// Sort for a deterministic response.
	sort.Strings(out)
	return out
}

// attemptedRedirectHost extracts only the parsed host of an
// attacker-controlled redirect URI (ADR-0005 §10). Unparseable values and
// hostless URIs yield a fixed placeholder; the raw value is never
// returned.
func attemptedRedirectHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return unparseableRedirectHost
	}
	return parsed.Host
}

// verifiedRedirectHost renders the host of the exact-match-verified
// redirect URI for display. The value is registered admin data, not
// attacker input; when it carries no host (custom-scheme registrations)
// the verbatim registered value is shown.
func verifiedRedirectHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return raw
	}
	return parsed.Host
}

// resolutionScopes attaches the authoritative catalog display data to each
// requested scope. Unknown tokens (which cannot survive the subset check
// against the catalog-validated client scopes, defensively) fall back to
// the bare token.
func resolutionScopes(requested []string) []ResolutionScope {
	out := make([]ResolutionScope, 0, len(requested))
	for _, scope := range requested {
		entry := ResolutionScope{Scope: scope, Label: scope}
		for _, def := range applications.ScopeCatalog {
			if def.Scope == scope {
				entry.Label = def.Label
				entry.Description = def.Description
				break
			}
		}
		out = append(out, entry)
	}
	return out
}

// alreadyAuthorizedResolution builds the reuse outcome (ADR-0005 §7).
func alreadyAuthorizedResolution(authRequestID string, view *AuthRequestView, facts ConsentClientFacts) Resolution {
	return Resolution{
		Status:          ResolutionAlreadyAuthorized,
		AuthRequestID:   authRequestID,
		ApplicationName: facts.Application.Name,
		RedirectHost:    verifiedRedirectHost(view.RedirectURI),
	}
}
