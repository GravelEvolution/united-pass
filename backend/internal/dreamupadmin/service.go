package dreamupadmin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

var (
	opaqueValuePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	requestIDPattern       = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
	idempotencyPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{32,160}$`)
	ifMatchPattern         = regexp.MustCompile(`^"(0|[1-9][0-9]*)"$`)
	reauthTokenPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	receiptHashPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	receiptMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$`)
)

type ServiceDependencies struct {
	Authorizer      permissions.Authorizer
	Registry        EventRegistry
	StepUps         StepUpReader
	AccountSecurity AccountSecurityEpochReader
	ReauthGrants    ReauthGrantVerifier
	Signer          AdministratorSigner
	Client          UpstreamClient
	UnitOfWork      adminstore.UnitOfWork
	Fingerprinter   OperationFingerprinter
}

type ServiceConfig struct {
	Now                     func() time.Time
	RequireDurableMutations bool
	MutationLease           time.Duration
}

type Service struct {
	authorizer              permissions.Authorizer
	registry                EventRegistry
	stepups                 StepUpReader
	accountSecurity         AccountSecurityEpochReader
	reauthGrants            ReauthGrantVerifier
	signer                  AdministratorSigner
	client                  UpstreamClient
	uow                     adminstore.UnitOfWork
	fingerprinter           OperationFingerprinter
	now                     func() time.Time
	requireDurableMutations bool
	mutationLease           time.Duration
}

func NewService(dependencies ServiceDependencies, config ServiceConfig) (*Service, error) {
	if dependencies.Authorizer == nil || dependencies.Registry == nil || dependencies.StepUps == nil || dependencies.Signer == nil || dependencies.Client == nil {
		return nil, ErrInvalidRequest
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.MutationLease == 0 {
		config.MutationLease = 30 * time.Second
	}
	if config.MutationLease < time.Second || config.MutationLease > 10*time.Minute || (config.RequireDurableMutations && (dependencies.UnitOfWork == nil || dependencies.Fingerprinter == nil)) {
		return nil, ErrInvalidRequest
	}
	return &Service{authorizer: dependencies.Authorizer, registry: dependencies.Registry, stepups: dependencies.StepUps, accountSecurity: dependencies.AccountSecurity, reauthGrants: dependencies.ReauthGrants, signer: dependencies.Signer, client: dependencies.Client, uow: dependencies.UnitOfWork, fingerprinter: dependencies.Fingerprinter, now: config.Now, requireDurableMutations: config.RequireDurableMutations, mutationLease: config.MutationLease}, nil
}

// Eligible reports whether the authenticated actor has at least one active,
// policy-authorized DreamUP event dashboard binding. It intentionally returns
// no event, role or count data and does not consult administrator step-up state;
// callers use it only to decide whether the protected administration entry
// point may be displayed.
func (s *Service) Eligible(ctx context.Context, actor Actor) (bool, error) {
	if s == nil || !validActor(actor) {
		return false, ErrInvalidRequest
	}
	query := adminpagination.Query{
		ActorID:   string(actor.UserID),
		ScopeKind: string(adminroles.ScopeSystem),
		ListKind:  "event_registry",
		Sort:      "id:asc",
		Limit:     adminpagination.MaxPageSize,
	}
	seenCursors := make(map[string]struct{})
	for {
		page, err := s.registry.ListEnabled(ctx, query)
		if err != nil {
			return false, err
		}
		for _, event := range page.Items {
			if !validRegisteredEvent(event) {
				continue
			}
			decision, checkErr := s.authorizer.Check(ctx, actor.UserID, permissions.ActionDashboardRead, permissions.Resource{Kind: "event", ID: event.EventID, EventID: event.EventID})
			if checkErr != nil {
				return false, checkErr
			}
			// The binding evidence is mandatory even when a policy decision says
			// allow. A generic account persona or principal role is never enough.
			if decision.Allowed && permissions.FixedRoleAllows(decision.Role, permissions.ActionDashboardRead) && decision.BindingID != "" && decision.BindingVersion > 0 {
				return true, nil
			}
		}
		if !page.HasMore {
			return false, nil
		}
		if page.NextCursor == "" {
			return false, ErrUpstream
		}
		if _, duplicate := seenCursors[page.NextCursor]; duplicate {
			return false, ErrUpstream
		}
		seenCursors[page.NextCursor] = struct{}{}
		query.Cursor = page.NextCursor
	}
}

func (s *Service) ListEvents(ctx context.Context, actor Actor) ([]EventSummary, error) {
	if s == nil || !validActor(actor) {
		return nil, ErrInvalidRequest
	}
	page, err := s.registry.ListEnabled(ctx, adminpagination.Query{ActorID: string(actor.UserID), ScopeKind: string(adminroles.ScopeSystem), ListKind: "event_registry", Sort: "id:asc", Limit: adminpagination.MaxPageSize})
	if err != nil {
		return nil, err
	}
	result := make([]EventSummary, 0, len(page.Items))
	for _, event := range page.Items {
		if !validRegisteredEvent(event) {
			continue
		}
		decision, checkErr := s.authorizer.Check(ctx, actor.UserID, permissions.ActionDashboardRead, permissions.Resource{Kind: "event", ID: event.EventID, EventID: event.EventID})
		if checkErr != nil {
			return nil, checkErr
		}
		if !decision.Allowed || !permissions.FixedRoleAllows(decision.Role, permissions.ActionDashboardRead) || decision.BindingID == "" || decision.BindingVersion <= 0 {
			continue
		}
		if _, stepErr := s.validAdministratorSession(ctx, actor, decision); stepErr != nil {
			if errors.Is(stepErr, ErrStepUpRequired) {
				return nil, stepErr
			}
			return nil, stepErr
		}
		result = append(result, EventSummary{EventID: event.EventID, DisplayName: event.DisplayName, Slug: event.Slug, Role: decision.Role, Counts: s.fetchEventCounts(ctx, actor, event.EventID)})
	}
	return result, nil
}

// OperationStatus replays only the durable, allowlisted outcome metadata for
// one mutation. It never reissues the mutation and never exposes the private
// DreamUP receipt hash or response body.
func (s *Service) OperationStatus(ctx context.Context, actor Actor, eventID, idempotencyKey string) (MutationStatus, error) {
	if s == nil || !validActor(actor) || !opaqueValuePattern.MatchString(eventID) || !idempotencyPattern.MatchString(idempotencyKey) {
		return MutationStatus{}, ErrInvalidRequest
	}
	event, err := s.registry.GetExact(ctx, eventID)
	if err != nil {
		if errors.Is(err, adminroles.ErrEventRegistryNotFound) || errors.Is(err, adminroles.ErrEventRegistryDisabled) {
			return MutationStatus{}, ErrNotFound
		}
		return MutationStatus{}, err
	}
	if !validRegisteredEvent(event) {
		return MutationStatus{}, ErrNotFound
	}
	decision, err := s.authorizer.Check(ctx, actor.UserID, permissions.ActionDashboardRead, permissions.Resource{Kind: "event", ID: eventID, EventID: eventID})
	if err != nil {
		return MutationStatus{}, err
	}
	if !decision.Allowed || !permissions.FixedRoleAllows(decision.Role, permissions.ActionDashboardRead) || decision.BindingID == "" || decision.BindingVersion <= 0 {
		return MutationStatus{}, ErrForbidden
	}
	if _, err := s.validAdministratorSession(ctx, actor, decision); err != nil {
		return MutationStatus{}, err
	}
	if s.uow == nil {
		return MutationStatus{}, ErrUpstream
	}
	var item adminstore.OutboxItem
	err = s.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		var lookupErr error
		item, lookupErr = repositories.Outbox.GetByIdempotencyKey(ctx, idempotencyKey)
		return lookupErr
	})
	if errors.Is(err, adminstore.ErrOperationNotFound) {
		return MutationStatus{}, ErrNotFound
	}
	if err != nil {
		return MutationStatus{}, err
	}
	// The event and initiating actor are durable row bindings. A mismatch is
	// deliberately indistinguishable from an absent operation.
	if item.Kind != adminstore.OperationCrossSystem || item.Result.Payload["event_id"] != eventID || item.Result.Payload["actor_id"] != string(actor.UserID) {
		return MutationStatus{}, ErrNotFound
	}
	return mutationStatusFromItem(item)
}

// fetchEventCounts returns the admission counts for one event by listing its
// applications through the DreamUP upstream. A failure is non-fatal: the
// dashboard simply shows zeros rather than breaking the event listing.
func (s *Service) fetchEventCounts(ctx context.Context, actor Actor, eventID string) EventCounts {
	counts := EventCounts{}
	requestID, err := randomRequestID()
	if err != nil {
		return counts
	}
	response, err := s.Proxy(ctx, actor, ProxyRequest{
		EventID:      eventID,
		Capability:   permissions.ActionApplicationReadBasic,
		ResourceKind: "event",
		ResourceID:   eventID,
		Method:       http.MethodGet,
		Path:         "/internal/v1/events/" + url.PathEscape(eventID) + "/applications",
		RequestID:    requestID,
	})
	if err != nil || response.StatusCode != http.StatusOK {
		return counts
	}
	var payload struct {
		Applications []struct {
			Status string `json:"status"`
		} `json:"applications"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		return counts
	}
	for _, app := range payload.Applications {
		counts.Total++
		switch app.Status {
		case "submitted", "under_review":
			counts.Pending++
		case "accepted":
			counts.Accepted++
		case "rejected":
			counts.Rejected++
		}
	}
	return counts
}

func randomRequestID() (string, error) {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "req_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (s *Service) Proxy(ctx context.Context, actor Actor, input ProxyRequest) (ProxyResponse, error) {
	if s == nil || !validActor(actor) || validateProxyRequest(input) != nil {
		return ProxyResponse{}, ErrInvalidRequest
	}
	event, err := s.registry.GetExact(ctx, input.EventID)
	if err != nil {
		if errors.Is(err, adminroles.ErrEventRegistryNotFound) || errors.Is(err, adminroles.ErrEventRegistryDisabled) {
			return ProxyResponse{}, ErrNotFound
		}
		return ProxyResponse{}, err
	}
	if !validRegisteredEvent(event) {
		return ProxyResponse{}, ErrNotFound
	}
	decision, err := s.authorizer.Check(ctx, actor.UserID, input.Capability, permissions.Resource{Kind: input.ResourceKind, ID: input.ResourceID, EventID: input.EventID})
	if err != nil {
		return ProxyResponse{}, err
	}
	slog.Info("dreamup proxy decision",
		"userID", actor.UserID,
		"capability", input.Capability,
		"resourceKind", input.ResourceKind,
		"resourceID", input.ResourceID,
		"eventID", input.EventID,
		"allowed", decision.Allowed,
		"role", decision.Role,
		"bindingID", decision.BindingID,
		"bindingVersion", decision.BindingVersion,
		"challengeVersion", decision.ChallengeVersion,
		"fixedRoleAllows", permissions.FixedRoleAllows(decision.Role, input.Capability),
	)
	if !decision.Allowed || !permissions.FixedRoleAllows(decision.Role, input.Capability) || decision.BindingID == "" || decision.BindingVersion <= 0 {
		return ProxyResponse{}, ErrForbidden
	}
	pathAndQuery, err := dreamupdelegation.CanonicalPathAndQuery(input.Path, input.Query)
	if err != nil {
		return ProxyResponse{}, ErrInvalidRequest
	}
	capability := dreamupdelegation.AdministratorCapability(input.Capability)
	highRisk := dreamupdelegation.RequiresFreshAdministratorProof(capability, input.Method)
	stepUpAt := time.Time{}
	challengeVersion := int64(0)
	reauthProofID := ""
	if highRisk {
		if input.ReauthenticationToken != "" {
			// Explicit one-shot credentials retain strict action-and-target-bound
			// consumption. A rejected token never downgrades to another proof.
			proof, proofErr := s.consumeHighRiskGrant(ctx, actor, input, decision)
			if proofErr != nil {
				return ProxyResponse{}, proofErr
			}
			stepUpAt, challengeVersion, reauthProofID = proof.CreatedAt, proof.ChallengeVersion, proof.GrantID
		} else if actor.AuthenticationTransport == AuthenticationTransportNativeMiniProgramBearer {
			// The native Mini Program no longer exposes the administrator security-
			// question workflow. Its short-lived, transport-bound server session is
			// revalidated against the account security epoch and the exact event role
			// binding here. A fresh opaque proof ID is then bound into the signed,
			// method/path/body-specific downstream assertion for this one request.
			sessionProof, proofErr := s.validNativeAdministratorSession(ctx, actor, decision)
			if proofErr != nil {
				return ProxyResponse{}, proofErr
			}
			reauthProofID, proofErr = randomNativeAuthorizationID()
			if proofErr != nil {
				return ProxyResponse{}, ErrUpstream
			}
			stepUpAt, challengeVersion = s.now().UTC(), sessionProof.ChallengeVersion
		} else {
			stepUp, stepErr := s.validLegacyCookieHighRiskStepUp(ctx, actor, decision)
			if stepErr != nil {
				return ProxyResponse{}, stepErr
			}
			stepUpAt, challengeVersion, reauthProofID = stepUp.VerifiedAt, stepUp.ChallengeVersion, stepUp.ID
		}
	} else {
		// Ordinary actions retain the longer durable administrator-session
		// proof. Supplying a bearer to an ordinary action is rejected rather
		// than silently broadening where the credential can travel.
		if input.ReauthenticationToken != "" {
			return ProxyResponse{}, ErrInvalidRequest
		}
		stepUp, stepErr := s.validAdministratorSession(ctx, actor, decision)
		if stepErr != nil {
			return ProxyResponse{}, stepErr
		}
		stepUpAt, challengeVersion = stepUp.VerifiedAt, stepUp.ChallengeVersion
	}
	assertion, err := s.signer.SignAdministrator(dreamupdelegation.AdministratorAssertion{
		Subject: actor.UserID, JWTID: input.RequestID, Capability: capability,
		Method: input.Method, PathAndQuery: pathAndQuery, BodySHA256: sha256Hex(input.Body), EventID: input.EventID,
		Role: decision.Role, RoleBindingID: decision.BindingID, RoleVersion: decision.BindingVersion,
		ChallengeVersion: challengeVersion, AuthTime: actor.AuthenticatedAt, StepUpAt: stepUpAt, ReauthGrantID: reauthProofID,
		IfMatch:        input.IfMatch,
		IdempotencyKey: input.IdempotencyKey,
	})
	if err != nil {
		return ProxyResponse{}, err
	}
	var operation *adminstore.OutboxItem
	if input.Method != http.MethodGet && s.uow != nil && s.fingerprinter != nil {
		operation, err = s.beginMutation(ctx, actor, input, pathAndQuery)
		if err != nil {
			return ProxyResponse{}, err
		}
	} else if input.Method != http.MethodGet && s.requireDurableMutations {
		return ProxyResponse{}, ErrUpstream
	}
	response, err := s.client.Execute(ctx, UpstreamRequest{
		Method: input.Method, Path: input.Path, Query: cloneQuery(input.Query), Body: append([]byte(nil), input.Body...), Assertion: assertion,
		RequestID: input.RequestID, IdempotencyKey: input.IdempotencyKey, IfMatch: input.IfMatch,
	})
	if err != nil {
		if operation != nil {
			finalizeCtx, cancel := mutationFinalizeContext(ctx)
			defer cancel()
			if status, deterministic := deterministicMutationFailure(err); deterministic {
				if finalizeErr := s.failMutation(finalizeCtx, *operation, status); finalizeErr != nil {
					return ProxyResponse{}, ErrUpstream
				}
			} else {
				_ = s.deferReceipt(finalizeCtx, *operation)
			}
		}
		return ProxyResponse{}, err
	}
	if operation != nil {
		finalizeCtx, cancel := mutationFinalizeContext(ctx)
		defer cancel()
		if err := s.settleMutation(finalizeCtx, *operation, response); err != nil {
			return ProxyResponse{}, err
		}
	}
	return ProxyResponse{StatusCode: response.StatusCode, Body: append([]byte(nil), response.Body...), RequestID: response.RequestID, ETag: response.ETag}, nil
}

func randomNativeAuthorizationID() (string, error) {
	buffer := make([]byte, 18)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "nma_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

// validAdministratorSession keeps the deployed browser security-question
// contract intact while using the native Mini Program's already validated,
// short-lived bearer session as its administrator-session proof.
func (s *Service) validAdministratorSession(ctx context.Context, actor Actor, decision permissions.Decision) (adminstepup.StepUpState, error) {
	if actor.AuthenticationTransport == AuthenticationTransportNativeMiniProgramBearer {
		return s.validNativeAdministratorSession(ctx, actor, decision)
	}
	return s.validStepUp(ctx, actor, decision)
}

func (s *Service) validNativeAdministratorSession(ctx context.Context, actor Actor, decision permissions.Decision) (adminstepup.StepUpState, error) {
	if actor.AuthenticationTransport != AuthenticationTransportNativeMiniProgramBearer || actor.SecurityEpoch < 1 || s.accountSecurity == nil || decision.BindingID == "" || decision.BindingVersion <= 0 {
		return adminstepup.StepUpState{}, ErrStepUpRequired
	}
	now := s.now().UTC()
	authenticatedAt := actor.AuthenticatedAt.UTC()
	if authenticatedAt.IsZero() || authenticatedAt.After(now.Add(dreamupdelegation.MaxClockSkew)) || now.Sub(authenticatedAt) > dreamupdelegation.MaxAdministratorLoginAge {
		return adminstepup.StepUpState{}, ErrStepUpRequired
	}
	currentEpoch, err := s.accountSecurity.CurrentEpoch(ctx, actor.UserID)
	if err != nil || currentEpoch < 1 || currentEpoch != actor.SecurityEpoch {
		return adminstepup.StepUpState{}, ErrStepUpRequired
	}
	challengeVersion := decision.ChallengeVersion
	if challengeVersion <= 0 {
		// The assertion schema requires a positive authorization generation. For
		// native accounts without a legacy security question, the authoritative
		// account epoch is the generation that invalidates all existing sessions.
		challengeVersion = int64(currentEpoch)
	}
	return adminstepup.StepUpState{
		SessionID: actor.SessionID, UserID: actor.UserID, ChallengeVersion: challengeVersion,
		SecurityEpoch: int64(currentEpoch), VerifiedAt: authenticatedAt, ExpiresAt: now.Add(dreamupdelegation.MaxClockSkew),
	}, nil
}

func (s *Service) consumeHighRiskGrant(ctx context.Context, actor Actor, input ProxyRequest, decision permissions.Decision) (auth.ReauthGrantData, error) {
	if s.reauthGrants == nil || input.ReauthenticationToken == "" {
		return auth.ReauthGrantData{}, ErrStepUpRequired
	}
	target, ok := highRiskGrantTarget(input)
	if !ok {
		return auth.ReauthGrantData{}, ErrStepUpRequired
	}
	proof, err := s.reauthGrants.VerifyAndConsumeData(ctx, input.ReauthenticationToken, string(input.Capability), actor.SessionID, target, "", "")
	if err != nil {
		return auth.ReauthGrantData{}, ErrStepUpRequired
	}
	now := s.now().UTC()
	createdAt := proof.CreatedAt.UTC()
	if proof.UserID != actor.UserID || proof.SessionID != actor.SessionID || proof.Action != string(input.Capability) || proof.Target != target || proof.ApplicationID != "" || proof.ClientID != "" || proof.GrantID == "" || proof.ChallengeVersion <= 0 || proof.ChallengeVersion != decision.ChallengeVersion || proof.SecurityEpoch < 1 || createdAt.IsZero() || createdAt.After(now.Add(dreamupdelegation.MaxClockSkew)) || createdAt.Before(actor.AuthenticatedAt.UTC().Add(-dreamupdelegation.MaxClockSkew)) || now.Sub(createdAt) > dreamupdelegation.MaxHighRiskStepUpAge {
		return auth.ReauthGrantData{}, ErrStepUpRequired
	}
	return proof, nil
}

// validLegacyCookieHighRiskStepUp preserves the already deployed DreamUP
// website contract without weakening the native Mini Program contract. The
// durable proof is bound to the exact browser session and user by the
// repository, revalidated here against the current challenge generation, and
// narrowed from its ordinary lifetime to the same five-minute signer window.
// Its stable database ID occupies the existing reauth_grant_id claim so the
// private DreamUP verifier sees the unchanged assertion schema.
func (s *Service) validLegacyCookieHighRiskStepUp(ctx context.Context, actor Actor, decision permissions.Decision) (adminstepup.StepUpState, error) {
	if actor.AuthenticationTransport != AuthenticationTransportBrowserCookie {
		return adminstepup.StepUpState{}, ErrStepUpRequired
	}
	state, err := s.validStepUp(ctx, actor, decision)
	if err != nil {
		return adminstepup.StepUpState{}, err
	}
	if s.accountSecurity == nil {
		return adminstepup.StepUpState{}, ErrStepUpRequired
	}
	currentEpoch, err := s.accountSecurity.CurrentEpoch(ctx, actor.UserID)
	if err != nil || int64(currentEpoch) < 1 || state.SecurityEpoch != int64(currentEpoch) {
		return adminstepup.StepUpState{}, ErrStepUpRequired
	}
	now := s.now().UTC()
	verifiedAt := state.VerifiedAt.UTC()
	if verifiedAt.After(now.Add(dreamupdelegation.MaxClockSkew)) || verifiedAt.Before(actor.AuthenticatedAt.UTC().Add(-dreamupdelegation.MaxClockSkew)) || now.Sub(verifiedAt) > dreamupdelegation.MaxHighRiskStepUpAge {
		return adminstepup.StepUpState{}, ErrStepUpRequired
	}
	return state, nil
}

// highRiskGrantTarget is server-authored from the already validated route
// projection. The client can request a grant for this value, but can never
// choose what resource the BFF redeems it against.
func highRiskGrantTarget(input ProxyRequest) (string, bool) {
	switch input.Capability {
	case permissions.ActionContentManage:
		return dreamUPGrantTarget(input.EventID, "event", input.EventID), true
	case permissions.ActionContactSubmissionManage:
		if input.ResourceKind == "contact_submission" {
			return dreamUPGrantTarget(input.EventID, "contact_submission", input.ResourceID), input.ResourceID != ""
		}
		return dreamUPGrantTarget(input.EventID, "event", input.EventID), true
	case permissions.ActionApplicationReview, permissions.ActionApplicationApproveAdmission, permissions.ActionApplicationDecide,
		permissions.ActionIdentityGrantConsume, permissions.ActionIdentityReadRestricted, permissions.ActionLegalRead:
		return dreamUPGrantTarget(input.EventID, input.ResourceKind, input.ResourceID), input.ResourceID != ""
	case permissions.ActionRegistrationManage, permissions.ActionCheckinScan, permissions.ActionCheckinManageWindow,
		permissions.ActionApplicationExport, permissions.ActionAuditRead, permissions.ActionRoleMigrationRead:
		return dreamUPGrantTarget(input.EventID, "event", input.EventID), true
	default:
		return "", false
	}
}

// dreamUPGrantTarget is a canonical, unambiguous JSON tuple. Event binding is
// explicit even for object-scoped actions, so an identifier collision across
// two events can never make a one-shot grant portable between them.
func dreamUPGrantTarget(eventID, resourceKind, resourceID string) string {
	encoded, _ := json.Marshal([4]string{"dreamup-admin-target/v1", eventID, resourceKind, resourceID})
	return string(encoded)
}

func (s *Service) beginMutation(ctx context.Context, actor Actor, input ProxyRequest, pathAndQuery string) (*adminstore.OutboxItem, error) {
	canonical, err := json.Marshal(struct {
		Actor, Event, Capability, Method, Path, Body, Headers, Idempotency string
	}{string(actor.UserID), input.EventID, string(input.Capability), input.Method, pathAndQuery, sha256Hex(input.Body), dreamupdelegation.AdministratorHeadersSHA256(input.IfMatch, input.IdempotencyKey), input.IdempotencyKey})
	if err != nil {
		return nil, ErrInvalidRequest
	}
	expectation, err := expectedMutationReceipt(input)
	if err != nil {
		return nil, err
	}
	fingerprint, err := s.fingerprinter.Fingerprint("dreamup-admin-bff-mutation", canonical)
	if err != nil {
		return nil, err
	}
	id, err := randomOperationID()
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	payload := map[string]string{
		"event_id":             input.EventID,
		"operation_request_id": input.RequestID,
		"actor_id":             string(actor.UserID),
		"receipt_action":       expectation.Action,
		"receipt_target_type":  expectation.TargetType,
	}
	if expectation.TargetID != "" {
		payload["receipt_target_id"] = expectation.TargetID
	}
	item := adminstore.OutboxItem{ID: id, Kind: adminstore.OperationCrossSystem, IdempotencyKey: input.IdempotencyKey, Fingerprint: fingerprint, Result: adminstore.AllowlistedResult{Code: "operation.pending", Payload: payload}, State: "pending", DeliveryPhase: adminstore.DeliveryPhaseNotSent, Version: 1, NextAttemptAt: now, CreatedAt: now, UpdatedAt: now}
	var claimed adminstore.OutboxItem
	err = s.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		stored, replay, createErr := repositories.Outbox.CreateOrReplay(ctx, item)
		if createErr != nil {
			return createErr
		}
		if replay && !validPendingMutationReplay(stored, item) {
			return adminstore.ErrIdempotencyConflict
		}
		claimed, createErr = repositories.Outbox.ClaimExact(ctx, stored.ID, stored.Version, now, s.mutationLease)
		if createErr != nil {
			return createErr
		}
		if createErr = repositories.Outbox.MarkDeliveryPhase(ctx, claimed.ID, claimed.Version, claimed.ClaimToken, adminstore.DeliveryPhaseIndeterminate, now); createErr != nil {
			return createErr
		}
		claimed.Version++
		claimed.DeliveryPhase = adminstore.DeliveryPhaseIndeterminate
		return nil
	})
	if errors.Is(err, adminstore.ErrIdempotencyConflict) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return &claimed, nil
}

func validPendingMutationReplay(stored, incoming adminstore.OutboxItem) bool {
	if stored.Kind != adminstore.OperationCrossSystem || stored.State != "pending" || stored.DeliveryPhase != adminstore.DeliveryPhaseNotSent || stored.Version <= 0 || stored.TerminalAt != nil || stored.Result.Code != "operation.pending" || stored.Result.Digest != "" {
		return false
	}
	for _, key := range []string{"event_id", "operation_request_id", "actor_id", "receipt_action", "receipt_target_type", "receipt_target_id"} {
		if stored.Result.Payload[key] != incoming.Result.Payload[key] {
			return false
		}
	}
	return stored.Result.Payload["response_status"] == "" && stored.Result.Payload["result_version"] == ""
}

func (s *Service) deferReceipt(ctx context.Context, item adminstore.OutboxItem) error {
	now := s.now().UTC()
	return s.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		return repositories.Outbox.DeferReceipt(ctx, item.ID, item.Version, item.ClaimToken, now.Add(time.Second), now)
	})
}

func (s *Service) settleMutation(ctx context.Context, item adminstore.OutboxItem, response UpstreamResponse) error {
	now := s.now().UTC()
	return s.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		if err := repositories.Outbox.MarkDeliveryPhase(ctx, item.ID, item.Version, item.ClaimToken, adminstore.DeliveryPhaseSent, now); err != nil {
			return err
		}
		payload := operationResultPayload(item)
		payload["response_status"] = strconv.Itoa(response.StatusCode)
		if resultVersion, ok := versionFromETag(response.ETag); ok {
			payload["result_version"] = strconv.FormatInt(resultVersion, 10)
		}
		result := adminstore.AllowlistedResult{Code: "operation.settled", Digest: sha256Hex(response.Body), Payload: payload}
		return repositories.Outbox.Settle(ctx, item.ID, item.Version+1, item.ClaimToken, result, now)
	})
}

func (s *Service) failMutation(ctx context.Context, item adminstore.OutboxItem, responseStatus int) error {
	now := s.now().UTC()
	return s.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		if err := repositories.Outbox.MarkDeliveryPhase(ctx, item.ID, item.Version, item.ClaimToken, adminstore.DeliveryPhaseSent, now); err != nil {
			return err
		}
		payload := operationResultPayload(item)
		payload["response_status"] = strconv.Itoa(responseStatus)
		return repositories.Outbox.Fail(ctx, item.ID, item.Version+1, item.ClaimToken, adminstore.AllowlistedResult{Code: "operation.failed", Payload: payload}, now)
	})
}

func operationResultPayload(item adminstore.OutboxItem) map[string]string {
	payload := map[string]string{
		"event_id":             item.Result.Payload["event_id"],
		"operation_request_id": item.Result.Payload["operation_request_id"],
		"actor_id":             item.Result.Payload["actor_id"],
		"receipt_action":       item.Result.Payload["receipt_action"],
		"receipt_target_type":  item.Result.Payload["receipt_target_type"],
	}
	if targetID := item.Result.Payload["receipt_target_id"]; targetID != "" {
		payload["receipt_target_id"] = targetID
	}
	return payload
}

type mutationReceiptExpectation struct {
	Action     string
	TargetType string
	TargetID   string
}

// expectedMutationReceipt binds a durable intent to the exact receipt family
// the allowlisted BFF route can create. This is required even though DreamUP's
// primary lookup also checks the idempotency key: its legacy identity-access
// fallback is request-ID based and must never settle an unrelated mutation.
func expectedMutationReceipt(input ProxyRequest) (mutationReceiptExpectation, error) {
	base := "/internal/v1/events/" + url.PathEscape(input.EventID)
	switch input.Capability {
	case permissions.ActionContentManage:
		var body struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(input.Body, &body); err != nil || (body.Action != "save_draft" && body.Action != "publish" && body.Action != "archive") || input.ResourceKind != "event_content" {
			return mutationReceiptExpectation{}, ErrInvalidRequest
		}
		switch {
		case input.Method == http.MethodPut && input.Path == base+"/content/intro" && input.ResourceID == input.EventID:
			// An existing intro can retain a legacy document ID, so only its
			// action/type are knowable before the mutation.
			return mutationReceiptExpectation{Action: "event_content.intro." + body.Action, TargetType: "event_content"}, nil
		case input.Method == http.MethodPost && input.Path == base+"/announcements" && input.ResourceID == input.EventID:
			return mutationReceiptExpectation{Action: "event_content.announcement." + body.Action, TargetType: "event_content"}, nil
		case input.Method == http.MethodPatch && input.Path == base+"/announcements/"+url.PathEscape(input.ResourceID):
			return mutationReceiptExpectation{Action: "event_content.announcement." + body.Action, TargetType: "event_content", TargetID: input.ResourceID}, nil
		}
	case permissions.ActionContactSubmissionManage:
		if input.Method == http.MethodPatch && input.ResourceKind == "contact_submission" && input.Path == base+"/contact-submissions/"+url.PathEscape(input.ResourceID)+"/resolution" {
			return mutationReceiptExpectation{Action: "contact_submission.resolved", TargetType: "contact_submission", TargetID: input.ResourceID}, nil
		}
	case permissions.ActionApplicationReview:
		if input.Method == http.MethodPut && input.ResourceKind == "application" && input.Path == base+"/applications/"+url.PathEscape(input.ResourceID)+"/reviews/me" {
			return mutationReceiptExpectation{Action: "application.review_saved", TargetType: "application", TargetID: input.ResourceID}, nil
		}
	case permissions.ActionApplicationApproveAdmission:
		if input.ResourceKind == "application" && input.Path == base+"/applications/"+url.PathEscape(input.ResourceID)+"/admission-consensus/approval" {
			switch input.Method {
			case http.MethodPut:
				return mutationReceiptExpectation{Action: "application.admission_approved", TargetType: "application", TargetID: input.ResourceID}, nil
			case http.MethodDelete:
				return mutationReceiptExpectation{Action: "application.admission_approval_withdrawn", TargetType: "application", TargetID: input.ResourceID}, nil
			}
		}
	case permissions.ActionApplicationDecide:
		var body struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(input.Body, &body); err == nil && input.Method == http.MethodPatch && input.ResourceKind == "application" && input.Path == base+"/applications/"+url.PathEscape(input.ResourceID)+"/decision" {
			switch body.Status {
			case "rejected":
				return mutationReceiptExpectation{Action: "application.rejected", TargetType: "application", TargetID: input.ResourceID}, nil
			case "waitlisted":
				return mutationReceiptExpectation{Action: "application.waitlisted", TargetType: "application", TargetID: input.ResourceID}, nil
			}
		}
	case permissions.ActionCheckinScan:
		if input.Method == http.MethodPost && input.ResourceKind == "event" && input.ResourceID == input.EventID && input.Path == base+"/checkins/scan" {
			return mutationReceiptExpectation{Action: "checkin.completed", TargetType: "application"}, nil
		}
	}
	return mutationReceiptExpectation{}, ErrInvalidRequest
}

func deterministicMutationFailure(err error) (int, bool) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusUnprocessableEntity, true
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden, true
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, true
	case errors.Is(err, ErrConflict):
		return http.StatusConflict, true
	default:
		return 0, false
	}
}

func mutationFinalizeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

func versionFromETag(etag string) (int64, bool) {
	if !ifMatchPattern.MatchString(etag) {
		return 0, false
	}
	version, err := strconv.ParseInt(strings.Trim(etag, `"`), 10, 64)
	return version, err == nil && version > 0
}

func mutationStatusFromItem(item adminstore.OutboxItem) (MutationStatus, error) {
	requestID := item.Result.Payload["operation_request_id"]
	if !requestIDPattern.MatchString(requestID) || item.UpdatedAt.IsZero() {
		return MutationStatus{}, ErrUpstream
	}
	status := MutationStatus{RequestID: requestID, UpdatedAt: item.UpdatedAt.UTC()}
	switch item.State {
	case "pending", "claimed":
		if item.Result.Code != "operation.pending" || item.Result.Digest != "" || item.Result.Payload["response_status"] != "" || item.Result.Payload["result_version"] != "" || item.TerminalAt != nil {
			return MutationStatus{}, ErrUpstream
		}
		status.Status = "pending"
	case "succeeded":
		if item.Result.Code != "operation.settled" || item.DeliveryPhase != adminstore.DeliveryPhaseSent || item.TerminalAt == nil || !receiptHashPattern.MatchString(item.Result.Digest) {
			return MutationStatus{}, ErrUpstream
		}
		status.Status = "succeeded"
	case "failed":
		if item.Result.Code != "operation.failed" || item.Result.Digest != "" || item.DeliveryPhase != adminstore.DeliveryPhaseSent || item.TerminalAt == nil {
			return MutationStatus{}, ErrUpstream
		}
		status.Status = "failed"
	case "needs_operator":
		if item.Result.Code != "operation.pending" || item.Result.Digest != "" || item.Result.Payload["response_status"] != "" || item.Result.Payload["result_version"] != "" || item.TerminalAt == nil || (item.DeliveryPhase != adminstore.DeliveryPhaseIndeterminate && item.DeliveryPhase != adminstore.DeliveryPhaseSent) {
			return MutationStatus{}, ErrUpstream
		}
		status.Status = "needs_operator"
	default:
		return MutationStatus{}, ErrUpstream
	}
	if raw := item.Result.Payload["response_status"]; raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 200 || value > 599 || (status.Status == "succeeded" && value >= 300) || (status.Status == "failed" && (value < 400 || value >= 500)) {
			return MutationStatus{}, ErrUpstream
		}
		status.ResponseStatus = &value
	} else if status.Status == "failed" {
		return MutationStatus{}, ErrUpstream
	}
	if raw := item.Result.Payload["result_version"]; raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value <= 0 || status.Status != "succeeded" {
			return MutationStatus{}, ErrUpstream
		}
		status.ResultVersion = &value
	}
	return status, nil
}

func randomOperationID() (string, error) {
	buffer := make([]byte, 18)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "aop_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (s *Service) validStepUp(ctx context.Context, actor Actor, decision permissions.Decision) (adminstepup.StepUpState, error) {
	now := s.now().UTC()
	// No role can manufacture freshness. A non-positive challenge version is
	// an unenrolled/invalid authorization state, including for super and top
	// administrators, and therefore fails closed.
	if decision.ChallengeVersion <= 0 {
		return adminstepup.StepUpState{}, ErrStepUpRequired
	}
	state, err := s.stepups.GetActiveForSession(ctx, actor.SessionID, actor.UserID, now)
	if err != nil || !opaqueValuePattern.MatchString(state.ID) || state.SessionID != actor.SessionID || state.UserID != actor.UserID || state.ChallengeVersion != decision.ChallengeVersion || state.VerifiedAt.IsZero() || state.VerifiedAt.After(now.Add(time.Minute)) || !now.Before(state.ExpiresAt) || state.RevokedAt != nil {
		return adminstepup.StepUpState{}, ErrStepUpRequired
	}
	return state, nil
}

func validateProxyRequest(input ProxyRequest) error {
	if !opaqueValuePattern.MatchString(input.EventID) || !opaqueValuePattern.MatchString(input.ResourceKind) || !opaqueValuePattern.MatchString(input.ResourceID) || !requestIDPattern.MatchString(input.RequestID) {
		return ErrInvalidRequest
	}
	if input.Method != http.MethodGet && input.Method != http.MethodPost && input.Method != http.MethodPut && input.Method != http.MethodPatch && input.Method != http.MethodDelete {
		return ErrInvalidRequest
	}
	if input.Capability == "" || !strings.HasPrefix(input.Path, "/internal/v1/events/"+url.PathEscape(input.EventID)+"/") || strings.Contains(input.Path, "?") || strings.Contains(input.Path, "#") {
		return ErrInvalidRequest
	}
	if input.ReauthenticationToken != "" && !reauthTokenPattern.MatchString(input.ReauthenticationToken) {
		return ErrInvalidRequest
	}
	mutation := input.Method != http.MethodGet
	if mutation {
		if !idempotencyPattern.MatchString(input.IdempotencyKey) || !ifMatchPattern.MatchString(input.IfMatch) {
			return ErrInvalidRequest
		}
	} else if input.IdempotencyKey != "" || input.IfMatch != "" || len(input.Body) != 0 {
		return ErrInvalidRequest
	}
	return nil
}

func validActor(actor Actor) bool {
	return opaqueValuePattern.MatchString(string(actor.UserID)) && opaqueValuePattern.MatchString(actor.SessionID) && !actor.AuthenticatedAt.IsZero()
}

func validRegisteredEvent(event adminroles.RegisteredEvent) bool {
	return event.Enabled && event.Series == "dreamup" && opaqueValuePattern.MatchString(event.EventID) && event.Slug != "" && event.DisplayName != ""
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func cloneQuery(values url.Values) url.Values {
	result := make(url.Values, len(values))
	for key, entries := range values {
		result[key] = append([]string(nil), entries...)
	}
	return result
}
