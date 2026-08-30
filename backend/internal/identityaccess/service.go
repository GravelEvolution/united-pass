package identityaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/rivo/uniseg"
	"golang.org/x/text/unicode/norm"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

const (
	requestLifetime = 24 * time.Hour
	grantLifetime   = 15 * time.Minute
	claimLifetime   = time.Minute
	stepUpFreshness = 5 * time.Minute
)

type TargetRef struct {
	Type TargetType
	ID   string
}

type TargetValidation struct {
	Target        TargetRef
	SubjectUserID identity.UserID
}

type TargetValidator interface {
	ValidateIdentityTarget(context.Context, string, TargetRef, []Field) (TargetValidation, error)
}

type ReasonCipher interface {
	Encrypt(adminstepup.EncryptionPurpose, string, string, int64, string) (adminstepup.EncryptedValue, error)
}

type RequestFingerprint struct {
	Version string
	KeyID   string
	Digest  string
}

type Fingerprinter interface {
	Fingerprint(string, []byte) (RequestFingerprint, error)
}

type LocalReceiptResult struct {
	Code    string
	Digest  string
	Payload map[string]string
}

type LocalOperationReceipt struct {
	ID             string
	IdempotencyKey string
	Fingerprint    RequestFingerprint
	Result         LocalReceiptResult
	State          string
	Version        int64
	CreatedAt      time.Time
	TerminalAt     *time.Time
}

type LocalReceiptRepository interface {
	CreateOrReplay(context.Context, LocalOperationReceipt) (LocalOperationReceipt, bool, error)
	CompleteLocal(context.Context, string, int64, LocalReceiptResult, time.Time) error
}

type AuthorizationEvidence struct {
	Role             adminroles.Role
	BindingID        string
	BindingVersion   int64
	ChallengeVersion int64
}

type AuthorizationRepository interface {
	Revalidate(context.Context, identity.UserID, string, AuthorizationEvidence) error
	CurrentGrantAuthorization(context.Context, identity.UserID, string) (AuthorizationEvidence, error)
}

type MutationRepositories struct {
	Access        Repository
	Authorization AuthorizationRepository
	Receipts      LocalReceiptRepository
}

type MutationUnitOfWork interface {
	WithinIdentityAccessMutation(context.Context, func(MutationRepositories) error) error
}

type ServiceDependencies struct {
	Repository      Repository
	UnitOfWork      MutationUnitOfWork
	Authorizer      permissions.Authorizer
	TargetValidator TargetValidator
	ReasonCipher    ReasonCipher
	Fingerprinter   Fingerprinter
}

type Service struct {
	repository      Repository
	uow             MutationUnitOfWork
	authorizer      permissions.Authorizer
	targetValidator TargetValidator
	reasonCipher    ReasonCipher
	fingerprinter   Fingerprinter
	now             func() time.Time
	newID           func(string) (string, error)
}

type ServiceOption func(*Service)

func WithClock(now func() time.Time) ServiceOption {
	return func(service *Service) {
		if now != nil {
			service.now = now
		}
	}
}

func WithIDGenerator(generator func(string) (string, error)) ServiceOption {
	return func(service *Service) {
		if generator != nil {
			service.newID = generator
		}
	}
}

func NewService(dependencies ServiceDependencies, options ...ServiceOption) *Service {
	service := &Service{
		repository: dependencies.Repository, uow: dependencies.UnitOfWork,
		authorizer: dependencies.Authorizer, targetValidator: dependencies.TargetValidator,
		reasonCipher: dependencies.ReasonCipher, fingerprinter: dependencies.Fingerprinter,
		now: func() time.Time { return time.Now().UTC() }, newID: newServiceID,
	}
	for _, option := range options {
		if option != nil {
			option(service)
		}
	}
	return service
}

type CreateRequestInput struct {
	ActorID        identity.UserID
	EventID        string
	Target         TargetRef
	Fields         []Field
	Reason         string
	CorrelationID  string
	IdempotencyKey string
}

type CreateRequestResult struct {
	Request  Request
	Replayed bool
}

func (s *Service) CreateRequest(ctx context.Context, input CreateRequestInput) (CreateRequestResult, error) {
	if err := s.ready(true); err != nil {
		return CreateRequestResult{}, err
	}
	input.EventID = strings.TrimSpace(input.EventID)
	input.Target.ID = strings.TrimSpace(input.Target.ID)
	if input.ActorID == "" || input.EventID == "" || input.Target.ID == "" || strings.TrimSpace(input.CorrelationID) == "" {
		return CreateRequestResult{}, ErrInvalidRequest
	}
	if !validIdempotencyKey(input.IdempotencyKey) {
		return CreateRequestResult{}, ErrInvalidIdempotencyKey
	}
	fields, err := normalizeFields(input.Fields)
	if err != nil {
		return CreateRequestResult{}, err
	}
	reason, err := normalizeReason(input.Reason)
	if err != nil {
		return CreateRequestResult{}, err
	}
	validated, err := s.targetValidator.ValidateIdentityTarget(ctx, input.EventID, input.Target, fields)
	if err != nil {
		return CreateRequestResult{}, fmt.Errorf("identityaccess: validate target: %w", err)
	}
	if validated.Target != input.Target || validated.SubjectUserID == "" || validated.SubjectUserID == input.ActorID {
		return CreateRequestResult{}, ErrInvalidRequest
	}
	authorization, err := s.authorize(ctx, input.ActorID, permissions.ActionIdentityAccessRequest, permissions.Resource{Kind: string(input.Target.Type), ID: input.Target.ID, EventID: input.EventID}, adminroles.RoleSeniorAdmin)
	if err != nil {
		return CreateRequestResult{}, err
	}
	canonical, err := json.Marshal(struct {
		Operation, ActorID, EventID, TargetType, TargetID, TargetSubject, Reason string
		Fields                                                                   []Field
	}{"request", string(input.ActorID), input.EventID, string(input.Target.Type), input.Target.ID, string(validated.SubjectUserID), reason, fields})
	if err != nil {
		return CreateRequestResult{}, err
	}
	fingerprint, err := s.fingerprint("identityaccess.request", canonical)
	if err != nil {
		return CreateRequestResult{}, err
	}
	requestID, err := s.newID("iar_")
	if err != nil {
		return CreateRequestResult{}, err
	}
	reasonID, err := s.newID("reason_")
	if err != nil {
		return CreateRequestResult{}, err
	}
	receiptID, err := s.newID("aop_")
	if err != nil {
		return CreateRequestResult{}, err
	}
	sealed, err := s.reasonCipher.Encrypt(adminstepup.PurposeProtectedReason, string(input.ActorID), reasonID, 1, reason)
	if err != nil || sealed.KeyID == "" || len(sealed.Nonce) == 0 || len(sealed.Ciphertext) == 0 {
		if err == nil {
			err = ErrInvalidRequest
		}
		return CreateRequestResult{}, fmt.Errorf("identityaccess: encrypt reason: %w", err)
	}
	var result CreateRequestResult
	err = s.uow.WithinIdentityAccessMutation(ctx, func(repositories MutationRepositories) error {
		if err := validateMutationRepositories(repositories); err != nil {
			return err
		}
		if err := repositories.Authorization.Revalidate(ctx, input.ActorID, input.EventID, authorization); err != nil {
			return ErrForbidden
		}
		now := s.now().UTC()
		receipt, replay, err := repositories.Receipts.CreateOrReplay(ctx, LocalOperationReceipt{ID: receiptID, IdempotencyKey: input.IdempotencyKey, Fingerprint: fingerprint, State: "pending", Version: 1, CreatedAt: now})
		if err != nil {
			return err
		}
		if replay {
			stored, err := decodeCreateResult(receipt.Result)
			if err != nil {
				return err
			}
			stored.Replayed = true
			result = stored
			return nil
		}
		request := Request{ID: requestID, EventID: input.EventID, RequesterID: input.ActorID, TargetSubject: validated.SubjectUserID, TargetType: input.Target.Type, TargetID: input.Target.ID, Fields: fields, Status: StatusPending, ReasonID: reasonID, Version: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(requestLifetime)}
		created, err := repositories.Access.CreateRequest(ctx, request, ProtectedReason{ID: reasonID, OwnerID: input.ActorID, KeyID: sealed.KeyID, Nonce: append([]byte(nil), sealed.Nonce...), Ciphertext: append([]byte(nil), sealed.Ciphertext...), CreatedAt: now}, Audit{ActorID: input.ActorID, RequestID: input.CorrelationID, Action: string(permissions.ActionIdentityAccessRequest)})
		if err != nil {
			return err
		}
		stored := encodeRequestResult("identity_access.requested", created)
		if err := repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, stored, now); err != nil {
			return err
		}
		result = CreateRequestResult{Request: created}
		return nil
	})
	if err != nil {
		return CreateRequestResult{}, err
	}
	return result, nil
}

type DecideInput struct {
	ActorID         identity.UserID
	EventID         string
	AccessRequestID string
	Approved        bool
	Fields          []Field
	ExpectedVersion int64
	StepUp          auth.ReauthGrantData
	CorrelationID   string
	IdempotencyKey  string
}

type DecideResult struct {
	Request  Request
	Grant    *Grant
	Replayed bool
}

func (s *Service) Decide(ctx context.Context, input DecideInput) (DecideResult, error) {
	if err := s.ready(false); err != nil {
		return DecideResult{}, err
	}
	input.EventID, input.AccessRequestID = strings.TrimSpace(input.EventID), strings.TrimSpace(input.AccessRequestID)
	if input.ActorID == "" || input.EventID == "" || input.AccessRequestID == "" || strings.TrimSpace(input.CorrelationID) == "" {
		return DecideResult{}, ErrInvalidDecision
	}
	if input.ExpectedVersion <= 0 {
		return DecideResult{}, ErrIfMatchRequired
	}
	if !validIdempotencyKey(input.IdempotencyKey) {
		return DecideResult{}, ErrInvalidIdempotencyKey
	}
	fields := []Field(nil)
	var err error
	if input.Approved {
		fields, err = normalizeFields(input.Fields)
		if err != nil {
			return DecideResult{}, err
		}
	} else if len(input.Fields) != 0 {
		return DecideResult{}, ErrInvalidDecision
	}
	authorization, err := s.authorize(ctx, input.ActorID, permissions.ActionIdentityAccessApprove, permissions.Resource{Kind: "identity_access_request", ID: input.AccessRequestID, EventID: input.EventID}, adminroles.RoleSuperAdmin)
	if err != nil {
		return DecideResult{}, err
	}
	canonical, err := json.Marshal(struct {
		Operation, ActorID, EventID, RequestID string
		Approved                               bool
		Fields                                 []Field
		ExpectedVersion                        int64
	}{"decide", string(input.ActorID), input.EventID, input.AccessRequestID, input.Approved, fields, input.ExpectedVersion})
	if err != nil {
		return DecideResult{}, err
	}
	fingerprint, err := s.fingerprint("identityaccess.decide", canonical)
	if err != nil {
		return DecideResult{}, err
	}
	receiptID, err := s.newID("aop_")
	if err != nil {
		return DecideResult{}, err
	}
	var result DecideResult
	err = s.uow.WithinIdentityAccessMutation(ctx, func(repositories MutationRepositories) error {
		if err := validateMutationRepositories(repositories); err != nil {
			return err
		}
		if err := repositories.Authorization.Revalidate(ctx, input.ActorID, input.EventID, authorization); err != nil {
			return ErrForbidden
		}
		now := s.now().UTC()
		receipt, replay, err := repositories.Receipts.CreateOrReplay(ctx, LocalOperationReceipt{ID: receiptID, IdempotencyKey: input.IdempotencyKey, Fingerprint: fingerprint, State: "pending", Version: 1, CreatedAt: now})
		if err != nil {
			return err
		}
		if replay {
			stored, err := decodeDecisionResult(receipt.Result)
			if err != nil {
				return err
			}
			stored.Replayed = true
			result = stored
			return nil
		}
		request, err := repositories.Access.GetRequest(ctx, input.EventID, input.AccessRequestID)
		if err != nil {
			return err
		}
		if request.Status != StatusPending || request.Version != input.ExpectedVersion || !now.Before(request.ExpiresAt) {
			return ErrConflict
		}
		if err := ValidateDecision(request, Decision{ApproverID: input.ActorID, Approved: input.Approved, RequestID: request.ID, DecidedAt: now}); err != nil {
			return err
		}
		if err := validateStepUp(input.StepUp, input.ActorID, input.AccessRequestID, authorization.ChallengeVersion, now); err != nil {
			return err
		}
		if input.Approved && !fieldSubset(fields, request.Fields) {
			return ErrInvalidDecision
		}
		requesterAuthorization, err := repositories.Authorization.CurrentGrantAuthorization(ctx, request.RequesterID, input.EventID)
		if err != nil || requesterAuthorization.Role != adminroles.RoleSeniorAdmin {
			return ErrForbidden
		}
		grantAuthorization := GrantAuthorization{RoleBindingID: requesterAuthorization.BindingID, RoleBindingVersion: requesterAuthorization.BindingVersion, ChallengeVersion: requesterAuthorization.ChallengeVersion, FieldSetHash: fieldSetHash(fields)}
		outcome, err := repositories.Access.Decide(ctx, input.EventID, request.ID, input.ExpectedVersion, Decision{ApproverID: input.ActorID, Approved: input.Approved, RequestID: request.ID, DecidedAt: now}, fields, grantAuthorization, Audit{ActorID: input.ActorID, RequestID: input.CorrelationID, Action: string(permissions.ActionIdentityAccessApprove)})
		if err != nil {
			return err
		}
		stored := encodeDecisionResult(outcome)
		if err := repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, stored, now); err != nil {
			return err
		}
		result = DecideResult{Request: outcome.Request, Grant: outcome.Grant}
		return nil
	})
	if err != nil {
		return DecideResult{}, err
	}
	return result, nil
}

type ClaimInput struct {
	ActorID         identity.UserID
	EventID         string
	GrantID         string
	ExpectedVersion int64
	CorrelationID   string
	IdempotencyKey  string
}

type ClaimResult struct {
	Claim    Claim
	Replayed bool
}

func (s *Service) Claim(ctx context.Context, input ClaimInput) (ClaimResult, error) {
	if err := s.ready(false); err != nil {
		return ClaimResult{}, err
	}
	input.EventID, input.GrantID = strings.TrimSpace(input.EventID), strings.TrimSpace(input.GrantID)
	if input.ActorID == "" || input.EventID == "" || input.GrantID == "" || strings.TrimSpace(input.CorrelationID) == "" {
		return ClaimResult{}, ErrInvalidRequest
	}
	if input.ExpectedVersion <= 0 {
		return ClaimResult{}, ErrIfMatchRequired
	}
	if !validIdempotencyKey(input.IdempotencyKey) {
		return ClaimResult{}, ErrInvalidIdempotencyKey
	}
	authorization, err := s.authorize(ctx, input.ActorID, permissions.ActionIdentityGrantConsume, permissions.Resource{Kind: "identity_access_grant", ID: input.GrantID, EventID: input.EventID}, adminroles.RoleSeniorAdmin)
	if err != nil {
		return ClaimResult{}, err
	}
	canonical, err := json.Marshal(struct {
		Operation, ActorID, EventID, GrantID string
		ExpectedVersion                      int64
	}{"claim", string(input.ActorID), input.EventID, input.GrantID, input.ExpectedVersion})
	if err != nil {
		return ClaimResult{}, err
	}
	fingerprint, err := s.fingerprint("identityaccess.claim", canonical)
	if err != nil {
		return ClaimResult{}, err
	}
	receiptID, err := s.newID("aop_")
	if err != nil {
		return ClaimResult{}, err
	}
	var result ClaimResult
	err = s.uow.WithinIdentityAccessMutation(ctx, func(repositories MutationRepositories) error {
		if err := validateMutationRepositories(repositories); err != nil {
			return err
		}
		if err := repositories.Authorization.Revalidate(ctx, input.ActorID, input.EventID, authorization); err != nil {
			return ErrForbidden
		}
		now := s.now().UTC()
		receipt, replay, err := repositories.Receipts.CreateOrReplay(ctx, LocalOperationReceipt{ID: receiptID, IdempotencyKey: input.IdempotencyKey, Fingerprint: fingerprint, State: "pending", Version: 1, CreatedAt: now})
		if err != nil {
			return err
		}
		if replay {
			claim, err := decodeClaimResult(receipt.Result)
			if err != nil {
				return err
			}
			result = ClaimResult{Claim: claim, Replayed: true}
			return nil
		}
		claim, err := repositories.Access.Claim(ctx, input.EventID, input.GrantID, input.ActorID, input.ExpectedVersion, authorization, now, Audit{ActorID: input.ActorID, RequestID: input.CorrelationID, Action: string(permissions.ActionIdentityGrantConsume)})
		if err != nil {
			return err
		}
		if claim.ClaimNonce == "" || claim.LeaseExpiresAt.Sub(now) <= 0 || claim.LeaseExpiresAt.Sub(now) > claimLifetime {
			return ErrInvalidStoredResult
		}
		stored := encodeClaimResult(claim)
		if err := repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, stored, now); err != nil {
			return err
		}
		result = ClaimResult{Claim: claim}
		return nil
	})
	if err != nil {
		return ClaimResult{}, err
	}
	return result, nil
}

type SettleInput struct {
	ActorID         identity.UserID
	EventID         string
	GrantID         string
	ExpectedVersion int64
	ClaimNonce      string
	ReceiptHash     string
	CorrelationID   string
	IdempotencyKey  string
}

type SettleResult struct {
	GrantID  string
	Version  int64
	Replayed bool
}

func (s *Service) Settle(ctx context.Context, input SettleInput) (SettleResult, error) {
	if err := s.ready(false); err != nil {
		return SettleResult{}, err
	}
	input.EventID, input.GrantID = strings.TrimSpace(input.EventID), strings.TrimSpace(input.GrantID)
	if input.ActorID == "" || input.EventID == "" || input.GrantID == "" || input.ClaimNonce == "" || !opaqueDigestPattern.MatchString(input.ReceiptHash) || strings.TrimSpace(input.CorrelationID) == "" {
		return SettleResult{}, ErrInvalidRequest
	}
	if input.ExpectedVersion <= 0 {
		return SettleResult{}, ErrIfMatchRequired
	}
	if !validIdempotencyKey(input.IdempotencyKey) {
		return SettleResult{}, ErrInvalidIdempotencyKey
	}
	authorization, err := s.authorize(ctx, input.ActorID, permissions.ActionIdentityGrantConsume, permissions.Resource{Kind: "identity_access_grant", ID: input.GrantID, EventID: input.EventID}, adminroles.RoleSeniorAdmin)
	if err != nil {
		return SettleResult{}, err
	}
	canonical, err := json.Marshal(struct {
		Operation, ActorID, EventID, GrantID, ClaimNonceHash, ReceiptHash string
		ExpectedVersion                                                   int64
	}{"settle", string(input.ActorID), input.EventID, input.GrantID, hashOpaque(input.ClaimNonce), input.ReceiptHash, input.ExpectedVersion})
	if err != nil {
		return SettleResult{}, err
	}
	fingerprint, err := s.fingerprint("identityaccess.settle", canonical)
	if err != nil {
		return SettleResult{}, err
	}
	receiptID, err := s.newID("aop_")
	if err != nil {
		return SettleResult{}, err
	}
	var result SettleResult
	err = s.uow.WithinIdentityAccessMutation(ctx, func(repositories MutationRepositories) error {
		if err := validateMutationRepositories(repositories); err != nil {
			return err
		}
		if err := repositories.Authorization.Revalidate(ctx, input.ActorID, input.EventID, authorization); err != nil {
			return ErrForbidden
		}
		now := s.now().UTC()
		receipt, replay, err := repositories.Receipts.CreateOrReplay(ctx, LocalOperationReceipt{ID: receiptID, IdempotencyKey: input.IdempotencyKey, Fingerprint: fingerprint, State: "pending", Version: 1, CreatedAt: now})
		if err != nil {
			return err
		}
		if replay {
			stored, err := decodeSettleResult(receipt.Result)
			if err != nil {
				return err
			}
			stored.Replayed = true
			result = stored
			return nil
		}
		version, err := repositories.Access.Settle(ctx, input.EventID, input.GrantID, input.ActorID, input.ExpectedVersion, input.ClaimNonce, input.ReceiptHash, authorization, now, Audit{ActorID: input.ActorID, RequestID: input.CorrelationID, Action: string(permissions.ActionIdentityGrantConsume)})
		if err != nil {
			return err
		}
		stored := encodeSettleResult(input.GrantID, version)
		if err := repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, stored, now); err != nil {
			return err
		}
		result = SettleResult{GrantID: input.GrantID, Version: version}
		return nil
	})
	if err != nil {
		return SettleResult{}, err
	}
	return result, nil
}

func (s *Service) ListOwn(ctx context.Context, actor identity.UserID, query adminpagination.Query) (Page, error) {
	if err := s.ready(false); err != nil {
		return Page{}, err
	}
	query.ActorID, query.ScopeKind, query.ListKind = string(actor), "event", ListKindOwn
	if _, err := s.authorize(ctx, actor, permissions.ActionIdentityAccessRequest, permissions.Resource{Kind: "identity_access_list", ID: query.EventID, EventID: query.EventID}, adminroles.RoleSeniorAdmin); err != nil {
		return Page{}, err
	}
	return s.repository.ListOwn(ctx, actor, query)
}

func (s *Service) ListApprovalQueue(ctx context.Context, actor identity.UserID, query adminpagination.Query) (Page, error) {
	if err := s.ready(false); err != nil {
		return Page{}, err
	}
	query.ActorID, query.ScopeKind, query.ListKind = string(actor), "event", ListKindApprovalQueue
	if _, err := s.authorize(ctx, actor, permissions.ActionIdentityAccessApprove, permissions.Resource{Kind: "identity_access_queue", ID: query.EventID, EventID: query.EventID}, adminroles.RoleSuperAdmin); err != nil {
		return Page{}, err
	}
	return s.repository.ListApprovalQueue(ctx, query)
}

func (s *Service) GetOwn(ctx context.Context, actor identity.UserID, eventID, requestID string) (Request, error) {
	if err := s.ready(false); err != nil {
		return Request{}, err
	}
	if _, err := s.authorize(ctx, actor, permissions.ActionIdentityAccessRequest, permissions.Resource{Kind: "identity_access_request", ID: requestID, EventID: eventID}, adminroles.RoleSeniorAdmin); err != nil {
		return Request{}, err
	}
	request, err := s.repository.GetRequest(ctx, eventID, requestID)
	if err != nil || request.RequesterID != actor {
		if err != nil {
			return Request{}, err
		}
		return Request{}, ErrNotFound
	}
	return request, nil
}

func (s *Service) GetForApproval(ctx context.Context, actor identity.UserID, eventID, requestID string) (Request, error) {
	if err := s.ready(false); err != nil {
		return Request{}, err
	}
	if _, err := s.authorize(ctx, actor, permissions.ActionIdentityAccessApprove, permissions.Resource{Kind: "identity_access_request", ID: requestID, EventID: eventID}, adminroles.RoleSuperAdmin); err != nil {
		return Request{}, err
	}
	return s.repository.GetRequest(ctx, eventID, requestID)
}

func (s *Service) authorize(ctx context.Context, actor identity.UserID, action permissions.Action, resource permissions.Resource, required adminroles.Role) (AuthorizationEvidence, error) {
	if s == nil || s.authorizer == nil || actor == "" {
		return AuthorizationEvidence{}, ErrForbidden
	}
	decision, err := s.authorizer.Check(ctx, actor, action, resource)
	if err != nil {
		return AuthorizationEvidence{}, fmt.Errorf("identityaccess: authorize: %w", err)
	}
	if !decision.Allowed || !roleSatisfies(decision.Role, required) || decision.BindingID == "" || decision.BindingVersion <= 0 || decision.ChallengeVersion <= 0 {
		return AuthorizationEvidence{}, ErrForbidden
	}
	return AuthorizationEvidence{Role: decision.Role, BindingID: decision.BindingID, BindingVersion: decision.BindingVersion, ChallengeVersion: decision.ChallengeVersion}, nil
}

// roleSatisfies reports whether the decision role satisfies a required role.
// top_admin carries the same authority as super_admin but has its own
// display identity, so it satisfies every super_admin requirement.
func roleSatisfies(decision, required adminroles.Role) bool {
	if decision == required {
		return true
	}
	return decision == adminroles.RoleTopAdmin && required == adminroles.RoleSuperAdmin
}

func (s *Service) ready(create bool) error {
	if s == nil || s.repository == nil || s.uow == nil || s.authorizer == nil || s.fingerprinter == nil || s.now == nil || s.newID == nil || (create && (s.targetValidator == nil || s.reasonCipher == nil)) {
		return ErrInvalidRequest
	}
	return nil
}

func validateMutationRepositories(repositories MutationRepositories) error {
	if repositories.Access == nil || repositories.Authorization == nil || repositories.Receipts == nil {
		return ErrInvalidRequest
	}
	return nil
}

func (s *Service) fingerprint(purpose string, canonical []byte) (RequestFingerprint, error) {
	fingerprint, err := s.fingerprinter.Fingerprint(purpose, canonical)
	if err != nil || fingerprint.Version == "" || fingerprint.KeyID == "" || fingerprint.Digest == "" {
		if err == nil {
			err = ErrInvalidRequest
		}
		return RequestFingerprint{}, fmt.Errorf("identityaccess: fingerprint: %w", err)
	}
	return fingerprint, nil
}

func normalizeFields(fields []Field) ([]Field, error) {
	request := Request{EventID: "event", RequesterID: "requester", TargetSubject: "target", TargetType: TargetApplication, TargetID: "target", Fields: append([]Field(nil), fields...)}
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	result := append([]Field(nil), fields...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func fieldSubset(subset, full []Field) bool {
	if len(subset) == 0 || len(subset) > len(full) {
		return false
	}
	allowed := make(map[Field]bool, len(full))
	for _, field := range full {
		allowed[field] = true
	}
	for _, field := range subset {
		if !allowed[field] {
			return false
		}
	}
	return true
}

func fieldSetHash(fields []Field) string {
	parts := make([]string, len(fields))
	for i, field := range fields {
		parts[i] = string(field)
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func normalizeReason(raw string) (string, error) {
	normalized := strings.TrimSpace(norm.NFKC.String(raw))
	count := uniseg.GraphemeClusterCount(normalized)
	if count < 20 || count > 500 {
		return "", ErrInvalidReason
	}
	for _, value := range normalized {
		if unicode.IsControl(value) || unicode.Is(unicode.Cf, value) || value == '\u200d' {
			return "", ErrInvalidReason
		}
	}
	return normalized, nil
}

func validateStepUp(grant auth.ReauthGrantData, actor identity.UserID, target string, challengeVersion int64, now time.Time) error {
	if grant.GrantID == "" || grant.UserID != actor || grant.Action != auth.ReauthActionAdminOAApproval || grant.Target != target || grant.ChallengeVersion != challengeVersion || grant.CreatedAt.IsZero() || grant.CreatedAt.After(now.Add(time.Minute)) || now.Sub(grant.CreatedAt) > stepUpFreshness {
		return ErrStepUpRequired
	}
	return nil
}

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,160}$`)
var opaqueDigestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,240}$`)

func validIdempotencyKey(value string) bool { return idempotencyKeyPattern.MatchString(value) }

func hashOpaque(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func encodeRequestResult(code string, request Request) LocalReceiptResult {
	payload := map[string]string{"request_id": request.ID, "status": string(request.Status), "version": strconv.FormatInt(request.Version, 10)}
	return storedResult(code, payload)
}

func decodeCreateResult(result LocalReceiptResult) (CreateRequestResult, error) {
	request, err := decodeRequestResult(result, "identity_access.requested")
	return CreateRequestResult{Request: request}, err
}

func encodeDecisionResult(outcome DecisionOutcome) LocalReceiptResult {
	payload := map[string]string{"request_id": outcome.Request.ID, "status": string(outcome.Request.Status), "version": strconv.FormatInt(outcome.Request.Version, 10)}
	if outcome.Grant != nil {
		payload["grant_id"] = outcome.Grant.ID
	}
	return storedResult("identity_access.decided", payload)
}

func decodeDecisionResult(result LocalReceiptResult) (DecideResult, error) {
	request, err := decodeRequestResult(result, "identity_access.decided")
	if err != nil {
		return DecideResult{}, err
	}
	var grant *Grant
	if id := result.Payload["grant_id"]; id != "" {
		if !strings.HasPrefix(id, "iag_") {
			return DecideResult{}, ErrInvalidStoredResult
		}
		grant = &Grant{ID: id}
	}
	return DecideResult{Request: request, Grant: grant}, nil
}

func decodeRequestResult(result LocalReceiptResult, code string) (Request, error) {
	if result.Code != code || result.Payload == nil || result.Digest != storedResult(code, result.Payload).Digest {
		return Request{}, ErrInvalidStoredResult
	}
	version, err := strconv.ParseInt(result.Payload["version"], 10, 64)
	status := Status(result.Payload["status"])
	if err != nil || version <= 0 || !strings.HasPrefix(result.Payload["request_id"], "iar_") || (status != StatusPending && status != StatusApproved && status != StatusRejected && status != StatusRevoked) {
		return Request{}, ErrInvalidStoredResult
	}
	return Request{ID: result.Payload["request_id"], Status: status, Version: version}, nil
}

func encodeClaimResult(claim Claim) LocalReceiptResult {
	return storedResult("identity_access.claimed", map[string]string{"grant_id": claim.GrantID, "status": string(GrantClaimed), "version": strconv.FormatInt(claim.Version, 10)})
}

func decodeClaimResult(result LocalReceiptResult) (Claim, error) {
	if result.Code != "identity_access.claimed" || result.Payload == nil || result.Digest != storedResult(result.Code, result.Payload).Digest {
		return Claim{}, ErrInvalidStoredResult
	}
	version, err := strconv.ParseInt(result.Payload["version"], 10, 64)
	if err != nil || version <= 0 || result.Payload["status"] != string(GrantClaimed) || !strings.HasPrefix(result.Payload["grant_id"], "iag_") {
		return Claim{}, ErrInvalidStoredResult
	}
	return Claim{GrantID: result.Payload["grant_id"], Version: version}, nil
}

func encodeSettleResult(grantID string, version int64) LocalReceiptResult {
	return storedResult("identity_access.settled", map[string]string{"grant_id": grantID, "status": string(GrantSettled), "version": strconv.FormatInt(version, 10)})
}

func decodeSettleResult(result LocalReceiptResult) (SettleResult, error) {
	if result.Code != "identity_access.settled" || result.Payload == nil || result.Digest != storedResult(result.Code, result.Payload).Digest {
		return SettleResult{}, ErrInvalidStoredResult
	}
	version, err := strconv.ParseInt(result.Payload["version"], 10, 64)
	if err != nil || version <= 0 || result.Payload["status"] != string(GrantSettled) || !strings.HasPrefix(result.Payload["grant_id"], "iag_") {
		return SettleResult{}, ErrInvalidStoredResult
	}
	return SettleResult{GrantID: result.Payload["grant_id"], Version: version}, nil
}

func storedResult(code string, payload map[string]string) LocalReceiptResult {
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := []string{code}
	for _, key := range keys {
		parts = append(parts, key, payload[key])
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return LocalReceiptResult{Code: code, Digest: base64.RawURLEncoding.EncodeToString(digest[:]), Payload: payload}
}

func newServiceID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}
