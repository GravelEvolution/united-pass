package adminroles

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

var (
	ErrInvalidRoleMutation        = errors.New("adminroles: invalid role mutation")
	ErrRoleMutationForbidden      = errors.New("adminroles: role mutation forbidden")
	ErrOrdinarySuperAdminMutation = errors.New("adminroles: ordinary path cannot mutate super admin")
	ErrSelfRoleMutation           = errors.New("adminroles: self role mutation forbidden")
	ErrInvalidIdempotencyKey      = errors.New("adminroles: globally random idempotency key required")
	ErrIfMatchRequired            = errors.New("adminroles: If-Match version required")
	ErrRoleIdempotencyConflict    = errors.New("adminroles: idempotency conflict")
	ErrInvalidStoredRoleResult    = errors.New("adminroles: invalid stored role result")
)

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

type ProtectedReasonConsumer interface {
	ConsumeOwned(context.Context, string, identity.UserID, string, time.Time, time.Time) error
}

type RoleManagementDecision struct {
	Allowed        bool
	Role           Role
	BindingID      string
	BindingVersion int64
	Scope          Scope
}

type ActorAuthorizationRepository interface {
	Revalidate(context.Context, identity.UserID, string, RoleManagementDecision) error
}

type RoleMutationRepositories struct {
	Roles              Repository
	ActorAuthorization ActorAuthorizationRepository
	EventRegistry      EventRegistry
	Reasons            ProtectedReasonConsumer
	Receipts           LocalReceiptRepository
}

type RoleMutationUnitOfWork interface {
	WithinRoleMutation(context.Context, func(RoleMutationRepositories) error) error
}

type RoleManagementAuthorizer interface {
	CheckRoleManagement(context.Context, identity.UserID, string) (RoleManagementDecision, error)
}

type RoleMutationResult struct {
	BindingID string
	Version   int64
}

type CreateRoleInput struct {
	ActorID        identity.UserID
	TargetUserID   identity.UserID
	EventID        string
	Role           Role
	ReasonID       string
	RequestID      string
	IdempotencyKey string
}

type UpdateRoleInput struct {
	ActorID         identity.UserID
	TargetUserID    identity.UserID
	BindingID       string
	EventID         string
	Role            Role
	ReasonID        string
	RequestID       string
	IdempotencyKey  string
	ExpectedVersion int64
}

type DisableRoleInput struct {
	ActorID         identity.UserID
	TargetUserID    identity.UserID
	BindingID       string
	EventID         string
	ReasonID        string
	RequestID       string
	IdempotencyKey  string
	ExpectedVersion int64
}

type RoleServiceOption func(*Service)

type Service struct {
	uow           RoleMutationUnitOfWork
	authorizer    RoleManagementAuthorizer
	fingerprinter Fingerprinter
	now           func() time.Time
	newID         func(string) (string, error)
}

func NewService(uow RoleMutationUnitOfWork, authorizer RoleManagementAuthorizer, fingerprinter Fingerprinter, options ...RoleServiceOption) *Service {
	service := &Service{uow: uow, authorizer: authorizer, fingerprinter: fingerprinter, now: func() time.Time { return time.Now().UTC() }, newID: newRoleOperationID}
	for _, option := range options {
		if option != nil {
			option(service)
		}
	}
	return service
}

func WithRoleClock(now func() time.Time) RoleServiceOption {
	return func(service *Service) {
		if now != nil {
			service.now = now
		}
	}
}

func WithRoleIDGenerator(generator func(string) (string, error)) RoleServiceOption {
	return func(service *Service) {
		if generator != nil {
			service.newID = generator
		}
	}
}

func (s *Service) CreateRole(ctx context.Context, input CreateRoleInput) (RoleMutationResult, error) {
	if err := s.validateCommon(input.ActorID, input.TargetUserID, input.EventID, input.ReasonID, input.RequestID, input.IdempotencyKey); err != nil {
		return RoleMutationResult{}, err
	}
	if err := validateOrdinaryRole(input.Role); err != nil {
		return RoleMutationResult{}, err
	}
	authorization, err := s.authorize(ctx, input.ActorID, input.EventID)
	if err != nil {
		return RoleMutationResult{}, err
	}
	canonical, err := json.Marshal(struct {
		Operation, ActorID, TargetUserID, EventID, Role, ReasonID string
	}{"create", string(input.ActorID), string(input.TargetUserID), input.EventID, string(input.Role), input.ReasonID})
	if err != nil {
		return RoleMutationResult{}, err
	}
	return s.execute(ctx, "adminroles.create", input.IdempotencyKey, canonical, "role.created", func(repositories RoleMutationRepositories, now time.Time) (Binding, error) {
		bindingID, err := s.newID("arb_")
		if err != nil {
			return Binding{}, fmt.Errorf("adminroles: generate binding id: %w", err)
		}
		return repositories.Roles.Create(ctx, Binding{ID: bindingID, UserID: input.TargetUserID, Role: input.Role, Scope: Scope{Kind: ScopeEvent, EventID: input.EventID}, Enabled: true, Version: 1, GrantedBy: input.ActorID, ReasonID: input.ReasonID, CreatedAt: now, UpdatedAt: now}, mutationAudit(input.ActorID, input.ReasonID, input.RequestID))
	}, input.EventID, input.ReasonID, input.ActorID, authorization)
}

func (s *Service) UpdateRole(ctx context.Context, input UpdateRoleInput) (RoleMutationResult, error) {
	if input.ExpectedVersion <= 0 {
		return RoleMutationResult{}, ErrIfMatchRequired
	}
	if err := s.validateCommon(input.ActorID, input.TargetUserID, input.EventID, input.ReasonID, input.RequestID, input.IdempotencyKey); err != nil {
		return RoleMutationResult{}, err
	}
	if strings.TrimSpace(input.BindingID) == "" {
		return RoleMutationResult{}, ErrInvalidRoleMutation
	}
	if err := validateOrdinaryRole(input.Role); err != nil {
		return RoleMutationResult{}, err
	}
	authorization, err := s.authorize(ctx, input.ActorID, input.EventID)
	if err != nil {
		return RoleMutationResult{}, err
	}
	canonical, err := json.Marshal(struct {
		Operation, ActorID, TargetUserID, BindingID, EventID, Role, ReasonID string
		ExpectedVersion                                                      int64
	}{"update", string(input.ActorID), string(input.TargetUserID), input.BindingID, input.EventID, string(input.Role), input.ReasonID, input.ExpectedVersion})
	if err != nil {
		return RoleMutationResult{}, err
	}
	return s.execute(ctx, "adminroles.update", input.IdempotencyKey, canonical, "role.updated", func(repositories RoleMutationRepositories, now time.Time) (Binding, error) {
		scope := Scope{Kind: ScopeEvent, EventID: input.EventID}
		current, err := repositories.Roles.GetForScope(ctx, input.TargetUserID, scope)
		if err != nil {
			return Binding{}, err
		}
		if current.ID != input.BindingID || current.Version != input.ExpectedVersion {
			return Binding{}, ErrBindingConflict
		}
		if current.Role == RoleSuperAdmin || current.Role == RoleTopAdmin {
			return Binding{}, ErrOrdinarySuperAdminMutation
		}
		next := current
		next.Role, next.GrantedBy, next.ReasonID, next.UpdatedAt = input.Role, input.ActorID, input.ReasonID, now
		return repositories.Roles.Update(ctx, next, input.ExpectedVersion, mutationAudit(input.ActorID, input.ReasonID, input.RequestID))
	}, input.EventID, input.ReasonID, input.ActorID, authorization)
}

func (s *Service) DisableRole(ctx context.Context, input DisableRoleInput) (RoleMutationResult, error) {
	if input.ExpectedVersion <= 0 {
		return RoleMutationResult{}, ErrIfMatchRequired
	}
	if err := s.validateCommon(input.ActorID, input.TargetUserID, input.EventID, input.ReasonID, input.RequestID, input.IdempotencyKey); err != nil {
		return RoleMutationResult{}, err
	}
	if strings.TrimSpace(input.BindingID) == "" {
		return RoleMutationResult{}, ErrInvalidRoleMutation
	}
	authorization, err := s.authorize(ctx, input.ActorID, input.EventID)
	if err != nil {
		return RoleMutationResult{}, err
	}
	canonical, err := json.Marshal(struct {
		Operation, ActorID, TargetUserID, BindingID, EventID, ReasonID string
		ExpectedVersion                                                int64
	}{"disable", string(input.ActorID), string(input.TargetUserID), input.BindingID, input.EventID, input.ReasonID, input.ExpectedVersion})
	if err != nil {
		return RoleMutationResult{}, err
	}
	return s.execute(ctx, "adminroles.disable", input.IdempotencyKey, canonical, "role.disabled", func(repositories RoleMutationRepositories, _ time.Time) (Binding, error) {
		scope := Scope{Kind: ScopeEvent, EventID: input.EventID}
		current, err := repositories.Roles.GetForScope(ctx, input.TargetUserID, scope)
		if err != nil {
			return Binding{}, err
		}
		if current.ID != input.BindingID || current.Version != input.ExpectedVersion {
			return Binding{}, ErrBindingConflict
		}
		if current.Role == RoleSuperAdmin || current.Role == RoleTopAdmin {
			return Binding{}, ErrOrdinarySuperAdminMutation
		}
		return repositories.Roles.Disable(ctx, current.ID, input.ExpectedVersion, mutationAudit(input.ActorID, input.ReasonID, input.RequestID))
	}, input.EventID, input.ReasonID, input.ActorID, authorization)
}

type roleMutation func(RoleMutationRepositories, time.Time) (Binding, error)

func (s *Service) execute(ctx context.Context, purpose, idempotencyKey string, canonical []byte, resultCode string, mutate roleMutation, eventID, reasonID string, actorID identity.UserID, authorization RoleManagementDecision) (RoleMutationResult, error) {
	if s == nil || s.uow == nil || s.fingerprinter == nil || s.now == nil || s.newID == nil {
		return RoleMutationResult{}, ErrInvalidRoleMutation
	}
	fingerprint, err := s.fingerprinter.Fingerprint(purpose, canonical)
	if err != nil || fingerprint.Version == "" || fingerprint.KeyID == "" || fingerprint.Digest == "" {
		if err == nil {
			err = ErrInvalidRoleMutation
		}
		return RoleMutationResult{}, fmt.Errorf("adminroles: fingerprint mutation: %w", err)
	}
	receiptID, err := s.newID("aop_")
	if err != nil {
		return RoleMutationResult{}, fmt.Errorf("adminroles: generate receipt id: %w", err)
	}
	var outcome RoleMutationResult
	err = s.uow.WithinRoleMutation(ctx, func(repositories RoleMutationRepositories) error {
		if repositories.Roles == nil || repositories.ActorAuthorization == nil || repositories.EventRegistry == nil || repositories.Reasons == nil || repositories.Receipts == nil {
			return ErrInvalidRoleMutation
		}
		if _, err := repositories.EventRegistry.GetExact(ctx, eventID); err != nil {
			return err
		}
		if err := repositories.ActorAuthorization.Revalidate(ctx, actorID, eventID, authorization); err != nil {
			return err
		}
		now := s.now().UTC()
		receipt, replay, err := repositories.Receipts.CreateOrReplay(ctx, LocalOperationReceipt{ID: receiptID, IdempotencyKey: idempotencyKey, Fingerprint: fingerprint, State: "pending", Version: 1, CreatedAt: now})
		if err != nil {
			return err
		}
		if replay {
			stored, err := decodeStoredRoleResult(receipt.Result, resultCode)
			if err != nil {
				return err
			}
			outcome = stored
			return nil
		}
		binding, err := mutate(repositories, now)
		if err != nil {
			return err
		}
		if binding.ID == "" || binding.Version <= 0 {
			return ErrInvalidStoredRoleResult
		}
		if err := repositories.Reasons.ConsumeOwned(ctx, reasonID, actorID, "role", now, now.AddDate(2, 0, 0)); err != nil {
			return err
		}
		result := encodeStoredRoleResult(resultCode, binding.ID, binding.Version)
		if err := repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, result, now); err != nil {
			return err
		}
		outcome = RoleMutationResult{BindingID: binding.ID, Version: binding.Version}
		return nil
	})
	if err != nil {
		return RoleMutationResult{}, err
	}
	return outcome, nil
}

func (s *Service) validateCommon(actorID, targetID identity.UserID, eventID, reasonID, requestID, idempotencyKey string) error {
	if actorID == "" || targetID == "" || strings.TrimSpace(eventID) == "" || strings.TrimSpace(reasonID) == "" || strings.TrimSpace(requestID) == "" {
		return ErrInvalidRoleMutation
	}
	if actorID == targetID {
		return ErrSelfRoleMutation
	}
	if !validIdempotencyKey(idempotencyKey) {
		return ErrInvalidIdempotencyKey
	}
	return nil
}

func (s *Service) authorize(ctx context.Context, actorID identity.UserID, eventID string) (RoleManagementDecision, error) {
	if s == nil || s.authorizer == nil {
		return RoleManagementDecision{}, ErrRoleMutationForbidden
	}
	decision, err := s.authorizer.CheckRoleManagement(ctx, actorID, eventID)
	if err != nil {
		return RoleManagementDecision{}, fmt.Errorf("adminroles: authorize role management: %w", err)
	}
	if !decision.Allowed || strings.TrimSpace(decision.BindingID) == "" || decision.BindingVersion <= 0 || ValidateRoleScope(decision.Role, decision.Scope) != nil {
		return RoleManagementDecision{}, ErrRoleMutationForbidden
	}
	return decision, nil
}

func validateOrdinaryRole(role Role) error {
	if role == RoleSuperAdmin || role == RoleTopAdmin {
		return ErrOrdinarySuperAdminMutation
	}
	if role != RoleAdmin && role != RoleSeniorAdmin {
		return ErrInvalidRoleMutation
	}
	return nil
}

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,160}$`)

func validIdempotencyKey(key string) bool {
	return idempotencyKeyPattern.MatchString(key)
}

func mutationAudit(actor identity.UserID, reasonID, requestID string) MutationAudit {
	return MutationAudit{ActorID: actor, ReasonID: reasonID, RequestID: requestID, Action: "event.role.manage"}
}

func encodeStoredRoleResult(code, bindingID string, version int64) LocalReceiptResult {
	payload := map[string]string{"binding_id": bindingID, "version": strconv.FormatInt(version, 10)}
	digest := sha256.Sum256([]byte(code + "\x00" + bindingID + "\x00" + payload["version"]))
	return LocalReceiptResult{Code: code, Digest: base64.RawURLEncoding.EncodeToString(digest[:]), Payload: payload}
}

func decodeStoredRoleResult(result LocalReceiptResult, wantCode string) (RoleMutationResult, error) {
	if result.Code != wantCode || result.Payload == nil {
		return RoleMutationResult{}, ErrInvalidStoredRoleResult
	}
	bindingID := result.Payload["binding_id"]
	version, err := strconv.ParseInt(result.Payload["version"], 10, 64)
	if err != nil || !strings.HasPrefix(bindingID, "arb_") || version <= 0 {
		return RoleMutationResult{}, ErrInvalidStoredRoleResult
	}
	want := encodeStoredRoleResult(wantCode, bindingID, version)
	if result.Digest != want.Digest {
		return RoleMutationResult{}, ErrInvalidStoredRoleResult
	}
	return RoleMutationResult{BindingID: bindingID, Version: version}, nil
}

func newRoleOperationID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}
