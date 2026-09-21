package adminstepup

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
	"unicode"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/rivo/uniseg"
	"golang.org/x/text/unicode/norm"
)

const (
	MinQuestionGraphemes = 5
	MaxQuestionGraphemes = 200
	MinAnswerGraphemes   = 7
	MaxAnswerGraphemes   = 256
)

var (
	ErrInvalidQuestion        = errors.New("adminstepup: invalid question")
	ErrInvalidAnswer          = errors.New("adminstepup: invalid answer")
	ErrForbiddenChallengeText = errors.New("adminstepup: forbidden challenge text")
	ErrQuestionEqualsAnswer   = errors.New("adminstepup: question equals answer")
	ErrDisabled               = errors.New("adminstepup: disabled")
	ErrEnrollmentRequired     = errors.New("adminstepup: enrollment required")
	ErrEnrollmentNotAllowed   = errors.New("adminstepup: enrollment not allowed")
	ErrRotationRequired       = errors.New("adminstepup: rotation required")
	ErrLocked                 = errors.New("adminstepup: locked")
	ErrInvalidChallengeAnswer = errors.New("adminstepup: invalid challenge answer")
	ErrRateLimited            = errors.New("adminstepup: rate limited")
	ErrRateLimitUnavailable   = errors.New("adminstepup: rate limit unavailable")
	ErrInvalidIdempotencyKey  = errors.New("adminstepup: globally random idempotency key required")
	ErrIdempotencyConflict    = errors.New("adminstepup: idempotency conflict")
	ErrIfMatchRequired        = errors.New("adminstepup: If-Match challenge version required")
	ErrInvalidStoredReceipt   = errors.New("adminstepup: invalid stored receipt")
	ErrInvalidActionTarget    = errors.New("adminstepup: invalid action target")
	ErrUnsupportedAction      = errors.New("adminstepup: unsupported action")
	ErrInvalidVerifyRequest   = errors.New("adminstepup: incomplete verification request")
)

type State string

const (
	StatePendingEnrollment State = "pending_enrollment"
	StateRecoveryPending   State = "recovery_pending"
	StateActive            State = "active"
	StateMustRotate        State = "must_rotate"
	StateDisabled          State = "disabled"
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

type ApprovalRevoker interface {
	RevokeForUser(context.Context, identity.UserID, time.Time) error
}

type RedisPurgeEnqueuer interface {
	Enqueue(context.Context, string, identity.UserID, RequestFingerprint, time.Time) error
}

type AuditEvent struct {
	ID         string
	ActorID    identity.UserID
	EventID    string
	RequestID  string
	Action     string
	Target     string
	Result     string
	OccurredAt time.Time
}

type AuditRecorder interface {
	Record(context.Context, AuditEvent) error
}

type StepUpMutationRepositories struct {
	Challenges      Repository
	AccountSecurity AccountSecurityEpochReader
	Receipts        LocalReceiptRepository
	Approvals       ApprovalRevoker
	Purges          RedisPurgeEnqueuer
	Audit           AuditRecorder
}

type StepUpMutationUnitOfWork interface {
	WithinStepUpMutation(context.Context, func(StepUpMutationRepositories) error) error
}

type BindingReader interface {
	GetForScope(context.Context, identity.UserID, adminroles.Scope) (adminroles.Binding, error)
}

type RateLimiter interface {
	Check(context.Context, identity.UserID, string) (time.Duration, error)
}

type CredentialHasher interface {
	Hash(context.Context, string) (string, string, error)
	Verify(context.Context, string, string, string) (bool, error)
}

type QuestionCipher interface {
	Encrypt(EncryptionPurpose, string, string, int64, string) (EncryptedValue, error)
	Decrypt(EncryptionPurpose, string, string, int64, EncryptedValue) (string, error)
}

type GrantStore interface {
	CreateGrant(context.Context, string, auth.ReauthGrantData, time.Duration) error
}

// AccountSecurityEpochReader reads the account-wide users.security_epoch.
// Production supplies a transaction-scoped PostgreSQL adapter so grants and
// durable proofs are stamped in the same serializable transaction as their
// receipts.
type AccountSecurityEpochReader interface {
	CurrentEpoch(context.Context, identity.UserID) (securitystate.Epoch, error)
}

type ServiceDependencies struct {
	Repository     Repository
	Bindings       BindingReader
	UnitOfWork     StepUpMutationUnitOfWork
	Limiter        RateLimiter
	Hasher         CredentialHasher
	QuestionCipher QuestionCipher
	Fingerprinter  Fingerprinter
	GrantStore     GrantStore
}

type ServiceConfig struct {
	GeneralFreshness  time.Duration
	HighRiskFreshness time.Duration
	GrantTTL          time.Duration
}

type ServiceOption func(*Service)

type Service struct {
	repository  Repository
	bindings    BindingReader
	uow         StepUpMutationUnitOfWork
	limiter     RateLimiter
	hasher      CredentialHasher
	cipher      QuestionCipher
	fingerprint Fingerprinter
	grants      GrantStore
	config      ServiceConfig
	now         func() time.Time
	newID       func(string) (string, error)
	newToken    func() (string, error)
}

func NewService(dependencies ServiceDependencies, config ServiceConfig, options ...ServiceOption) (*Service, error) {
	if dependencies.Repository == nil || dependencies.Bindings == nil || dependencies.UnitOfWork == nil || dependencies.Limiter == nil || dependencies.Hasher == nil || dependencies.QuestionCipher == nil || dependencies.Fingerprinter == nil || dependencies.GrantStore == nil {
		return nil, errors.New("adminstepup: incomplete service dependencies")
	}
	if config.GeneralFreshness <= 0 || config.HighRiskFreshness <= 0 || config.HighRiskFreshness > config.GeneralFreshness || config.GrantTTL <= 0 {
		return nil, errors.New("adminstepup: invalid service configuration")
	}
	service := &Service{
		repository: dependencies.Repository, bindings: dependencies.Bindings, uow: dependencies.UnitOfWork,
		limiter: dependencies.Limiter, hasher: dependencies.Hasher, cipher: dependencies.QuestionCipher,
		fingerprint: dependencies.Fingerprinter, grants: dependencies.GrantStore, config: config,
		now: func() time.Time { return time.Now().UTC() }, newID: newRandomID, newToken: newRandomToken,
	}
	for _, option := range options {
		if option != nil {
			option(service)
		}
	}
	return service, nil
}

func WithClock(clock func() time.Time) ServiceOption {
	return func(service *Service) {
		if clock != nil {
			service.now = clock
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

func WithTokenGenerator(generator func() (string, error)) ServiceOption {
	return func(service *Service) {
		if generator != nil {
			service.newToken = generator
		}
	}
}

type EnrollInput struct {
	UserID         identity.UserID
	EventID        string
	Question       string
	Answer         string
	IdempotencyKey string
	RequestID      string
}

type VerifyRequest struct {
	UserID            identity.UserID
	SessionID         string
	EventID           string
	Answer            string
	Action            string
	Target            string
	ClientFingerprint string
	IdempotencyKey    string
	RequestID         string
}

type VerifyResult struct {
	State            State
	VerifiedAt       time.Time
	ExpiresAt        time.Time
	ReauthGrant      string
	GrantID          string
	ChallengeVersion int64
	Replayed         bool
}

type RotateInput struct {
	UserID            identity.UserID
	EventID           string
	OldAnswer         string
	NewQuestion       string
	NewAnswer         string
	ClientFingerprint string
	IdempotencyKey    string
	RequestID         string
	ExpectedVersion   int64
}

type ChallengeView struct {
	State             State
	Question          string
	Version           int64
	CredentialVersion int64
	LockedUntil       *time.Time
}

func (s *Service) State(ctx context.Context, userID identity.UserID, eventID string) (State, error) {
	if err := s.requireBinding(ctx, userID, eventID); err != nil {
		if errors.Is(err, ErrDisabled) {
			return StateDisabled, nil
		}
		return "", err
	}
	challenge, err := s.repository.Get(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return StatePendingEnrollment, nil
	}
	if err != nil {
		return "", err
	}
	return challengeState(challenge), nil
}

func (s *Service) Challenge(ctx context.Context, userID identity.UserID, eventID string) (ChallengeView, error) {
	state, err := s.State(ctx, userID, eventID)
	if err != nil {
		return ChallengeView{}, err
	}
	if state == StateDisabled || state == StatePendingEnrollment {
		return ChallengeView{State: state}, nil
	}
	material, err := s.repository.GetCredentialForVerification(ctx, userID)
	if errors.Is(err, ErrNotFound) && state == StateRecoveryPending {
		challenge, readErr := s.repository.Get(ctx, userID)
		if readErr != nil {
			return ChallengeView{}, readErr
		}
		return ChallengeView{State: state, Version: challenge.Version, CredentialVersion: challenge.CredentialVersion, LockedUntil: challenge.LockedUntil}, nil
	}
	if err != nil {
		return ChallengeView{}, err
	}
	question, err := s.cipher.Decrypt(PurposeChallengeQuestion, string(userID), challengeRecordID(userID), material.Challenge.CredentialVersion, EncryptedValue{KeyID: material.QuestionKeyID, Nonce: material.QuestionNonce, Ciphertext: material.QuestionCiphertext})
	if err != nil {
		return ChallengeView{}, err
	}
	return ChallengeView{State: state, Question: question, Version: material.Challenge.Version, CredentialVersion: material.Challenge.CredentialVersion, LockedUntil: material.Challenge.LockedUntil}, nil
}

// InitialEnrollmentAllowed permits the one bootstrap exception needed when
// the first system super-administrator predates administrator challenges. It
// never applies to event-scoped administrators or to an account that already
// has challenge material; subsequent enrollment still requires the normal
// MFA-backed recovery path.
func (s *Service) InitialEnrollmentAllowed(ctx context.Context, userID identity.UserID, eventID string) (bool, error) {
	if s == nil || userID == "" || strings.TrimSpace(eventID) == "" {
		return false, nil
	}
	binding, err := s.bindings.GetForScope(ctx, userID, adminroles.Scope{Kind: adminroles.ScopeSystem})
	if err != nil {
		if errors.Is(err, adminroles.ErrBindingNotFound) {
			return false, nil
		}
		return false, err
	}
	if !binding.Enabled || binding.DisabledAt != nil || (binding.Role != adminroles.RoleSuperAdmin && binding.Role != adminroles.RoleTopAdmin) {
		return false, nil
	}
	_, err = s.repository.Get(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	return false, err
}

func (s *Service) Enroll(ctx context.Context, input EnrollInput) (Challenge, error) {
	if err := validateMutationIdentity(input.UserID, input.EventID, input.RequestID, input.IdempotencyKey); err != nil {
		return Challenge{}, err
	}
	if err := s.requireBinding(ctx, input.UserID, input.EventID); err != nil {
		return Challenge{}, err
	}
	question, err := NormalizeQuestion(input.Question)
	if err != nil {
		return Challenge{}, err
	}
	answer, err := NormalizeAnswer(input.Answer)
	if err != nil {
		return Challenge{}, err
	}
	if question == answer {
		return Challenge{}, ErrQuestionEqualsAnswer
	}
	canonical, _ := json.Marshal(struct {
		UserID   identity.UserID `json:"userId"`
		EventID  string          `json:"eventId"`
		Question string          `json:"question"`
		Answer   string          `json:"answer"`
	}{input.UserID, input.EventID, question, answer})
	fingerprint, err := s.fingerprint.Fingerprint("adminstepup.enroll", canonical)
	if err != nil {
		return Challenge{}, err
	}
	now := s.now()
	var result Challenge
	err = s.uow.WithinStepUpMutation(ctx, func(repositories StepUpMutationRepositories) error {
		receipt, replay, err := s.beginReceipt(ctx, repositories.Receipts, input.IdempotencyKey, fingerprint, now)
		if err != nil {
			return err
		}
		if replay {
			stored, err := decodeChallengeReceipt(receipt.Result, "challenge.enrolled")
			if err != nil {
				return err
			}
			result = stored
			result.UserID = input.UserID
			return nil
		}
		expected := int64(0)
		current, getErr := repositories.Challenges.Get(ctx, input.UserID)
		switch {
		case errors.Is(getErr, ErrNotFound):
		case getErr != nil:
			return getErr
		case current.Status == ChallengeRecoveryPending:
			expected = current.Version
		default:
			return ErrEnrollmentNotAllowed
		}
		phc, pepperKeyID, err := s.hasher.Hash(ctx, answer)
		if err != nil {
			return err
		}
		credentialVersion := int64(1)
		if expected > 0 {
			credentialVersion = current.CredentialVersion + 1
		}
		sealed, err := s.cipher.Encrypt(PurposeChallengeQuestion, string(input.UserID), challengeRecordID(input.UserID), credentialVersion, question)
		if err != nil {
			return err
		}
		result, err = repositories.Challenges.PutCredential(ctx, CredentialMaterial{Challenge: Challenge{UserID: input.UserID, Status: ChallengeActive}, QuestionKeyID: sealed.KeyID, QuestionNonce: sealed.Nonce, QuestionCiphertext: sealed.Ciphertext, AnswerPHC: phc, AnswerPepperKeyID: pepperKeyID}, expected)
		if err != nil {
			return err
		}
		if err := repositories.Audit.Record(ctx, AuditEvent{ID: receipt.ID, ActorID: input.UserID, EventID: input.EventID, RequestID: input.RequestID, Action: "admin.challenge.enroll", Target: string(input.UserID), Result: "succeeded", OccurredAt: now}); err != nil {
			return err
		}
		return repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, encodeChallengeReceipt("challenge.enrolled", result, StateActive), now)
	})
	return result, err
}

func (s *Service) Verify(ctx context.Context, input VerifyRequest) (VerifyResult, error) {
	if err := validateMutationIdentity(input.UserID, input.EventID, input.RequestID, input.IdempotencyKey); err != nil {
		return VerifyResult{}, err
	}
	if input.SessionID == "" || input.Action == "" || input.ClientFingerprint == "" {
		return VerifyResult{}, ErrInvalidVerifyRequest
	}
	if !isSupportedAdminAction(input.Action) {
		return VerifyResult{}, ErrUnsupportedAction
	}
	if !validAdminActionTarget(input.UserID, input.EventID, input.Action, input.Target) {
		return VerifyResult{}, ErrInvalidActionTarget
	}
	if err := s.requireBinding(ctx, input.UserID, input.EventID); err != nil {
		return VerifyResult{}, err
	}
	answer, err := NormalizeAnswer(input.Answer)
	if err != nil {
		return VerifyResult{}, err
	}
	canonical, _ := json.Marshal(struct {
		UserID            identity.UserID `json:"userId"`
		SessionID         string          `json:"sessionId"`
		EventID           string          `json:"eventId"`
		Answer            string          `json:"answer"`
		Action            string          `json:"action"`
		Target            string          `json:"target"`
		ClientFingerprint string          `json:"clientFingerprint"`
	}{input.UserID, input.SessionID, input.EventID, answer, input.Action, input.Target, input.ClientFingerprint})
	fingerprint, err := s.fingerprint.Fingerprint("adminstepup.verify", canonical)
	if err != nil {
		return VerifyResult{}, err
	}
	now := s.now()
	var result VerifyResult
	var terminalErr error
	err = s.uow.WithinStepUpMutation(ctx, func(repositories StepUpMutationRepositories) error {
		receipt, replay, err := s.beginReceipt(ctx, repositories.Receipts, input.IdempotencyKey, fingerprint, now)
		if err != nil {
			return err
		}
		if replay {
			result, terminalErr = decodeVerifyReplay(receipt.Result)
			result.Replayed = true
			return nil
		}
		material, err := repositories.Challenges.GetCredentialForVerification(ctx, input.UserID)
		if errors.Is(err, ErrNotFound) {
			return ErrEnrollmentRequired
		}
		if err != nil {
			return err
		}
		state := challengeState(material.Challenge)
		if state == StateMustRotate && input.Action != auth.ReauthActionAdminChallengeRotate {
			return ErrRotationRequired
		}
		if material.Challenge.LockedUntil != nil && material.Challenge.LockedUntil.After(now) {
			return ErrLocked
		}
		if _, err := s.limiter.Check(ctx, input.UserID, input.ClientFingerprint); err != nil {
			if errors.Is(err, ErrRateLimited) {
				return ErrRateLimited
			}
			return fmt.Errorf("%w: %v", ErrRateLimitUnavailable, err)
		}
		verified, err := s.hasher.Verify(ctx, answer, material.AnswerPHC, material.AnswerPepperKeyID)
		if err != nil {
			return err
		}
		if !verified {
			challenge, err := repositories.Challenges.RecordFailure(ctx, input.UserID, material.Challenge.Version, now)
			if err != nil {
				return err
			}
			code := "challenge.rejected"
			terminalErr = ErrInvalidChallengeAnswer
			if challenge.LockedUntil != nil && challenge.LockedUntil.After(now) {
				code, terminalErr = "challenge.locked", ErrLocked
			}
			if err := repositories.Audit.Record(ctx, AuditEvent{ID: receipt.ID, ActorID: input.UserID, EventID: input.EventID, RequestID: input.RequestID, Action: input.Action, Target: input.Target, Result: "denied", OccurredAt: now}); err != nil {
				return err
			}
			return repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, encodeReceipt(code, challenge.Version, challengeState(challenge)), now)
		}
		stepupID, err := s.newID("asu_")
		if err != nil {
			return err
		}
		// Every successful answer refreshes the durable general session proof.
		// A high-risk request receives a separate, short-lived one-shot grant;
		// it must not shorten or substitute this general dashboard proof.
		if repositories.AccountSecurity == nil {
			return ErrInvalidVerifyRequest
		}
		accountEpoch, err := repositories.AccountSecurity.CurrentEpoch(ctx, input.UserID)
		if err != nil {
			return err
		}
		if accountEpoch < 1 {
			return ErrInvalidVerifyRequest
		}
		if err := repositories.Challenges.PutStepUp(ctx, StepUpState{ID: stepupID, SessionID: input.SessionID, UserID: input.UserID, ChallengeVersion: material.Challenge.CredentialVersion, SecurityEpoch: int64(accountEpoch), VerifiedAt: now, ExpiresAt: now.Add(s.config.GeneralFreshness)}); err != nil {
			return err
		}
		result = VerifyResult{State: state, VerifiedAt: now, ExpiresAt: now.Add(s.config.GeneralFreshness), ChallengeVersion: material.Challenge.CredentialVersion}
		if isHighRiskAdminAction(input.Action) {
			bearer, err := s.newToken()
			if err != nil {
				return err
			}
			grantID, err := s.newID("rgr_")
			if err != nil {
				return err
			}
			grantTTL := min(s.config.GrantTTL, s.config.HighRiskFreshness)
			data := auth.ReauthGrantData{GrantID: grantID, UserID: input.UserID, SessionID: input.SessionID, Action: input.Action, Target: input.Target, CreatedAt: now, SecurityEpoch: accountEpoch, ChallengeVersion: material.Challenge.CredentialVersion}
			// Create the external one-shot credential before PostgreSQL commits.
			// A store failure rolls back proof/audit/receipt so the same semantic
			// retry can run again. A later database failure may leave only an
			// unreachable, short-TTL hashed grant whose raw bearer was never sent.
			if err := s.grants.CreateGrant(ctx, hashBearer(bearer), data, grantTTL); err != nil {
				return err
			}
			result.ReauthGrant, result.GrantID, result.ExpiresAt = bearer, grantID, now.Add(grantTTL)
		}
		if err := repositories.Audit.Record(ctx, AuditEvent{ID: receipt.ID, ActorID: input.UserID, EventID: input.EventID, RequestID: input.RequestID, Action: input.Action, Target: input.Target, Result: "succeeded", OccurredAt: now}); err != nil {
			return err
		}
		return repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, encodeReceipt("challenge.verified", material.Challenge.CredentialVersion, state), now)
	})
	if err != nil {
		return VerifyResult{}, err
	}
	if terminalErr != nil {
		return result, terminalErr
	}
	return result, nil
}

func (s *Service) Rotate(ctx context.Context, input RotateInput) (Challenge, error) {
	if err := validateMutationIdentity(input.UserID, input.EventID, input.RequestID, input.IdempotencyKey); err != nil {
		return Challenge{}, err
	}
	if input.ExpectedVersion <= 0 {
		return Challenge{}, ErrIfMatchRequired
	}
	if input.ClientFingerprint == "" {
		return Challenge{}, errors.New("adminstepup: client fingerprint required")
	}
	if err := s.requireBinding(ctx, input.UserID, input.EventID); err != nil {
		return Challenge{}, err
	}
	oldAnswer, err := NormalizeAnswer(input.OldAnswer)
	if err != nil {
		return Challenge{}, err
	}
	newQuestion, err := NormalizeQuestion(input.NewQuestion)
	if err != nil {
		return Challenge{}, err
	}
	newAnswer, err := NormalizeAnswer(input.NewAnswer)
	if err != nil {
		return Challenge{}, err
	}
	if newQuestion == newAnswer {
		return Challenge{}, ErrQuestionEqualsAnswer
	}
	canonical, _ := json.Marshal(struct {
		UserID            identity.UserID `json:"userId"`
		EventID           string          `json:"eventId"`
		OldAnswer         string          `json:"oldAnswer"`
		NewQuestion       string          `json:"newQuestion"`
		NewAnswer         string          `json:"newAnswer"`
		ClientFingerprint string          `json:"clientFingerprint"`
		ExpectedVersion   int64           `json:"expectedVersion"`
	}{input.UserID, input.EventID, oldAnswer, newQuestion, newAnswer, input.ClientFingerprint, input.ExpectedVersion})
	fingerprint, err := s.fingerprint.Fingerprint("adminstepup.rotate", canonical)
	if err != nil {
		return Challenge{}, err
	}
	now := s.now()
	var result Challenge
	var terminalErr error
	err = s.uow.WithinStepUpMutation(ctx, func(repositories StepUpMutationRepositories) error {
		receipt, replay, err := s.beginReceipt(ctx, repositories.Receipts, input.IdempotencyKey, fingerprint, now)
		if err != nil {
			return err
		}
		if replay {
			result, terminalErr = decodeRotateReplay(receipt.Result)
			result.UserID = input.UserID
			return nil
		}
		material, err := repositories.Challenges.GetCredentialForVerification(ctx, input.UserID)
		if errors.Is(err, ErrNotFound) {
			return ErrEnrollmentRequired
		}
		if err != nil {
			return err
		}
		if material.Challenge.Version != input.ExpectedVersion {
			return ErrConflict
		}
		if material.Challenge.LockedUntil != nil && material.Challenge.LockedUntil.After(now) {
			return ErrLocked
		}
		if _, err := s.limiter.Check(ctx, input.UserID, input.ClientFingerprint); err != nil {
			if errors.Is(err, ErrRateLimited) {
				return ErrRateLimited
			}
			return fmt.Errorf("%w: %v", ErrRateLimitUnavailable, err)
		}
		verified, err := s.hasher.Verify(ctx, oldAnswer, material.AnswerPHC, material.AnswerPepperKeyID)
		if err != nil {
			return err
		}
		if !verified {
			challenge, err := repositories.Challenges.RecordFailure(ctx, input.UserID, material.Challenge.Version, now)
			if err != nil {
				return err
			}
			code := "challenge.rejected"
			terminalErr = ErrInvalidChallengeAnswer
			if challenge.LockedUntil != nil && challenge.LockedUntil.After(now) {
				terminalErr, code = ErrLocked, "challenge.locked"
			}
			if err := repositories.Audit.Record(ctx, AuditEvent{ID: receipt.ID, ActorID: input.UserID, EventID: input.EventID, RequestID: input.RequestID, Action: auth.ReauthActionAdminChallengeRotate, Target: string(input.UserID), Result: "denied", OccurredAt: now}); err != nil {
				return err
			}
			return repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, encodeReceipt(code, challenge.Version, challengeState(challenge)), now)
		}
		phc, pepperKeyID, err := s.hasher.Hash(ctx, newAnswer)
		if err != nil {
			return err
		}
		nextCredentialVersion := material.Challenge.CredentialVersion + 1
		sealed, err := s.cipher.Encrypt(PurposeChallengeQuestion, string(input.UserID), challengeRecordID(input.UserID), nextCredentialVersion, newQuestion)
		if err != nil {
			return err
		}
		result, err = repositories.Challenges.PutCredential(ctx, CredentialMaterial{Challenge: Challenge{UserID: input.UserID, Status: ChallengeActive}, QuestionKeyID: sealed.KeyID, QuestionNonce: sealed.Nonce, QuestionCiphertext: sealed.Ciphertext, AnswerPHC: phc, AnswerPepperKeyID: pepperKeyID}, input.ExpectedVersion)
		if err != nil {
			return err
		}
		if err := repositories.Challenges.RevokeForUser(ctx, input.UserID, now); err != nil {
			return err
		}
		if err := repositories.Approvals.RevokeForUser(ctx, input.UserID, now); err != nil {
			return err
		}
		if err := repositories.Purges.Enqueue(ctx, receipt.ID, input.UserID, fingerprint, now); err != nil {
			return err
		}
		if err := repositories.Audit.Record(ctx, AuditEvent{ID: receipt.ID, ActorID: input.UserID, EventID: input.EventID, RequestID: input.RequestID, Action: auth.ReauthActionAdminChallengeRotate, Target: string(input.UserID), Result: "succeeded", OccurredAt: now}); err != nil {
			return err
		}
		return repositories.Receipts.CompleteLocal(ctx, receipt.ID, receipt.Version, encodeChallengeReceipt("challenge.rotated", result, StateActive), now)
	})
	if err != nil {
		return Challenge{}, err
	}
	if terminalErr != nil {
		return Challenge{}, terminalErr
	}
	return result, nil
}

func (s *Service) beginReceipt(ctx context.Context, receipts LocalReceiptRepository, key string, fingerprint RequestFingerprint, now time.Time) (LocalOperationReceipt, bool, error) {
	id, err := s.newID("aop_")
	if err != nil {
		return LocalOperationReceipt{}, false, err
	}
	return receipts.CreateOrReplay(ctx, LocalOperationReceipt{ID: id, IdempotencyKey: key, Fingerprint: fingerprint, State: "pending", Version: 1, CreatedAt: now})
}

func (s *Service) requireBinding(ctx context.Context, userID identity.UserID, eventID string) error {
	if userID == "" || eventID == "" {
		return ErrDisabled
	}
	if binding, err := s.bindings.GetForScope(ctx, userID, adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: eventID}); err == nil && binding.Enabled && binding.DisabledAt == nil {
		return nil
	} else if err != nil && !errors.Is(err, adminroles.ErrBindingNotFound) {
		return err
	}
	if binding, err := s.bindings.GetForScope(ctx, userID, adminroles.Scope{Kind: adminroles.ScopeSystem}); err == nil && binding.Enabled && binding.DisabledAt == nil && (binding.Role == adminroles.RoleSuperAdmin || binding.Role == adminroles.RoleTopAdmin) {
		return nil
	} else if err != nil && !errors.Is(err, adminroles.ErrBindingNotFound) {
		return err
	}
	return ErrDisabled
}

func challengeState(challenge Challenge) State {
	switch challenge.Status {
	case ChallengeRecoveryPending:
		return StateRecoveryPending
	case ChallengeActive:
		if challenge.MustRotate {
			return StateMustRotate
		}
		return StateActive
	default:
		return StateDisabled
	}
}

var (
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,160}$`)
)

func validateMutationIdentity(userID identity.UserID, eventID, requestID, idempotencyKey string) error {
	if userID == "" || strings.TrimSpace(eventID) == "" || strings.TrimSpace(requestID) == "" {
		return errors.New("adminstepup: incomplete mutation identity")
	}
	if !idempotencyKeyPattern.MatchString(idempotencyKey) {
		return ErrInvalidIdempotencyKey
	}
	return nil
}

func isAdminReauthAction(action string) bool {
	switch action {
	case auth.ReauthActionAdminRoleManagement, auth.ReauthActionAdminEventRegistry,
		auth.ReauthActionAdminOAApproval, auth.ReauthActionAdminRestrictedView,
		auth.ReauthActionAdminLegalView, auth.ReauthActionAdminExport,
		auth.ReauthActionAdminChallengeRotate, auth.ReauthActionAdminCheckinWindowManage:
		return true
	default:
		return false
	}
}

func isSupportedAdminAction(action string) bool {
	if isAdminReauthAction(action) {
		return true
	}
	canonical := permissions.Action(action)
	// event.identity_access.request predates the private BFF delegation
	// contract and is still consumed by its direct authority workflow.
	return canonical == permissions.ActionIdentityAccessRequest || permissions.IsDreamUPDelegatedAdministratorAction(canonical)
}

func isHighRiskAdminAction(action string) bool {
	if isAdminReauthAction(action) {
		return true
	}
	return permissions.IsDreamUPHighRiskDelegatedAdministratorAction(permissions.Action(action))
}

func validAdminActionTarget(userID identity.UserID, eventID, action, target string) bool {
	if target == "" || target != strings.TrimSpace(target) {
		return false
	}
	switch action {
	case auth.ReauthActionAdminRoleManagement, auth.ReauthActionAdminEventRegistry, auth.ReauthActionAdminCheckinWindowManage:
		return target == eventID
	case auth.ReauthActionAdminChallengeRotate:
		return target == string(userID)
	}
	canonical := permissions.Action(action)
	if permissions.IsDreamUPHighRiskDelegatedAdministratorAction(canonical) {
		_, ok := permissions.ParseDreamUPReauthenticationTarget(eventID, canonical, target)
		return ok
	}
	return true
}

func encodeReceipt(code string, version int64, state State) LocalReceiptResult {
	versionText := strconv.FormatInt(version, 10)
	digest := sha256.Sum256([]byte("adminstepup-receipt/v1\x00" + code + "\x00" + versionText + "\x00" + string(state)))
	return LocalReceiptResult{Code: code, Digest: base64.RawURLEncoding.EncodeToString(digest[:]), Payload: map[string]string{"version": versionText, "status": string(state)}}
}

func encodeChallengeReceipt(code string, challenge Challenge, state State) LocalReceiptResult {
	versionText := strconv.FormatInt(challenge.Version, 10)
	credentialText := strconv.FormatInt(challenge.CredentialVersion, 10)
	digest := sha256.Sum256([]byte("adminstepup-challenge-receipt/v1\x00" + code + "\x00" + versionText + "\x00" + credentialText + "\x00" + string(state)))
	return LocalReceiptResult{Code: code, Digest: base64.RawURLEncoding.EncodeToString(digest[:]), Payload: map[string]string{"version": versionText, "credential_version": credentialText, "status": string(state)}}
}

func decodeReceiptVersion(result LocalReceiptResult, wantCode string) (int64, error) {
	if result.Code != wantCode || result.Payload == nil {
		return 0, ErrInvalidStoredReceipt
	}
	version, err := strconv.ParseInt(result.Payload["version"], 10, 64)
	state := State(result.Payload["status"])
	if err != nil || version <= 0 || (state != StateActive && state != StateMustRotate && state != StateRecoveryPending) || encodeReceipt(wantCode, version, state).Digest != result.Digest {
		return 0, ErrInvalidStoredReceipt
	}
	return version, nil
}

func decodeVerifyReplay(result LocalReceiptResult) (VerifyResult, error) {
	version, err := decodeReceiptVersion(result, result.Code)
	if err != nil {
		return VerifyResult{}, err
	}
	state := State(result.Payload["status"])
	switch result.Code {
	case "challenge.verified":
		return VerifyResult{State: state, ChallengeVersion: version}, nil
	case "challenge.rejected":
		return VerifyResult{State: state, ChallengeVersion: version}, ErrInvalidChallengeAnswer
	case "challenge.locked":
		return VerifyResult{State: state, ChallengeVersion: version}, ErrLocked
	default:
		return VerifyResult{}, ErrInvalidStoredReceipt
	}
}

func decodeChallengeReceipt(result LocalReceiptResult, wantCode string) (Challenge, error) {
	if result.Code != wantCode || result.Payload == nil {
		return Challenge{}, ErrInvalidStoredReceipt
	}
	version, versionErr := strconv.ParseInt(result.Payload["version"], 10, 64)
	credentialVersion, credentialErr := strconv.ParseInt(result.Payload["credential_version"], 10, 64)
	state := State(result.Payload["status"])
	challenge := Challenge{Status: ChallengeActive, Version: version, CredentialVersion: credentialVersion}
	if versionErr != nil || credentialErr != nil || version <= 0 || credentialVersion <= 0 || state != StateActive || encodeChallengeReceipt(wantCode, challenge, state).Digest != result.Digest {
		return Challenge{}, ErrInvalidStoredReceipt
	}
	return challenge, nil
}

func decodeRotateReplay(result LocalReceiptResult) (Challenge, error) {
	switch result.Code {
	case "challenge.rotated":
		return decodeChallengeReceipt(result, "challenge.rotated")
	case "challenge.rejected":
		version, err := decodeReceiptVersion(result, result.Code)
		if err != nil {
			return Challenge{}, err
		}
		challenge := Challenge{Status: ChallengeActive, Version: version}
		return challenge, ErrInvalidChallengeAnswer
	case "challenge.locked":
		version, err := decodeReceiptVersion(result, result.Code)
		if err != nil {
			return Challenge{}, err
		}
		challenge := Challenge{Status: ChallengeActive, Version: version}
		return challenge, ErrLocked
	default:
		return Challenge{}, ErrInvalidStoredReceipt
	}
}

func challengeRecordID(userID identity.UserID) string { return "challenge:" + string(userID) }

func newRandomID(prefix string) (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func newRandomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashBearer(token string) string {
	digest := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", digest[:])
}

func NormalizeQuestion(value string) (string, error) {
	normalized := norm.NFKC.String(value)
	if hasForbiddenChallengeRune(normalized) {
		return "", ErrForbiddenChallengeText
	}
	count := uniseg.GraphemeClusterCount(normalized)
	if count < MinQuestionGraphemes || count > MaxQuestionGraphemes {
		return "", ErrInvalidQuestion
	}
	return normalized, nil
}

func NormalizeAnswer(value string) (string, error) {
	normalized := norm.NFKC.String(value)
	if hasForbiddenChallengeRune(normalized) {
		return "", ErrForbiddenChallengeText
	}
	normalized = strings.TrimSpace(normalized)
	count := uniseg.GraphemeClusterCount(normalized)
	if count < MinAnswerGraphemes || count > MaxAnswerGraphemes {
		return "", ErrInvalidAnswer
	}
	return normalized, nil
}

func ValidateQuestionAnswer(question, answer string) error {
	normalizedQuestion, err := NormalizeQuestion(question)
	if err != nil {
		return err
	}
	normalizedAnswer, err := NormalizeAnswer(answer)
	if err != nil {
		return err
	}
	if normalizedQuestion == normalizedAnswer {
		return ErrQuestionEqualsAnswer
	}
	return nil
}

func hasForbiddenChallengeRune(value string) bool {
	for _, r := range value {
		if unicode.Is(unicode.C, r) {
			return true
		}
	}
	return false
}
