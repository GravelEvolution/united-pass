package adminbootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/adminstepup"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

const (
	ExpectedLoginName = "El107t"
	ShanghaiEventID   = "evt_dreamup_shanghai_2026"
)

type Change struct {
	Action           string
	TargetUserID     identity.UserID
	ExpectedUsername string
	Provider         string
	ProviderTenantID string
	ProviderSubject  string
	Event            adminroles.RegisteredEvent
}

type VerifiedApproval struct {
	ID, RequestHash, OperatorUserID, KeyID string
	Signature                              []byte
	ExpiresAt, CreatedAt                   time.Time
}

type BootstrapState struct {
	Binding   adminroles.Binding
	Challenge adminstepup.Challenge
	Event     adminroles.RegisteredEvent
}

type Mutation struct {
	RequestHash string
	Approvals   []VerifiedApproval
	State       BootstrapState
	Credential  adminstepup.CredentialMaterial
}

type Repository interface {
	Apply(context.Context, Mutation) (BootstrapState, error)
	Readback(context.Context, identity.UserID, string) (BootstrapState, error)
}

type AnswerHasher interface {
	Hash(context.Context, string) (string, string, error)
}
type QuestionCipher interface {
	Encrypt(adminstepup.EncryptionPurpose, string, string, int64, string) (adminstepup.EncryptedValue, error)
}

type Dependencies struct {
	Local      LocalIdentityReadback
	Provider   ProviderIdentityReadback
	Repository Repository
	Hasher     AnswerHasher
	Cipher     QuestionCipher
	Approvals  *ApprovalKeyring
	Now        func() time.Time
}

type Service struct{ deps Dependencies }

type Input struct {
	Change           Change
	Approvals        []Approval
	Question, Answer string
}

type Result struct {
	Status     string
	Username   string
	UserID     identity.UserID
	BindingID  string
	EventID    string
	MustRotate bool
}

func NewService(deps Dependencies) (*Service, error) {
	if deps.Local == nil || deps.Provider == nil || deps.Repository == nil || deps.Hasher == nil || deps.Cipher == nil || deps.Approvals == nil {
		return nil, errors.New("adminbootstrap: incomplete dependencies")
	}
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{deps: deps}, nil
}

func (s *Service) Bootstrap(ctx context.Context, input Input) (Result, error) {
	if err := validateChange(input.Change); err != nil {
		return Result{}, err
	}
	if err := s.verifyIdentity(ctx, input.Change); err != nil {
		return Result{}, err
	}
	now := s.deps.Now().UTC().Truncate(time.Second)
	hash, approvals, err := verifyApprovals(input.Change, input.Approvals, s.deps.Approvals, now)
	if err != nil {
		return Result{}, err
	}
	phc, pepperID, err := s.deps.Hasher.Hash(ctx, input.Answer)
	if err != nil {
		return Result{}, errors.New("adminbootstrap: invalid challenge material")
	}
	question, err := adminstepup.NormalizeQuestion(input.Question)
	if err != nil {
		return Result{}, errors.New("adminbootstrap: invalid challenge material")
	}
	sealed, err := s.deps.Cipher.Encrypt(adminstepup.PurposeChallengeQuestion, string(input.Change.TargetUserID), challengeRecordID(input.Change.TargetUserID), 1, question)
	if err != nil {
		return Result{}, errors.New("adminbootstrap: invalid challenge material")
	}
	bindingID := "arb_" + hash[:32]
	operator := identity.UserID(approvals[0].OperatorUserID)
	state := BootstrapState{
		Binding:   adminroles.Binding{ID: bindingID, UserID: input.Change.TargetUserID, Role: adminroles.RoleSuperAdmin, Scope: adminroles.Scope{Kind: adminroles.ScopeSystem}, Enabled: true, Version: 1, GrantedBy: operator, ReasonID: "bootstrap_" + hash[:32], CreatedAt: now, UpdatedAt: now},
		Challenge: adminstepup.Challenge{UserID: input.Change.TargetUserID, Status: adminstepup.ChallengeActive, MustRotate: true, CredentialVersion: 1, SecurityEpoch: 1, Version: 1, CreatedAt: now, UpdatedAt: now},
		Event:     input.Change.Event,
	}
	state.Event.Enabled, state.Event.Version, state.Event.CreatedAt, state.Event.UpdatedAt = true, 1, now, now
	if state.Event.AuthoritativeReadAt.IsZero() {
		state.Event.AuthoritativeReadAt = now
	}
	credential := adminstepup.CredentialMaterial{Challenge: state.Challenge, QuestionKeyID: sealed.KeyID, QuestionNonce: sealed.Nonce, QuestionCiphertext: sealed.Ciphertext, AnswerPHC: phc, AnswerPepperKeyID: pepperID}
	applied, err := s.deps.Repository.Apply(ctx, Mutation{RequestHash: hash, Approvals: approvals, State: state, Credential: credential})
	if err != nil {
		return Result{}, err
	}
	return resultFromState("created", input.Change.ExpectedUsername, applied), nil
}

func (s *Service) Readback(ctx context.Context, change Change) (Result, error) {
	if err := validateChange(change); err != nil {
		return Result{}, err
	}
	if err := s.verifyIdentity(ctx, change); err != nil {
		return Result{}, err
	}
	state, err := s.deps.Repository.Readback(ctx, change.TargetUserID, change.Event.EventID)
	if err != nil {
		return Result{}, err
	}
	if !exactState(change, state) {
		return Result{}, ErrBootstrapDrift
	}
	return resultFromState("verified", change.ExpectedUsername, state), nil
}

func (s *Service) verifyIdentity(ctx context.Context, change Change) error {
	local, err := s.deps.Local.ReadExact(ctx, change.TargetUserID, change.Provider, change.ProviderTenantID, change.ProviderSubject)
	if err != nil || local.UserID != change.TargetUserID || local.Status != identity.UserStatusActive || local.Provider != change.Provider || local.ProviderTenantID != change.ProviderTenantID || local.ProviderSubject != change.ProviderSubject {
		return ErrIdentityMismatch
	}
	provider, err := s.deps.Provider.ReadExact(ctx, change.ProviderTenantID, change.ProviderSubject)
	if err != nil || !provider.Enabled || provider.Subject != change.ProviderSubject || provider.LoginName != change.ExpectedUsername {
		return ErrIdentityMismatch
	}
	return nil
}

func validateChange(change Change) error {
	if change.Action != GrantSuper || change.TargetUserID == "" || change.ExpectedUsername != ExpectedLoginName || change.Provider != "zitadel" || strings.TrimSpace(change.ProviderTenantID) == "" || strings.TrimSpace(change.ProviderSubject) == "" || change.Event.EventID != ShanghaiEventID || change.Event.Series != "dreamup" || change.Event.Slug != "dreamup-shanghai-2026" || strings.TrimSpace(change.Event.DisplayName) == "" || strings.TrimSpace(change.Event.SourceVersion) == "" {
		return ErrIdentityMismatch
	}
	return nil
}

func exactState(change Change, state BootstrapState) bool {
	return state.Binding.UserID == change.TargetUserID && state.Binding.Role == adminroles.RoleSuperAdmin && state.Binding.Scope == (adminroles.Scope{Kind: adminroles.ScopeSystem}) && state.Binding.Enabled && state.Binding.DisabledAt == nil && state.Binding.Version > 0 && state.Challenge.UserID == change.TargetUserID && state.Challenge.Status == adminstepup.ChallengeActive && state.Challenge.MustRotate && state.Challenge.CredentialVersion > 0 && state.Challenge.SecurityEpoch > 0 && state.Event.EventID == change.Event.EventID && state.Event.Series == change.Event.Series && state.Event.Slug == change.Event.Slug && state.Event.DisplayName == change.Event.DisplayName && state.Event.SourceVersion == change.Event.SourceVersion && state.Event.Enabled
}

func resultFromState(status, username string, state BootstrapState) Result {
	return Result{Status: status, Username: username, UserID: state.Binding.UserID, BindingID: state.Binding.ID, EventID: state.Event.EventID, MustRotate: state.Challenge.MustRotate}
}

func challengeRecordID(userID identity.UserID) string {
	digest := sha256.Sum256([]byte("united-pass/admin-challenge/v1\x00" + string(userID)))
	return "challenge_" + hex.EncodeToString(digest[:16])
}
