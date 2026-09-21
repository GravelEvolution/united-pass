package wechat

import (
	"context"
	"errors"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

var (
	// ErrNotRegistered intentionally does not distinguish a missing binding,
	// disabled account or malformed provider identity to an HTTP caller.
	ErrNotRegistered   = errors.New("wechat: account is not available")
	ErrBindingMismatch = errors.New("wechat: binding does not belong to current user")
	// ErrPhoneConflict is returned when the verified phone is already owned by
	// another account or would replace a different phone on the linked account.
	// Callers must never use the phone to select or merge an account.
	ErrPhoneConflict = errors.New("wechat: verified phone conflicts with account authority")
)

// BindingReader is satisfied by the PostgreSQL user repository. The service
// keeps its dependency to the narrow explicit-link read model: it never uses
// email, phone, nickname or provider display data for account resolution.
type BindingReader interface {
	GetIdentityLink(context.Context, string, string, string) (identity.IdentityLink, error)
	GetByID(context.Context, identity.UserID) (identity.User, error)
}

// PhoneWriter is the narrow self-service mutation needed after a verified
// WeChat getPhoneNumber flow. Its implementation must atomically re-check the
// exact provider subject and active target account, and may only add an empty
// phone or verify the identical legacy phone. It must fail closed rather than
// overwrite or use the phone to select/merge an account.
type PhoneWriter interface {
	CompleteLinkedWithVerifiedPhone(context.Context, identity.UserID, string, string, string) error
}

type Service struct {
	verifier Verifier
	reader   BindingReader
	phones   PhoneWriter
}

func NewService(verifier Verifier, reader BindingReader, phones PhoneWriter) *Service {
	return &Service{verifier: verifier, reader: reader, phones: phones}
}

// ResolveLogin proves the one-time WeChat login code and resolves only an
// existing, explicitly linked active account. It never creates or merges an
// account as a side effect of login.
func (s *Service) ResolveLogin(ctx context.Context, loginCode string) (identity.User, error) {
	if s == nil || s.verifier == nil || s.reader == nil {
		return identity.User{}, ErrUnavailable
	}
	proof, err := s.verifier.VerifyLogin(ctx, loginCode)
	if err != nil {
		return identity.User{}, err
	}
	link, err := s.reader.GetIdentityLink(ctx, ProviderName, proof.TenantID, proof.Subject)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return identity.User{}, ErrNotRegistered
		}
		return identity.User{}, ErrUnavailable
	}
	user, err := s.reader.GetByID(ctx, link.UserID)
	if err != nil || !user.Status.CanAuthenticate() {
		return identity.User{}, ErrNotRegistered
	}
	return user, nil
}

// BindVerifiedPhone proves the current WeChat identity link and independently
// redeems a fresh AppID-scoped getPhoneNumber authorization. The provider's
// phone response carries no OpenID, so this service deliberately makes no
// same-WeChat-subject claim between the two one-time codes.
func (s *Service) BindVerifiedPhone(ctx context.Context, userID identity.UserID, loginCode, phoneCode string) error {
	if s == nil || s.verifier == nil || s.reader == nil || s.phones == nil || userID == "" {
		return ErrUnavailable
	}
	proof, err := s.verifier.VerifyRegistration(ctx, loginCode, phoneCode)
	if err != nil {
		return err
	}
	link, err := s.reader.GetIdentityLink(ctx, ProviderName, proof.TenantID, proof.Subject)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return ErrBindingMismatch
		}
		return ErrUnavailable
	}
	if link.UserID != userID {
		return ErrBindingMismatch
	}
	if err := s.phones.CompleteLinkedWithVerifiedPhone(ctx, userID, proof.TenantID, proof.Subject, proof.Phone); err != nil {
		switch {
		case errors.Is(err, ErrPhoneConflict):
			return ErrPhoneConflict
		case errors.Is(err, identity.ErrIdentityLinkConflict):
			return ErrBindingMismatch
		case errors.Is(err, identity.ErrUserNotFound):
			return ErrNotRegistered
		default:
			return ErrUnavailable
		}
	}
	return nil
}
