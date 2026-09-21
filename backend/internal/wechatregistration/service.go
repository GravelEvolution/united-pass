// Package wechatregistration creates a pending United Pass account only after
// the server verifies a Mini Program identity proof. The legacy registration
// entry point and onboarding both require a WeChat phone proof. Both paths reuse
// the existing provider/email verification lifecycle and never create an
// active account at login time.
package wechatregistration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
)

const userIDPrefix = "user_"

type CreateInput struct {
	Registration registration.CreateInput
	LoginCode    string
	PhoneCode    string
}

// CreateVerifiedInput is accepted only after an upstream onboarding use case
// has exchanged the one-time WeChat codes. Client-supplied OpenID, phone or
// tenant values must never be used to construct Proof.
type CreateVerifiedInput struct {
	Registration registration.CreateInput
	Proof        wechat.IdentityProof
	// ExpectedUserID is set only when recovering an existing pending
	// reservation bound into the upstream encrypted onboarding challenge.
	ExpectedUserID string
}

type PendingUser struct {
	User           registration.PendingUser
	Phone          string
	TenantID       string
	Subject        string
	ExpectedUserID string
	ProviderIntent ProviderIntent
}

// ProviderIntent is the exact credential-bearing provider request that a
// retryable pending reservation is allowed to replay. The repository persists
// only a memory-hard verifier of this value, never the password or this
// structure itself.
type ProviderIntent struct {
	Username    string
	DisplayName string
	Email       string
	Password    string
}

// Repository must atomically reserve (or reconcile and reuse) the local
// pending user, consumer persona, primary provider link and verified WeChat
// link. Returning the durable user ID makes retries use the same provider
// identity after an ambiguous upstream failure.
type Repository interface {
	ReservePendingWithWeChat(context.Context, PendingUser) (string, error)
}

type Config struct {
	PublicOrigin   string
	TokenTTL       time.Duration
	Now            func() time.Time
	GenerateUserID func() (string, error)
	GenerateToken  func() (string, error)
}

type Service struct {
	verifier wechat.Verifier
	provider registration.Provider
	repo     Repository
	tokens   registration.TokenStore
	cfg      Config
}

func NewService(verifier wechat.Verifier, provider registration.Provider, repo Repository, tokens registration.TokenStore, cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.GenerateUserID == nil {
		cfg.GenerateUserID = generateUserID
	}
	if cfg.GenerateToken == nil {
		cfg.GenerateToken = session.GenerateToken
	}
	return &Service{verifier: verifier, provider: provider, repo: repo, tokens: tokens, cfg: cfg}
}

func (s *Service) Create(ctx context.Context, input CreateInput) (registration.CreateResult, error) {
	if s == nil || s.verifier == nil || s.provider == nil || s.repo == nil || s.tokens == nil || s.cfg.TokenTTL <= 0 {
		return registration.CreateResult{}, registration.ErrUnavailable
	}
	if err := registration.ValidateCreate(input.Registration); err != nil {
		return registration.CreateResult{}, err
	}
	proof, err := s.VerifyRegistration(ctx, input.LoginCode, input.PhoneCode)
	if err != nil {
		return registration.CreateResult{}, err
	}
	return s.CreateVerified(ctx, CreateVerifiedInput{Registration: input.Registration, Proof: proof})
}

// VerifyRegistration exchanges both fresh Mini Program codes and returns only
// the server-derived identity proof. HTTP callers use this split operation so
// attacker-selected email buckets are charged only after WeChat has accepted
// both one-time proofs. It never creates or reserves a United Pass account.
func (s *Service) VerifyRegistration(ctx context.Context, loginCode, phoneCode string) (wechat.IdentityProof, error) {
	if s == nil || s.verifier == nil {
		return wechat.IdentityProof{}, registration.ErrUnavailable
	}
	if wechat.ValidateCode(loginCode) != nil || wechat.ValidateCode(phoneCode) != nil {
		return wechat.IdentityProof{}, registration.ErrInvalidInput
	}
	proof, err := s.verifier.VerifyRegistration(ctx, loginCode, phoneCode)
	if err != nil {
		if errors.Is(err, wechat.ErrInvalidCode) || errors.Is(err, wechat.ErrRejected) {
			return wechat.IdentityProof{}, registration.ErrInvalidInput
		}
		return wechat.IdentityProof{}, registration.ErrUnavailable
	}
	if proof.TenantID == "" || proof.Subject == "" || proof.Phone == "" ||
		strings.TrimSpace(proof.TenantID) != proof.TenantID ||
		strings.TrimSpace(proof.Subject) != proof.Subject ||
		strings.TrimSpace(proof.Phone) != proof.Phone {
		return wechat.IdentityProof{}, registration.ErrInvalidInput
	}
	return proof, nil
}

// CreateVerified creates a pending account from a proof already verified by
// an upstream onboarding use case or the legacy HTTP adapter. The stable
// WeChat tenant, subject and verified phone are all mandatory. This method
// performs no provider-code exchange and therefore cannot replay a wx.login or
// getPhoneNumber code.
func (s *Service) CreateVerified(ctx context.Context, input CreateVerifiedInput) (registration.CreateResult, error) {
	if err := registration.ValidateCreate(input.Registration); err != nil {
		return registration.CreateResult{}, err
	}
	if input.Proof.TenantID == "" || input.Proof.Subject == "" || input.Proof.Phone == "" ||
		strings.TrimSpace(input.Proof.TenantID) != input.Proof.TenantID ||
		strings.TrimSpace(input.Proof.Subject) != input.Proof.Subject ||
		strings.TrimSpace(input.Proof.Phone) != input.Proof.Phone {
		return registration.CreateResult{}, registration.ErrInvalidInput
	}
	if input.ExpectedUserID != "" && !validUserID(input.ExpectedUserID) {
		return registration.CreateResult{}, registration.ErrInvalidInput
	}
	return s.createVerified(ctx, input)
}

func (s *Service) createVerified(ctx context.Context, input CreateVerifiedInput) (registration.CreateResult, error) {
	if s == nil || s.provider == nil || s.repo == nil || s.tokens == nil || s.cfg.TokenTTL <= 0 {
		return registration.CreateResult{}, registration.ErrUnavailable
	}
	proof := input.Proof
	userID := input.ExpectedUserID
	if userID == "" {
		var err error
		userID, err = s.cfg.GenerateUserID()
		if err != nil || !validUserID(userID) {
			return registration.CreateResult{}, registration.ErrUnavailable
		}
	}
	pending := PendingUser{
		User:  registration.PendingUser{UserID: userID, DisplayName: input.Registration.DisplayName, Email: input.Registration.Email, Status: registration.StatusPending},
		Phone: proof.Phone, TenantID: proof.TenantID, Subject: proof.Subject,
		ExpectedUserID: input.ExpectedUserID,
		ProviderIntent: ProviderIntent{
			Username: input.Registration.Username, DisplayName: input.Registration.DisplayName,
			Email: input.Registration.Email, Password: input.Registration.Password,
		},
	}
	reservedUserID, err := s.repo.ReservePendingWithWeChat(ctx, pending)
	if err != nil {
		if errors.Is(err, registration.ErrConflict) || errors.Is(err, registration.ErrInvalidInput) {
			return registration.CreateResult{}, err
		}
		return registration.CreateResult{}, registration.ErrUnavailable
	}
	if !validUserID(reservedUserID) {
		return registration.CreateResult{}, registration.ErrUnavailable
	}
	if input.ExpectedUserID != "" && reservedUserID != input.ExpectedUserID {
		return registration.CreateResult{}, registration.ErrConflict
	}
	if err := s.provider.CreateUser(ctx, registration.ProviderUser{
		UserID: reservedUserID, Username: input.Registration.Username, DisplayName: input.Registration.DisplayName,
		Email: input.Registration.Email, Password: input.Registration.Password,
		VerificationURLTemplate: verificationURL(s.cfg.PublicOrigin, input.Registration.RequestID),
	}); err != nil {
		// Keep the verified, still-pending local reservation. A subsequent
		// request with fresh WeChat proofs reconciles it and retries the same
		// provider user ID. Deleting here made cleanup failures permanently
		// strand the email/phone/WeChat identities.
		if errors.Is(err, registration.ErrConflict) || errors.Is(err, registration.ErrInvalidInput) {
			return registration.CreateResult{}, err
		}
		return registration.CreateResult{}, registration.ErrUnavailable
	}
	token, err := s.cfg.GenerateToken()
	if err != nil || token == "" {
		return registration.CreateResult{}, registration.ErrUnavailable
	}
	issuedAt := s.cfg.Now().UTC()
	record := registration.TokenRecord{UserID: reservedUserID, RequestID: input.Registration.RequestID}
	if err := s.tokens.Create(ctx, token, record, s.cfg.TokenTTL); err != nil {
		// Provider creation is idempotent for the controlled user ID. Keeping
		// the reservation makes a Redis outage retryable without risking an
		// active account or an incomplete binding.
		return registration.CreateResult{}, registration.ErrUnavailable
	}
	return registration.CreateResult{RegistrationToken: token, ExpiresAt: issuedAt.Add(s.cfg.TokenTTL)}, nil
}

func generateUserID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return userIDPrefix + hex.EncodeToString(buf), nil
}

func validUserID(value string) bool {
	if len(value) != len(userIDPrefix)+32 || value[:len(userIDPrefix)] != userIDPrefix {
		return false
	}
	_, err := hex.DecodeString(value[len(userIDPrefix):])
	return err == nil
}

func verificationURL(origin, requestID string) string {
	return strings.TrimRight(origin, "/") + "/verify-email#userId={{.UserID}}&code={{.Code}}&requestId=" + url.QueryEscape(requestID)
}
