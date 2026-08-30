// Package accountcontact coordinates verified changes to a user's primary
// email address without changing the stable United Pass user identity.
package accountcontact

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

var (
	ErrInvalidInput       = errors.New("accountcontact: invalid input")
	ErrConflict           = errors.New("accountcontact: email conflict")
	ErrVerificationFailed = errors.New("accountcontact: verification failed")
	ErrUnavailable        = errors.New("accountcontact: unavailable")

	requestIDPattern             = regexp.MustCompile(`^email_change_[0-9a-f]{32}$`)
	emailVerificationCodePattern = regexp.MustCompile(`^[A-Z0-9]{6}$`)
)

type BeginInput struct {
	UserID identity.UserID
	Email  string
}

type BeginProviderInput struct {
	UserID                  identity.UserID
	Email                   string
	VerificationURLTemplate string
}

type VerifyInput struct {
	UserID    identity.UserID
	RequestID string
	Code      string
}

type BeginResult struct{ RequestID string }

type VerifyResult struct{ Email string }

type Provider interface {
	BeginEmailChange(context.Context, BeginProviderInput) error
	VerifyEmailChange(context.Context, identity.UserID, string) (string, error)
}

type Repository interface {
	UpdateVerifiedEmail(context.Context, identity.UserID, string) error
}

// EmailValidator is the delivery-policy port shared with public registration
// at the composition root. It is evaluated before the identity provider is
// asked to set a pending email or send a verification message. Implementations
// must return ErrInvalidInput for a definitively unusable address and
// ErrUnavailable for transient resolution or provider failures.
type EmailValidator interface {
	Validate(context.Context, string) error
}

type Config struct {
	PublicOrigin      string
	GenerateRequestID func() (string, error)
	EmailValidator    EmailValidator
}

type Service struct {
	provider Provider
	repo     Repository
	cfg      Config
}

func NewService(provider Provider, repo Repository, cfg Config) *Service {
	if cfg.GenerateRequestID == nil {
		cfg.GenerateRequestID = generateRequestID
	}
	return &Service{provider: provider, repo: repo, cfg: cfg}
}

func (s *Service) Begin(ctx context.Context, input BeginInput) (BeginResult, error) {
	if s == nil || s.provider == nil || s.repo == nil || input.UserID == "" {
		return BeginResult{}, ErrUnavailable
	}
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return BeginResult{}, err
	}
	if err := s.validateEmail(ctx, email); err != nil {
		return BeginResult{}, err
	}
	requestID, err := s.cfg.GenerateRequestID()
	if err != nil || !requestIDPattern.MatchString(requestID) {
		return BeginResult{}, ErrUnavailable
	}
	origin := strings.TrimRight(s.cfg.PublicOrigin, "/")
	if parsed, parseErr := url.Parse(origin); parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return BeginResult{}, ErrUnavailable
	}
	verificationURL := origin + "/account#emailChangeRequestId=" + url.QueryEscape(requestID) + "&code={{.Code}}"
	if err := s.provider.BeginEmailChange(ctx, BeginProviderInput{UserID: input.UserID, Email: email, VerificationURLTemplate: verificationURL}); err != nil {
		switch {
		case errors.Is(err, ErrConflict):
			return BeginResult{}, ErrConflict
		case errors.Is(err, ErrInvalidInput):
			return BeginResult{}, ErrInvalidInput
		default:
			return BeginResult{}, ErrUnavailable
		}
	}
	return BeginResult{RequestID: requestID}, nil
}

func (s *Service) Verify(ctx context.Context, input VerifyInput) (VerifyResult, error) {
	if s == nil || s.provider == nil || s.repo == nil || input.UserID == "" || !requestIDPattern.MatchString(input.RequestID) || !IsValidEmailVerificationCode(input.Code) {
		return VerifyResult{}, ErrVerificationFailed
	}
	email, err := s.provider.VerifyEmailChange(ctx, input.UserID, input.Code)
	if err != nil {
		if errors.Is(err, ErrVerificationFailed) {
			return VerifyResult{}, ErrVerificationFailed
		}
		return VerifyResult{}, ErrUnavailable
	}
	email, err = NormalizeEmail(email)
	if err != nil {
		return VerifyResult{}, ErrUnavailable
	}
	if err := s.repo.UpdateVerifiedEmail(ctx, input.UserID, email); err != nil {
		if errors.Is(err, ErrConflict) {
			return VerifyResult{}, ErrConflict
		}
		return VerifyResult{}, ErrUnavailable
	}
	return VerifyResult{Email: email}, nil
}

// IsValidEmailVerificationCode mirrors the pinned ZITADEL email-code
// generator: six case-sensitive ASCII characters drawn from A-Z and 0-9.
// Numeric-only and letter-only values remain possible because the provider
// samples each position independently; callers must not normalize case.
func IsValidEmailVerificationCode(value string) bool {
	return emailVerificationCodePattern.MatchString(value)
}

func (s *Service) validateEmail(ctx context.Context, email string) error {
	if s == nil || s.cfg.EmailValidator == nil {
		return ErrUnavailable
	}
	if err := s.cfg.EmailValidator.Validate(ctx, email); err != nil {
		if errors.Is(err, ErrInvalidInput) {
			return ErrInvalidInput
		}
		return ErrUnavailable
	}
	return nil
}

func NormalizeEmail(value string) (string, error) {
	if value != strings.TrimSpace(value) || len(value) > 254 || !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: email", ErrInvalidInput)
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return "", fmt.Errorf("%w: email", ErrInvalidInput)
	}
	return strings.ToLower(value), nil
}

func generateRequestID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "email_change_" + hex.EncodeToString(random), nil
}
