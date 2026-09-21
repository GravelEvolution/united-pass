// Package registration coordinates public account registration across the
// identity provider, the durable United Pass identity store, and short-lived
// opaque registration state.
package registration

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
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	StatusPending = "pending"
	maxRequestID  = 200
)

var (
	ErrInvalidInput = errors.New("registration: invalid input")
	ErrConflict     = errors.New("registration: account conflict")
	// ErrPhoneConflict preserves the public conflict class while allowing
	// WeChat onboarding to return a stable, phone-specific error. Callers must
	// never use the phone to select or merge an account.
	ErrPhoneConflict      = fmt.Errorf("%w: verified phone belongs to another account", ErrConflict)
	ErrVerificationFailed = errors.New("registration: verification failed")
	ErrTokenNotFound      = errors.New("registration: token not found")
	ErrUnavailable        = errors.New("registration: unavailable")

	usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)
	userIDPattern   = regexp.MustCompile(`^user_[0-9a-f]{32}$`)
)

type CreateInput struct {
	Username      string
	DisplayName   string
	Email         string
	Password      string
	AcceptedTerms bool
	RequestID     string
}

type ProviderUser struct {
	UserID                  string
	Username                string
	DisplayName             string
	Email                   string
	Password                string
	VerificationURLTemplate string
}

type PendingUser struct {
	UserID        string
	DisplayName   string
	Email         string
	EmailVerified bool
	Status        string
}

type VerifyInput struct {
	UserID    string
	Code      string
	RequestID string
}

type VerifyEmailInput struct {
	UserID string
	Code   string
}

type ResendEmailInput struct {
	UserID                  string
	VerificationURLTemplate string
}

type TokenRecord struct {
	UserID    string `json:"userId"`
	RequestID string `json:"requestId,omitempty"`
}

type CreateResult struct {
	RegistrationToken string
	ExpiresAt         time.Time
}

type VerifyResult struct{ RequestID string }

type Provider interface {
	CreateUser(context.Context, ProviderUser) error
	DeleteUser(context.Context, string) error
	VerifyEmail(context.Context, VerifyEmailInput) error
	ResendEmail(context.Context, ResendEmailInput) error
}

type Repository interface {
	CreatePending(context.Context, PendingUser) error
	DeletePending(context.Context, string) error
	IsPending(context.Context, string) (bool, error)
	ActivateVerified(context.Context, string) error
}

type TokenStore interface {
	Create(context.Context, string, TokenRecord, time.Duration) error
	Get(context.Context, string) (TokenRecord, error)
	Delete(context.Context, string) error
}

type Config struct {
	PublicOrigin   string
	TokenTTL       time.Duration
	EmailValidator EmailValidator
	Now            func() time.Time
	GenerateUserID func() (string, error)
	GenerateToken  func() (string, error)
}

type Service struct {
	provider Provider
	repo     Repository
	tokens   TokenStore
	cfg      Config
}

func NewService(provider Provider, repo Repository, tokens TokenStore, cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.GenerateUserID == nil {
		cfg.GenerateUserID = generateUserID
	}
	if cfg.GenerateToken == nil {
		cfg.GenerateToken = session.GenerateToken
	}
	return &Service{provider: provider, repo: repo, tokens: tokens, cfg: cfg}
}

func (s *Service) Create(ctx context.Context, input CreateInput) (CreateResult, error) {
	if s == nil || s.provider == nil || s.repo == nil || s.tokens == nil || s.cfg.TokenTTL <= 0 {
		return CreateResult{}, ErrUnavailable
	}
	if err := ValidateCreate(input); err != nil {
		return CreateResult{}, err
	}
	if s.cfg.EmailValidator != nil {
		if err := s.cfg.EmailValidator.Validate(ctx, input.Email); err != nil {
			return CreateResult{}, err
		}
	}

	userID, err := s.cfg.GenerateUserID()
	if err != nil || !userIDPattern.MatchString(userID) {
		return CreateResult{}, ErrUnavailable
	}
	token, err := s.cfg.GenerateToken()
	if err != nil || token == "" {
		return CreateResult{}, ErrUnavailable
	}
	record := TokenRecord{UserID: userID, RequestID: input.RequestID}
	issuedAt := s.cfg.Now().UTC()
	if err := s.tokens.Create(ctx, token, record, s.cfg.TokenTTL); err != nil {
		return CreateResult{}, ErrUnavailable
	}
	cleanupToken := func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.tokens.Delete(cleanupCtx, token)
	}

	pending := PendingUser{
		UserID: userID, DisplayName: input.DisplayName, Email: input.Email,
		EmailVerified: false, Status: StatusPending,
	}
	if err := s.repo.CreatePending(ctx, pending); err != nil {
		cleanupToken()
		if errors.Is(err, ErrConflict) {
			return CreateResult{}, ErrConflict
		}
		return CreateResult{}, ErrUnavailable
	}
	cleanupPending := func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = s.repo.DeletePending(cleanupCtx, userID)
	}

	providerUser := ProviderUser{
		UserID: userID, Username: input.Username, DisplayName: input.DisplayName,
		Email: input.Email, Password: input.Password,
		VerificationURLTemplate: s.verificationURL(input.RequestID),
	}
	if err := s.provider.CreateUser(ctx, providerUser); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = s.provider.DeleteUser(cleanupCtx, userID)
		cancel()
		cleanupPending()
		cleanupToken()
		if errors.Is(err, ErrConflict) {
			return CreateResult{}, ErrConflict
		}
		if errors.Is(err, ErrInvalidInput) {
			return CreateResult{}, ErrInvalidInput
		}
		return CreateResult{}, ErrUnavailable
	}

	return CreateResult{RegistrationToken: token, ExpiresAt: issuedAt.Add(s.cfg.TokenTTL)}, nil
}

func (s *Service) Verify(ctx context.Context, input VerifyInput) (VerifyResult, error) {
	if s == nil || s.provider == nil || s.repo == nil {
		return VerifyResult{}, ErrUnavailable
	}
	if err := ValidateVerify(input); err != nil {
		return VerifyResult{}, err
	}
	pending, err := s.repo.IsPending(ctx, input.UserID)
	if err != nil {
		return VerifyResult{}, ErrUnavailable
	}
	if !pending {
		// Keep the public result indistinguishable from a bad provider code,
		// while avoiding an identity-provider RPC for random syntactically valid
		// user IDs or already-settled registrations.
		return VerifyResult{}, ErrVerificationFailed
	}
	if err := s.provider.VerifyEmail(ctx, VerifyEmailInput{UserID: input.UserID, Code: input.Code}); err != nil {
		if errors.Is(err, ErrVerificationFailed) {
			return VerifyResult{}, ErrVerificationFailed
		}
		return VerifyResult{}, ErrUnavailable
	}
	if err := s.repo.ActivateVerified(ctx, input.UserID); err != nil {
		if errors.Is(err, ErrVerificationFailed) {
			return VerifyResult{}, ErrVerificationFailed
		}
		return VerifyResult{}, ErrUnavailable
	}
	return VerifyResult{RequestID: input.RequestID}, nil
}

func (s *Service) Resend(ctx context.Context, rawToken string) error {
	if s == nil || s.provider == nil || s.tokens == nil {
		return ErrUnavailable
	}
	if rawToken == "" || len(rawToken) > 512 {
		return ErrTokenNotFound
	}
	record, err := s.tokens.Get(ctx, rawToken)
	if err != nil || !userIDPattern.MatchString(record.UserID) || validateOptionalRequestID(record.RequestID) != nil {
		if errors.Is(err, ErrTokenNotFound) || err == nil {
			return ErrTokenNotFound
		}
		return ErrUnavailable
	}
	if err := s.provider.ResendEmail(ctx, ResendEmailInput{
		UserID: record.UserID, VerificationURLTemplate: s.verificationURL(record.RequestID),
	}); err != nil {
		if errors.Is(err, ErrVerificationFailed) {
			return ErrVerificationFailed
		}
		return ErrUnavailable
	}
	return nil
}

func ValidateCreate(input CreateInput) error {
	if input.Username != strings.TrimSpace(input.Username) || !usernamePattern.MatchString(input.Username) {
		return fmt.Errorf("%w: username", ErrInvalidInput)
	}
	if input.DisplayName != strings.TrimSpace(input.DisplayName) || utf8.RuneCountInString(input.DisplayName) < 1 || utf8.RuneCountInString(input.DisplayName) > 100 {
		return fmt.Errorf("%w: display name", ErrInvalidInput)
	}
	if input.Email != strings.TrimSpace(input.Email) || len(input.Email) > 254 {
		return fmt.Errorf("%w: email", ErrInvalidInput)
	}
	address, err := mail.ParseAddress(input.Email)
	if err != nil || address.Address != input.Email {
		return fmt.Errorf("%w: email", ErrInvalidInput)
	}
	if isBlockedRegistrationEmail(input.Email) {
		// Keep the public error deliberately indistinguishable from other email
		// validation failures. The deny-list reason must not become an oracle for
		// disposable-mail operators probing the registration surface.
		return fmt.Errorf("%w: email", ErrInvalidInput)
	}
	passwordRunes := utf8.RuneCountInString(input.Password)
	var hasLower, hasUpper, hasNumber, hasSymbol bool
	for _, character := range input.Password {
		hasLower = hasLower || unicode.IsLower(character)
		hasUpper = hasUpper || unicode.IsUpper(character)
		hasNumber = hasNumber || unicode.IsDigit(character)
		hasSymbol = hasSymbol || unicode.IsPunct(character) || unicode.IsSymbol(character)
	}
	if !utf8.ValidString(input.Password) || passwordRunes < 12 || passwordRunes > 128 || !hasLower || !hasUpper || !hasNumber || !hasSymbol {
		return fmt.Errorf("%w: password", ErrInvalidInput)
	}
	if !input.AcceptedTerms {
		return fmt.Errorf("%w: terms", ErrInvalidInput)
	}
	if err := validateOptionalRequestID(input.RequestID); err != nil {
		return err
	}
	return nil
}

func ValidateVerify(input VerifyInput) error {
	if !userIDPattern.MatchString(input.UserID) || input.Code == "" || len(input.Code) > 256 || strings.TrimSpace(input.Code) != input.Code {
		return ErrVerificationFailed
	}
	if err := validateOptionalRequestID(input.RequestID); err != nil {
		return err
	}
	return nil
}

func validateOptionalRequestID(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > maxRequestID || !utf8.ValidString(value) {
		return fmt.Errorf("%w: request id", ErrInvalidInput)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: request id", ErrInvalidInput)
		}
	}
	return nil
}

func (s *Service) verificationURL(requestID string) string {
	origin := strings.TrimRight(s.cfg.PublicOrigin, "/")
	return origin + "/verify-email#userId={{.UserID}}&code={{.Code}}&requestId=" + url.QueryEscape(requestID)
}

func generateUserID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "user_" + hex.EncodeToString(buf), nil
}
