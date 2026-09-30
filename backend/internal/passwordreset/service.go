package passwordreset

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/email"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	MinPasswordRunes = 12
	maxPasswordRunes = 128
	maxIdentifierLen = 254
	maxTokenLen      = 512

	EventResetRequested = "account.password_reset_requested"
	EventResetCompleted = "account.password_reset_completed"
	OperationReset      = "password.reset"
)

var (
	ErrInvalidToken          = errors.New("passwordreset: invalid token")
	ErrWeakPassword          = errors.New("passwordreset: weak password")
	ErrPasswordChangeFailed  = errors.New("passwordreset: password change failed")
	ErrPasswordChangeUnknown = errors.New("passwordreset: password change unknown")
	ErrUnavailable           = errors.New("passwordreset: unavailable")
)

type TokenRecord struct {
	UserID string `json:"userId"`
}

type RequestInput struct {
	Identifier string
}

type ConfirmInput struct {
	Token       string
	NewPassword string
}

type ConfirmResult struct {
	UserID          identity.UserID
	RevokedSessions int
}

type UserReader interface {
	GetByEmail(context.Context, string) (identity.User, error)
}

type TokenStore interface {
	Create(context.Context, string, TokenRecord, time.Duration) error
	Consume(context.Context, string) (TokenRecord, error)
}

type PasswordSetter interface {
	SetPassword(context.Context, identity.UserID, auth.SecretPassword) error
}

type SessionRevoker interface {
	RevokeAllUserSessionsByAdmin(context.Context, identity.UserID) (int, string, error)
}

type Mailer interface {
	Send(context.Context, email.Message) error
}

type Auditor interface {
	RecordSessionEvent(context.Context, session.SecurityAuditEvent) error
}

type Config struct {
	PublicOrigin  string
	TokenTTL      time.Duration
	FromName      string
	Now           func() time.Time
	GenerateToken func() (string, error)
}

type Service struct {
	users     UserReader
	tokens    TokenStore
	passwords PasswordSetter
	sessions  SessionRevoker
	mailer    Mailer
	auditor   Auditor
	cfg       Config
	logger    *slog.Logger
}

func NewService(users UserReader, tokens TokenStore, passwords PasswordSetter, sessions SessionRevoker, mailer Mailer, auditor Auditor, cfg Config, logger *slog.Logger) *Service {
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = 30 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.GenerateToken == nil {
		cfg.GenerateToken = session.GenerateToken
	}
	return &Service{
		users:     users,
		tokens:    tokens,
		passwords: passwords,
		sessions:  sessions,
		mailer:    mailer,
		auditor:   auditor,
		cfg:       cfg,
		logger:    logger,
	}
}

func (s *Service) Request(ctx context.Context, input RequestInput) error {
	if s == nil || s.users == nil || s.tokens == nil || s.mailer == nil || s.cfg.TokenTTL <= 0 {
		return ErrUnavailable
	}
	address := normalizeEmail(input.Identifier)
	if address == "" {
		return nil
	}
	user, err := s.users.GetByEmail(ctx, address)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return nil
		}
		return ErrUnavailable
	}
	if user.Status != identity.UserStatusActive || !user.EmailVerified || user.Email == "" {
		return nil
	}
	token, err := s.cfg.GenerateToken()
	if err != nil {
		return ErrUnavailable
	}
	if err := s.tokens.Create(ctx, token, TokenRecord{UserID: string(user.ID)}, s.cfg.TokenTTL); err != nil {
		return ErrUnavailable
	}
	message := email.Message{
		To:      user.Email,
		Subject: "MoonStone 账户密码重置",
		HTML:    resetEmailHTML(user.DisplayName, s.resetLink(token), s.cfg.TokenTTL),
	}
	if err := s.mailer.Send(ctx, message); err != nil {
		s.lg().Warn("password reset email delivery failed",
			"userId", string(user.ID),
			"errorClass", observability.ClassifyError(err),
		)
		return nil
	}
	s.recordAudit(ctx, user.ID, EventResetRequested)
	return nil
}

func (s *Service) Confirm(ctx context.Context, input ConfirmInput) (ConfirmResult, error) {
	if s == nil || s.tokens == nil || s.passwords == nil {
		return ConfirmResult{}, ErrUnavailable
	}
	if err := ValidatePassword(input.NewPassword); err != nil {
		return ConfirmResult{}, err
	}
	if input.Token == "" || len(input.Token) > maxTokenLen || strings.TrimSpace(input.Token) != input.Token {
		return ConfirmResult{}, ErrInvalidToken
	}
	record, err := s.tokens.Consume(ctx, input.Token)
	if err != nil || record.UserID == "" {
		return ConfirmResult{}, ErrInvalidToken
	}
	userID := identity.UserID(record.UserID)
	if err := s.passwords.SetPassword(ctx, userID, auth.NewSecretPassword(input.NewPassword)); err != nil {
		s.lg().Warn("password reset provider mutation failed",
			"userId", string(userID),
			"errorClass", observability.ClassifyError(err),
		)
		if errors.Is(err, auth.ErrPasswordChangeUnknown) {
			return ConfirmResult{}, ErrPasswordChangeUnknown
		}
		return ConfirmResult{}, ErrPasswordChangeFailed
	}
	result := ConfirmResult{UserID: userID}
	if s.sessions != nil {
		revoked, providerFailure, revokeErr := s.sessions.RevokeAllUserSessionsByAdmin(ctx, userID)
		result.RevokedSessions = revoked
		if revokeErr != nil {
			s.lg().Warn("password reset session revocation failed",
				"userId", string(userID),
				"revoked", revoked,
				"providerFailureClass", providerFailure,
				"errorClass", observability.ClassifyError(revokeErr),
			)
		}
	}
	s.recordAudit(ctx, userID, EventResetCompleted)
	return result, nil
}

func ValidatePassword(password string) error {
	if !utf8.ValidString(password) {
		return ErrWeakPassword
	}
	runes := utf8.RuneCountInString(password)
	if runes < MinPasswordRunes || runes > maxPasswordRunes {
		return ErrWeakPassword
	}
	var hasLower, hasUpper, hasNumber, hasSymbol bool
	for _, character := range password {
		hasLower = hasLower || unicode.IsLower(character)
		hasUpper = hasUpper || unicode.IsUpper(character)
		hasNumber = hasNumber || unicode.IsDigit(character)
		hasSymbol = hasSymbol || unicode.IsPunct(character) || unicode.IsSymbol(character)
	}
	if !hasLower || !hasUpper || !hasNumber || !hasSymbol {
		return ErrWeakPassword
	}
	return nil
}

func normalizeEmail(identifier string) string {
	trimmed := strings.TrimSpace(identifier)
	if trimmed == "" || len(trimmed) > maxIdentifierLen || !strings.Contains(trimmed, "@") {
		return ""
	}
	address, err := mail.ParseAddress(trimmed)
	if err != nil || address.Address != trimmed {
		return ""
	}
	return strings.ToLower(trimmed)
}

func (s *Service) resetLink(token string) string {
	origin := strings.TrimRight(s.cfg.PublicOrigin, "/")
	return origin + "/reset-password?token=" + url.QueryEscape(token)
}

func (s *Service) recordAudit(ctx context.Context, userID identity.UserID, eventType string) {
	if s.auditor == nil || userID == "" {
		return
	}
	err := s.auditor.RecordSessionEvent(ctx, session.SecurityAuditEvent{
		EventType:   eventType,
		ActorUserID: userID,
		Operation:   OperationReset,
		Result:      session.AuditOutcomeSuccess,
		OccurredAt:  s.cfg.Now(),
	})
	if err != nil {
		s.lg().Warn("password reset audit record failed",
			"event", eventType,
			"userId", string(userID),
			"errorClass", observability.ClassifyError(err),
		)
	}
}

func (s *Service) lg() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.New(slog.DiscardHandler)
}

func resetEmailHTML(displayName, link string, ttl time.Duration) string {
	greeting := "你好"
	if strings.TrimSpace(displayName) != "" {
		greeting = "你好，" + escapeHTML(displayName)
	}
	minutes := int(ttl.Minutes())
	return `<div style="font-family:'Helvetica Neue',Arial,sans-serif;font-size:14px;color:#1f2329;line-height:1.7">` +
		`<p>` + greeting + `：</p>` +
		`<p>我们收到了重置 MoonStone 统一门户账户密码的请求。点击下面的链接设置新密码：</p>` +
		`<p><a href="` + escapeHTML(link) + `" style="display:inline-block;padding:10px 20px;background:#4b5cf5;color:#ffffff;border-radius:6px;text-decoration:none">重置密码</a></p>` +
		`<p>链接 ` + strconv.Itoa(minutes) + ` 分钟内有效，且只能使用一次。</p>` +
		`<p>如果这不是你本人的操作，请忽略这封邮件，你的密码不会发生变化。</p>` +
		`<p style="color:#8f959e">MoonStone DreamUP</p>` +
		`</div>`
}

func escapeHTML(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return replacer.Replace(value)
}
