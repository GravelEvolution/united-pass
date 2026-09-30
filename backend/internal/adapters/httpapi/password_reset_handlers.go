package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/passwordreset"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	CodePasswordResetTokenInvalid = "password.reset_token_invalid"
	maxPasswordResetIdentifierLen = 320
)

type PasswordResetService interface {
	Request(context.Context, passwordreset.RequestInput) error
	Confirm(context.Context, passwordreset.ConfirmInput) (passwordreset.ConfirmResult, error)
}

type PasswordResetRateChecker interface {
	CheckPasswordReset(ctx context.Context, ip, identifierHash string, ipLimit, accountLimit int, window time.Duration) (bool, time.Duration, error)
}

type PasswordResetPolicy struct {
	RequestIPLimit      int
	RequestAccountLimit int
	ConfirmIPLimit      int
	Window              time.Duration
}

type PasswordResetHandlers struct {
	service PasswordResetService
	rate    PasswordResetRateChecker
	policy  PasswordResetPolicy
	logger  *slog.Logger
}

func NewPasswordResetHandlers(service PasswordResetService, rate PasswordResetRateChecker, policy PasswordResetPolicy, logger *slog.Logger) *PasswordResetHandlers {
	if policy.Window <= 0 {
		policy.Window = 15 * time.Minute
	}
	if policy.RequestIPLimit <= 0 {
		policy.RequestIPLimit = 10
	}
	if policy.RequestAccountLimit <= 0 {
		policy.RequestAccountLimit = 5
	}
	if policy.ConfirmIPLimit <= 0 {
		policy.ConfirmIPLimit = 30
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &PasswordResetHandlers{service: service, rate: rate, policy: policy, logger: logger}
}

func (h *PasswordResetHandlers) Mount(router chi.Router) {
	router.Post("/auth/password-reset", h.Request)
	router.Post("/auth/password-reset/confirm", h.Confirm)
}

type passwordResetRequestBody struct {
	Identifier string `json:"identifier"`
}

type passwordResetConfirmBody struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func (h *PasswordResetHandlers) Request(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil {
		WriteInternalError(w, r)
		return
	}
	var body passwordResetRequestBody
	if err := decodeJSONBody(w, r, &body, "password reset request"); err != nil {
		return
	}
	identifier := strings.TrimSpace(body.Identifier)
	if identifier == "" || len(identifier) > maxPasswordResetIdentifierLen {
		WriteValidation(w, r, "请输入你注册时使用的邮箱地址。", []FieldError{{Field: "identifier", Message: "请输入有效的邮箱地址。"}})
		return
	}
	if !h.allow(w, r, h.policy.RequestIPLimit, h.policy.RequestAccountLimit, identifier) {
		return
	}
	if err := h.service.Request(r.Context(), passwordreset.RequestInput{Identifier: identifier}); err != nil {
		if errors.Is(err, passwordreset.ErrUnavailable) {
			WriteInternalError(w, r)
			return
		}
		h.logger.Warn("password reset request failed", "errorClass", err.Error())
	}
	writeJSONNoStore(w, r, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (h *PasswordResetHandlers) Confirm(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil {
		WriteInternalError(w, r)
		return
	}
	var body passwordResetConfirmBody
	if err := decodeJSONBody(w, r, &body, "password reset confirmation"); err != nil {
		return
	}
	if !h.allow(w, r, h.policy.ConfirmIPLimit, 0, "") {
		return
	}
	if _, err := h.service.Confirm(r.Context(), passwordreset.ConfirmInput{Token: body.Token, NewPassword: body.NewPassword}); err != nil {
		switch {
		case errors.Is(err, passwordreset.ErrWeakPassword):
			WriteValidation(w, r, "新密码强度不足。", []FieldError{{
				Field:   "newPassword",
				Message: "至少 12 个字符，且同时包含大写字母、小写字母、数字和符号。",
			}})
		case errors.Is(err, passwordreset.ErrInvalidToken):
			writeError(w, r, http.StatusUnprocessableEntity, CodePasswordResetTokenInvalid, "重置链接无效或已过期，请重新申请。", nil)
		case errors.Is(err, passwordreset.ErrPasswordChangeFailed), errors.Is(err, passwordreset.ErrPasswordChangeUnknown):
			writeError(w, r, http.StatusBadGateway, CodeProviderUnavailable, "密码重置失败，请稍后重试。", nil)
		default:
			WriteInternalError(w, r)
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", requestID(r))
	w.WriteHeader(http.StatusNoContent)
}

func (h *PasswordResetHandlers) allow(w http.ResponseWriter, r *http.Request, ipLimit, accountLimit int, identifier string) bool {
	if h.rate == nil || ipLimit <= 0 {
		return true
	}
	hash := ""
	if identifier != "" {
		hash = session.HashToken(strings.ToLower(identifier))
	}
	allowed, retryAfter, err := h.rate.CheckPasswordReset(r.Context(), clientIP(r), hash, ipLimit, accountLimit, h.policy.Window)
	if err != nil {
		h.logger.Warn("password reset rate check failed", "errorClass", err.Error())
		writeError(w, r, http.StatusTooManyRequests, CodeRateLimited, "请求过于频繁，请稍后再试。", nil)
		return false
	}
	if !allowed {
		if retryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		}
		writeError(w, r, http.StatusTooManyRequests, CodeRateLimited, "请求过于频繁，请稍后再试。", nil)
		return false
	}
	return true
}
