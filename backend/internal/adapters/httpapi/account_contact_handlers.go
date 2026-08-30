package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/accountcontact"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

const maxAccountContactBodyBytes = 16 << 10

type AccountContactService interface {
	Begin(context.Context, accountcontact.BeginInput) (accountcontact.BeginResult, error)
	Verify(context.Context, accountcontact.VerifyInput) (accountcontact.VerifyResult, error)
}

type AccountContactRateChecker interface {
	CheckAccountEmailChangeBegin(context.Context, string, string, int, time.Duration) (bool, time.Duration, error)
	CheckAccountEmailChangeVerify(context.Context, string, string, int, time.Duration) (bool, time.Duration, error)
}

type AccountContactHandlers struct {
	service        AccountContactService
	rate           AccountContactRateChecker
	reauth         ReauthVerifier
	expectedOrigin string
	limit          int
	window         time.Duration
	logger         *slog.Logger
}

func NewAccountContactHandlers(service AccountContactService, rate AccountContactRateChecker, reauth ReauthVerifier, expectedOrigin string, limit int, window time.Duration, logger *slog.Logger) *AccountContactHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &AccountContactHandlers{service: service, rate: rate, reauth: reauth, expectedOrigin: strings.TrimRight(expectedOrigin, "/"), limit: limit, window: window, logger: logger}
}

func (h *AccountContactHandlers) BeginEmailChange(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if !h.prepare(w, r) {
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAccountContactBodyBytes)
	if err := decodeJSONBody(w, r, &body, "begin account email change"); err != nil {
		return
	}
	if !h.checkRate(w, r, "begin", string(principal.UserID)) {
		return
	}
	if !h.consumeReauthGrant(w, r, string(principal.SessionID)) {
		return
	}
	result, err := h.service.Begin(r.Context(), accountcontact.BeginInput{UserID: principal.UserID, Email: body.Email})
	if err != nil {
		h.writeError(w, r, "begin", err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, map[string]any{"status": "verification_required", "requestId": result.RequestID})
}

func (h *AccountContactHandlers) VerifyEmailChange(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if !h.prepare(w, r) {
		return
	}
	var body struct {
		RequestID string `json:"requestId"`
		Code      string `json:"code"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAccountContactBodyBytes)
	if err := decodeJSONBody(w, r, &body, "verify account email change"); err != nil {
		return
	}
	// The budget is bound to the authenticated user, not the caller-chosen
	// request ID. Rotating bogus request IDs must not reset verification
	// attempts.
	if !h.checkRate(w, r, "verify", string(principal.UserID)) {
		return
	}
	result, err := h.service.Verify(r.Context(), accountcontact.VerifyInput{UserID: principal.UserID, RequestID: body.RequestID, Code: body.Code})
	if err != nil {
		h.writeError(w, r, "verify", err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]any{"status": "verified", "email": result.Email})
}

func (h *AccountContactHandlers) consumeReauthGrant(w http.ResponseWriter, r *http.Request, sessionID string) bool {
	token := r.Header.Get("X-Reauthentication-Token")
	if h.reauth == nil || token == "" || sessionID == "" {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	if err := h.reauth.VerifyAndConsume(r.Context(), token, auth.ReauthActionEmailChange, sessionID, "", "", ""); err != nil {
		h.logger.Warn("account email change reauthentication rejected", "requestId", requestID(r), "errorClass", observability.ClassifyError(err))
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	return true
}

func (h *AccountContactHandlers) prepare(w http.ResponseWriter, r *http.Request) bool {
	if h == nil || h.service == nil || h.rate == nil {
		WriteProviderUnavailable(w, r)
		return false
	}
	if r.Header.Get("Origin") != h.expectedOrigin {
		writeError(w, r, http.StatusForbidden, codeOriginMismatch, "请求来源无效。", nil)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "请求必须使用 JSON 格式。", nil)
		return false
	}
	return true
}

func (h *AccountContactHandlers) checkRate(w http.ResponseWriter, r *http.Request, operation, value string) bool {
	digest := sha256.Sum256([]byte(value))
	keyHash := hex.EncodeToString(digest[:])
	var allowed bool
	var retry time.Duration
	var err error
	if operation == "begin" {
		allowed, retry, err = h.rate.CheckAccountEmailChangeBegin(r.Context(), clientIP(r), keyHash, h.limit, h.window)
	} else {
		allowed, retry, err = h.rate.CheckAccountEmailChangeVerify(r.Context(), clientIP(r), keyHash, h.limit, h.window)
	}
	if err != nil {
		h.logger.Error("account email change rate limit failed", "requestId", requestID(r), "operation", operation, "errorClass", observability.ClassifyError(err))
		WriteRateLimited(w, r, int(h.window.Seconds()))
		return false
	}
	if !allowed {
		WriteRateLimited(w, r, int((retry+time.Second-1)/time.Second))
		return false
	}
	return true
}

func (h *AccountContactHandlers) writeError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	switch {
	case errors.Is(err, accountcontact.ErrInvalidInput):
		WriteValidation(w, r, "请输入有效的邮箱地址。", nil)
	case errors.Is(err, accountcontact.ErrConflict):
		writeError(w, r, http.StatusConflict, "account.email_conflict", "该邮箱无法绑定，请更换邮箱或稍后重试。", nil)
	case errors.Is(err, accountcontact.ErrVerificationFailed):
		writeError(w, r, http.StatusUnprocessableEntity, "account.email_verification_failed", "验证码无效、已失效或已使用。", nil)
	default:
		h.logger.Error("account email change failed", "requestId", requestID(r), "operation", operation, "errorClass", observability.ClassifyError(err))
		WriteProviderUnavailable(w, r)
	}
}
