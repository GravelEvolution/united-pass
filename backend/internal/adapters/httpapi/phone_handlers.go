//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-20
// Description: HTTP handlers for phone binding verification (SMS)
//

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/phoneverify"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const maxPhoneVerifyBodyBytes = 16 << 10

// PhoneVerifyService abstracts the phone binding verification flow.
type PhoneVerifyService interface {
	Request(context.Context, phoneverify.RequestInput) (phoneverify.RequestResult, error)
	Verify(context.Context, phoneverify.VerifyInput) (string, error)
}

// PhoneVerifyHandlers serves POST /api/v1/me/phone-change and
// POST /api/v1/me/phone-change/verify. Both run behind RequireSession and
// RequireCSRF; the same-origin check mirrors the account contact endpoints.
type PhoneVerifyHandlers struct {
	service        PhoneVerifyService
	expectedOrigin string
	logger         *slog.Logger
	risk           *RiskGuard
	rate           PhoneVerifyRateChecker
	rateLimit      int
	rateWindow     time.Duration
}

// PhoneVerifyRateChecker bounds how often one account may start a phone change.
type PhoneVerifyRateChecker interface {
	CheckAccountPhoneChangeBegin(context.Context, string, string, int, time.Duration) (bool, time.Duration, error)
}

type PhoneVerifyHandlerOption func(*PhoneVerifyHandlers)

func WithPhoneVerifyRiskGuard(guard *RiskGuard) PhoneVerifyHandlerOption {
	return func(h *PhoneVerifyHandlers) { h.risk = guard }
}

func WithPhoneVerifyRateChecker(checker PhoneVerifyRateChecker, limit int, window time.Duration) PhoneVerifyHandlerOption {
	return func(h *PhoneVerifyHandlers) {
		h.rate = checker
		h.rateLimit = limit
		h.rateWindow = window
	}
}

// NewPhoneVerifyHandlers builds the phone verification handlers.
func NewPhoneVerifyHandlers(service PhoneVerifyService, expectedOrigin string, logger *slog.Logger, options ...PhoneVerifyHandlerOption) *PhoneVerifyHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	handlers := &PhoneVerifyHandlers{
		service:        service,
		expectedOrigin: strings.TrimRight(expectedOrigin, "/"),
		logger:         logger,
	}
	for _, option := range options {
		option(handlers)
	}
	return handlers
}

// RequestPhoneChange handles POST /api/v1/me/phone-change. It validates the
// target phone, sends an SMS verification code and returns a request ID.
func (h *PhoneVerifyHandlers) RequestPhoneChange(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if !h.prepare(w, r) {
		return
	}
	var body struct {
		Phone string `json:"phone"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPhoneVerifyBodyBytes)
	if err := decodeJSONBody(w, r, &body, "begin phone change"); err != nil {
		return
	}
	phone, err := phoneverify.NormalizePhone(body.Phone)
	if err != nil {
		WriteValidation(w, r, "请输入有效的手机号码。", nil)
		return
	}
	if !h.checkRate(w, r, principal) {
		return
	}
	if h.risk != nil && !h.risk.Require(w, r, riskdefense.OperationPhoneChange, phoneChangeRiskIdentifier(principal.UserID, phone)) {
		return
	}
	result, err := h.service.Request(r.Context(), phoneverify.RequestInput{UserID: principal.UserID, Phone: phone})
	if err != nil {
		h.writeError(w, r, "begin", err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, map[string]any{"status": "verification_required", "requestId": result.RequestID})
}

func (h *PhoneVerifyHandlers) checkRate(w http.ResponseWriter, r *http.Request, principal session.Principal) bool {
	if h == nil || h.rate == nil || h.rateLimit <= 0 || h.rateWindow <= 0 {
		return true
	}
	allowed, retry, err := h.rate.CheckAccountPhoneChangeBegin(
		r.Context(), clientIP(r), hashRiskValue(string(principal.UserID)), h.rateLimit, h.rateWindow,
	)
	if err != nil {
		h.logger.Error("phone change rate limit failed", "requestId", requestID(r), "errorClass", observability.ClassifyError(err))
		WriteRateLimited(w, r, int(h.rateWindow.Seconds()))
		return false
	}
	if !allowed {
		WriteRateLimited(w, r, int((retry+time.Second-1)/time.Second))
		return false
	}
	return true
}

func phoneChangeRiskIdentifier(userID identity.UserID, phone string) string {
	return hashRiskValue(string(userID) + "\x00" + phone)
}

// VerifyPhoneChange handles POST /api/v1/me/phone-change/verify. It consumes
// the SMS code and, on success, binds the phone to the user.
func (h *PhoneVerifyHandlers) VerifyPhoneChange(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, maxPhoneVerifyBodyBytes)
	if err := decodeJSONBody(w, r, &body, "verify phone change"); err != nil {
		return
	}
	phone, err := h.service.Verify(r.Context(), phoneverify.VerifyInput{
		UserID: principal.UserID, RequestID: body.RequestID, Code: body.Code,
	})
	if err != nil {
		h.writeError(w, r, "verify", err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]any{"status": "verified", "phone": phone})
}

func (h *PhoneVerifyHandlers) prepare(w http.ResponseWriter, r *http.Request) bool {
	if h == nil || h.service == nil {
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

func (h *PhoneVerifyHandlers) writeError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	switch {
	case errors.Is(err, phoneverify.ErrInvalidInput):
		WriteValidation(w, r, "请输入有效的手机号码。", nil)
	case errors.Is(err, phoneverify.ErrVerificationFailed):
		writeError(w, r, http.StatusUnprocessableEntity, "account.phone_verification_failed", "验证码无效、已失效或已使用。", nil)
	default:
		h.logger.Error("phone change failed", "requestId", requestID(r), "operation", operation, "errorClass", observability.ClassifyError(err))
		WriteProviderUnavailable(w, r)
	}
}
