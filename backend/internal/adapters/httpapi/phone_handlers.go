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

	"github.com/GravelEvolution/united-pass/backend/internal/phoneverify"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
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
}

// NewPhoneVerifyHandlers builds the phone verification handlers.
func NewPhoneVerifyHandlers(service PhoneVerifyService, expectedOrigin string, logger *slog.Logger) *PhoneVerifyHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &PhoneVerifyHandlers{
		service:        service,
		expectedOrigin: strings.TrimRight(expectedOrigin, "/"),
		logger:         logger,
	}
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
	result, err := h.service.Request(r.Context(), phoneverify.RequestInput{UserID: principal.UserID, Phone: body.Phone})
	if err != nil {
		h.writeError(w, r, "begin", err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, map[string]any{"status": "verification_required", "requestId": result.RequestID})
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
