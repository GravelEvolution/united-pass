package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/riskdefense"
)

const (
	maxRegistrationBodyBytes = 32 << 10
	registrationDecoyDelay   = 140 * time.Millisecond
)

const (
	codeRegistrationClosed             = "registration.closed"
	codeRegistrationConflict           = "registration.conflict"
	codeRegistrationVerificationFailed = "registration.verification_failed"
	codeRegistrationTokenInvalid       = "registration.token_invalid"
	codeRegistrationFormInvalid        = "registration.form_invalid"
	codeRegistrationFormNotReady       = "registration.form_not_ready"
	codeOriginMismatch                 = "origin_mismatch"
	codeUnsupportedMediaType           = "request.unsupported_media_type"
)

type RegistrationService interface {
	Create(context.Context, registration.CreateInput) (registration.CreateResult, error)
	Verify(context.Context, registration.VerifyInput) (registration.VerifyResult, error)
	Resend(context.Context, string) error
}

type RegistrationRateChecker interface {
	CheckRegistrationFormIntent(context.Context, string, registration.Limit) (bool, time.Duration, error)
	CheckRegistrationCreate(context.Context, string, string, string, registration.CreateRatePolicy) (bool, time.Duration, error)
	CheckRegistrationVerify(context.Context, string, string, registration.Limit) (bool, time.Duration, error)
	CheckRegistrationResend(context.Context, string, string, registration.Limit) (bool, time.Duration, error)
}

type RegistrationFormDefense interface {
	Issue(context.Context, registration.FormIntentBinding) (registration.FormIntentResult, error)
	Consume(context.Context, string, registration.FormIntentBinding) error
	IsBlocked(context.Context, registration.AbuseFingerprint) (bool, error)
	RecordHit(context.Context, registration.AbuseFingerprint, registration.HoneypotReason, string) (registration.AbuseDisposition, error)
	Decoy() (registration.FormIntentResult, error)
	ClassifyHoneypot(*string) registration.HoneypotReason
}

type RegistrationHandlers struct {
	service        RegistrationService
	rate           RegistrationRateChecker
	enabled        bool
	expectedOrigin string
	policy         registration.RatePolicy
	logger         *slog.Logger
	risk           *RiskGuard
	formDefense    RegistrationFormDefense
}

type RegistrationHandlerOption func(*RegistrationHandlers)

func WithRegistrationRiskGuard(guard *RiskGuard) RegistrationHandlerOption {
	return func(h *RegistrationHandlers) { h.risk = guard }
}

func WithRegistrationFormDefense(defense RegistrationFormDefense) RegistrationHandlerOption {
	return func(h *RegistrationHandlers) { h.formDefense = defense }
}

func NewRegistrationHandlers(service RegistrationService, rate RegistrationRateChecker, enabled bool, expectedOrigin string, policy registration.RatePolicy, logger *slog.Logger, options ...RegistrationHandlerOption) *RegistrationHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	h := &RegistrationHandlers{
		service: service, rate: rate, enabled: enabled, expectedOrigin: strings.TrimRight(expectedOrigin, "/"),
		policy: policy, logger: logger,
	}
	for _, option := range options {
		if option != nil {
			option(h)
		}
	}
	return h
}

func (h *RegistrationHandlers) Mount(router chi.Router) {
	h.MountCreate(router)
	h.MountEmailLifecycle(router)
}

func (h *RegistrationHandlers) MountCreate(router chi.Router) {
	router.Post("/registrations/form-intents", h.IssueFormIntent)
	router.Post("/registrations", h.Create)
}

func (h *RegistrationHandlers) MountEmailLifecycle(router chi.Router) {
	router.Post("/registrations/email/verify", h.VerifyEmail)
	router.Post("/registrations/email/resend", h.ResendEmail)
}

type registrationCreateRequest struct {
	Username        string  `json:"username"`
	DisplayName     string  `json:"displayName"`
	Email           string  `json:"email"`
	Password        string  `json:"password"`
	AcceptedTerms   bool    `json:"acceptedTerms"`
	RequestID       string  `json:"requestId"`
	FormIntentToken string  `json:"formIntentToken"`
	AutomationBrief *string `json:"automationBrief"`
}

type registrationFormIntentRequest struct{}

type registrationVerifyRequest struct {
	UserID    string `json:"userId"`
	Code      string `json:"code"`
	RequestID string `json:"requestId"`
}

type registrationResendRequest struct {
	RegistrationToken string `json:"registrationToken"`
}

func (h *RegistrationHandlers) Create(w http.ResponseWriter, r *http.Request) {
	if !h.prepare(w, r) {
		return
	}
	var body registrationCreateRequest
	if !decodeRegistrationJSON(w, r, &body) {
		return
	}
	if h.formDefense == nil {
		WriteProviderUnavailable(w, r)
		return
	}
	reason := h.formDefense.ClassifyHoneypot(body.AutomationBrief)
	if reason == registration.HoneypotMissing {
		writeError(w, r, http.StatusUnprocessableEntity, codeRegistrationFormInvalid, "注册页面已更新，请刷新后重试。", nil)
		return
	}
	if body.FormIntentToken == "" {
		writeError(w, r, http.StatusUnprocessableEntity, codeRegistrationFormInvalid, "注册页面已更新，请刷新后重试。", nil)
		return
	}
	if reason != "" {
		// A honeypot value becomes a high-confidence signal only after the
		// caller proves possession of a current, bound, server-timed intent.
		// This prevents direct API callers from framing an arbitrary address.
		if !h.consumeRegistrationFormIntent(w, r, body.FormIntentToken) {
			return
		}
		h.rejectAutomatedRegistration(w, r, registrationFingerprint(r), reason)
		return
	}
	fingerprint := registrationFingerprint(r)
	blocked, err := h.formDefense.IsBlocked(r.Context(), fingerprint)
	if err != nil {
		WriteProviderUnavailable(w, r)
		return
	}
	if blocked {
		h.writeDecoyRegistration(w, r)
		return
	}
	input := registration.CreateInput{
		Username: body.Username, DisplayName: body.DisplayName, Email: body.Email,
		Password: body.Password, AcceptedTerms: body.AcceptedTerms, RequestID: body.RequestID,
	}
	if err := registration.ValidateCreate(input); err != nil {
		h.writeServiceError(w, r, "create", err)
		return
	}
	if !h.checkRate(w, r, "create", strings.ToLower(strings.TrimSpace(body.Email))) {
		return
	}
	if h.risk != nil && !h.risk.Require(w, r, riskdefense.OperationRegistration, hashRiskValue(strings.ToLower(strings.TrimSpace(body.Email)))) {
		return
	}
	if !h.consumeRegistrationFormIntent(w, r, body.FormIntentToken) {
		return
	}
	result, err := h.service.Create(r.Context(), input)
	if err != nil {
		h.writeServiceError(w, r, "create", err)
		return
	}
	h.writeCreated(w, r, result.RegistrationToken, result.ExpiresAt)
}

func (h *RegistrationHandlers) consumeRegistrationFormIntent(w http.ResponseWriter, r *http.Request, token string) bool {
	if err := h.formDefense.Consume(r.Context(), token, registrationFormIntentBinding(r, h.policy)); err != nil {
		switch {
		case errors.Is(err, registration.ErrFormIntentTooYoung):
			writeError(w, r, http.StatusUnprocessableEntity, codeRegistrationFormNotReady, "请稍候片刻再提交注册。", nil)
		case errors.Is(err, registration.ErrFormIntentInvalid):
			writeError(w, r, http.StatusUnprocessableEntity, codeRegistrationFormInvalid, "注册页面已失效，请刷新后重试。", nil)
		default:
			WriteProviderUnavailable(w, r)
		}
		return false
	}
	return true
}

func (h *RegistrationHandlers) IssueFormIntent(w http.ResponseWriter, r *http.Request) {
	if !h.prepare(w, r) {
		return
	}
	if h.formDefense == nil {
		WriteProviderUnavailable(w, r)
		return
	}
	var body registrationFormIntentRequest
	if !decodeRegistrationJSON(w, r, &body) {
		return
	}
	if !clientIPAbuseEligible(r) {
		h.logger.Error("registration form-intent trusted client network unavailable", "requestId", requestID(r))
		WriteProviderUnavailable(w, r)
		return
	}
	networkHash := registration.HashAbuseValue(clientNetwork(clientIP(r), h.policy.Create.IPv4NetBits, h.policy.Create.IPv6NetBits))
	allowed, retryAfter, err := h.rate.CheckRegistrationFormIntent(r.Context(), networkHash, h.policy.FormIntent)
	if err != nil {
		h.logger.Error("registration form-intent rate limit failed", "requestId", requestID(r), "errorClass", observability.ClassifyError(err))
		WriteProviderUnavailable(w, r)
		return
	}
	if !allowed {
		seconds := int((retryAfter + time.Second - 1) / time.Second)
		WriteRateLimited(w, r, seconds)
		return
	}
	result, err := h.formDefense.Issue(r.Context(), registrationFormIntentBinding(r, h.policy))
	if err != nil {
		WriteProviderUnavailable(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, struct {
		FormIntentToken string    `json:"formIntentToken"`
		ExpiresAt       time.Time `json:"expiresAt"`
	}{FormIntentToken: result.Token, ExpiresAt: result.ExpiresAt})
}

func (h *RegistrationHandlers) writeCreated(w http.ResponseWriter, r *http.Request, token string, expiresAt time.Time) {
	writeJSONNoStore(w, r, http.StatusCreated, struct {
		Status            string    `json:"status"`
		RegistrationToken string    `json:"registrationToken"`
		ExpiresAt         time.Time `json:"expiresAt"`
	}{Status: "verification_required", RegistrationToken: token, ExpiresAt: expiresAt})
}

func (h *RegistrationHandlers) rejectAutomatedRegistration(w http.ResponseWriter, r *http.Request, fingerprint registration.AbuseFingerprint, reason registration.HoneypotReason) {
	disposition, err := h.formDefense.RecordHit(r.Context(), fingerprint, reason, requestID(r))
	if err != nil {
		h.logger.Error("registration honeypot recording failed", "requestId", requestID(r), "reason", reason.String(), "errorClass", observability.ClassifyError(err))
	} else {
		h.logger.Warn("registration honeypot triggered", "requestId", requestID(r), "reason", reason.String(), "ipStrikeCount", disposition.IPStrikeCount, "ipBlocked", disposition.IPBlocked, "longIPBlock", disposition.LongIPBlock)
	}
	h.writeDecoyRegistration(w, r)
}

func (h *RegistrationHandlers) writeDecoyRegistration(w http.ResponseWriter, r *http.Request) {
	timer := time.NewTimer(registrationDecoyDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-r.Context().Done():
		return
	}
	result, err := h.formDefense.Decoy()
	if err != nil {
		WriteProviderUnavailable(w, r)
		return
	}
	h.writeCreated(w, r, result.Token, result.ExpiresAt)
}

func registrationFingerprint(r *http.Request) registration.AbuseFingerprint {
	deviceID := readCookie(r, RiskDeviceCookieName)
	deviceHash := ""
	if deviceID != "" {
		deviceHash = registration.HashAbuseValue(deviceID)
	}
	return registration.AbuseFingerprint{
		ClientIPHash:          registration.HashAbuseValue(clientIP(r)),
		ClientIPBlockEligible: clientIPAbuseEligible(r),
		DeviceIDHash:          deviceHash,
		UserAgentHash:         registration.HashAbuseValue(r.UserAgent()),
	}
}

func registrationFormIntentBinding(r *http.Request, policy registration.RatePolicy) registration.FormIntentBinding {
	deviceID := readCookie(r, RiskDeviceCookieName)
	deviceHash := ""
	if deviceID != "" {
		deviceHash = registration.HashAbuseValue(deviceID)
	}
	client := clientIP(r)
	return registration.FormIntentBinding{
		UserAgentHash:     registration.HashAbuseValue(r.UserAgent()),
		ClientNetworkHash: registration.HashAbuseValue(clientNetwork(client, policy.Create.IPv4NetBits, policy.Create.IPv6NetBits)),
		DeviceIDHash:      deviceHash,
	}
}

func (h *RegistrationHandlers) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if !h.prepare(w, r) {
		return
	}
	var body registrationVerifyRequest
	if !decodeRegistrationJSON(w, r, &body) {
		return
	}
	input := registration.VerifyInput{UserID: body.UserID, Code: body.Code, RequestID: body.RequestID}
	if err := registration.ValidateVerify(input); err != nil {
		h.writeServiceError(w, r, "verify", registration.ErrVerificationFailed)
		return
	}
	if !h.checkRate(w, r, "verify", body.UserID) {
		return
	}
	result, err := h.service.Verify(r.Context(), input)
	if err != nil {
		h.writeServiceError(w, r, "verify", err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, struct {
		Status    string `json:"status"`
		RequestID string `json:"requestId,omitempty"`
	}{Status: "verified", RequestID: result.RequestID})
}

func (h *RegistrationHandlers) ResendEmail(w http.ResponseWriter, r *http.Request) {
	if !h.prepare(w, r) {
		return
	}
	var body registrationResendRequest
	if !decodeRegistrationJSON(w, r, &body) {
		return
	}
	if body.RegistrationToken == "" || len(body.RegistrationToken) > 512 {
		h.writeServiceError(w, r, "resend", registration.ErrTokenNotFound)
		return
	}
	if !h.checkRate(w, r, "resend", body.RegistrationToken) {
		return
	}
	if err := h.service.Resend(r.Context(), body.RegistrationToken); err != nil {
		h.writeServiceError(w, r, "resend", err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{Status: "verification_sent"})
}

func (h *RegistrationHandlers) prepare(w http.ResponseWriter, r *http.Request) bool {
	if h == nil || !h.enabled || h.service == nil || h.rate == nil {
		writeError(w, r, http.StatusNotFound, codeRegistrationClosed, "注册暂未开放。", nil)
		return false
	}
	return validateTrustedBrowserMutation(w, r, h.expectedOrigin)
}

func (h *RegistrationHandlers) checkRate(w http.ResponseWriter, r *http.Request, operation, value string) bool {
	key := sha256.Sum256([]byte(value))
	keyHash := hex.EncodeToString(key[:])
	var (
		allowed    bool
		retryAfter time.Duration
		err        error
	)
	client := clientIP(r)
	switch operation {
	case "create":
		allowed, retryAfter, err = h.rate.CheckRegistrationCreate(
			r.Context(), client, clientNetwork(client, h.policy.Create.IPv4NetBits, h.policy.Create.IPv6NetBits), keyHash, h.policy.Create,
		)
	case "verify":
		allowed, retryAfter, err = h.rate.CheckRegistrationVerify(r.Context(), client, keyHash, h.policy.Verify)
	default:
		allowed, retryAfter, err = h.rate.CheckRegistrationResend(r.Context(), client, keyHash, h.policy.Resend)
	}
	if err != nil {
		h.logger.Error("registration rate limit failed", "requestId", requestID(r), "operation", operation, "errorClass", observability.ClassifyError(err))
		WriteRateLimited(w, r, int(h.operationWindow(operation).Seconds()))
		return false
	}
	if !allowed {
		seconds := int((retryAfter + time.Second - 1) / time.Second)
		WriteRateLimited(w, r, seconds)
		return false
	}
	return true
}

func (h *RegistrationHandlers) operationWindow(operation string) time.Duration {
	switch operation {
	case "create":
		return h.policy.Create.ClientIP.Window
	case "verify":
		return h.policy.Verify.Window
	default:
		return h.policy.Resend.Window
	}
}

func (h *RegistrationHandlers) writeServiceError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	switch {
	case errors.Is(err, registration.ErrInvalidInput):
		message := "请检查注册信息后重试。"
		if strings.HasSuffix(err.Error(), ": password") {
			message = "密码需为 12–128 个字符，并同时包含大写字母、小写字母、数字和符号。"
		}
		WriteValidation(w, r, message, nil)
	case errors.Is(err, registration.ErrConflict):
		writeError(w, r, http.StatusConflict, codeRegistrationConflict, "无法完成注册，请检查信息或稍后重试。", nil)
	case errors.Is(err, registration.ErrVerificationFailed):
		writeError(w, r, http.StatusUnprocessableEntity, codeRegistrationVerificationFailed, "验证链接无效、已失效或已使用。", nil)
	case errors.Is(err, registration.ErrTokenNotFound):
		writeError(w, r, http.StatusUnprocessableEntity, codeRegistrationTokenInvalid, "注册状态已失效，请重新注册。", nil)
	default:
		h.logger.Error("registration operation failed", "requestId", requestID(r), "operation", operation, "errorClass", observability.ClassifyError(err))
		WriteProviderUnavailable(w, r)
	}
}

func decodeRegistrationJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegistrationBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			WriteRequestBodyTooLarge(w, r)
		} else {
			WriteBadRequest(w, r, "请求体格式不正确。")
		}
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		WriteBadRequest(w, r, "请求体包含多余的数据。")
		return false
	}
	return true
}
