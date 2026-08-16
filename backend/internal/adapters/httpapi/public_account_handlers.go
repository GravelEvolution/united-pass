//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Public registration, email verification and password recovery HTTP API
//

package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

const (
	registrationVerificationTTL = 24 * time.Hour
	passwordResetTTL            = 15 * time.Minute
	publicAccountRateLimit      = 5
	publicAccountRateWindow     = 15 * time.Minute
	publicProviderDeadline      = 10 * time.Second
	publicSettlementTimeout     = 15 * time.Second
	publicPasswordMinLength     = 12
	publicPasswordMaxLength     = 200
)

const (
	CodeLifecycleTokenInvalid = "auth.lifecycle_token_invalid"
	CodeLifecycleTokenExpired = "auth.lifecycle_token_expired"
	CodeRegistrationConflict  = "auth.registration_conflict"
	CodeLifecycleRejected     = "auth.lifecycle_rejected"
	CodePasswordResetDegraded = "auth.password_reset_degraded"
)

var registrationUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$`)

type PublicAccountStore interface {
	CreatePendingRegistration(
		ctx context.Context,
		userID identity.UserID,
		provider, providerTenantID, username string,
		info identity.ProviderUserInfo,
	) error
	GetPublicAccountBinding(
		ctx context.Context,
		userID identity.UserID,
		provider, providerTenantID string,
	) (auth.PublicAccountBinding, error)
	FindPasswordResetBinding(
		ctx context.Context,
		provider, providerTenantID, providerSubject string,
	) (auth.PublicAccountBinding, error)
	ActivatePendingRegistration(ctx context.Context, binding auth.PublicAccountBinding) error
}

// PublicAccountHandlers owns credential-bearing logged-out flows. Provider
// verification codes and passwords are request-local only; the local token is
// authenticated ciphertext and contains no plaintext email or provider ID.
type PublicAccountHandlers struct {
	store          PublicAccountStore
	provider       auth.PublicAccountProvider
	rateChecker    ContactRateChecker
	security       MutationAuthority
	auditor        session.SecurityAuditor
	tokens         session.Encryptor
	providerName   string
	providerTenant string
	publicOrigin   string
	logger         *slog.Logger
	now            func() time.Time
}

func NewPublicAccountHandlers(
	store PublicAccountStore,
	provider auth.PublicAccountProvider,
	rateChecker ContactRateChecker,
	security MutationAuthority,
	auditor session.SecurityAuditor,
	tokens session.Encryptor,
	providerName, providerTenant, publicOrigin string,
	logger *slog.Logger,
) *PublicAccountHandlers {
	return &PublicAccountHandlers{
		store: store, provider: provider, rateChecker: rateChecker,
		security: security, auditor: auditor, tokens: tokens,
		providerName: providerName, providerTenant: providerTenant,
		publicOrigin: strings.TrimRight(publicOrigin, "/"), logger: logger,
		now: func() time.Time { return time.Now().UTC() },
	}
}

type publicRegistrationRequest struct {
	Username      string `json:"username"`
	Email         string `json:"email"`
	Password      string `json:"password"`
	TermsAccepted bool   `json:"termsAccepted"`
}

type publicRegistrationResponse struct {
	UserID string `json:"userId"`
	Status string `json:"status"`
}

type passwordResetRequest struct {
	Identifier string `json:"identifier"`
}

type passwordResetCompletionRequest struct {
	Token       string `json:"token"`
	Code        string `json:"code"`
	NewPassword string `json:"newPassword"`
}

type emailVerificationRequest struct {
	Token string `json:"token"`
	Code  string `json:"code"`
}

type lifecycleTokenPayload struct {
	Version   int             `json:"v"`
	Kind      string          `json:"kind"`
	UserID    identity.UserID `json:"userId"`
	ExpiresAt int64           `json:"expiresAt"`
}

const (
	lifecycleRegistration  = "registration_email"
	lifecyclePasswordReset = "password_reset"
)

func (h *PublicAccountHandlers) Register(w http.ResponseWriter, r *http.Request) {
	if !allowSameOriginJSON(w, r, h.publicOrigin, "注册") {
		return
	}
	var input publicRegistrationRequest
	if err := decodeJSONBody(w, r, &input, "registration"); err != nil {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	fieldErrors := validateRegistration(input)
	if len(fieldErrors) > 0 {
		WriteValidation(w, r, "请求参数校验失败。", fieldErrors)
		return
	}
	if !h.checkPublicRate(w, r, hashIdentifier("register:"+strings.ToLower(input.Username))) {
		return
	}
	if !h.ready() {
		WriteProviderUnavailable(w, r)
		return
	}

	userID, err := generatePublicUserID()
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	token, err := h.sealToken(lifecycleRegistration, userID, h.now().Add(registrationVerificationTTL))
	if err != nil {
		h.logError(r, "registration token creation failed", err)
		WriteInternalError(w, r)
		return
	}
	verificationURL := lifecycleURL(h.publicOrigin, "/verify-email", token)

	callCtx, cancel := context.WithTimeout(r.Context(), publicProviderDeadline)
	providerInfo, providerErr := h.provider.Register(callCtx, auth.RegistrationInput{
		Username: input.Username, Email: input.Email,
		Password:             auth.NewSecretPassword(input.Password),
		EmailVerificationURL: verificationURL,
	})
	cancel()
	if providerErr != nil {
		h.writeRegistrationError(w, r, providerErr)
		return
	}
	if err := h.store.CreatePendingRegistration(
		r.Context(), userID, h.providerName, h.providerTenant, input.Username, providerInfo,
	); err != nil {
		// Provider creation happened first because ZITADEL needs to send the
		// verification code. Compensate a failed local atomic registration so
		// no provider-only login identity survives.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(context.Background()), publicProviderDeadline)
		cleanupErr := h.provider.DeleteRegisteredUser(cleanupCtx, providerInfo.Subject)
		cleanupCancel()
		if cleanupErr != nil {
			h.logError(r, "registration compensation failed", cleanupErr)
		}
		if errors.Is(err, auth.ErrRegistrationConflict) {
			writeError(w, r, http.StatusConflict, CodeRegistrationConflict, "账户名或邮箱已被使用。", nil)
			return
		}
		h.logError(r, "pending registration persistence failed", err)
		WriteInternalError(w, r)
		return
	}

	writeJSONNoStore(w, r, http.StatusCreated, publicRegistrationResponse{
		UserID: string(userID), Status: "email_verification_required",
	})
}

// RequestPasswordReset always returns the same accepted response once the
// syntactic/rate boundary passes. Account absence, unverified email, missing
// local binding and provider notification failures are never distinguishable
// to the caller.
func (h *PublicAccountHandlers) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	if !allowSameOriginJSON(w, r, h.publicOrigin, "密码重置") {
		return
	}
	var input passwordResetRequest
	if err := decodeJSONBody(w, r, &input, "password reset request"); err != nil {
		return
	}
	input.Identifier = strings.TrimSpace(input.Identifier)
	if input.Identifier == "" || utf8.RuneCountInString(input.Identifier) > 254 {
		WriteValidation(w, r, "请求参数校验失败。", []FieldError{{Field: "identifier", Message: "请输入有效的账户名或邮箱。"}})
		return
	}
	if !h.checkPublicRate(w, r, hashIdentifier("reset-request:"+strings.ToLower(input.Identifier))) {
		return
	}
	if h.ready() {
		h.beginPasswordReset(r, input.Identifier)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
}

func (h *PublicAccountHandlers) beginPasswordReset(r *http.Request, identifier string) {
	callCtx, cancel := context.WithTimeout(r.Context(), publicProviderDeadline)
	providerInfo, err := h.provider.FindPasswordResetIdentity(callCtx, identifier)
	cancel()
	if err != nil {
		if !errors.Is(err, auth.ErrPublicAccountNotFound) {
			h.logError(r, "password reset identity resolution failed", err)
		}
		return
	}
	binding, err := h.store.FindPasswordResetBinding(
		r.Context(), h.providerName, h.providerTenant, providerInfo.Subject,
	)
	if err != nil {
		if !errors.Is(err, auth.ErrPublicAccountNotFound) {
			h.logError(r, "password reset local binding resolution failed", err)
		}
		return
	}
	token, err := h.sealToken(lifecyclePasswordReset, binding.UserID, h.now().Add(passwordResetTTL))
	if err != nil {
		h.logError(r, "password reset token creation failed", err)
		return
	}
	resetURL := lifecycleURL(h.publicOrigin, "/reset-password", token)
	callCtx, cancel = context.WithTimeout(r.Context(), publicProviderDeadline)
	err = h.provider.BeginPasswordReset(callCtx, binding.ProviderSubject, resetURL)
	cancel()
	if err != nil {
		h.logError(r, "password reset notification failed", err)
	}
}

func (h *PublicAccountHandlers) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if !allowSameOriginJSON(w, r, h.publicOrigin, "密码重置") {
		return
	}
	var input passwordResetCompletionRequest
	if err := decodeJSONBody(w, r, &input, "password reset"); err != nil {
		return
	}
	input.Token = strings.TrimSpace(input.Token)
	input.Code = strings.TrimSpace(input.Code)
	if passwordMessage := validatePublicPassword(input.NewPassword); passwordMessage != "" {
		WriteValidation(w, r, "请求参数校验失败。", []FieldError{{Field: "newPassword", Message: passwordMessage}})
		return
	}
	if !validVerificationCode(input.Code) {
		h.writeInvalidLifecycleToken(w, r)
		return
	}
	if !h.checkPublicRate(w, r, hashIdentifier("reset:"+input.Token)) {
		return
	}
	payload, err := h.openToken(input.Token, lifecyclePasswordReset)
	if err != nil {
		h.writeTokenError(w, r, err)
		return
	}
	binding, err := h.store.GetPublicAccountBinding(
		r.Context(), payload.UserID, h.providerName, h.providerTenant,
	)
	if err != nil || binding.Status != identity.UserStatusActive {
		h.writeInvalidLifecycleToken(w, r)
		return
	}
	if h.provider == nil || h.security == nil {
		WriteProviderUnavailable(w, r)
		return
	}

	intent, err := h.security.Acquire(r.Context(), binding.UserID)
	if err != nil {
		if errors.Is(err, securitystate.ErrIntentHeld) {
			writeError(w, r, http.StatusConflict, CodePasswordChangeInProgress, "已有密码修改正在进行，请稍后重试。", nil)
			return
		}
		h.logError(r, "password reset intent acquisition failed", err)
		WriteInternalError(w, r)
		return
	}

	callCtx, cancel := context.WithTimeout(r.Context(), publicProviderDeadline)
	providerErr := h.provider.ResetPassword(
		callCtx, binding.ProviderSubject, input.Code, auth.NewSecretPassword(input.NewPassword),
	)
	cancel()
	if providerErr != nil && !errors.Is(providerErr, auth.ErrPasswordChangeUnknown) {
		h.settleResetFailure(r, binding.UserID, intent)
		if errors.Is(providerErr, auth.ErrLifecycleRejected) || errors.Is(providerErr, auth.ErrLifecycleCodeInvalid) {
			writeError(w, r, http.StatusUnprocessableEntity, CodeLifecycleRejected, "重置链接无效、已过期，或新密码不符合安全策略。", nil)
			return
		}
		h.logError(r, "password reset provider failure", providerErr)
		WriteProviderUnavailable(w, r)
		return
	}

	providerOutcome := securitystate.ProviderOutcomeSuccess
	if errors.Is(providerErr, auth.ErrPasswordChangeUnknown) {
		providerOutcome = securitystate.ProviderOutcomeUnknown
	}
	if h.settlePasswordReset(w, r, binding.UserID, intent, providerOutcome) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *PublicAccountHandlers) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if !allowSameOriginJSON(w, r, h.publicOrigin, "邮箱验证") {
		return
	}
	var input emailVerificationRequest
	if err := decodeJSONBody(w, r, &input, "email verification"); err != nil {
		return
	}
	input.Token = strings.TrimSpace(input.Token)
	input.Code = strings.TrimSpace(input.Code)
	if !validVerificationCode(input.Code) {
		h.writeInvalidLifecycleToken(w, r)
		return
	}
	if !h.checkPublicRate(w, r, hashIdentifier("verify:"+input.Token)) {
		return
	}
	payload, err := h.openToken(input.Token, lifecycleRegistration)
	if err != nil {
		h.writeTokenError(w, r, err)
		return
	}
	binding, err := h.store.GetPublicAccountBinding(
		r.Context(), payload.UserID, h.providerName, h.providerTenant,
	)
	if err != nil || binding.Status != identity.UserStatusPending {
		h.writeInvalidLifecycleToken(w, r)
		return
	}
	if h.provider == nil {
		WriteProviderUnavailable(w, r)
		return
	}
	callCtx, cancel := context.WithTimeout(r.Context(), publicProviderDeadline)
	err = h.provider.VerifyRegistrationEmail(callCtx, binding.ProviderSubject, binding.Email, input.Code)
	cancel()
	if err != nil {
		if errors.Is(err, auth.ErrLifecycleCodeInvalid) {
			h.writeInvalidLifecycleToken(w, r)
			return
		}
		h.logError(r, "registration email verification failed", err)
		WriteProviderUnavailable(w, r)
		return
	}
	if err := h.store.ActivatePendingRegistration(r.Context(), binding); err != nil {
		if errors.Is(err, auth.ErrLifecycleCodeInvalid) || errors.Is(err, auth.ErrPublicAccountNotFound) {
			h.writeInvalidLifecycleToken(w, r)
			return
		}
		// A retry is safe: the provider adapter performs authoritative
		// verified-email readback when the provider already consumed the code.
		h.logError(r, "registration activation settlement failed", err)
		WriteInternalError(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PublicAccountHandlers) settleResetFailure(
	r *http.Request,
	userID identity.UserID,
	intent securitystate.Intent,
) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), publicSettlementTimeout)
	defer cancel()
	if err := h.security.SettleConfirmedFailure(ctx, userID, intent.IntentID); err != nil {
		h.logError(r, "password reset failure settlement failed", err)
	}
}

func (h *PublicAccountHandlers) settlePasswordReset(
	w http.ResponseWriter,
	r *http.Request,
	userID identity.UserID,
	intent securitystate.Intent,
	providerOutcome securitystate.ProviderOutcome,
) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), publicSettlementTimeout)
	defer cancel()
	newEpoch, err := h.security.RecordOutcome(ctx, userID, intent.IntentID, providerOutcome)
	if err != nil {
		h.logError(r, "password reset epoch advancement failed", err)
		h.recordResetAudit(ctx, r, userID, intent, 0, providerOutcome, securitystate.SettlementOutcomeDegraded)
		writeError(w, r, http.StatusInternalServerError, CodePasswordResetDegraded, "密码重置状态不确定，请稍后使用新密码尝试登录。", nil)
		return false
	}
	intent.Status = securitystate.IntentOutcomeRecorded
	intent.ProviderOutcome = providerOutcome
	result, settleErr := h.security.SettleIntent(ctx, intent, newEpoch, nil)
	if settleErr != nil && result.Outcome == securitystate.SettlementOutcomeNone {
		result.Outcome = securitystate.SettlementOutcomeDegraded
	}
	h.recordResetAudit(ctx, r, userID, intent, newEpoch, providerOutcome, result.Outcome)
	if providerOutcome == securitystate.ProviderOutcomeUnknown || settleErr != nil ||
		result.Outcome != securitystate.SettlementOutcomeSettled {
		if settleErr != nil {
			h.logError(r, "password reset session settlement failed", settleErr)
		}
		writeError(w, r, http.StatusInternalServerError, CodePasswordResetDegraded, "密码重置状态不确定，请稍后使用新密码尝试登录。", nil)
		return false
	}
	return true
}

func (h *PublicAccountHandlers) recordResetAudit(
	ctx context.Context,
	r *http.Request,
	userID identity.UserID,
	intent securitystate.Intent,
	newEpoch securitystate.Epoch,
	providerOutcome securitystate.ProviderOutcome,
	settlementOutcome securitystate.SettlementOutcome,
) {
	if h.auditor == nil {
		return
	}
	if err := h.auditor.RecordSessionEvent(ctx, session.SecurityAuditEvent{
		EventType: "account.password_reset", ActorUserID: userID,
		RequestID: request.ID(r.Context()), Operation: "account.password.reset",
		Result: session.AuditOutcomeSuccess, OccurredAt: h.now(),
		ProviderOutcome: string(providerOutcome), SettlementOutcome: string(settlementOutcome),
		IntentID: intent.IntentID, FromEpoch: int64(intent.EpochAtAcquire), ToEpoch: int64(newEpoch),
	}); err != nil {
		h.logError(r, "password reset audit failed", err)
	}
}

func (h *PublicAccountHandlers) sealToken(kind string, userID identity.UserID, expiresAt time.Time) (string, error) {
	if h.tokens == nil {
		return "", session.ErrMissingEncryptionKey
	}
	encoded, err := json.Marshal(lifecycleTokenPayload{
		Version: 1, Kind: kind, UserID: userID, ExpiresAt: expiresAt.Unix(),
	})
	if err != nil {
		return "", err
	}
	return h.tokens.Encrypt("up-lifecycle-v1:" + string(encoded))
}

var errLifecycleTokenExpired = errors.New("lifecycle token expired")

func (h *PublicAccountHandlers) openToken(token, expectedKind string) (lifecycleTokenPayload, error) {
	if h.tokens == nil || token == "" || len(token) > 4096 {
		return lifecycleTokenPayload{}, session.ErrInvalidCiphertext
	}
	plaintext, err := h.tokens.Decrypt(token)
	if err != nil || !strings.HasPrefix(plaintext, "up-lifecycle-v1:") {
		return lifecycleTokenPayload{}, session.ErrInvalidCiphertext
	}
	var payload lifecycleTokenPayload
	if err := json.Unmarshal([]byte(strings.TrimPrefix(plaintext, "up-lifecycle-v1:")), &payload); err != nil {
		return lifecycleTokenPayload{}, session.ErrInvalidCiphertext
	}
	if payload.Version != 1 || payload.Kind != expectedKind || payload.UserID == "" || payload.ExpiresAt <= 0 {
		return lifecycleTokenPayload{}, session.ErrInvalidCiphertext
	}
	if !h.now().Before(time.Unix(payload.ExpiresAt, 0)) {
		return lifecycleTokenPayload{}, errLifecycleTokenExpired
	}
	return payload, nil
}

func (h *PublicAccountHandlers) ready() bool {
	return h.store != nil && h.provider != nil && h.rateChecker != nil && h.tokens != nil &&
		h.providerName != "" && h.providerTenant != "" && h.publicOrigin != ""
}

func (h *PublicAccountHandlers) checkPublicRate(w http.ResponseWriter, r *http.Request, keyHash string) bool {
	if h.rateChecker == nil {
		WriteRateLimited(w, r, int(publicAccountRateWindow.Seconds()))
		return false
	}
	allowed, retryAfter, err := h.rateChecker.CheckContact(
		r.Context(), clientIP(r), keyHash, publicAccountRateLimit, publicAccountRateWindow,
	)
	if err != nil {
		h.logError(r, "public account rate limit failed", err)
		WriteRateLimited(w, r, int(publicAccountRateWindow.Seconds()))
		return false
	}
	if !allowed {
		WriteRateLimited(w, r, int(retryAfter.Seconds()))
		return false
	}
	return true
}

func (h *PublicAccountHandlers) writeRegistrationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrRegistrationConflict):
		writeError(w, r, http.StatusConflict, CodeRegistrationConflict, "账户名或邮箱已被使用。", nil)
	case errors.Is(err, auth.ErrLifecycleRejected):
		writeError(w, r, http.StatusUnprocessableEntity, CodeLifecycleRejected, "账户信息或密码不符合身份提供方策略。", nil)
	default:
		h.logError(r, "registration provider failure", err)
		WriteProviderUnavailable(w, r)
	}
}

func (h *PublicAccountHandlers) writeTokenError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errLifecycleTokenExpired) {
		writeError(w, r, http.StatusGone, CodeLifecycleTokenExpired, "该链接已过期，请重新发起请求。", nil)
		return
	}
	h.writeInvalidLifecycleToken(w, r)
}

func (h *PublicAccountHandlers) writeInvalidLifecycleToken(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusUnprocessableEntity, CodeLifecycleTokenInvalid, "该链接无效、已过期或已被使用。", nil)
}

func (h *PublicAccountHandlers) logError(r *http.Request, message string, err error) {
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Error(message,
		"requestId", request.ID(r.Context()),
		"errorClass", observability.ClassifyError(err),
		"errorDetail", observability.RedactedError(err, 256),
	)
}

func validateRegistration(input publicRegistrationRequest) []FieldError {
	var fieldErrors []FieldError
	if !registrationUsernamePattern.MatchString(input.Username) {
		fieldErrors = append(fieldErrors, FieldError{Field: "username", Message: "账户名须为 3 至 32 位字母、数字、点、下划线或连字符。"})
	}
	address, err := mail.ParseAddress(input.Email)
	if err != nil || !strings.EqualFold(address.Address, input.Email) || len(input.Email) > 254 {
		fieldErrors = append(fieldErrors, FieldError{Field: "email", Message: "请输入有效的邮箱地址。"})
	}
	if message := validatePublicPassword(input.Password); message != "" {
		fieldErrors = append(fieldErrors, FieldError{Field: "password", Message: message})
	}
	if !input.TermsAccepted {
		fieldErrors = append(fieldErrors, FieldError{Field: "termsAccepted", Message: "请阅读并同意服务条款。"})
	}
	return fieldErrors
}

func validatePublicPassword(password string) string {
	length := utf8.RuneCountInString(password)
	if length < publicPasswordMinLength || length > publicPasswordMaxLength {
		return fmt.Sprintf("密码长度必须为 %d 至 %d 个字符。", publicPasswordMinLength, publicPasswordMaxLength)
	}
	return ""
}

func generatePublicUserID() (identity.UserID, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("httpapi: generate registration user id: %w", err)
	}
	return identity.UserID("user_" + hex.EncodeToString(bytes)), nil
}

func lifecycleURL(publicOrigin, path, token string) string {
	// Keep the provider template placeholder literal. QueryEscape is applied
	// only to the opaque United Pass token; ZITADEL substitutes {{.Code}}
	// before it sends the final browser URL.
	return strings.TrimRight(publicOrigin, "/") + path + "?token=" +
		url.QueryEscape(token) + "&code={{.Code}}"
}
