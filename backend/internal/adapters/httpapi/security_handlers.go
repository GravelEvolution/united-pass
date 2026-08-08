//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Account security factor handlers (TOTP, passkeys, summary)
//

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// Account security factor endpoints (ADR-0006 §7/§8). The provider is the
// factor authority: no local factor state exists beyond the reauth and
// enrollment transients, and every listing is a provider readback. All
// mutations consume a step-up reauthentication grant bound to the caller's
// user + session + action (+ target for passkey removal); enrollment
// confirmation consumes the short-lived single-use enrollmentToken minted at
// the begin step instead of a second reauth ceremony.

// Stable factor error codes (non-enumerating where noted).
const (
	CodeFactorAlreadySet  = "factor.already_set"
	CodeFactorNotFound    = "factor.not_found"
	CodeFactorInvalid     = "factor.invalid_code"
	CodeEnrollmentInvalid = "enrollment.invalid"
)

// EnrollmentTokenStore abstracts factor enrollment challenge persistence.
// The Redis adapter satisfies this interface; tests can use an in-memory
// fake. Semantics follow the reauth grant pattern: single-use, atomic
// single-winner consumption, fail closed on loss.
type EnrollmentTokenStore interface {
	CreateEnrollment(ctx context.Context, tokenHash string, data auth.EnrollmentData, ttl time.Duration) error
	// ConsumeEnrollment atomically reads and deletes the enrollment;
	// exactly one concurrent consumer ever receives it.
	ConsumeEnrollment(ctx context.Context, tokenHash string) (auth.EnrollmentData, error)
}

// SecurityHandlers serves GET /api/v1/me/security and the TOTP/passkey
// lifecycle endpoints. All routes require a valid session and CSRF token
// (middleware-enforced); factor writes additionally consume a reauth grant.
type SecurityHandlers struct {
	factors       auth.FactorManager
	reauth        ReauthVerifier
	enrollments   EnrollmentTokenStore
	enrollmentTTL time.Duration
	logger        *slog.Logger
}

// NewSecurityHandlers builds the security factor handlers. enrollmentTTL
// bounds how long a begin→confirm enrollment stays valid.
func NewSecurityHandlers(
	factors auth.FactorManager,
	reauth ReauthVerifier,
	enrollments EnrollmentTokenStore,
	enrollmentTTL time.Duration,
	logger *slog.Logger,
) *SecurityHandlers {
	return &SecurityHandlers{
		factors:       factors,
		reauth:        reauth,
		enrollments:   enrollments,
		enrollmentTTL: enrollmentTTL,
		logger:        logger,
	}
}

// --- Wire shapes (frozen, ADR-0006 §8) ---

type securitySummaryView struct {
	Password      passwordView  `json:"password"`
	TOTP          totpView      `json:"totp"`
	Passkeys      []passkeyView `json:"passkeys"`
	RecoveryCodes recoveryView  `json:"recoveryCodes"`
}

type passwordView struct {
	Set bool `json:"set"`
}

type totpView struct {
	Enabled bool `json:"enabled"`
}

type passkeyView struct {
	PasskeyID string     `json:"passkeyId"`
	CreatedAt *time.Time `json:"createdAt"`
	State     string     `json:"state"`
}

// recoveryView is the fixed deferred-by-architecture payload (ADR-0006 §9):
// recovery codes are never available in real mode.
type recoveryView struct {
	Available      bool   `json:"available"`
	DeferredReason string `json:"deferredReason"`
}

func toSecuritySummaryView(summary auth.FactorSummary) securitySummaryView {
	passkeys := make([]passkeyView, 0, len(summary.Passkeys))
	for _, key := range summary.Passkeys {
		passkeys = append(passkeys, passkeyView{
			PasskeyID: key.ID,
			CreatedAt: key.CreatedAt,
			State:     string(key.State),
		})
	}
	return securitySummaryView{
		Password: passwordView{Set: summary.PasswordSet},
		TOTP:     totpView{Enabled: summary.TOTPEnabled},
		Passkeys: passkeys,
		RecoveryCodes: recoveryView{
			Available:      false,
			DeferredReason: "provider_unsupported",
		},
	}
}

// GetSecurityFactors handles GET /api/v1/me/security: the provider-derived
// factor summary. No reauthentication is required (read-only).
func (h *SecurityHandlers) GetSecurityFactors(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	summary, err := h.factors.FactorSummary(r.Context(), principal.UserID)
	if err != nil {
		h.logSecurityEvent("security.factor_summary_failed", principal.UserID, "", err)
		h.writeFactorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toSecuritySummaryView(summary))
}

// --- TOTP lifecycle (ADR-0006 §7) ---

// BeginTOTPEnrollment handles POST /api/v1/me/security/totp/enrollment. It
// consumes the reauth grant for account.totp.enroll, registers a pending
// TOTP factor on the provider and returns the secret material exactly once.
// SECURITY: the response is secret-bearing (secret + otpauth URI) and is the
// only place they ever appear; it carries Cache-Control: no-store and is
// never logged or persisted locally.
func (h *SecurityHandlers) BeginTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if !h.consumeReauthGrant(w, r, principal, auth.ReauthActionTOTPEnroll, "", "security.totp_enrollment_begun") {
		return
	}

	enrollment, err := h.factors.BeginTOTPEnrollment(r.Context(), principal.UserID)
	if err != nil {
		h.logSecurityEvent("security.totp_enrollment_begun", principal.UserID, "totp", err)
		h.writeFactorError(w, r, err)
		return
	}

	token, err := h.issueEnrollment(r.Context(), principal, auth.EnrollmentTOTP, "")
	if err != nil {
		// The provider already holds a pending registration, but without a
		// usable enrollment token the confirm step cannot proceed safely:
		// fail closed. The pending registration can be discarded by a fresh
		// begin (provider replaces it) or removed.
		h.logSecurityEvent("security.totp_enrollment_begun", principal.UserID, "totp", err)
		WriteInternalError(w, r)
		return
	}

	h.logSecurityEvent("security.totp_enrollment_begun", principal.UserID, "totp", nil)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, struct {
		EnrollmentToken string `json:"enrollmentToken"`
		Secret          string `json:"secret"`
		OTPAuthURI      string `json:"otpauthUri"`
	}{EnrollmentToken: token, Secret: enrollment.Secret, OTPAuthURI: enrollment.OTPAuthURI})
}

type totpConfirmRequest struct {
	EnrollmentToken string `json:"enrollmentToken"`
	Code            string `json:"code"`
}

// ConfirmTOTPEnrollment handles POST /api/v1/me/security/totp/enrollment/confirm.
// It consumes the single-use enrollmentToken (single-winner via the store's
// atomic consume), verifies the binding, and activates the factor on the
// provider. A wrong code consumes the enrollment: retries must start a fresh
// enrollment (idempotency-safe, ADR-0006 §7).
func (h *SecurityHandlers) ConfirmTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	var req totpConfirmRequest
	if err := decodeJSONBody(w, r, &req, "totp enrollment confirm"); err != nil {
		return
	}
	if req.Code == "" {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "验证码不能为空。", nil)
		return
	}

	if !h.consumeEnrollment(w, r, principal, req.EnrollmentToken, auth.EnrollmentTOTP) {
		return
	}

	if err := h.factors.ConfirmTOTPEnrollment(r.Context(), principal.UserID, req.Code); err != nil {
		h.logSecurityEvent("security.totp_enrollment_confirmed", principal.UserID, "totp", err)
		h.writeFactorError(w, r, err)
		return
	}

	h.logSecurityEvent("security.totp_enrollment_confirmed", principal.UserID, "totp", nil)
	writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "confirmed"})
}

// RemoveTOTP handles DELETE /api/v1/me/security/totp. It consumes the reauth
// grant for account.totp.remove, removes the factor and performs a provider
// readback: the response carries the fresh factor summary, never state
// inferred from local memory.
func (h *SecurityHandlers) RemoveTOTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if !h.consumeReauthGrant(w, r, principal, auth.ReauthActionTOTPRemove, "", "security.totp_removed") {
		return
	}

	if err := h.factors.RemoveTOTP(r.Context(), principal.UserID); err != nil {
		h.logSecurityEvent("security.totp_removed", principal.UserID, "totp", err)
		h.writeFactorError(w, r, err)
		return
	}

	summary, err := h.factors.FactorSummary(r.Context(), principal.UserID)
	if err != nil {
		// Removal succeeded but the readback failed: report the provider
		// failure instead of pretending to know the resulting state.
		h.logSecurityEvent("security.totp_removed", principal.UserID, "totp", err)
		h.writeFactorError(w, r, err)
		return
	}
	h.logSecurityEvent("security.totp_removed", principal.UserID, "totp", nil)
	writeJSON(w, http.StatusOK, toSecuritySummaryView(summary))
}

// --- Passkey lifecycle (ADR-0006 §8) ---

// BeginPasskeyEnrollment handles POST /api/v1/me/security/passkeys/enrollment.
// It consumes the reauth grant for account.passkey.enroll and returns the
// provider's WebAuthn creation options verbatim together with the passkeyId
// and a single-use enrollmentToken bound to that passkeyId.
func (h *SecurityHandlers) BeginPasskeyEnrollment(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if !h.consumeReauthGrant(w, r, principal, auth.ReauthActionPasskeyEnroll, "", "security.passkey_enrollment_begun") {
		return
	}

	enrollment, err := h.factors.BeginPasskeyEnrollment(r.Context(), principal.UserID)
	if err != nil {
		h.logSecurityEvent("security.passkey_enrollment_begun", principal.UserID, "passkey", err)
		h.writeFactorError(w, r, err)
		return
	}

	// The enrollment token is bound to the provider-issued passkeyId so the
	// confirm step can never verify a different passkey than the one this
	// enrollment minted (ADR-0006 §4 Target semantics).
	token, err := h.issueEnrollment(r.Context(), principal, auth.EnrollmentPasskey, enrollment.PasskeyID)
	if err != nil {
		h.logSecurityEvent("security.passkey_enrollment_begun", principal.UserID, "passkey", err)
		WriteInternalError(w, r)
		return
	}

	h.logSecurityEvent("security.passkey_enrollment_begun", principal.UserID, "passkey", nil)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// CreationOptions is embedded as a raw JSON object (verbatim for
	// navigator.credentials.create), never as an escaped string.
	_ = json.NewEncoder(w).Encode(struct {
		EnrollmentToken string          `json:"enrollmentToken"`
		PasskeyID       string          `json:"passkeyId"`
		CreationOptions json.RawMessage `json:"publicKeyCredentialCreationOptions"`
	}{EnrollmentToken: token, PasskeyID: enrollment.PasskeyID, CreationOptions: enrollment.CreationOptions})
}

type passkeyConfirmRequest struct {
	EnrollmentToken     string          `json:"enrollmentToken"`
	PublicKeyCredential json.RawMessage `json:"publicKeyCredential"`
	PasskeyName         string          `json:"passkeyName"`
}

// ConfirmPasskeyEnrollment handles POST /api/v1/me/security/passkeys/enrollment/confirm.
// It consumes the enrollmentToken, verifies the user/session/target binding,
// and forwards the browser attestation to the provider. Attestation payloads
// are never logged or audited (only sizes/outcomes, ADR-0006 §8).
func (h *SecurityHandlers) ConfirmPasskeyEnrollment(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	var req passkeyConfirmRequest
	if err := decodeJSONBody(w, r, &req, "passkey enrollment confirm"); err != nil {
		return
	}
	if len(req.PublicKeyCredential) == 0 {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "缺少凭据数据。", nil)
		return
	}

	data, ok := h.consumeEnrollmentData(w, r, principal, req.EnrollmentToken, auth.EnrollmentPasskey)
	if !ok {
		return
	}

	if err := h.factors.ConfirmPasskeyEnrollment(r.Context(), principal.UserID, data.Target, req.PasskeyName, req.PublicKeyCredential); err != nil {
		h.logSecurityEvent("security.passkey_enrollment_confirmed", principal.UserID, "passkey", err)
		h.writeFactorError(w, r, err)
		return
	}

	h.logSecurityEvent("security.passkey_enrollment_confirmed", principal.UserID, "passkey", nil)
	writeJSON(w, http.StatusOK, struct {
		Status    string `json:"status"`
		PasskeyID string `json:"passkeyId"`
	}{Status: "confirmed", PasskeyID: data.Target})
}

// RemovePasskey handles DELETE /api/v1/me/security/passkeys/{passkeyId}. The
// reauth grant is consumed only when its Target equals the route passkeyId —
// a grant minted for passkey A can never remove passkey B (ADR-0006 §4/§8).
// Unknown or foreign passkeyIds map to the stable non-enumeration 404.
func (h *SecurityHandlers) RemovePasskey(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	passkeyID := chi.URLParam(r, "passkeyId")
	if passkeyID == "" {
		writeError(w, r, http.StatusNotFound, CodeFactorNotFound, "通行密钥不存在或已被移除。", nil)
		return
	}
	if !h.consumeReauthGrant(w, r, principal, auth.ReauthActionPasskeyRemove, passkeyID, "security.passkey_removed") {
		return
	}

	if err := h.factors.RemovePasskey(r.Context(), principal.UserID, passkeyID); err != nil {
		h.logSecurityEvent("security.passkey_removed", principal.UserID, "passkey", err)
		h.writeFactorError(w, r, err)
		return
	}

	summary, err := h.factors.FactorSummary(r.Context(), principal.UserID)
	if err != nil {
		h.logSecurityEvent("security.passkey_removed", principal.UserID, "passkey", err)
		h.writeFactorError(w, r, err)
		return
	}
	h.logSecurityEvent("security.passkey_removed", principal.UserID, "passkey", nil)
	writeJSON(w, http.StatusOK, toSecuritySummaryView(summary))
}

// --- Shared seams ---

// consumeReauthGrant consumes the step-up grant carried in
// X-Reauthentication-Token for the given account action (+ optional target
// binding). It fails closed: a missing verifier, an absent token or any
// verification failure denies the operation with the stable reauth error.
func (h *SecurityHandlers) consumeReauthGrant(w http.ResponseWriter, r *http.Request, principal session.Principal, action, target, event string) bool {
	token := r.Header.Get("X-Reauthentication-Token")
	var err error
	if h.reauth == nil || token == "" {
		err = errors.New("reauthentication unavailable")
	} else {
		// Account actions carry empty application/client bindings; the
		// grant's user + session + action + target bindings are verified
		// inside VerifyAndConsume.
		err = h.reauth.VerifyAndConsume(r.Context(), token, action, string(principal.SessionID), target, "", "")
	}
	if err != nil {
		h.logSecurityEvent(event, principal.UserID, "", err)
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	return true
}

// issueEnrollment mints a single-use enrollment token bound to the caller's
// user + session (+ factor kind and optional target) and stores its hash.
// Token generation is fail-closed: a crypto/rand failure aborts the flow.
func (h *SecurityHandlers) issueEnrollment(ctx context.Context, principal session.Principal, kind auth.EnrollmentKind, target string) (string, error) {
	token, err := session.GenerateToken()
	if err != nil {
		return "", err
	}
	data := auth.EnrollmentData{
		UserID:    principal.UserID,
		SessionID: string(principal.SessionID),
		Kind:      kind,
		Target:    target,
	}
	if err := h.enrollments.CreateEnrollment(ctx, session.HashToken(token), data, h.enrollmentTTL); err != nil {
		return "", err
	}
	return token, nil
}

// consumeEnrollment consumes an enrollment token and verifies its binding
// for the expected factor kind. It reports whether the flow may continue.
func (h *SecurityHandlers) consumeEnrollment(w http.ResponseWriter, r *http.Request, principal session.Principal, token string, kind auth.EnrollmentKind) bool {
	_, ok := h.consumeEnrollmentData(w, r, principal, token, kind)
	return ok
}

// consumeEnrollmentData is consumeEnrollment returning the verified record
// (needed when the binding carries a target, e.g. passkey confirmations).
func (h *SecurityHandlers) consumeEnrollmentData(w http.ResponseWriter, r *http.Request, principal session.Principal, token string, kind auth.EnrollmentKind) (auth.EnrollmentData, bool) {
	if token == "" {
		writeError(w, r, http.StatusForbidden, CodeEnrollmentInvalid, "绑定流程已失效，请重新开始。", nil)
		return auth.EnrollmentData{}, false
	}
	data, err := h.enrollments.ConsumeEnrollment(r.Context(), session.HashToken(token))
	if err != nil {
		if errors.Is(err, auth.ErrEnrollmentNotFound) {
			writeError(w, r, http.StatusForbidden, CodeEnrollmentInvalid, "绑定流程已失效，请重新开始。", nil)
			return auth.EnrollmentData{}, false
		}
		h.lg().Error("enrollment consume failed",
			"requestId", request.ID(r.Context()),
			"errorClass", observability.ClassifyError(err),
		)
		WriteInternalError(w, r)
		return auth.EnrollmentData{}, false
	}
	// Binding verification is fail closed: wrong user, wrong session or a
	// kind mismatch denies the confirmation.
	if data.UserID != principal.UserID || data.SessionID != string(principal.SessionID) || data.Kind != kind {
		writeError(w, r, http.StatusForbidden, CodeEnrollmentInvalid, "绑定流程已失效，请重新开始。", nil)
		return auth.EnrollmentData{}, false
	}
	return data, true
}

// writeFactorError maps factor sentinel errors onto the stable HTTP
// contract. Provider detail is never leaked; unexpected errors fall back to
// the generic internal envelope.
func (h *SecurityHandlers) writeFactorError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrFactorAlreadySet):
		writeError(w, r, http.StatusConflict, CodeFactorAlreadySet, "该认证方式已绑定，如需更换请先移除。", nil)
	case errors.Is(err, auth.ErrFactorNotSet):
		writeError(w, r, http.StatusNotFound, CodeFactorNotFound, "认证方式不存在或已被移除。", nil)
	case errors.Is(err, auth.ErrInvalidFactorCode):
		writeError(w, r, http.StatusBadRequest, CodeFactorInvalid, "验证失败，请重试。", nil)
	case errors.Is(err, auth.ErrProviderUnavailable):
		WriteProviderUnavailable(w, r)
	default:
		WriteInternalError(w, r)
	}
}

// logSecurityEvent emits a structured factor security event. Payloads stay
// minimal: user, factor kind and outcome — never secrets, codes or
// attestation material (ADR-0006 §12).
func (h *SecurityHandlers) logSecurityEvent(event string, userID identity.UserID, kind string, err error) {
	logger := h.lg()
	if err != nil {
		logger.Warn(event,
			"userId", string(userID),
			"factorKind", kind,
			"outcome", "failed",
			"errorClass", observability.ClassifyError(err),
		)
		return
	}
	logger.Info(event,
		"userId", string(userID),
		"factorKind", kind,
		"outcome", "success",
	)
}

// lg returns the configured logger or the slog default so nil-wired handlers
// (tests) never panic.
func (h *SecurityHandlers) lg() *slog.Logger {
	if h.logger != nil {
		return h.logger
	}
	return slog.Default()
}
