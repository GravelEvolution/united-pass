//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Password change handler (ADR-0006 §6)
//

package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// CodePasswordChangeFailed is the single stable error of the password change
// path (ADR-0006 §6): every provider-side failure surfaces as this code,
// fail closed, never pretending success and never leaking provider detail.
const CodePasswordChangeFailed = "provider.password_change_failed"

// EventPasswordChanged is the durable security event recorded after a fully
// successful password change. Its payload never carries password material.
const EventPasswordChanged = "account.password_changed"

// PasswordHandlers serves POST /api/v1/me/security/password (ADR-0006 §6).
// The provider is the password authority: United Pass never stores, hashes
// or mirrors passwords. Identity proof is the consumed
// account.password.change reauth grant — the mutation never re-accepts a
// current password.
type PasswordHandlers struct {
	passwords   auth.PasswordManager
	reauth      ReauthVerifier
	sessions    *session.Service
	auditor     session.SecurityAuditor
	cookieAttrs SessionCookieAttributes
	logger      *slog.Logger
}

// NewPasswordHandlers builds the password change handler. cookieAttrs follow
// the session cookie configuration; auditor may be nil (log-only audit).
func NewPasswordHandlers(
	passwords auth.PasswordManager,
	reauth ReauthVerifier,
	sessions *session.Service,
	auditor session.SecurityAuditor,
	cfg config.Config,
	logger *slog.Logger,
) *PasswordHandlers {
	return &PasswordHandlers{
		passwords:   passwords,
		reauth:      reauth,
		sessions:    sessions,
		auditor:     auditor,
		cookieAttrs: CookieAttributesFromConfig(cfg.Session),
		logger:      logger,
	}
}

// changePasswordRequest is the frozen wire shape of
// POST /api/v1/me/security/password (ADR-0006 §6): {newPassword} only — the
// reauth ceremony already proved the current password, so the mutation never
// re-accepts one and no currentPassword field exists.
type changePasswordRequest struct {
	NewPassword string `json:"newPassword"`
}

// ChangePassword handles POST /api/v1/me/security/password.
//
// Frozen flow (ADR-0006 §6):
//  1. RequireSession + RequireCSRF (middleware-enforced);
//  2. consume the account.password.change reauth grant — the sole proof of
//     identity; the body carries newPassword only;
//  3. provider SetPassword (newPassword-only mode). A provider failure means
//     ZERO local side effects: the stable provider.password_change_failed
//     error is returned and nothing else runs;
//  4. rotate the current session: new session token + new CSRF token,
//     cookies re-issued, SessionID stable, the old token dead;
//  5. revoke all other sessions of the user (best-effort provider
//     revocation inside the session service);
//  6. durable account.password_changed audit — no password material in the
//     payload.
func (h *PasswordHandlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	var req changePasswordRequest
	if err := decodeJSONBody(w, r, &req, "password change"); err != nil {
		return
	}
	if req.NewPassword == "" {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "新密码不能为空。", nil)
		return
	}

	// Reauthentication is the sole identity proof: consume the
	// account.password.change grant bound to this user + session. The
	// mutation never re-accepts a current password (ADR-0006 §6 step 2).
	if !h.consumeReauthGrant(w, r, principal) {
		return
	}

	// Provider call first, fail closed: a provider failure means zero local
	// side effects — no rotation, no revocation, no audit, no cookie change.
	// The plaintext is wrapped in the redacted SecretPassword type and never
	// reaches logs, audit, Redis or PostgreSQL.
	if err := h.passwords.SetPassword(r.Context(), principal.UserID, auth.NewSecretPassword(req.NewPassword)); err != nil {
		h.logSecurityEvent(principal, err)
		writeError(w, r, http.StatusBadGateway, CodePasswordChangeFailed, "密码修改失败，请稍后重试。", nil)
		return
	}

	// Rotate the current session: SessionID stable, new session token + new
	// CSRF token, the old token dead. The sealed provider credential
	// survives: the ZITADEL SetPassword response carries no session handle,
	// so the frozen re-seal clause takes its "otherwise" branch (ADR-0006 §6
	// step 4).
	rotated, err := h.sessions.RotateSession(r.Context(), ReadSessionCookie(r))
	if err != nil {
		// The password was changed but this session could not be rotated.
		// Fail closed: the old token must never stay usable after a
		// password change. A vanished or expired session means a concurrent
		// logout/revocation or the expiry sweep won the race — the caller
		// must log in again with the new password. An infrastructure
		// failure additionally forces the current session down so no old
		// token survives a half-completed rotation.
		if !errors.Is(err, session.ErrSessionNotFound) && !errors.Is(err, session.ErrSessionExpired) {
			_ = h.sessions.DeleteSession(r.Context(), ReadSessionCookie(r))
		}
		h.lg().Error("session rotation after password change failed",
			"requestId", request.ID(r.Context()),
			"userId", string(principal.UserID),
			"sessionId", string(principal.SessionID),
			"errorClass", observability.ClassifyError(err),
		)
		h.logSecurityEvent(principal, err)
		ClearSessionCookie(w, h.cookieAttrs)
		ClearCSRFCookie(w, h.cookieAttrs)
		WriteUnauthorized(w, r)
		return
	}

	// Revoke every other session of the user (ADR-0006 §6 step 4 + §2
	// rule 3; best-effort provider revocation runs inside the session
	// service). The current session is never touched here.
	if _, err := h.sessions.RevokeAllOtherSessions(r.Context(), principal.UserID, principal.SessionID); err != nil {
		// The password change and the rotation already succeeded: re-issue
		// the rotated cookies anyway so the caller is not stranded with a
		// token no cookie carries, then fail the response closed — the
		// bulk revocation could not be completed (never pretend success).
		SetSessionCookie(w, rotated.SessionToken, sessionCookieMaxAge(rotated.RemainingTTL), h.cookieAttrs)
		SetCSRFCookie(w, rotated.CSRFToken, sessionCookieMaxAge(rotated.RemainingTTL), h.cookieAttrs)
		h.logSecurityEvent(principal, err)
		WriteInternalError(w, r)
		return
	}

	// Durable audit on the fully successful path only; the payload never
	// carries password material (ADR-0006 §6 step 5).
	h.recordPasswordChangedAudit(r, principal)

	h.logSecurityEvent(principal, nil)
	SetSessionCookie(w, rotated.SessionToken, sessionCookieMaxAge(rotated.RemainingTTL), h.cookieAttrs)
	SetCSRFCookie(w, rotated.CSRFToken, sessionCookieMaxAge(rotated.RemainingTTL), h.cookieAttrs)
	w.WriteHeader(http.StatusNoContent)
}

// consumeReauthGrant consumes the step-up grant carried in
// X-Reauthentication-Token for account.password.change. It mirrors the
// frozen SecurityHandlers semantics: a missing verifier, an absent token or
// any verification failure denies the operation with the stable reauth
// error. Account actions carry empty application/client and target
// bindings; the user + session + action bindings are verified inside
// VerifyAndConsume.
func (h *PasswordHandlers) consumeReauthGrant(w http.ResponseWriter, r *http.Request, principal session.Principal) bool {
	token := r.Header.Get("X-Reauthentication-Token")
	var err error
	if h.reauth == nil || token == "" {
		err = errors.New("reauthentication unavailable")
	} else {
		err = h.reauth.VerifyAndConsume(r.Context(), token, auth.ReauthActionPasswordChange, string(principal.SessionID), "", "", "")
	}
	if err != nil {
		h.logSecurityEvent(principal, err)
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	return true
}

// recordPasswordChangedAudit persists the durable account.password_changed
// row. Best-effort at the call site (mirrors the frozen session revocation
// audit): the password change already succeeded, so a recorder failure is
// logged as an operational/security defect — making the audit gap visible —
// but never masks the outcome.
func (h *PasswordHandlers) recordPasswordChangedAudit(r *http.Request, principal session.Principal) {
	if h.auditor == nil {
		return
	}
	err := h.auditor.RecordSessionEvent(r.Context(), session.SecurityAuditEvent{
		EventType:   EventPasswordChanged,
		ActorUserID: principal.UserID,
		SessionID:   principal.SessionID,
		RequestID:   request.ID(r.Context()),
		Operation:   auth.ReauthActionPasswordChange,
		Result:      session.AuditOutcomeSuccess,
		OccurredAt:  time.Now(),
	})
	if err != nil {
		h.lg().Warn("password change audit record failed",
			"event", EventPasswordChanged,
			"userId", string(principal.UserID),
			"sessionId", string(principal.SessionID),
			"errorClass", observability.ClassifyError(err),
		)
	}
}

// logSecurityEvent emits the structured password security event. Payloads
// stay minimal: user, session and outcome — the password itself never
// enters a log line (ADR-0006 §6/§12).
func (h *PasswordHandlers) logSecurityEvent(principal session.Principal, err error) {
	logger := h.lg()
	if err != nil {
		logger.Warn(EventPasswordChanged,
			"userId", string(principal.UserID),
			"sessionId", string(principal.SessionID),
			"outcome", "failed",
			"errorClass", observability.ClassifyError(err),
		)
		return
	}
	logger.Info(EventPasswordChanged,
		"userId", string(principal.UserID),
		"sessionId", string(principal.SessionID),
		"outcome", "success",
	)
}

// lg returns the configured logger or the slog default so nil-wired handlers
// (tests) never panic.
func (h *PasswordHandlers) lg() *slog.Logger {
	if h.logger != nil {
		return h.logger
	}
	return slog.Default()
}
