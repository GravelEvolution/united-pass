//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Password change handler (ADR-0006 §6, amended by ADR-0007)
//

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// CodePasswordChangeFailed is the stable error of a confirmed provider
// rejection (ADR-0006 §6, frozen; ADR-0007 Decision 7): zero local side
// effects, never pretending success, never leaking provider detail.
const CodePasswordChangeFailed = "provider.password_change_failed"

// CodePasswordChangeInProgress is the stable single-winner rejection
// (ADR-0007 Decision 3/7): a concurrent mutation already holds the user's
// durable intent, and this request fails closed before any provider call —
// zero provider calls, zero side effects (closes B4).
const CodePasswordChangeInProgress = "password.change_in_progress"

// CodeSettlementDegraded is the stable settlement-degraded error pinned by
// the implementation (ADR-0007 Decision 7): the epoch advanced but the
// local settlement could not fully complete. The response never reports
// success; rotated credentials are issued when available so the caller is
// not stranded.
const CodeSettlementDegraded = "password.settlement_degraded"

// EventPasswordChanged is the durable security event recorded on every
// provider-committed terminal path (ADR-0007 Decision 5, closes B5). Its
// payload never carries password material.
const EventPasswordChanged = "account.password_changed"

const (
	defaultProviderDeadline  = 10 * time.Second
	defaultSettlementTimeout = 15 * time.Second
)

// MutationAuthority is the narrow seam over the authoritative security-state
// ledger for one password mutation (ADR-0007 Decision 3). PostgreSQL is the
// single authority for acquisition, outcome recording, epoch advancement and
// settlement — Redis may mirror hot-path state at most and never decides.
type MutationAuthority interface {
	// Acquire establishes the durable per-user intent before any provider
	// call (single-winner gate). ErrIntentHeld when a non-terminal intent
	// already exists.
	Acquire(ctx context.Context, userID identity.UserID) (securitystate.Intent, error)
	// SettleConfirmedFailure settles the active intent with the epoch
	// unchanged after a confirmed provider rejection.
	SettleConfirmedFailure(ctx context.Context, userID identity.UserID, intentID int64) error
	// RecordOutcome records the provider outcome and advances the epoch by
	// exactly one in the same CAS-fenced transaction, returning the new
	// epoch.
	RecordOutcome(ctx context.Context, userID identity.UserID, intentID int64, outcome securitystate.ProviderOutcome) (securitystate.Epoch, error)
	// SettleIntent drives rotation and generation-scoped cleanup into the
	// terminal settled state.
	SettleIntent(ctx context.Context, intent securitystate.Intent, newEpoch securitystate.Epoch, rotate securitystate.RotateFunc) (securitystate.SettlementResult, error)
}

// PasswordHandlers serves POST /api/v1/me/security/password (ADR-0006 §6,
// amended by ADR-0007). The provider is the password authority: United Pass
// never stores, hashes or mirrors passwords. Identity proof is the consumed
// account.password.change reauth grant — the mutation never re-accepts a
// current password.
type PasswordHandlers struct {
	passwords         auth.PasswordManager
	reauth            ReauthVerifier
	sessions          *session.Service
	security          MutationAuthority
	auditor           session.SecurityAuditor
	cookieAttrs       SessionCookieAttributes
	providerDeadline  time.Duration
	settlementTimeout time.Duration
	logger            *slog.Logger
}

// NewPasswordHandlers builds the password change handler. cookieAttrs follow
// the session cookie configuration; auditor may be nil (log-only audit);
// security is the authoritative PostgreSQL mutation ledger (ADR-0007
// Decision 3 — never a Redis-only authority). providerDeadline bounds the
// provider call; settlementTimeout bounds the detached settlement run. Zero
// durations fall back to the frozen-safe defaults.
func NewPasswordHandlers(
	passwords auth.PasswordManager,
	reauth ReauthVerifier,
	sessions *session.Service,
	security MutationAuthority,
	auditor session.SecurityAuditor,
	providerDeadline time.Duration,
	settlementTimeout time.Duration,
	cfg config.Config,
	logger *slog.Logger,
) *PasswordHandlers {
	if providerDeadline <= 0 {
		providerDeadline = defaultProviderDeadline
	}
	if settlementTimeout <= 0 {
		settlementTimeout = defaultSettlementTimeout
	}
	return &PasswordHandlers{
		passwords:         passwords,
		reauth:            reauth,
		sessions:          sessions,
		security:          security,
		auditor:           auditor,
		cookieAttrs:       CookieAttributesFromConfig(cfg.Session),
		providerDeadline:  providerDeadline,
		settlementTimeout: settlementTimeout,
		logger:            logger,
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
// Reworked flow (ADR-0006 §6 amended by ADR-0007):
//  1. RequireSession + RequireCSRF (middleware-enforced, shared
//     security-state validator);
//  2. consume the account.password.change reauth grant — the sole proof of
//     identity (its epoch binding and the sensitive-consumption barrier are
//     verified inside the grant verifier);
//  3. acquire the durable single-winner mutation intent from the PostgreSQL
//     ledger BEFORE any provider call (Decision 3, closes B4): a concurrent
//     mutation fails closed here with the stable
//     password.change_in_progress — zero provider calls, zero side effects;
//  4. provider SetPassword (newPassword-only mode) under a bounded deadline;
//     a confirmed rejection settles the intent with the epoch unchanged —
//     zero local side effects (frozen §6 semantics, Decision 2 row 1);
//  5. success or unknown outcome: outcome_recorded + epoch++ is the FIRST
//     local effect, in one CAS-fenced transaction under a detached, bounded
//     context (the ordering invariant; a client disconnect can never cancel
//     the settlement after the provider may have committed);
//  6. settlement: rotate + re-stamp the current session, then the
//     generation-scoped cleanup RevokeSessionsBeforeEpoch — never the
//     generation-unaware bulk revoke (F4) — then the terminal settle;
//  7. durable account.password_changed audit with providerOutcome and
//     settlementOutcome on every provider-committed terminal path
//     (Decision 5, closes B5);
//  8. HTTP outcome per the Decision 7 table.
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

	// Single-winner fencing before the provider call (ADR-0007 Decision 3,
	// closes B4): the durable PostgreSQL intent ledger is the only
	// authority. The executing request completed its session/reauth
	// validation before acquiring the intent and never re-enters the
	// promotion middleware, so it is not caught by its own barrier.
	intent, err := h.security.Acquire(r.Context(), principal.UserID)
	if err != nil {
		h.logSecurityEvent(principal, err)
		if errors.Is(err, securitystate.ErrIntentHeld) {
			writeError(w, r, http.StatusConflict, CodePasswordChangeInProgress, "已有密码修改正在进行，请稍后重试。", nil)
			return
		}
		// Authoritative-store failure before the provider call: fail closed
		// with zero side effects.
		WriteInternalError(w, r)
		return
	}

	// Provider call under the bounded provider deadline. The plaintext is
	// wrapped in the redacted SecretPassword type and never reaches logs,
	// audit, Redis or PostgreSQL.
	callCtx, callCancel := context.WithTimeout(r.Context(), h.providerDeadline)
	providerErr := h.passwords.SetPassword(callCtx, principal.UserID, auth.NewSecretPassword(req.NewPassword))
	callCancel()

	switch {
	case providerErr == nil:
		h.settleCommitted(w, r, principal, intent, securitystate.ProviderOutcomeSuccess)
	case errors.Is(providerErr, auth.ErrPasswordChangeUnknown):
		h.settleCommitted(w, r, principal, intent, securitystate.ProviderOutcomeUnknown)
	default:
		// Confirmed provider rejection (Decision 2 row 1): settle the
		// intent with the epoch unchanged — zero local side effects, the
		// old generation resumes validity (frozen §6 semantics). No durable
		// event is written (frozen behavior preserved, Decision 5).
		h.releaseConfirmedFailure(r, principal, intent)
		h.logSecurityEvent(principal, providerErr)
		writeError(w, r, http.StatusBadGateway, CodePasswordChangeFailed, "密码修改失败，请稍后重试。", nil)
	}
}

// releaseConfirmedFailure settles the active intent as confirmed_failure
// under a detached, bounded context so a client disconnect still releases
// the fence. A failure here is logged: takeover reconciles the abandoned
// intent after lease expiry, and the response semantics never depend on it.
func (h *PasswordHandlers) releaseConfirmedFailure(r *http.Request, principal session.Principal, intent securitystate.Intent) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), h.settlementTimeout)
	defer cancel()
	if err := h.security.SettleConfirmedFailure(ctx, principal.UserID, intent.IntentID); err != nil {
		h.lg().Error("confirmed-failure intent settlement failed; takeover will reconcile after lease expiry",
			"requestId", request.ID(r.Context()),
			"userId", string(principal.UserID),
			"intentId", intent.IntentID,
			"errorClass", observability.ClassifyError(err),
		)
	}
}

// settleCommitted runs the post-provider settlement for a committed outcome
// (success or unknown, Decision 2 rows 2–5): outcome_recorded + epoch
// advancement is the FIRST local effect, then rotation, generation-scoped
// cleanup and the terminal settle, then the mandatory durable audit attempt,
// then the Decision 7 HTTP outcome. Everything authoritative runs under a
// detached, bounded context — never the HTTP request context.
func (h *PasswordHandlers) settleCommitted(w http.ResponseWriter, r *http.Request, principal session.Principal, intent securitystate.Intent, providerOutcome securitystate.ProviderOutcome) {
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), h.settlementTimeout)
	defer cancel()

	// Ordering invariant: record the outcome and advance the epoch by
	// exactly one in the same CAS-fenced transaction (Decision 3).
	newEpoch, err := h.security.RecordOutcome(settleCtx, principal.UserID, intent.IntentID, providerOutcome)
	if err != nil {
		// The epoch boundary could not be established by this request.
		h.lg().Error("outcome record + epoch advancement failed after a committed provider call",
			"requestId", request.ID(r.Context()),
			"userId", string(principal.UserID),
			"intentId", intent.IntentID,
			"providerOutcome", string(providerOutcome),
			"errorClass", observability.ClassifyError(err),
		)
		h.recordPasswordChangedAudit(r, principal, providerOutcome, securitystate.SettlementOutcomeDegraded, intent, 0)
		if errors.Is(err, securitystate.ErrFenceLost) {
			// A takeover already recorded the outcome and advanced the
			// epoch exactly once: the old generation is dead. Force
			// re-login.
			ClearSessionCookie(w, h.cookieAttrs)
			ClearCSRFCookie(w, h.cookieAttrs)
			WriteUnauthorized(w, r)
			return
		}
		// Authoritative-store failure: the intent stays active and takeover
		// reconciles after lease expiry. Never report success.
		writeError(w, r, http.StatusInternalServerError, CodeSettlementDegraded, "密码修改未完成，请重新登录。", nil)
		return
	}

	intent.Status = securitystate.IntentOutcomeRecorded
	intent.ProviderOutcome = providerOutcome

	// Rotation re-stamps the current session onto the new epoch; only a
	// confirmed success keeps it. Unknown always forces re-login, so no
	// rotated credential is ever minted for it (Decision 2 row 5).
	var rotate securitystate.RotateFunc
	var rotated *session.RotateSessionResult
	if providerOutcome == securitystate.ProviderOutcomeSuccess {
		rotate = func(ctx context.Context) (vanished bool, rotateErr error) {
			result, err := h.sessions.RotateSession(ctx, ReadSessionCookie(r), newEpoch)
			if err != nil {
				if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) {
					// A concurrent logout/revocation or the expiry sweep
					// won the race: the session vanished.
					return true, nil
				}
				return false, err
			}
			rotated = &result
			return false, nil
		}
	}

	// Settlement: rotation + generation-scoped cleanup (F4 — only sessions
	// stamped before the new epoch are ever touched; the generation-unaware
	// bulk revoke is never used here) + terminal settle.
	result, settleErr := h.security.SettleIntent(settleCtx, intent, newEpoch, rotate)
	if settleErr != nil && result.Outcome == securitystate.SettlementOutcomeNone {
		result.Outcome = securitystate.SettlementOutcomeDegraded
	}

	// Mandatory durable audit attempt on every provider-committed terminal
	// path (Decision 5, closes B5): the two orthogonal facts stay separate
	// additive fields. A password change may never vanish from durable
	// history.
	h.recordPasswordChangedAudit(r, principal, providerOutcome, result.Outcome, intent, newEpoch)
	h.logSettlement(principal, providerOutcome, result, newEpoch, settleErr)

	// HTTP outcomes per the Decision 7 table.
	switch {
	case providerOutcome == securitystate.ProviderOutcomeUnknown:
		// Unknown never reports success and always forces re-login: every
		// old-generation artifact is invalid regardless of Redis state.
		ClearSessionCookie(w, h.cookieAttrs)
		ClearCSRFCookie(w, h.cookieAttrs)
		WriteUnauthorized(w, r)
	case result.Outcome == securitystate.SettlementOutcomeSettled && rotated != nil:
		SetSessionCookie(w, rotated.SessionToken, sessionCookieMaxAge(rotated.RemainingTTL), h.cookieAttrs)
		SetCSRFCookie(w, rotated.CSRFToken, sessionCookieMaxAge(rotated.RemainingTTL), h.cookieAttrs)
		w.WriteHeader(http.StatusNoContent)
	case result.Outcome == securitystate.SettlementOutcomeSettledRelogin:
		// The epoch advanced but the current session vanished: every
		// pre-change session and capability is invalid; re-login required.
		ClearSessionCookie(w, h.cookieAttrs)
		ClearCSRFCookie(w, h.cookieAttrs)
		WriteUnauthorized(w, r)
	default:
		// Degraded settlement (cleanup/rotation/transition failure): the
		// epoch boundary still holds; the response never reports success.
		// Rotated credentials are issued when available so the caller is
		// not stranded with a token no cookie carries.
		if rotated != nil {
			SetSessionCookie(w, rotated.SessionToken, sessionCookieMaxAge(rotated.RemainingTTL), h.cookieAttrs)
			SetCSRFCookie(w, rotated.CSRFToken, sessionCookieMaxAge(rotated.RemainingTTL), h.cookieAttrs)
		}
		writeError(w, r, http.StatusInternalServerError, CodeSettlementDegraded, "密码修改未完成，请重新登录。", nil)
	}
}

// consumeReauthGrant consumes the step-up grant carried in
// X-Reauthentication-Token for account.password.change. It mirrors the
// frozen SecurityHandlers semantics: a missing verifier, an absent token or
// any verification failure denies the operation with the stable reauth
// error. Account actions carry empty application/client and target
// bindings; the user + session + action bindings, the stamped-epoch binding
// and the sensitive-consumption barrier are verified inside
// VerifyAndConsume (ADR-0007 Decision 5 two-phase barrier).
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
// row with the Decision 5 additive fields: providerOutcome and
// settlementOutcome as separate facts, plus the intentId / fromEpoch /
// toEpoch forensic context. Best-effort at the call site (mirrors the
// frozen session revocation audit): a recorder failure is logged as an
// operational/security defect — making the audit gap visible — but never
// masks the outcome.
func (h *PasswordHandlers) recordPasswordChangedAudit(
	r *http.Request,
	principal session.Principal,
	providerOutcome securitystate.ProviderOutcome,
	settlementOutcome securitystate.SettlementOutcome,
	intent securitystate.Intent,
	toEpoch securitystate.Epoch,
) {
	if h.auditor == nil {
		return
	}
	err := h.auditor.RecordSessionEvent(r.Context(), session.SecurityAuditEvent{
		EventType:         EventPasswordChanged,
		ActorUserID:       principal.UserID,
		SessionID:         principal.SessionID,
		RequestID:         request.ID(r.Context()),
		Operation:         auth.ReauthActionPasswordChange,
		Result:            session.AuditOutcomeSuccess,
		OccurredAt:        time.Now(),
		ProviderOutcome:   string(providerOutcome),
		SettlementOutcome: string(settlementOutcome),
		IntentID:          intent.IntentID,
		FromEpoch:         int64(intent.EpochAtAcquire),
		ToEpoch:           int64(toEpoch),
	})
	if err != nil {
		h.lg().Warn("password change audit record failed",
			"event", EventPasswordChanged,
			"userId", string(principal.UserID),
			"sessionId", string(principal.SessionID),
			"intentId", intent.IntentID,
			"providerOutcome", string(providerOutcome),
			"settlementOutcome", string(settlementOutcome),
			"errorClass", observability.ClassifyError(err),
		)
	}
}

// logSettlement emits the structured settlement event. Payloads stay
// minimal: user, session, intent and outcome classification — the password
// itself never enters a log line (ADR-0006 §6/§12).
func (h *PasswordHandlers) logSettlement(principal session.Principal, providerOutcome securitystate.ProviderOutcome, result securitystate.SettlementResult, newEpoch securitystate.Epoch, err error) {
	logger := h.lg()
	if err != nil {
		logger.Warn(EventPasswordChanged,
			"userId", string(principal.UserID),
			"sessionId", string(principal.SessionID),
			"providerOutcome", string(providerOutcome),
			"settlementOutcome", string(result.Outcome),
			"newEpoch", int64(newEpoch),
			"outcome", "degraded",
			"errorClass", observability.ClassifyError(err),
		)
		return
	}
	logger.Info(EventPasswordChanged,
		"userId", string(principal.UserID),
		"sessionId", string(principal.SessionID),
		"providerOutcome", string(providerOutcome),
		"settlementOutcome", string(result.Outcome),
		"newEpoch", int64(newEpoch),
		"outcome", "success",
	)
}

// logSecurityEvent emits the structured password security event for
// pre-settlement failures. Payloads stay minimal: user, session and outcome
// — the password itself never enters a log line (ADR-0006 §6/§12).
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
