//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: HTTP handlers for the sensitive-action re-authentication flow
//

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// Reauthentication for high-risk operations (ADR-0004 §7). The flow mirrors
// login MFA: an opaque random challenge token is bound to user + session +
// action + target resource, verified against the provider with an atomic
// claim/consume pattern, and completed into a strictly single-use grant that
// the target operation consumes atomically. Raw tokens never reach Redis —
// only their SHA-256 hashes are used as keys. Redis loss only invalidates
// challenges and grants (fail closed).

// ReauthAuthenticator verifies the current session user against the
// authentication provider, keyed by the stable United Pass user ID — never
// by a browser-supplied identifier, so a challenge can never authenticate a
// different account than the session's own. RevokeProviderSession terminates
// the temporary provider session a reauthentication created, at every
// terminal state (ADR-0004 §7).
type ReauthAuthenticator interface {
	VerifyUserPassword(ctx context.Context, userID identity.UserID, password string) (auth.AuthenticationResult, error)
	CompleteMFA(ctx context.Context, input auth.MFAChallengeInput) (auth.AuthenticationResult, error)
	RevokeProviderSession(ctx context.Context, sessionReference string) error
}

// ReauthChallengeStore abstracts reauthentication challenge persistence. The
// Redis adapter satisfies this interface; tests can use an in-memory fake.
// Semantics mirror MFAChallengeStore: atomic single-winner claim, fail-closed
// consume, challenge TTL never extended.
type ReauthChallengeStore interface {
	CreateChallenge(ctx context.Context, tokenHash string, data auth.ReauthChallengeData, ttl time.Duration) error
	ClaimChallenge(ctx context.Context, tokenHash, claimID string) (auth.ReauthChallengeData, error)
	ReleaseChallenge(ctx context.Context, tokenHash, claimID string) error
	ConsumeChallenge(ctx context.Context, tokenHash, claimID string) error
	IncrementChallengeAttempts(ctx context.Context, tokenHash string, maxAttempts int) (int, error)
	// PopExpiredChallenges atomically pops up to limit cleanup entries for
	// challenges whose record no longer exists (expired or abandoned), so the
	// cleanup worker can revoke their temporary provider sessions.
	PopExpiredChallenges(ctx context.Context, limit int) ([]auth.ExpiredReauthChallenge, error)
}

// ReauthGrantStore abstracts single-use grant persistence. The Redis adapter
// satisfies this interface; tests can use an in-memory fake.
type ReauthGrantStore interface {
	CreateGrant(ctx context.Context, tokenHash string, data auth.ReauthGrantData, ttl time.Duration) error
	// ConsumeGrant atomically reads and deletes the grant; exactly one
	// concurrent consumer ever receives it.
	ConsumeGrant(ctx context.Context, tokenHash string) (auth.ReauthGrantData, error)
}

// ReauthRateChecker abstracts the reauthentication rate limiter. The Redis
// rate limiter satisfies this interface; a nil checker fails closed.
type ReauthRateChecker interface {
	CheckReauth(ctx context.Context, ip, keyHash string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
}

// ReauthEventRecorder records reauthentication audit rows. The applications
// Service satisfies this interface; audit payloads never contain secrets.
type ReauthEventRecorder interface {
	RecordEvent(ctx context.Context, eventType string, actor identity.UserID, appID applications.ApplicationID, clientID applications.OAuthClientID, requestID, operation string, result applications.SecurityEventResult, failureClass string)
}

// SensitiveConsumptionGate validates the consumption of a sensitive
// capability (reauth grant, enrollment token) against the user's
// authoritative security state (ADR-0007 Decision 5): a stamp behind the
// current epoch or any non-terminal mutation intent denies the consumption
// until settled. Satisfied by the security-state service; the interface
// lives here (close to the consumer) per AGENTS.md §8.
type SensitiveConsumptionGate interface {
	AllowSensitiveConsumption(ctx context.Context, userID identity.UserID, stampedEpoch securitystate.Epoch) error
}

// ReauthHandlers serves POST /api/v1/auth/reauthentication and
// POST /api/v1/auth/reauthentication/mfa. Both routes require a valid
// session and CSRF token (middleware-enforced).
type ReauthHandlers struct {
	authenticator ReauthAuthenticator
	challenges    ReauthChallengeStore
	grants        ReauthGrantStore
	rateChecker   ReauthRateChecker
	auditor       ReauthEventRecorder
	challengeTTL  time.Duration
	grantTTL      time.Duration
	maxAttempts   int
	rateLimit     int
	rateWindow    time.Duration
	revokeTimeout time.Duration
	auditTimeout  time.Duration
	logger        *slog.Logger
}

// NewReauthHandlers builds the reauthentication handlers from configuration.
func NewReauthHandlers(
	authenticator ReauthAuthenticator,
	challenges ReauthChallengeStore,
	grants ReauthGrantStore,
	rateChecker ReauthRateChecker,
	auditor ReauthEventRecorder,
	challengeTTL, grantTTL time.Duration,
	maxAttempts, rateLimit int,
	rateWindow time.Duration,
	logger *slog.Logger,
) *ReauthHandlers {
	return &ReauthHandlers{
		authenticator: authenticator,
		challenges:    challenges,
		grants:        grants,
		rateChecker:   rateChecker,
		auditor:       auditor,
		challengeTTL:  challengeTTL,
		grantTTL:      grantTTL,
		maxAttempts:   maxAttempts,
		rateLimit:     rateLimit,
		rateWindow:    rateWindow,
		revokeTimeout: reauthRevokeTimeout,
		auditTimeout:  reauthAuditTimeout,
		logger:        logger,
	}
}

// reauthRequest is the JSON body for POST /api/v1/auth/reauthentication.
type reauthRequest struct {
	Action        string `json:"action"`
	ApplicationID string `json:"applicationId"`
	ClientID      string `json:"clientId"`
	// Target is the generic action-specific binding (ADR-0006 §4): required
	// for account.passkey.remove (the passkeyId), forbidden everywhere else.
	Target   string `json:"target"`
	Password string `json:"password"`
}

// reauthMfaRequest is the JSON body for POST /api/v1/auth/reauthentication/mfa.
type reauthMfaRequest struct {
	ReauthToken      string          `json:"reauthToken"`
	Method           string          `json:"method"`
	Code             string          `json:"code"`
	PasskeyAssertion json.RawMessage `json:"passkeyAssertion"`
}

// reauthGrantResponse is the 200 body: a single-use grant token.
type reauthGrantResponse struct {
	Status      string    `json:"status"`
	ReauthToken string    `json:"reauthToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// reauthChallengeResponse is the 202 body: an opaque challenge token.
type reauthChallengeResponse struct {
	Status                string          `json:"status"`
	ReauthToken           string          `json:"reauthToken"`
	AvailableMethods      []string        `json:"availableMethods"`
	PasskeyRequestOptions json.RawMessage `json:"passkeyRequestOptions,omitempty"`
	ExpiresAt             time.Time       `json:"expiresAt"`
}

// isValidReauthAction reports whether the declared action is recognized.
// account.sessions.revoke_others is intentionally absent: it is reserved but
// never accepted, so no grant can ever be minted for it (ADR-0006 §4).
func isValidReauthAction(action string) bool {
	switch action {
	case auth.ReauthActionApplicationDelete,
		auth.ReauthActionClientDelete,
		auth.ReauthActionClientSecretRotate,
		auth.ReauthActionPasswordChange,
		auth.ReauthActionTOTPEnroll,
		auth.ReauthActionTOTPRemove,
		auth.ReauthActionPasskeyEnroll,
		auth.ReauthActionPasskeyRemove,
		auth.ReauthActionUserDisable,
		auth.ReauthActionUserSessionsRevoke,
		auth.ReauthActionEmployeeOffboard,
		auth.ReauthActionProviderEnable,
		auth.ReauthActionProviderDisable,
		auth.ReauthActionProviderIdentityLink,
		auth.ReauthActionPolicyPublish,
		auth.ReauthActionAuditExport,
		auth.ReauthActionPersonalDataExport,
		auth.ReauthActionAccountDelete:
		return true
	default:
		return false
	}
}

// reauthNeedsClient reports whether the action binds the grant to a client.
func reauthNeedsClient(action string) bool {
	return action == auth.ReauthActionClientDelete || action == auth.ReauthActionClientSecretRotate
}

func isValidReauthTarget(raw string) bool {
	if raw == "" || len(raw) > 128 {
		return false
	}
	for _, value := range raw {
		if !(value >= 'a' && value <= 'z') && !(value >= 'A' && value <= 'Z') &&
			!(value >= '0' && value <= '9') && value != '_' && value != '-' {
			return false
		}
	}
	return true
}

// Request handles POST /api/v1/auth/reauthentication. It verifies the
// current session user's password for the declared high-risk action and
// either issues the single-use grant immediately (200) or a challenge (202)
// when a second factor must complete the verification.
func (h *ReauthHandlers) Request(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	var req reauthRequest
	if err := decodeJSONBody(w, r, &req, "reauthentication"); err != nil {
		return
	}
	if !isValidReauthAction(req.Action) {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "不支持的重新认证操作。", nil)
		return
	}
	if req.Password == "" {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "密码不能为空。", nil)
		return
	}
	if auth.IsAccountReauthAction(req.Action) {
		// Account actions bind user + session + action only: application and
		// client bindings are forbidden (a fake applicationId must never be
		// accepted), and Target carries the passkeyId exclusively for
		// account.passkey.remove (ADR-0006 §4).
		if req.ApplicationID != "" || req.ClientID != "" {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "账户安全操作不支持应用或客户端绑定。", nil)
			return
		}
		if req.Action == auth.ReauthActionPasskeyRemove {
			if req.Target == "" {
				writeError(w, r, http.StatusBadRequest, CodeBadRequest, "删除通行密钥需要指定目标。", nil)
				return
			}
		} else if req.Target != "" {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "该操作不支持目标绑定。", nil)
			return
		}
	} else if auth.IsTargetReauthAction(req.Action) {
		if req.ApplicationID != "" || req.ClientID != "" || !isValidReauthTarget(req.Target) {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "该管理操作需要且仅支持精确目标绑定。", nil)
			return
		}
		if (req.Action == auth.ReauthActionPersonalDataExport || req.Action == auth.ReauthActionAccountDelete) &&
			req.Target != string(principal.UserID) {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "隐私权利操作只能绑定当前账户。", nil)
			return
		}
	} else {
		if req.ApplicationID == "" || !applications.HasApplicationIDPrefix(req.ApplicationID) {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "目标应用不能为空或格式不正确。", nil)
			return
		}
		if reauthNeedsClient(req.Action) && (req.ClientID == "" || !applications.HasOAuthClientIDPrefix(req.ClientID)) {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "目标客户端不能为空或格式不正确。", nil)
			return
		}
		if req.Target != "" {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "该操作不支持目标绑定。", nil)
			return
		}
	}

	// Rate limit keyed on IP + hashed session user. Fail closed.
	if !h.checkRateLimit(w, r, hashIdentifier(string(principal.UserID))) {
		return
	}

	appID := applications.ApplicationID(req.ApplicationID)
	clientID := applications.OAuthClientID(req.ClientID)
	h.auditor.RecordEvent(r.Context(), applications.EventReauthenticationRequested, principal.UserID,
		appID, clientID, request.ID(r.Context()), req.Action, applications.SecurityEventSuccess, "")

	result, err := h.authenticator.VerifyUserPassword(r.Context(), principal.UserID, req.Password)
	if err != nil {
		h.logger.Error("reauthentication provider error",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}

	switch result.Status {
	case auth.StatusAuthenticated:
		// The temporary provider session has served its purpose: revoke it
		// at this terminal state regardless of whether the grant issuance
		// below succeeds (fail closed either way).
		h.revokeProviderSession(r, result.ProviderSessionReference, principal.UserID, appID, clientID, req.Action)
		h.issueGrant(w, r, principal, req.Action, req.ApplicationID, req.ClientID, req.Target)

	case auth.StatusMFARequired:
		h.createChallenge(w, r, principal, req, result)

	case auth.StatusProviderUnavailable:
		WriteProviderUnavailable(w, r)

	case auth.StatusInvalidCredentials, auth.StatusLocked, auth.StatusExpired:
		h.recordReauthFailure(r, principal.UserID, appID, clientID, req.Action, "invalid_credentials")
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "密码不正确或账户当前不可用。", nil)

	default:
		h.recordReauthFailure(r, principal.UserID, appID, clientID, req.Action, "internal")
		WriteInternalError(w, r)
	}
}

// CompleteMFA handles POST /api/v1/auth/reauthentication/mfa using the same
// atomic claim/consume pattern as login MFA. The challenge binding (user,
// session) is re-checked fail closed before any provider call; on success a
// single-use grant bound to the challenge's action and resource is issued.
func (h *ReauthHandlers) CompleteMFA(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	var req reauthMfaRequest
	if err := decodeJSONBody(w, r, &req, "reauthentication MFA"); err != nil {
		return
	}
	if req.ReauthToken == "" || req.Method == "" {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "重新认证令牌和验证方式不能为空。", nil)
		return
	}
	method := auth.MFAMethod(req.Method)
	switch method {
	case auth.MFAMethodTOTP:
		if req.Code == "" {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "totp 验证需要提供 code。", nil)
			return
		}
	case auth.MFAMethodPasskey:
		if len(req.PasskeyAssertion) == 0 {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "passkey 验证需要提供 passkeyAssertion。", nil)
			return
		}
	default:
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "不支持的验证方式。", nil)
		return
	}

	tokenHash := session.HashToken(req.ReauthToken)

	// Rate limit keyed on IP + challenge token hash. Fail closed.
	if !h.checkRateLimit(w, r, tokenHash) {
		return
	}

	claimID, err := generateClaimID()
	if err != nil {
		h.logger.Error("reauth claim id generation failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}
	challenge, err := h.challenges.ClaimChallenge(r.Context(), tokenHash, claimID)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrReauthChallengeNotFound):
			writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "重新认证挑战已过期或不存在，请重新发起操作。", nil)
			return
		case errors.Is(err, auth.ErrReauthChallengeClaimed):
			writeError(w, r, http.StatusTooManyRequests, CodeRateLimited, "验证正在进行中，请稍后重试。", nil)
			return
		default:
			h.logger.Error("reauth challenge claim failed",
				"requestId", requestID(r),
				"errorClass", observability.ClassifyError(err),
				"errorDetail", observability.RedactedError(err, 256),
			)
			WriteInternalError(w, r)
			return
		}
	}

	// Binding check: a challenge issued to one user or session can never be
	// completed from another. Any mismatch consumes the challenge fail closed
	// and revokes the challenge's temporary provider session.
	if challenge.UserID != principal.UserID || challenge.SessionID != string(principal.SessionID) {
		_ = h.challenges.ConsumeChallenge(r.Context(), tokenHash, claimID)
		h.revokeProviderSession(r, challenge.ProviderSessionID, principal.UserID,
			applications.ApplicationID(challenge.ApplicationID),
			applications.OAuthClientID(challenge.ClientID), challenge.Action)
		h.recordReauthFailure(r, principal.UserID,
			applications.ApplicationID(challenge.ApplicationID),
			applications.OAuthClientID(challenge.ClientID),
			challenge.Action, "binding_mismatch")
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "验证失败，请重试。", nil)
		return
	}

	result, err := h.authenticator.CompleteMFA(r.Context(), auth.MFAChallengeInput{
		ProviderSessionID: challenge.ProviderSessionID,
		Method:            method,
		Code:              req.Code,
		PasskeyAssertion:  req.PasskeyAssertion,
	})
	if err != nil {
		_ = h.challenges.ReleaseChallenge(r.Context(), tokenHash, claimID)
		h.logger.Error("reauth completion provider error",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}

	switch result.Status {
	case auth.StatusAuthenticated:
		if err := h.challenges.ConsumeChallenge(r.Context(), tokenHash, claimID); err != nil {
			h.logger.Error("reauth challenge consume failed",
				"requestId", requestID(r),
				"errorClass", observability.ClassifyError(err),
				"errorDetail", observability.RedactedError(err, 256),
			)
			WriteInternalError(w, r)
			return
		}
		// Terminal success: revoke the temporary provider session before
		// issuing the grant (best-effort, never blocks the grant).
		h.revokeProviderSession(r, result.ProviderSessionReference, principal.UserID,
			applications.ApplicationID(challenge.ApplicationID),
			applications.OAuthClientID(challenge.ClientID), challenge.Action)
		h.issueGrant(w, r, principal, challenge.Action, challenge.ApplicationID, challenge.ClientID, challenge.Target)

	case auth.StatusInvalidCredentials:
		attempts, incErr := h.challenges.IncrementChallengeAttempts(r.Context(), tokenHash, h.maxAttempts)
		if incErr != nil {
			if errors.Is(incErr, auth.ErrReauthMaxAttemptsExceeded) {
				_ = h.challenges.ConsumeChallenge(r.Context(), tokenHash, claimID)
				// Terminal failure: the challenge is gone, so its temporary
				// provider session must not outlive it.
				h.revokeProviderSession(r, challenge.ProviderSessionID, principal.UserID,
					applications.ApplicationID(challenge.ApplicationID),
					applications.OAuthClientID(challenge.ClientID), challenge.Action)
				h.recordReauthFailure(r, principal.UserID,
					applications.ApplicationID(challenge.ApplicationID),
					applications.OAuthClientID(challenge.ClientID),
					challenge.Action, "max_attempts_exceeded")
				writeError(w, r, http.StatusTooManyRequests, CodeRateLimited, "验证尝试次数过多，请稍后重新发起操作。", nil)
				return
			}
			if !errors.Is(incErr, auth.ErrReauthChallengeNotFound) {
				h.logger.Error("reauth attempt increment failed",
					"requestId", requestID(r),
					"errorClass", observability.ClassifyError(incErr),
					"errorDetail", observability.RedactedError(incErr, 256),
				)
			}
		}
		_ = h.challenges.ReleaseChallenge(r.Context(), tokenHash, claimID)
		h.recordReauthFailure(r, principal.UserID,
			applications.ApplicationID(challenge.ApplicationID),
			applications.OAuthClientID(challenge.ClientID),
			challenge.Action, "invalid_credentials")
		remaining := h.maxAttempts - attempts
		if remaining < 0 {
			remaining = 0
		}
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized,
			fmt.Sprintf("验证码错误。剩余尝试次数 %d 次。", remaining), nil)

	case auth.StatusExpired:
		_ = h.challenges.ConsumeChallenge(r.Context(), tokenHash, claimID)
		// Terminal failure: revoke the challenge's temporary provider session.
		h.revokeProviderSession(r, challenge.ProviderSessionID, principal.UserID,
			applications.ApplicationID(challenge.ApplicationID),
			applications.OAuthClientID(challenge.ClientID), challenge.Action)
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "验证挑战已过期，请重新发起操作。", nil)

	default:
		_ = h.challenges.ReleaseChallenge(r.Context(), tokenHash, claimID)
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "验证失败，请重试。", nil)
	}
}

// checkRateLimit enforces the reauthentication rate limit. Any checker
// failure denies the attempt fail closed with the full window as retry hint.
func (h *ReauthHandlers) checkRateLimit(w http.ResponseWriter, r *http.Request, keyHash string) bool {
	if h.rateChecker == nil {
		WriteRateLimited(w, r, int(h.rateWindow.Seconds()))
		return false
	}
	ip := clientIP(r)
	allowed, retryAfter, err := h.rateChecker.CheckReauth(r.Context(), ip, keyHash, h.rateLimit, h.rateWindow)
	if err != nil {
		h.logger.Error("reauth rate limit check failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteRateLimited(w, r, int(h.rateWindow.Seconds()))
		return false
	}
	if !allowed {
		WriteRateLimited(w, r, int(retryAfter.Seconds()))
		return false
	}
	return true
}

// issueGrant creates the single-use grant and returns it exactly once. The
// grant token is random and opaque; only its hash reaches Redis. The grant
// is stamped with the issuing session's security epoch (ADR-0007 Decision
// 1); the middleware gate guarantees that stamp is current at mint time.
func (h *ReauthHandlers) issueGrant(w http.ResponseWriter, r *http.Request, principal session.Principal, action, applicationID, clientID, target string) {
	record, ok := SessionRecordFromContext(r.Context())
	if !ok {
		// Unreachable under RequireSession; fail closed rather than mint an
		// unstamped grant.
		h.logger.Error("reauth grant mint without session record", "requestId", requestID(r))
		WriteInternalError(w, r)
		return
	}
	token, err := session.GenerateToken()
	if err != nil {
		h.logger.Error("reauth grant token generation failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}
	now := time.Now().UTC()
	data := auth.ReauthGrantData{
		UserID:        principal.UserID,
		SessionID:     string(principal.SessionID),
		Action:        action,
		ApplicationID: applicationID,
		ClientID:      clientID,
		Target:        target,
		CreatedAt:     now,
		SecurityEpoch: record.SecurityEpoch,
	}
	if err := h.grants.CreateGrant(r.Context(), session.HashToken(token), data, h.grantTTL); err != nil {
		h.logger.Error("reauth grant creation failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}
	h.auditor.RecordEvent(r.Context(), applications.EventReauthenticationSucceeded, principal.UserID,
		applications.ApplicationID(applicationID), applications.OAuthClientID(clientID),
		request.ID(r.Context()), action, applications.SecurityEventSuccess, "")
	writeJSONNoStore(w, r, http.StatusOK, reauthGrantResponse{
		Status:      "granted",
		ReauthToken: token,
		ExpiresAt:   now.Add(h.grantTTL),
	})
}

// createChallenge stores a reauthentication challenge and answers 202. Only
// totp and passkey methods are exposed; without any usable method the
// request fails closed.
//
// Cleanup guard: the password verification above already created a temporary
// provider session. Every early-exit path below must revoke it — the session
// is exempt from revocation only once the challenge is safely stored and the
// terminal-state paths take over (ADR-0004 §7).
func (h *ReauthHandlers) createChallenge(w http.ResponseWriter, r *http.Request, principal session.Principal, req reauthRequest, result auth.AuthenticationResult) {
	methods := make([]string, 0, len(result.AvailableMethods))
	for _, m := range result.AvailableMethods {
		if m == auth.MFAMethodTOTP || m == auth.MFAMethodPasskey {
			methods = append(methods, string(m))
		}
	}
	if len(methods) == 0 {
		h.revokeProviderSession(r, result.ProviderSessionID, principal.UserID,
			applications.ApplicationID(req.ApplicationID), applications.OAuthClientID(req.ClientID), req.Action)
		h.logger.Error("reauth challenge has no usable mfa methods", "requestId", requestID(r))
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "当前无法完成验证，请稍后重试。", nil)
		return
	}

	token, err := session.GenerateToken()
	if err != nil {
		h.revokeProviderSession(r, result.ProviderSessionID, principal.UserID,
			applications.ApplicationID(req.ApplicationID), applications.OAuthClientID(req.ClientID), req.Action)
		h.logger.Error("reauth challenge token generation failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}
	record, ok := SessionRecordFromContext(r.Context())
	if !ok {
		// Unreachable under RequireSession; fail closed and revoke the
		// temporary provider session (cleanup guard).
		h.revokeProviderSession(r, result.ProviderSessionID, principal.UserID,
			applications.ApplicationID(req.ApplicationID), applications.OAuthClientID(req.ClientID), req.Action)
		h.logger.Error("reauth challenge mint without session record", "requestId", requestID(r))
		WriteInternalError(w, r)
		return
	}
	now := time.Now().UTC()
	data := auth.ReauthChallengeData{
		UserID:                principal.UserID,
		SessionID:             string(principal.SessionID),
		Action:                req.Action,
		ApplicationID:         req.ApplicationID,
		ClientID:              req.ClientID,
		Target:                req.Target,
		ProviderSessionID:     result.ProviderSessionID,
		AvailableMethods:      result.AvailableMethods,
		PasskeyRequestOptions: result.PasskeyRequestOptions,
		CreatedAt:             now,
		SecurityEpoch:         record.SecurityEpoch,
	}
	if err := h.challenges.CreateChallenge(r.Context(), session.HashToken(token), data, h.challengeTTL); err != nil {
		h.revokeProviderSession(r, result.ProviderSessionID, principal.UserID,
			applications.ApplicationID(req.ApplicationID), applications.OAuthClientID(req.ClientID), req.Action)
		h.logger.Error("reauth challenge creation failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, reauthChallengeResponse{
		Status:                "mfa_required",
		ReauthToken:           token,
		AvailableMethods:      methods,
		PasskeyRequestOptions: result.PasskeyRequestOptions,
		ExpiresAt:             now.Add(h.challengeTTL),
	})
}

// reauthRevokeTimeout bounds a best-effort provider session revocation after
// the local reauthentication outcome is already decided.
const reauthRevokeTimeout = 10 * time.Second

// reauthAuditTimeout bounds the failure-audit write. It is always a fresh
// deadline derived from the detached base context — never from the
// revocation context, which may already be expired when the provider timed
// out (an expired audit context would silently drop the security event).
const reauthAuditTimeout = 3 * time.Second

// revokeProviderSession terminates a temporary provider session at a
// reauthentication terminal state (ADR-0004 §7). It is strictly best-effort:
// the local outcome (grant issued or fail closed) is already decided, and a
// revocation failure only records a security event and a warning log — the
// session then relies on provider-side expiry. Empty references are skipped.
//
// Revocation and its failure audit run on a detached, short-timeout context:
// the request context may already be cancelled when the client disconnects,
// and the password-direct path has no cleanup-index fallback, so the
// revocation must not inherit that cancellation.
func (h *ReauthHandlers) revokeProviderSession(r *http.Request, sessionReference string, actor identity.UserID, appID applications.ApplicationID, clientID applications.OAuthClientID, action string) {
	if sessionReference == "" {
		return
	}
	baseCtx := context.WithoutCancel(r.Context())

	revokeCtx, revokeCancel := context.WithTimeout(baseCtx, h.revokeTimeout)
	err := h.authenticator.RevokeProviderSession(revokeCtx, sessionReference)
	revokeCancel()
	if err == nil {
		return
	}

	h.logger.Warn("reauth provider session revocation failed",
		"requestId", requestID(r),
		"errorClass", observability.ClassifyError(err),
		"errorDetail", observability.RedactedError(err, 256),
	)

	// Do not reuse revokeCtx: if the provider timed out, that context is
	// already expired and the audit write would fail immediately. The
	// "revocation failed" security event must get its own fresh deadline.
	auditCtx, auditCancel := context.WithTimeout(baseCtx, h.auditTimeout)
	defer auditCancel()
	h.auditor.RecordEvent(auditCtx, applications.EventProviderSessionRevokeFailed, actor,
		appID, clientID, request.ID(r.Context()), action, applications.SecurityEventDenied,
		string(observability.ClassifyError(err)))
}

// recordReauthFailure records a denied reauthentication audit row. Audit
// recording is best-effort and never contains credentials.
func (h *ReauthHandlers) recordReauthFailure(r *http.Request, actor identity.UserID, appID applications.ApplicationID, clientID applications.OAuthClientID, action, failureClass string) {
	h.auditor.RecordEvent(r.Context(), applications.EventReauthenticationFailed, actor,
		appID, clientID, request.ID(r.Context()), action, applications.SecurityEventDenied, failureClass)
}

// ReauthGrants verifies and atomically consumes single-use reauthentication
// grants on behalf of high-risk operations. It satisfies the ReauthVerifier
// interface consumed by ApplicationHandlers. Any binding mismatch (action,
// session, application, client) or reuse fails closed. Consumption is
// additionally gated by the authoritative security state (ADR-0007 Decision
// 5): a stale stamp or a non-terminal mutation intent denies it.
type ReauthGrants struct {
	grants   ReauthGrantStore
	security SensitiveConsumptionGate
}

// NewReauthGrants builds the grant verifier from the grant store and the
// sensitive-consumption gate (the security-state service in production;
// nil only in tests that never exercise the barrier).
func NewReauthGrants(grants ReauthGrantStore, security SensitiveConsumptionGate) *ReauthGrants {
	return &ReauthGrants{grants: grants, security: security}
}

// VerifyAndConsume atomically consumes the grant token and checks every
// binding against the requested operation. A consumed grant can never be
// reused, even if the token is intercepted. target carries the
// action-specific binding (ADR-0006 §4): the passkeyId for
// account.passkey.remove, empty everywhere else; any mismatch — including a
// grant minted for a different passkey — fails closed.
func (g *ReauthGrants) VerifyAndConsume(ctx context.Context, token, action, sessionID, target string, appID applications.ApplicationID, clientID applications.OAuthClientID) error {
	if token == "" || action == "" || sessionID == "" {
		return errors.New("httpapi: reauthentication grant unavailable")
	}
	data, err := g.grants.ConsumeGrant(ctx, session.HashToken(token))
	if err != nil {
		return err
	}
	if data.Action != action ||
		data.SessionID != sessionID ||
		data.Target != target ||
		data.ApplicationID != string(appID) ||
		data.ClientID != string(clientID) {
		return errors.New("httpapi: reauthentication grant binding mismatch")
	}
	// Authoritative security-state gate (ADR-0007 Decision 5): the grant is
	// already consumed (single-use, no replay even on denial). A stale epoch
	// stamp or a non-terminal mutation intent denies the sensitive
	// consumption fail closed.
	if g.security != nil {
		if err := g.security.AllowSensitiveConsumption(ctx, data.UserID, data.SecurityEpoch); err != nil {
			return fmt.Errorf("httpapi: reauthentication grant security gate: %w", err)
		}
	}
	return nil
}
