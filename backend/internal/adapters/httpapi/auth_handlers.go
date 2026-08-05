package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// MFAChallengeStore abstracts MFA challenge persistence for the auth handlers.
// The Redis adapter satisfies this interface; tests can use an in-memory fake.
//
// Challenges are single-use: the handler generates a random claimID and calls
// Claim before verification. Claim is atomic (SET NX PX on a dedicated lock
// key) so concurrent verification of the same challenge is impossible. The
// challenge's own TTL is never modified; Consume must succeed (fail closed)
// before a session may be created.
type MFAChallengeStore interface {
	Create(ctx context.Context, mfaTokenHash string, data auth.MFAChallengeData, ttl time.Duration) error
	Get(ctx context.Context, mfaTokenHash string) (auth.MFAChallengeData, error)
	// Claim atomically reserves a challenge for verification with a
	// caller-generated claimID. Only one concurrent request can claim a given
	// challenge; the second gets auth.ErrMFAChallengeClaimed.
	Claim(ctx context.Context, mfaTokenHash, claimID string) (auth.MFAChallengeData, error)
	// Consume atomically deletes a claimed challenge (single-use). It returns
	// auth.ErrMFAChallengeNotHeld when the claimID no longer holds the lock,
	// and auth.ErrMFAChallengeNotFound when the challenge is already gone.
	Consume(ctx context.Context, mfaTokenHash, claimID string) error
	// Release removes the claim lock (only if claimID still holds it) so the
	// user can retry after a failed verification.
	Release(ctx context.Context, mfaTokenHash, claimID string) error
	IncrementAttempts(ctx context.Context, mfaTokenHash string, maxAttempts int) (int, error)
}

// RateChecker abstracts rate limiting. The Redis rate limiter satisfies this
// interface; tests can use a fake that always allows.
type RateChecker interface {
	// CheckLogin returns whether the login attempt is allowed and how long to
	// wait before retrying. When Redis is unavailable, allowed=false (fail
	// closed).
	CheckLogin(ctx context.Context, ip string, identifierHash string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
	// CheckMFA returns whether the MFA attempt is allowed.
	CheckMFA(ctx context.Context, ip string, mfaTokenHash string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
}

// AuthHandlers serves the authentication endpoints: login, MFA, and logout.
type AuthHandlers struct {
	authenticator  auth.Authenticator
	sessionSvc     *session.Service
	mfaStore       MFAChallengeStore
	rateChecker    RateChecker
	userChecker    UserStatusChecker
	cookieAttrs    SessionCookieAttributes
	mfaTTL         time.Duration
	mfaMaxAttempts int
	loginLimit     int
	loginWindow    time.Duration
	mfaLimit       int
	mfaWindow      time.Duration
	sessionTTL     time.Duration
	rememberTTL    time.Duration
	logger         *slog.Logger
}

// NewAuthHandlers builds AuthHandlers from the given dependencies and configuration.
func NewAuthHandlers(
	authenticator auth.Authenticator,
	sessionSvc *session.Service,
	mfaStore MFAChallengeStore,
	rateChecker RateChecker,
	userChecker UserStatusChecker,
	cfg config.Config,
	logger *slog.Logger,
) *AuthHandlers {
	return &AuthHandlers{
		authenticator:  authenticator,
		sessionSvc:     sessionSvc,
		mfaStore:       mfaStore,
		rateChecker:    rateChecker,
		userChecker:    userChecker,
		cookieAttrs:    CookieAttributesFromConfig(cfg.Session),
		mfaTTL:         cfg.MFA.ChallengeTTL,
		mfaMaxAttempts: cfg.MFA.MaxAttempts,
		loginLimit:     cfg.RateLimit.LoginLimit,
		loginWindow:    cfg.RateLimit.LoginWindow,
		mfaLimit:       cfg.RateLimit.MFALimit,
		mfaWindow:      cfg.RateLimit.MFAWindow,
		sessionTTL:     cfg.Session.TTL,
		rememberTTL:    cfg.Session.RememberTTL,
		logger:         logger,
	}
}

// loginRequest is the JSON body for POST /api/v1/auth/sessions.
type loginRequest struct {
	Identifier      string `json:"identifier"`
	Password        string `json:"password"`
	Remember        bool   `json:"remember"`
	ResumeRequestID string `json:"resumeRequestId"`
}

// mfaRequiredResponse is the JSON body for the 202 MFA-required response.
// The mfaToken is an opaque, randomly generated United Pass token — it never
// contains provider credentials. PasskeyRequestOptions is the WebAuthn
// PublicKeyCredentialRequestOptions (JSON) when passkey is available.
type mfaRequiredResponse struct {
	Status                string    `json:"status"`
	MFAToken              string    `json:"mfaToken"`
	AvailableMethods      []string  `json:"availableMethods"`
	PasskeyRequestOptions string    `json:"passkeyRequestOptions,omitempty"`
	ExpiresAt             time.Time `json:"expiresAt"`
}

// mfaChallengeRequest is the JSON body for POST /api/v1/auth/sessions/mfa.
type mfaChallengeRequest struct {
	MFAToken string `json:"mfaToken"`
	Method   string `json:"method"`
	Code     string `json:"code"`
}

// Login handles POST /api/v1/auth/sessions.
//
// Flow:
//  1. Parse and validate the JSON request body.
//  2. Check the login rate limit (IP + identifier hash).
//  3. Call the Authenticator to begin password authentication.
//  4. If authenticated, create a session and set cookies. Return 204.
//  5. If MFA required, store an MFA challenge in Redis. Return 202 with mfaToken.
//  6. On any failure, return a generic error that does not reveal whether the
//     account exists.
func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeLoginRequest(w, r, &req); err != nil {
		return
	}

	ip := clientIP(r)
	identifierHash := hashIdentifier(req.Identifier)

	// Rate limit check. Fail closed: if Redis is unavailable, deny the attempt.
	allowed, retryAfter, err := h.rateChecker.CheckLogin(r.Context(), ip, identifierHash, h.loginLimit, h.loginWindow)
	if err != nil {
		h.logger.Error("login rate limit check failed",
			"requestId", requestID(r),
			"ip", ip,
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteRateLimited(w, r, int(h.loginWindow.Seconds()))
		return
	}
	if !allowed {
		WriteRateLimited(w, r, int(retryAfter.Seconds()))
		return
	}

	// Begin authentication via the provider adapter.
	result, err := h.authenticator.BeginPasswordAuthentication(r.Context(), auth.PasswordAuthenticationInput{
		Identifier:      req.Identifier,
		Password:        req.Password,
		ResumeRequestID: req.ResumeRequestID,
	})
	if err != nil {
		h.logger.Error("authentication provider error",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}

	switch result.Status {
	case auth.StatusAuthenticated:
		h.handleAuthenticated(w, r, result, req.Remember)

	case auth.StatusMFARequired:
		h.handleMFARequired(w, r, result, req.Remember)

	case auth.StatusInvalidCredentials, auth.StatusLocked:
		// Generic error: do not reveal whether the account exists or is locked.
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "账户名或密码错误。", nil)

	case auth.StatusProviderUnavailable:
		h.logger.Error("authentication provider unavailable",
			"requestId", requestID(r),
		)
		WriteInternalError(w, r)

	default:
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "账户名或密码错误。", nil)
	}
}

// handleAuthenticated creates a session and sets cookies for a fully
// authenticated user.
func (h *AuthHandlers) handleAuthenticated(w http.ResponseWriter, r *http.Request, result auth.AuthenticationResult, remember bool) {
	// Verify the user is still permitted to authenticate.
	if h.userChecker != nil {
		if err := h.userChecker.CanUseSession(r.Context(), result.UserID); err != nil {
			writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "账户名或密码错误。", nil)
			return
		}
	}

	sessionResult, err := h.sessionSvc.CreateSession(r.Context(), session.CreateSessionInput{
		UserID:                   result.UserID,
		Provider:                 result.Provider,
		ProviderSessionReference: result.ProviderSessionReference,
		AuthenticationMethods:    result.AuthenticationMethods,
		Remember:                 remember,
		UserAgent:                r.UserAgent(),
	})
	if err != nil {
		h.logger.Error("session creation failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}

	ttl := h.sessionTTL
	if remember {
		ttl = h.rememberTTL
	}
	maxAge := sessionCookieMaxAge(ttl)

	SetSessionCookie(w, sessionResult.SessionToken, maxAge, h.cookieAttrs)
	SetCSRFCookie(w, sessionResult.CSRFToken, maxAge, h.cookieAttrs)

	w.WriteHeader(http.StatusNoContent)
}

// handleMFARequired stores an MFA challenge and returns the mfaToken to the
// client. The mfaToken is a fresh opaque token generated here with crypto/rand;
// provider session credentials never leave the server. The provider session
// ID (needed to complete the second factor) is stored in the challenge.
func (h *AuthHandlers) handleMFARequired(w http.ResponseWriter, r *http.Request, result auth.AuthenticationResult, remember bool) {
	mfaToken, err := session.GenerateMFAToken()
	if err != nil {
		h.logger.Error("mfa token generation failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}

	mfaTokenHash := session.HashToken(mfaToken)
	challenge := auth.MFAChallengeData{
		UserID:                result.UserID,
		Provider:              result.Provider,
		AuthenticationMethods: result.AuthenticationMethods,
		AvailableMethods:      result.AvailableMethods,
		ProviderSessionID:     result.ProviderSessionID,
		PasskeyRequestOptions: result.PasskeyRequestOptions,
		Attempts:              0,
		CreatedAt:             time.Now().UTC(),
	}

	if err := h.mfaStore.Create(r.Context(), mfaTokenHash, challenge, h.mfaTTL); err != nil {
		h.logger.Error("mfa challenge store failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}

	methods := make([]string, len(result.AvailableMethods))
	for i, m := range result.AvailableMethods {
		methods[i] = string(m)
	}

	resp := mfaRequiredResponse{
		Status:                "mfa_required",
		MFAToken:              mfaToken,
		AvailableMethods:      methods,
		PasskeyRequestOptions: result.PasskeyRequestOptions,
		ExpiresAt:             time.Now().UTC().Add(h.mfaTTL),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(resp)
}

// CompleteMFA handles POST /api/v1/auth/sessions/mfa.
//
// Flow:
//  1. Parse and validate the JSON request body.
//  2. Check the MFA rate limit (IP + MFA token hash).
//  3. Atomically claim the MFA challenge with a fresh claimID. Claim is
//     single-winner: concurrent requests for the same challenge cannot both
//     proceed to verification, which prevents two sessions being established
//     from one challenge. The claim lock lives in a separate key and does not
//     extend the challenge's own TTL.
//  4. Call the Authenticator to complete MFA.
//  5. If authenticated, consume the challenge (single-use). Consumption is
//     fail closed: if Consume fails, no session is created.
//  6. If invalid credentials, increment attempts and release the claim so the
//     user can retry. If max attempts is exceeded, consume the challenge.
//  7. If the challenge is expired, consume it and return a generic error.
func (h *AuthHandlers) CompleteMFA(w http.ResponseWriter, r *http.Request) {
	var req mfaChallengeRequest
	if err := decodeJSONBody(w, r, &req, "MFA challenge"); err != nil {
		return
	}

	if req.MFAToken == "" || req.Method == "" {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "MFA 令牌和验证方式不能为空。", nil)
		return
	}

	method := auth.MFAMethod(req.Method)
	if !isValidMFAMethod(method) {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "不支持的验证方式。", nil)
		return
	}

	ip := clientIP(r)
	mfaTokenHash := session.HashToken(req.MFAToken)

	// Rate limit check.
	allowed, retryAfter, err := h.rateChecker.CheckMFA(r.Context(), ip, mfaTokenHash, h.mfaLimit, h.mfaWindow)
	if err != nil {
		h.logger.Error("mfa rate limit check failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteRateLimited(w, r, int(h.mfaWindow.Seconds()))
		return
	}
	if !allowed {
		WriteRateLimited(w, r, int(retryAfter.Seconds()))
		return
	}

	// Atomically claim the challenge for verification. Only one request may
	// hold the claim lock; concurrent requests are rejected here so a single
	// MFA token can never establish two sessions. The claim ID must be
	// unpredictable; a random generation failure fails closed before any
	// provider call or session creation.
	claimID, err := generateClaimID()
	if err != nil {
		h.logger.Error("mfa claim id generation failed",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}
	challenge, err := h.mfaStore.Claim(r.Context(), mfaTokenHash, claimID)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrMFAChallengeNotFound):
			writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "验证挑战已过期或不存在，请重新登录。", nil)
			return
		case errors.Is(err, auth.ErrMFAChallengeClaimed):
			writeError(w, r, http.StatusTooManyRequests, CodeRateLimited, "验证正在进行中，请稍后重试。", nil)
			return
		default:
			h.logger.Error("mfa challenge claim failed",
				"requestId", requestID(r),
				"errorClass", observability.ClassifyError(err),
				"errorDetail", observability.RedactedError(err, 256),
			)
			WriteInternalError(w, r)
			return
		}
	}

	// Attempt MFA verification via the provider adapter. The provider session
	// ID comes from the stored challenge; the browser-supplied mfaToken is
	// only a lookup key and never reaches the provider.
	result, err := h.authenticator.CompleteMFA(r.Context(), auth.MFAChallengeInput{
		ProviderSessionID: challenge.ProviderSessionID,
		Method:            method,
		Code:              req.Code,
	})
	if err != nil {
		// Provider failure: release the claim so the user can retry. The
		// challenge is not lost.
		_ = h.mfaStore.Release(r.Context(), mfaTokenHash, claimID)
		h.logger.Error("mfa completion provider error",
			"requestId", requestID(r),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}

	switch result.Status {
	case auth.StatusAuthenticated:
		// Consume the challenge (single-use) BEFORE creating the session. This
		// is fail closed: if the challenge expired during verification or
		// consumption fails for any reason, no session is created and the
		// token cannot be replayed.
		if err := h.mfaStore.Consume(r.Context(), mfaTokenHash, claimID); err != nil {
			h.logger.Error("mfa challenge consume failed",
				"requestId", requestID(r),
				"errorClass", observability.ClassifyError(err),
				"errorDetail", observability.RedactedError(err, 256),
			)
			WriteInternalError(w, r)
			return
		}

		// Create session.
		h.handleAuthenticated(w, r, result, false)

	case auth.StatusInvalidCredentials:
		// Increment the attempt counter. The claim lock is still held by this
		// request, so no other request can interfere with the count.
		attempts, incErr := h.mfaStore.IncrementAttempts(r.Context(), mfaTokenHash, h.mfaMaxAttempts)
		if incErr != nil {
			if errors.Is(incErr, auth.ErrMFAMaxAttemptsExceeded) {
				_ = h.mfaStore.Consume(r.Context(), mfaTokenHash, claimID)
				writeError(w, r, http.StatusTooManyRequests, CodeRateLimited, "验证尝试次数过多，请稍后重新登录。", nil)
				return
			}
			if !errors.Is(incErr, auth.ErrMFAChallengeNotFound) {
				h.logger.Error("mfa attempt increment failed",
					"requestId", requestID(r),
					"errorClass", observability.ClassifyError(incErr),
					"errorDetail", observability.RedactedError(incErr, 256),
				)
			}
		}
		// Release the claim so the user can retry within the remaining
		// attempt budget.
		_ = h.mfaStore.Release(r.Context(), mfaTokenHash, claimID)
		remaining := h.mfaMaxAttempts - attempts
		if remaining < 0 {
			remaining = 0
		}
		msg := fmt.Sprintf("验证码错误。剩余尝试次数 %d 次。", remaining)
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, msg, nil)

	case auth.StatusExpired:
		_ = h.mfaStore.Consume(r.Context(), mfaTokenHash, claimID)
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "验证挑战已过期，请重新登录。", nil)

	default:
		_ = h.mfaStore.Release(r.Context(), mfaTokenHash, claimID)
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "验证失败，请重试。", nil)
	}
}

// Logout handles DELETE /api/v1/auth/session.
//
// This endpoint requires a valid session and CSRF token. It:
//  1. Deletes the local Redis session.
//  2. Best-effort revokes the provider session (the stored provider session
//     reference is decrypted from its AES-GCM ciphertext first).
//  3. Clears both cookies.
//  4. Returns 204 No Content.
//
// The endpoint is idempotent: if the session is already gone, it still returns
// 204 and clears the cookies. Provider unavailability does not prevent local
// session invalidation.
func (h *AuthHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	token := ReadSessionCookie(r)
	record, _ := SessionRecordFromContext(r.Context())

	// Delete the local session.
	if token != "" {
		_ = h.sessionSvc.DeleteSession(r.Context(), token)
	}

	// Best-effort provider session revocation. The reference is stored
	// encrypted (AES-GCM) per ADR-0002; decrypt it before handing it to the
	// provider adapter. Failure is logged but does not prevent local logout.
	if record.ProviderSessionReference != "" {
		ref, err := h.sessionSvc.DecryptProviderSessionReference(r.Context(), record.ProviderSessionReference)
		if err != nil {
			h.logger.Warn("provider session reference decrypt failed",
				"requestId", requestID(r),
				"errorClass", observability.ClassifyError(err),
				"errorDetail", observability.RedactedError(err, 256),
			)
		} else if ref != "" {
			if err := h.authenticator.RevokeProviderSession(r.Context(), ref); err != nil {
				h.logger.Warn("provider session revocation failed",
					"requestId", requestID(r),
					"errorClass", observability.ClassifyError(err),
					"errorDetail", observability.RedactedError(err, 256),
				)
			}
		}
	}

	ClearSessionCookie(w, h.cookieAttrs)
	ClearCSRFCookie(w, h.cookieAttrs)

	w.WriteHeader(http.StatusNoContent)
}

// decodeLoginRequest parses the login JSON body with strict validation.
func decodeLoginRequest(w http.ResponseWriter, r *http.Request, req *loginRequest) error {
	if err := decodeJSONBody(w, r, req, "login"); err != nil {
		return err
	}
	if req.Identifier == "" || req.Password == "" {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "账户名和密码不能为空。", nil)
		return errors.New("missing fields")
	}
	return nil
}

// decodeJSONBody is the shared JSON decoder for auth endpoints. It rejects
// unknown fields, oversized bodies, malformed JSON, and multiple JSON objects.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any, op string) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(target); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			WriteRequestBodyTooLarge(w, r)
			return err
		}
		if err.Error() == "EOF" || strings.Contains(err.Error(), "cannot unmarshal") {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest, "请求体格式不正确。", nil)
			return err
		}
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "请求体格式不正确。", nil)
		return err
	}

	// Reject trailing data (multiple JSON objects).
	if dec.More() {
		writeError(w, r, http.StatusBadRequest, CodeBadRequest, "请求体包含多余的数据。", nil)
		return errors.New("trailing data")
	}

	return nil
}

// isValidMFAMethod reports whether the method string is a recognized MFA method.
func isValidMFAMethod(m auth.MFAMethod) bool {
	switch m {
	case auth.MFAMethodTOTP, auth.MFAMethodPasskey, auth.MFAMethodRecovery:
		return true
	default:
		return false
	}
}

// hashIdentifier returns the hex-encoded SHA-256 hash of the login identifier.
// The hash is used as the rate-limit key component so the raw identifier (which
// may be an email or username) never appears in Redis keys.
func hashIdentifier(identifier string) string {
	h := sha256.Sum256([]byte(identifier))
	return hex.EncodeToString(h[:])
}

// generateClaimID returns a random hex string used as the MFA claim lock
// owner identifier. It must be unpredictable so an attacker cannot present a
// guessed claimID to release or consume a challenge they do not hold.
//
// On crypto/rand failure it returns an error; the caller must fail closed and
// not proceed with a fixed or weak claim ID.
func generateClaimID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("httpapi: generate mfa claim id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// clientIP extracts the client IP address from the request. It prefers the
// X-Forwarded-For header (first value) when present, falling back to
// RemoteAddr. This is sufficient for rate limiting; precise client IP
// determination is the reverse proxy's responsibility.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// Strip the port from RemoteAddr.
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		return addr[:idx]
	}
	return addr
}

// requestID extracts the request ID from the context for logging.
func requestID(r *http.Request) string {
	return r.Header.Get(RequestIDHeader)
}
