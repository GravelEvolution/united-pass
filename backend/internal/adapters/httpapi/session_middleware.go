//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: RequireSession middleware: validates the session cookie and injects the principal
//

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// UserStatusChecker checks whether a user is still permitted to hold an active
// session. The session middleware calls this on every authenticated request to
// ensure disabled users cannot use existing sessions. The interface is defined
// here (close to the consumer) per AGENTS.md §8.
type UserStatusChecker interface {
	// CanUseSession returns nil if the user may continue using the session,
	// or an error (typically identity.ErrUserNotFound) if the session must be
	// invalidated.
	CanUseSession(ctx context.Context, userID identity.UserID) error
}

// SecurityStateGate is the shared authoritative security-state validation
// applied by EVERY session-to-principal promotion path (ADR-0007 F1):
// RequireSession and OptionalSession both invoke it, and no path promotes a
// session without it. The epoch read, the active-intent barrier check and
// their fail-closed semantics live behind this interface exactly once.
type SecurityStateGate interface {
	// EvaluatePromotion returns the promotion verdict for a session stamped
	// with recordEpoch. The second return reports whether a non-terminal
	// mutation intent was observed; callers fire TriggerRecovery on it so
	// abandoned intents settle opportunistically.
	EvaluatePromotion(ctx context.Context, userID identity.UserID, recordEpoch securitystate.Epoch) (securitystate.PromotionVerdict, bool)
	// TriggerRecovery fires a detached, bounded opportunistic recovery run
	// for the user (never on the request path).
	TriggerRecovery(userID identity.UserID)
}

// promotionOutcome classifies one shared validation+promotion pass.
type promotionOutcome int

const (
	// promoted: the session may promote to principal.
	promoted promotionOutcome = iota
	// invalid: the session itself is missing/expired (frozen semantics: no
	// cookie clearing).
	promotionInvalid
	// epochStale: authoritative, permanent death — the session's stamped
	// epoch is behind the user's current epoch. Both cookies are cleared
	// (the single pinned exception to the frozen no-clearing rule).
	promotionEpochStale
	// deniedTransient: fail-closed denial without cookie clearing (a
	// pre-outcome active intent barrier or an authoritative-lookup failure).
	promotionDeniedTransient
)

// validateAndPromote is the one shared promotion pipeline (ADR-0007 F1):
// Redis session validation, user-status replay and the authoritative
// security-state gate. Both RequireSession and OptionalSession call it; they
// differ only in how a non-promotable outcome is reported.
func validateAndPromote(
	r *http.Request,
	svc *session.Service,
	checker UserStatusChecker,
	gate SecurityStateGate,
	token string,
	logger *slog.Logger,
) (session.Principal, session.SessionRecord, promotionOutcome) {
	principal, record, err := svc.ValidateSession(r.Context(), token)
	if err != nil {
		if !errors.Is(err, session.ErrSessionNotFound) && !errors.Is(err, session.ErrSessionExpired) {
			logger.Error("session validation failed",
				"requestId", request.ID(r.Context()),
				"errorClass", observability.ClassifyError(err),
				"errorDetail", observability.RedactedError(err, 256),
			)
		}
		return session.Principal{}, session.SessionRecord{}, promotionInvalid
	}

	// Check that the user is still permitted to use sessions. A
	// disabled user's sessions are treated as invalid even if the
	// Redis record has not expired yet.
	if checker != nil {
		if err := checker.CanUseSession(r.Context(), principal.UserID); err != nil {
			// Best-effort cleanup of the stale session.
			_ = svc.DeleteSession(r.Context(), token)
			return session.Principal{}, session.SessionRecord{}, promotionInvalid
		}
	}

	// Authoritative security-state gate (ADR-0007 F1): the epoch stamp is
	// replayed against the user's durable epoch and mutation-intent phase.
	// A nil gate keeps the pre-ADR-0007 behaviour for tests only;
	// production wiring always provides one.
	if gate != nil {
		verdict, observed := gate.EvaluatePromotion(r.Context(), principal.UserID, record.SecurityEpoch)
		if observed {
			// A non-terminal intent survived its owner: settle it
			// opportunistically, detached and bounded (F6).
			gate.TriggerRecovery(principal.UserID)
		}
		switch verdict {
		case securitystate.PromotionEpochStale:
			logger.Info("session promotion denied: stale security epoch",
				"requestId", request.ID(r.Context()),
				"userId", string(principal.UserID),
				"sessionId", string(record.SessionID),
				"sessionEpoch", int64(record.SecurityEpoch),
			)
			// The record is dead by definition; remove it best-effort so
			// the inventory does not carry pre-generation sessions.
			_ = svc.DeleteSession(r.Context(), token)
			return session.Principal{}, session.SessionRecord{}, promotionEpochStale
		case securitystate.PromotionDeniedTransient:
			// Fail closed, never clear cookies: either the pre-outcome
			// barrier of an active mutation or an authoritative-lookup
			// failure. Tokens that may still be valid are preserved.
			logger.Info("session promotion denied: transient security state",
				"requestId", request.ID(r.Context()),
				"userId", string(principal.UserID),
				"sessionId", string(record.SessionID),
			)
			return session.Principal{}, session.SessionRecord{}, promotionDeniedTransient
		}
	}

	// Best-effort touch to refresh idle timeout. Touch is throttled
	// by touchInterval inside the service, so it does not write to
	// Redis on every request.
	_ = svc.TouchSession(r.Context(), token)

	return principal, record, promoted
}

// clearAuthCookies removes both authentication cookies with attributes
// matching the ones they were set with.
func clearAuthCookies(w http.ResponseWriter, attrs SessionCookieAttributes) {
	ClearSessionCookie(w, attrs)
	ClearCSRFCookie(w, attrs)
}

// RequireSession middleware rejects requests without a valid session. It reads
// the up_session cookie, validates the session via session.Service, checks user
// status, applies the authoritative security-state gate (ADR-0007 F1) and
// places the Principal and SessionRecord in the request context.
//
// On failure it returns 401 with the standard error envelope. The session
// cookie is NOT cleared on failure — the browser retains it, but it will no
// longer authenticate — with one pinned exception: a session stamped with a
// stale security epoch is an authoritative, permanent death, so both cookies
// are cleared on both promotion paths (ADR-0007 Decision 5).
func RequireSession(svc *session.Service, checker UserStatusChecker, gate SecurityStateGate, attrs SessionCookieAttributes, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ReadSessionCookie(r)
			if token == "" {
				WriteUnauthorized(w, r)
				return
			}

			principal, record, outcome := validateAndPromote(r, svc, checker, gate, token, logger)
			switch outcome {
			case promotionEpochStale:
				clearAuthCookies(w, attrs)
				WriteUnauthorized(w, r)
				return
			case promotionInvalid, promotionDeniedTransient:
				WriteUnauthorized(w, r)
				return
			}

			ctx := WithPrincipal(r.Context(), principal)
			ctx = WithSessionRecord(ctx, record)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalSession middleware behaves like RequireSession but does not reject
// unauthenticated requests. When a valid session exists and the security-state
// gate allows promotion, the Principal and SessionRecord are placed in the
// context. When no session exists or the session cannot promote, the request
// proceeds without a principal. The same shared validation pipeline runs
// (ADR-0007 F1): an epoch-stale session clears both cookies even on this
// path; a transient denial degrades to anonymous without touching cookies.
//
// This is useful for endpoints that behave differently for authenticated vs
// anonymous users (e.g. showing a login page vs redirecting to the account).
func OptionalSession(svc *session.Service, checker UserStatusChecker, gate SecurityStateGate, attrs SessionCookieAttributes, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ReadSessionCookie(r)
			if token == "" {
				next.ServeHTTP(w, r)
				return
			}

			principal, record, outcome := validateAndPromote(r, svc, checker, gate, token, logger)
			if outcome == promotionEpochStale {
				clearAuthCookies(w, attrs)
				next.ServeHTTP(w, r)
				return
			}
			if outcome != promoted {
				next.ServeHTTP(w, r)
				return
			}

			ctx := WithPrincipal(r.Context(), principal)
			ctx = WithSessionRecord(ctx, record)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireCSRF middleware validates the CSRF token on state-changing requests.
// Safe methods (GET, HEAD, OPTIONS) are allowed without CSRF checks. All other
// methods require:
//  1. A valid session in the context (RequireSession must run first).
//  2. The up_csrf cookie value and X-CSRF-Token header value to match.
//  3. The matched value's hash to match the CSRFTokenHash in the session record.
//
// All comparisons use constant time to prevent timing attacks.
func RequireCSRF() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			record, ok := SessionRecordFromContext(r.Context())
			if !ok {
				// No session record means RequireSession did not run or the
				// request is anonymous. State-changing methods require a
				// session, so this is an authentication failure.
				WriteUnauthorized(w, r)
				return
			}

			cookieValue := ReadCSRFCookie(r)
			headerValue := ReadCSRFHeader(r)

			if !session.ValidateCSRF(cookieValue, headerValue, record) {
				WriteForbidden(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isSafeMethod reports whether the HTTP method is considered safe (no
// state mutation) per RFC 9110. Safe methods are exempt from CSRF checks.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// WriteUnauthorized writes a 401 with the standard error envelope.
func WriteUnauthorized(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "请先登录以继续。", nil)
}

// WriteForbidden writes a 403 with the standard error envelope.
func WriteForbidden(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusForbidden, CodeForbidden, "操作未被授权。", nil)
}

// WriteRateLimited writes a 429 with the standard error envelope and a
// Retry-After header (in seconds).
func WriteRateLimited(w http.ResponseWriter, r *http.Request, retryAfterSeconds int) {
	if retryAfterSeconds > 0 {
		w.Header().Set("Retry-After", itoa(retryAfterSeconds))
	}
	writeError(w, r, http.StatusTooManyRequests, CodeRateLimited, "请求过于频繁，请稍后再试。", nil)
}

// itoa converts an int to its decimal string representation without importing
// strconv (keeping the import list minimal for this middleware file).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
