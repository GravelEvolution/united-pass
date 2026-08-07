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

// RequireSession middleware rejects requests without a valid session. It reads
// the up_session cookie, validates the session via session.Service, checks user
// status, and places the Principal and SessionRecord in the request context.
//
// On failure it returns 401 with the standard error envelope. The session
// cookie is NOT cleared on failure — the browser retains it, but it will no
// longer authenticate. Logout is the only path that explicitly clears cookies.
func RequireSession(svc *session.Service, checker UserStatusChecker, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ReadSessionCookie(r)
			if token == "" {
				WriteUnauthorized(w, r)
				return
			}

			principal, record, err := svc.ValidateSession(r.Context(), token)
			if err != nil {
				if !errors.Is(err, session.ErrSessionNotFound) && !errors.Is(err, session.ErrSessionExpired) {
					logger.Error("session validation failed",
						"requestId", request.ID(r.Context()),
						"errorClass", observability.ClassifyError(err),
						"errorDetail", observability.RedactedError(err, 256),
					)
				}
				WriteUnauthorized(w, r)
				return
			}

			// Check that the user is still permitted to use sessions. A
			// disabled user's sessions are treated as invalid even if the
			// Redis record has not expired yet.
			if checker != nil {
				if err := checker.CanUseSession(r.Context(), principal.UserID); err != nil {
					// Best-effort cleanup of the stale session.
					_ = svc.DeleteSession(r.Context(), token)
					WriteUnauthorized(w, r)
					return
				}
			}

			// Best-effort touch to refresh idle timeout. Touch is throttled
			// by touchInterval inside the service, so it does not write to
			// Redis on every request.
			_ = svc.TouchSession(r.Context(), token)

			ctx := WithPrincipal(r.Context(), principal)
			ctx = WithSessionRecord(ctx, record)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalSession middleware behaves like RequireSession but does not reject
// unauthenticated requests. When a valid session exists, the Principal and
// SessionRecord are placed in the context. When no session exists or the
// session is invalid, the request proceeds without a principal.
//
// This is useful for endpoints that behave differently for authenticated vs
// anonymous users (e.g. showing a login page vs redirecting to the account).
func OptionalSession(svc *session.Service, checker UserStatusChecker, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ReadSessionCookie(r)
			if token == "" {
				next.ServeHTTP(w, r)
				return
			}

			principal, record, err := svc.ValidateSession(r.Context(), token)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			if checker != nil {
				if err := checker.CanUseSession(r.Context(), principal.UserID); err != nil {
					_ = svc.DeleteSession(r.Context(), token)
					next.ServeHTTP(w, r)
					return
				}
			}

			_ = svc.TouchSession(r.Context(), token)

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
