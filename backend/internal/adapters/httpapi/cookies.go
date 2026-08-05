package httpapi

import (
	"net/http"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
)

// Cookie and header names match the frontend contract exactly.
// See ../frontend/src/lib/api/constants.ts and ADR-0002.
const (
	SessionCookieName = "up_session"
	CSRFCookieName    = "up_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
)

// SessionCookieAttributes builds the attributes for the up_session cookie based
// on the environment configuration. In production, Secure=true and SameSite is
// enforced. In local development, Secure=false allows testing over HTTP.
type SessionCookieAttributes struct {
	Secure   bool
	SameSite http.SameSite
}

// CookieAttributesFromConfig returns cookie attributes matching the session
// configuration.
func CookieAttributesFromConfig(cfg config.SessionConfig) SessionCookieAttributes {
	sameSite := http.SameSiteLaxMode
	switch cfg.CookieSameSite {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}
	return SessionCookieAttributes{
		Secure:   cfg.CookieSecure,
		SameSite: sameSite,
	}
}

// SetSessionCookie sets the up_session cookie on the response with the given
// token and max age. A maxAge of 0 means the cookie is a session cookie
// (deleted when the browser closes). A negative maxAge deletes the cookie.
func SetSessionCookie(w http.ResponseWriter, token string, maxAge int, attrs SessionCookieAttributes) {
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   attrs.Secure,
		SameSite: attrs.SameSite,
		MaxAge:   maxAge,
	}
	http.SetCookie(w, cookie)
}

// SetCSRFCookie sets the up_csrf cookie on the response. Unlike the session
// cookie, this is NOT HttpOnly so JavaScript can read it and send it as the
// X-CSRF-Token header on write requests.
func SetCSRFCookie(w http.ResponseWriter, token string, maxAge int, attrs SessionCookieAttributes) {
	cookie := &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   attrs.Secure,
		SameSite: attrs.SameSite,
		MaxAge:   maxAge,
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie deletes the up_session cookie by setting MaxAge to -1.
func ClearSessionCookie(w http.ResponseWriter, attrs SessionCookieAttributes) {
	SetSessionCookie(w, "", -1, attrs)
}

// ClearCSRFCookie deletes the up_csrf cookie by setting MaxAge to -1.
func ClearCSRFCookie(w http.ResponseWriter, attrs SessionCookieAttributes) {
	SetCSRFCookie(w, "", -1, attrs)
}

// ReadSessionCookie extracts the raw session token from the request's
// up_session cookie. Returns empty string when the cookie is absent.
func ReadSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ReadCSRFCookie extracts the CSRF token from the request's up_csrf cookie.
// Returns empty string when the cookie is absent.
func ReadCSRFCookie(r *http.Request) string {
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ReadCSRFHeader extracts the CSRF token from the X-CSRF-Token request header.
func ReadCSRFHeader(r *http.Request) string {
	return r.Header.Get(CSRFHeaderName)
}

// sessionCookieMaxAge converts a TTL duration to a MaxAge in seconds for cookie
// attributes. Returns 0 for session-scoped cookies (browser-close lifetime).
func sessionCookieMaxAge(ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}
	return int(ttl.Seconds())
}
