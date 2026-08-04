/**
 * Shared API constants for Cookie names, CSRF header, and API base URL.
 *
 * See ADR-0006 for the full deployment topology decision.
 */

/** HttpOnly session cookie — set by the backend, not readable by JS. */
export const SESSION_COOKIE_NAME = "up_session";

/** Non-HttpOnly CSRF cookie — readable by JS, sent as X-CSRF-Token on writes. */
export const CSRF_COOKIE_NAME = "up_csrf";

/** Request header name for the CSRF token on write operations. */
export const CSRF_HEADER_NAME = "X-CSRF-Token";

/** Browser-side API base URL (same-origin via reverse proxy). */
export const BROWSER_API_BASE_URL = "/api/v1";

/** Server-side API base URL (direct to Go backend or reverse proxy). */
export const SERVER_API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8080/api/v1";
