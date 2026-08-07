// Package consent defines the consent/authorization orchestration seam of
// United Pass (ADR-0005). Phase 3.1 introduced the provider port: the
// authorization-request view, the provider callback result type, the stable
// provider error classes (contract §8), and the fake provider used by unit
// tests. Phase 3.2 adds the grant and decision-operation domain model with
// its store port and migration 00005. Resolution and decision services
// land in later Phase 3 milestones.
package consent

import (
	"errors"
	"fmt"
)

// ErrorClass is the stable, provider-independent classification of a
// provider authorization failure (ADR-0005 §8). Classes are the only values
// that may reach audit events or error responses; raw provider error text
// never does.
type ErrorClass string

// Stable provider error classes. The set is frozen by contract §8 plus the
// deterministic user-admission failure decided in ADR-0005 §8.
const (
	// ClassNotFound: the auth request is unknown to the provider. On
	// v2.71 this is externally indistinguishable from "expired" and from
	// "consumed by a successful CreateCallback" (ADR-0005 §4): it is
	// evidence only for terminating the request, never for a grant.
	ClassNotFound ErrorClass = "not_found"
	// ClassExpired: the provider reports the auth request as expired.
	ClassExpired ErrorClass = "expired"
	// ClassAlreadyCompleted: the auth request was already finalized
	// (provider one-shot semantics; second line of defense, ADR-0005 §5).
	ClassAlreadyCompleted ErrorClass = "already_completed"
	// ClassInvalidRedirect: the provider rejected the redirect URI.
	ClassInvalidRedirect ErrorClass = "invalid_redirect"
	// ClassInvalidScope: the provider rejected the requested scopes.
	ClassInvalidScope ErrorClass = "invalid_scope"
	// ClassProviderConflict: the provider rejected the call because of a
	// state conflict that is not the one-shot completion case.
	ClassProviderConflict ErrorClass = "provider_conflict"
	// ClassProviderUnavailable: transport, authentication or quota
	// failures; may heal by retry.
	ClassProviderUnavailable ErrorClass = "provider_unavailable"
	// ClassRateLimited: the provider throttled the call; may heal by
	// backoff.
	ClassRateLimited ErrorClass = "rate_limited"
	// ClassInternal: unexpected provider-side or adapter-side failure.
	ClassInternal ErrorClass = "internal"
	// ClassUserNotEligible: deterministic user-admission failure on the
	// Allow path (missing project grant / user grant while the
	// corresponding project check is enabled; gRPC PermissionDenied
	// OIDC-foSyH49RvL on v2.71). It never heals by retry and is never
	// mapped to provider_unavailable; the surface error is the stable
	// authorization.user_not_eligible.
	ClassUserNotEligible ErrorClass = "user_not_eligible"
)

// ProviderError is the classified provider authorization failure. Its Error
// output contains only the stable class — never raw provider messages — so
// it is safe to log and to surface to callers; the underlying transport
// error remains reachable through errors.Unwrap for internal handling only.
type ProviderError struct {
	class ErrorClass
	cause error
}

// NewProviderError wraps a provider failure with its stable class. A nil
// cause is allowed (synthetic errors, e.g. injected by the fake provider).
func NewProviderError(class ErrorClass, cause error) *ProviderError {
	return &ProviderError{class: class, cause: cause}
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("provider authorization failure: %s", e.class)
}

// Unwrap exposes the underlying provider error for internal handling. It
// must never be rendered into audit events or API responses.
func (e *ProviderError) Unwrap() error { return e.cause }

// Class returns the stable error class.
func (e *ProviderError) Class() ErrorClass { return e.class }

// ErrorClassOf extracts the stable class of a provider error. It reports
// false for errors that are not classified provider failures.
func ErrorClassOf(err error) (ErrorClass, bool) {
	var pe *ProviderError
	if errors.As(err, &pe) {
		return pe.class, true
	}
	return "", false
}

// IsClass reports whether err is a provider error of the given class.
func IsClass(err error, class ErrorClass) bool {
	c, ok := ErrorClassOf(err)
	return ok && c == class
}
