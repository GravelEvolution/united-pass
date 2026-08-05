package zitadel

import (
	"context"
	"errors"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// isPasskeyChallengeFailure reports whether a CreateSession error is a
// WebAuthN challenge issuance failure that should fall back to a
// challenge-less retry. ZITADEL returns codes.Internal with a WEBAU-* error
// when it cannot begin a passkey login (no passkeys registered for the user,
// RP not configured for the requested domain, etc.). Passkey challenges are
// best-effort: a failure to issue one must not block password + TOTP login.
func isPasskeyChallengeFailure(err error) bool {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		return false
	}
	msg := st.Message()
	return strings.Contains(msg, "WebAuthN") || strings.Contains(msg, "WEBAU-")
}

// errProviderPermission marks a ZITADEL error caused by insufficient service
// account permissions (NotFound + AUTHZ-*). It is classified at the specific
// operation boundary (GetSession, ListAuthenticationMethodTypes) as
// provider_unavailable: a server-side authorization/config fault must never
// masquerade as a user credential error (invalid_credentials).
var errProviderPermission = errors.New("zitadel: service account permission denied")

// isAuthZFailure reports whether a ZITADEL gRPC error is a service-account
// authorization failure: NotFound with an AUTHZ-* error id. Ordinary NotFound
// (e.g. an unknown login name, a deleted session) is NOT an authorization
// failure and keeps its normal classification.
func isAuthZFailure(err error) bool {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		return false
	}
	return strings.Contains(st.Message(), "AUTHZ-")
}

// mapAuthError converts a ZITADEL gRPC error into an auth status.
//
// Credentials failures must be generic: ZITADEL surfaces "user not found",
// "password invalid" and account-state errors as distinct codes, but the API
// contract requires one generic invalid_credentials response that never
// reveals whether an account exists or is locked.
//
// Any transport, authentication or quota failure is a server-side problem and
// maps to provider_unavailable (HTTP 500 by the handler), never to a user
// error.
//
// CALIBRATION (Phase 1.2 sign-off, ZITADEL v2.71.0, 2026-08-06): real gRPC
// codes observed against the local instance:
//
//	unknown login name            -> NotFound      (QUERY-Dfbg2)
//	wrong password                -> InvalidArgument (COMMAND-3M0fs)
//	wrong TOTP code               -> InvalidArgument (EVENT-8isk2)
//	missing/expired session        -> InvalidArgument (COMMAND-8N9ds) on
//	                                 SetSession, NotFound (QUERY-SFeaa) on
//	                                 GetSession
//	insufficient SA permission     -> NotFound      (AUTHZ-*)
//	invalid SA key / bad JWT       -> non-gRPC      (client construction)
//	provider unreachable           -> non-gRPC      (OIDC discovery)
//
// Both credential failures (unknown user, wrong password, wrong TOTP) and
// session-state failures map to the generic invalid_credentials status, which
// never reveals whether an account exists or is locked. ZITADEL surfaces
// insufficient service-account permission as NotFound (AUTHZ-*), not
// PermissionDenied, so it lands in InvalidCredentials rather than
// ProviderUnavailable; both are opaque to the client and safe.
func mapAuthError(err error) auth.AuthenticationStatus {
	if err == nil {
		return auth.StatusAuthenticated
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return auth.StatusProviderUnavailable
	}

	st, ok := status.FromError(err)
	if !ok {
		// Non-gRPC error (e.g. network layer): treat as unavailable.
		return auth.StatusProviderUnavailable
	}

	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled,
		codes.Unauthenticated, codes.PermissionDenied, codes.ResourceExhausted:
		return auth.StatusProviderUnavailable
	case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound,
		codes.Aborted, codes.OutOfRange:
		// Credential and session-state failures. NotFound covers a deleted or
		// expired session during MFA; both are user-visible failures.
		return auth.StatusInvalidCredentials
	default:
		// Unknown codes are server-side failures; never expose details.
		return auth.StatusProviderUnavailable
	}
}
