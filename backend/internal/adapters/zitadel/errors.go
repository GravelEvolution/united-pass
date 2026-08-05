package zitadel

import (
	"context"
	"errors"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
