//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: ZITADEL password management adapter (newPassword-only, ADR-0006 §6)
//

package zitadel

import (
	"context"
	"errors"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The Authenticator implements auth.PasswordManager: the password change runs
// under the backend service account against the provider-side user resolved
// from the identity link (ADR-0006 §6). United Pass never stores, hashes or
// mirrors passwords — the provider is the sole password authority.
var _ auth.PasswordManager = (*Authenticator)(nil)

// SetPassword sets the user's password on ZITADEL in the single frozen mode:
// the service account supplies newPassword only — no currentPassword, no
// verification code (V-3(a), live-proven; no fallback exists). Identity proof
// is the consumed account.password.change reauth grant, verified by the HTTP
// layer before this call. United Pass never stores, hashes or mirrors
// passwords — the provider is the sole password authority.
//
// Errors follow the ADR-0007 Decision 4 three-way classification:
//   - nil: the provider confirmed the change;
//   - auth.ErrPasswordChangeFailed: the provider definitively rejected the
//     change (a business error), or the provider was never called at all
//     (empty password guard, unresolvable identity link); zero local side
//     effects follow;
//   - auth.ErrPasswordChangeUnknown: a transport-level failure, timeout or
//     ambiguous response — the call may or may not have committed, and the
//     security boundary treats it as committed (fail closed).
//
// Provider detail and the password itself are never leaked.
func (a *Authenticator) SetPassword(ctx context.Context, userID identity.UserID, newPassword auth.SecretPassword) error {
	if newPassword.Empty() {
		return auth.ErrPasswordChangeFailed
	}
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		// The provider was never called: an unresolvable identity link or
		// an SA permission fault (the environment must fix the permission,
		// never the flow) is a definitive rejection of the change request
		// itself — confirmed failure, zero local side effects.
		return auth.ErrPasswordChangeFailed
	}
	_, err = a.users.SetPassword(ctx, &userv2.SetPasswordRequest{
		UserId: subject,
		NewPassword: &userv2.Password{
			Password:       newPassword.Password(),
			ChangeRequired: false,
		},
		// Verification stays nil: the SA-privileged newPassword-only mode.
	})
	if err != nil {
		return mapPasswordChangeError(err)
	}
	// The response carries no session handle, so the frozen re-seal clause
	// takes its "otherwise" branch: the current session's sealed provider
	// credential survives unchanged (ADR-0006 §6 step 4).
	return nil
}

// mapPasswordChangeError classifies a provider SetPassword error per
// ADR-0007 Decision 4. Transport-level failures, timeouts and ambiguous
// outcomes map to auth.ErrPasswordChangeUnknown (the call may or may not
// have committed; there is no local readback to disambiguate, and none is
// introduced). Every definitive business rejection — policy violations,
// permission faults, unknown users, quota refusals — maps to
// auth.ErrPasswordChangeFailed: the provider answered, and the answer was
// "not committed".
func mapPasswordChangeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return auth.ErrPasswordChangeUnknown
	}
	st, ok := status.FromError(err)
	if !ok {
		// Non-gRPC error (network layer): the outcome is undecidable.
		return auth.ErrPasswordChangeUnknown
	}
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled,
		codes.Internal, codes.DataLoss, codes.Unknown:
		// Transport-level / ambiguous: the commit state cannot be known.
		return auth.ErrPasswordChangeUnknown
	default:
		// Definitive business rejection: the change did not commit.
		return auth.ErrPasswordChangeFailed
	}
}
