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

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
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
// layer before this call. Every failure — an unresolvable identity link, an
// SA permission fault (the environment must fix the permission, never the
// flow), a policy rejection or a transport error — collapses into
// auth.ErrPasswordChangeFailed: the frozen contract exposes exactly one
// stable error and never leaks provider detail or the password itself.
func (a *Authenticator) SetPassword(ctx context.Context, userID identity.UserID, newPassword auth.SecretPassword) error {
	if newPassword.Empty() {
		return auth.ErrPasswordChangeFailed
	}
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
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
		return auth.ErrPasswordChangeFailed
	}
	// The response carries no session handle, so the frozen re-seal clause
	// takes its "otherwise" branch: the current session's sealed provider
	// credential survives unchanged (ADR-0006 §6 step 4).
	return nil
}
