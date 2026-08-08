//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: ZITADEL security factor lifecycle adapter (TOTP and passkeys)
//

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

// The Authenticator implements auth.FactorManager: factor writes run under
// the backend service account against the provider-side user resolved from
// the identity link (ADR-0006 §10). No local factor state is kept; every
// read is a provider readback.
var _ auth.FactorManager = (*Authenticator)(nil)

// BeginTOTPEnrollment registers a pending TOTP factor on ZITADEL and returns
// the secret material for the enroll UI. SECURITY: the returned secret and
// otpauth URI are secret-bearing; the caller must deliver them once in the
// begin response with Cache-Control: no-store and never log or persist them.
func (a *Authenticator) BeginTOTPEnrollment(ctx context.Context, userID identity.UserID) (auth.TOTPEnrollment, error) {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return auth.TOTPEnrollment{}, err
	}
	resp, err := a.users.RegisterTOTP(ctx, &userv2.RegisterTOTPRequest{UserId: subject})
	if err != nil {
		return auth.TOTPEnrollment{}, mapFactorWriteError(err)
	}
	if resp.Secret == "" || resp.Uri == "" {
		// Unexpected provider response shape: fail closed, never return a
		// half-initialized enrollment.
		return auth.TOTPEnrollment{}, auth.ErrProviderUnavailable
	}
	return auth.TOTPEnrollment{Secret: resp.Secret, OTPAuthURI: resp.Uri}, nil
}

// ConfirmTOTPEnrollment verifies a TOTP code against the pending enrollment,
// activating the factor. A wrong code maps to auth.ErrInvalidFactorCode; a
// missing enrollment maps to auth.ErrFactorNotSet.
func (a *Authenticator) ConfirmTOTPEnrollment(ctx context.Context, userID identity.UserID, code string) error {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return err
	}
	if code == "" {
		return auth.ErrInvalidFactorCode
	}
	_, err = a.users.VerifyTOTPRegistration(ctx, &userv2.VerifyTOTPRegistrationRequest{
		UserId: subject,
		Code:   code,
	})
	return mapFactorConfirmError(err)
}

// RemoveTOTP removes the TOTP factor. Removing an unenrolled factor maps to
// auth.ErrFactorNotSet (stable non-enumeration 404).
func (a *Authenticator) RemoveTOTP(ctx context.Context, userID identity.UserID) error {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return err
	}
	_, err = a.users.RemoveTOTP(ctx, &userv2.RemoveTOTPRequest{UserId: subject})
	return mapFactorWriteError(err)
}

// BeginPasskeyEnrollment starts a passkey registration on ZITADEL and
// returns the WebAuthn creation options (JSON object) for the browser
// ceremony. The relying-party domain from configuration is required; without
// it no valid challenge can be issued and the call fails closed.
func (a *Authenticator) BeginPasskeyEnrollment(ctx context.Context, userID identity.UserID) (auth.PasskeyEnrollment, error) {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return auth.PasskeyEnrollment{}, err
	}
	if a.domain == "" {
		// Passkey enrollment requires a configured relying-party domain
		// (same policy as passkey login challenges): fail closed.
		return auth.PasskeyEnrollment{}, auth.ErrProviderUnavailable
	}
	resp, err := a.users.RegisterPasskey(ctx, &userv2.RegisterPasskeyRequest{
		UserId: subject,
		Domain: a.domain,
	})
	if err != nil {
		return auth.PasskeyEnrollment{}, mapFactorWriteError(err)
	}
	if resp.PasskeyId == "" || resp.PublicKeyCredentialCreationOptions == nil {
		return auth.PasskeyEnrollment{}, auth.ErrProviderUnavailable
	}
	options, err := resp.PublicKeyCredentialCreationOptions.MarshalJSON()
	if err != nil {
		return auth.PasskeyEnrollment{}, fmt.Errorf("zitadel: encode passkey creation options: %w", err)
	}
	return auth.PasskeyEnrollment{PasskeyID: resp.PasskeyId, CreationOptions: options}, nil
}

// ConfirmPasskeyEnrollment verifies the browser attestation for the pending
// registration identified by passkeyID. The attestation payload is
// forwarded to the provider as-is and never logged.
func (a *Authenticator) ConfirmPasskeyEnrollment(ctx context.Context, userID identity.UserID, passkeyID, name string, publicKeyCredential json.RawMessage) error {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return err
	}
	if passkeyID == "" || len(publicKeyCredential) == 0 {
		return auth.ErrInvalidFactorCode
	}
	credential, err := structFromJSON(publicKeyCredential)
	if err != nil {
		return auth.ErrInvalidFactorCode
	}
	_, err = a.users.VerifyPasskeyRegistration(ctx, &userv2.VerifyPasskeyRegistrationRequest{
		UserId:              subject,
		PasskeyId:           passkeyID,
		PublicKeyCredential: credential,
		PasskeyName:         name,
	})
	return mapFactorConfirmError(err)
}

// RemovePasskey deletes one registered passkey. An unknown passkeyID maps to
// auth.ErrFactorNotSet (stable 404, non-enumeration).
func (a *Authenticator) RemovePasskey(ctx context.Context, userID identity.UserID, passkeyID string) error {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return err
	}
	if passkeyID == "" {
		return auth.ErrFactorNotSet
	}
	_, err = a.users.RemovePasskey(ctx, &userv2.RemovePasskeyRequest{
		UserId:    subject,
		PasskeyId: passkeyID,
	})
	return mapFactorWriteError(err)
}

// ListPasskeys returns the user's registered passkeys from the provider
// (readback only). Removed entries are never returned.
func (a *Authenticator) ListPasskeys(ctx context.Context, userID identity.UserID) ([]auth.PasskeyInfo, error) {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return a.listPasskeysBySubject(ctx, subject)
}

// FactorSummary returns the combined factor state for GET /me/security:
// password and TOTP flags from ListAuthenticationMethodTypes plus the
// passkey readback. Recovery codes are excluded by architecture (ADR-0006 §9).
func (a *Authenticator) FactorSummary(ctx context.Context, userID identity.UserID) (auth.FactorSummary, error) {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return auth.FactorSummary{}, err
	}
	methods, err := a.userAuthMethods(ctx, subject)
	if err != nil {
		if errors.Is(err, errProviderPermission) {
			// SA authorization failure: the distinct provider.forbidden class,
			// never collapsed into provider.unavailable (ADR-0006 §10).
			return auth.FactorSummary{}, auth.ErrProviderForbidden
		}
		return auth.FactorSummary{}, err
	}
	passkeys, err := a.listPasskeysBySubject(ctx, subject)
	if err != nil {
		return auth.FactorSummary{}, err
	}
	return auth.FactorSummary{
		PasswordSet: hasMethod(methods, userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSWORD),
		TOTPEnabled: hasMethod(methods, userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_TOTP),
		Passkeys:    passkeys,
	}, nil
}

// resolveProviderUser resolves the provider-side user ID for factor
// operations from the identity link bound to the stable user ID — never from
// a caller-supplied identifier, so factor writes can only target the
// session's own account. A missing link is a server-side inconsistency and
// fails closed as provider unavailable.
func (a *Authenticator) resolveProviderUser(ctx context.Context, userID identity.UserID) (string, error) {
	link, err := a.linker.GetIdentityLinkByUserID(ctx, a.provider, a.tenantID, userID)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return "", auth.ErrProviderUnavailable
		}
		return "", err
	}
	return link.ProviderSubject, nil
}

// listPasskeysBySubject reads the provider passkey list for a resolved
// provider user ID.
func (a *Authenticator) listPasskeysBySubject(ctx context.Context, subject string) ([]auth.PasskeyInfo, error) {
	resp, err := a.users.ListPasskeys(ctx, &userv2.ListPasskeysRequest{UserId: subject})
	if err != nil {
		return nil, mapFactorWriteError(err)
	}
	passkeys := make([]auth.PasskeyInfo, 0, len(resp.Result))
	for _, key := range resp.Result {
		if key == nil || key.State == userv2.AuthFactorState_AUTH_FACTOR_STATE_REMOVED {
			continue
		}
		state := auth.PasskeyStatePending
		if key.State == userv2.AuthFactorState_AUTH_FACTOR_STATE_READY {
			state = auth.PasskeyStateActive
		}
		passkeys = append(passkeys, auth.PasskeyInfo{
			ID:    key.Id,
			Name:  key.Name,
			State: state,
		})
	}
	return passkeys, nil
}
