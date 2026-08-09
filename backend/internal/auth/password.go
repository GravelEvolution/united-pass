//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Password management port contract (ADR-0006 §6)
//

package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// ErrPasswordChangeFailed is the confirmed-failure sentinel of the password
// change path (ADR-0006 §6, amended by ADR-0007 Decision 4): the provider
// definitively rejected the change (rejected policy, invalid arguments,
// unresolvable identity link before the provider call). Zero local side
// effects, epoch unchanged, the old generation resumes validity; the frozen
// contract exposes the stable error provider.password_change_failed.
var ErrPasswordChangeFailed = errors.New("auth: password change failed")

// ErrPasswordChangeUnknown is the ambiguous-outcome sentinel of the password
// change path (ADR-0007 Decision 4): the provider call timed out, its
// transport failed or its response was ambiguous, so the outcome can
// neither be confirmed nor denied. Unknown is treated as committed for
// boundary purposes (fail closed): the epoch advances, re-login is forced
// and the response never reports success.
var ErrPasswordChangeUnknown = errors.New("auth: password change outcome unknown")

// SecretPassword wraps a plaintext password so it can travel from the HTTP
// layer to the provider adapter without ever being printable by accident.
// The value is unexported and every rendering path (%v/%+v/%#v, slog) is
// redacted, mirroring the ProviderSessionToken pattern. The plaintext exists
// only in memory for the duration of the provider call; it is never logged,
// audited or persisted anywhere (ADR-0006 §6).
type SecretPassword struct {
	password string
}

// NewSecretPassword wraps a raw plaintext password.
func NewSecretPassword(password string) SecretPassword {
	return SecretPassword{password: password}
}

// Empty reports whether no password was supplied.
func (p SecretPassword) Empty() bool { return p.password == "" }

// Password returns the raw plaintext password (narrow seam for the provider
// adapter call; never log or persist the returned value).
func (p SecretPassword) Password() string { return p.password }

func (SecretPassword) String() string { return "[redacted password]" }

func (SecretPassword) GoString() string { return "[redacted password]" }

func (SecretPassword) LogValue() slog.Value {
	return slog.StringValue("[redacted password]")
}

// PasswordManager abstracts the provider-side password authority (ADR-0006
// §6). United Pass never stores, hashes or mirrors user passwords; the
// provider performs the change under the backend service account against the
// provider user resolved from the identity link — never from a
// caller-supplied provider identifier. Identity proof is the consumed
// account.password.change reauth grant, so implementations set the new
// password alone and never accept a current password. Implementations
// classify every failure per ADR-0007 Decision 4: a definitive provider
// rejection maps to ErrPasswordChangeFailed; a timeout, transport failure
// or ambiguous response maps to ErrPasswordChangeUnknown; the password
// itself and provider detail are never leaked.
type PasswordManager interface {
	// SetPassword sets the user's password on the provider using the
	// newPassword-only mode (SA privilege; live-proven V-3(a), no
	// fallback). It returns nil on confirmed success,
	// ErrPasswordChangeFailed on confirmed provider rejection and
	// ErrPasswordChangeUnknown when the outcome cannot be determined.
	SetPassword(ctx context.Context, userID identity.UserID, newPassword SecretPassword) error
}
