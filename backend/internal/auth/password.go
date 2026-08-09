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

// ErrPasswordChangeFailed is the single stable failure sentinel of the
// password change path (ADR-0006 §6). Every provider-side failure — an
// unreachable provider, a service-account permission fault, a rejected
// policy or an unresolvable identity link — collapses into it: the frozen
// contract exposes exactly one stable error (provider.password_change_failed),
// fails closed and never pretends success.
var ErrPasswordChangeFailed = errors.New("auth: password change failed")

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
// password alone and never accept a current password. Implementations must
// return only ErrPasswordChangeFailed (plus unexpected internal errors) and
// must never leak provider detail or the password itself.
type PasswordManager interface {
	// SetPassword sets the user's password on the provider using the
	// newPassword-only mode (SA privilege; live-proven V-3(a), no fallback).
	// Any failure maps to ErrPasswordChangeFailed.
	SetPassword(ctx context.Context, userID identity.UserID, newPassword SecretPassword) error
}
