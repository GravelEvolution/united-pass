//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Public account registration and credential-recovery provider contracts
//

package auth

import (
	"context"
	"errors"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// RegistrationInput contains the values needed to create a provider-owned
// human account. Password remains a redacted secret wrapper and must never be
// logged, persisted or returned.
type RegistrationInput struct {
	Username             string
	Email                string
	Password             SecretPassword
	EmailVerificationURL string
}

// PublicAccountBinding is the exact local/provider binding used by a public
// lifecycle capability. Identifiers supplied by the browser are never used
// to select this binding during verification or password mutation.
type PublicAccountBinding struct {
	UserID           identity.UserID
	Provider         string
	ProviderTenantID string
	ProviderSubject  string
	Email            string
	Status           identity.UserStatus
}

// PublicAccountProvider is the narrow provider seam used by logged-out
// registration, email-verification and password-recovery endpoints. United
// Pass owns the stable local user ID; the provider owns credentials and
// verification codes.
type PublicAccountProvider interface {
	Register(ctx context.Context, input RegistrationInput) (identity.ProviderUserInfo, error)
	DeleteRegisteredUser(ctx context.Context, providerSubject string) error
	FindPasswordResetIdentity(ctx context.Context, identifier string) (identity.ProviderUserInfo, error)
	BeginPasswordReset(ctx context.Context, providerSubject, resetURL string) error
	ResetPassword(ctx context.Context, providerSubject, verificationCode string, password SecretPassword) error
	VerifyRegistrationEmail(ctx context.Context, providerSubject, expectedEmail, verificationCode string) error
}

var (
	// ErrPublicAccountNotFound is intentionally collapsed into the generic
	// password-reset-request response at the HTTP boundary.
	ErrPublicAccountNotFound = errors.New("public account not found")
	// ErrRegistrationConflict covers an existing provider username or email.
	ErrRegistrationConflict = errors.New("registration identity already exists")
	// ErrLifecycleCodeInvalid covers an invalid, expired or already-consumed
	// provider verification code. Provider detail is never exposed.
	ErrLifecycleCodeInvalid = errors.New("account lifecycle verification code invalid")
	// ErrLifecycleRejected covers a provider policy rejection such as a
	// password that does not satisfy the authoritative provider policy.
	ErrLifecycleRejected = errors.New("account lifecycle operation rejected")
)
