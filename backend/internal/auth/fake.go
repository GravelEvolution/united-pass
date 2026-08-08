//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: In-memory fake authenticator for tests and development
//

// Package auth also provides a FakeAuthenticator for testing and local
// development when no real authentication provider is configured. This fake
// is NOT a production implementation and must never be used as one.
package auth

import (
	"context"
	"errors"
	"sync"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// ErrFakeNotConfigured is returned when the fake authenticator has no user
// matching the given identifier.
var ErrFakeNotConfigured = errors.New("fake authenticator: no matching user")

// FakeUser is a user configured on the FakeAuthenticator for testing.
type FakeUser struct {
	UserID      identity.UserID
	Identifier  string
	Password    string // plaintext, only for testing — never in production
	UserStatus  identity.UserStatus
	Provider    string
	SessionRef  string
	RequiresMFA bool
	MFAMethods  []MFAMethod
	MFACode     string // fixed TOTP code for testing
}

// FakeAuthenticator is a test-only implementation of Authenticator. It holds
// users in memory and does not call any external provider. It is safe for
// concurrent use.
//
// SECURITY: This type must never be used in production. It exists solely so
// that Phase 1 HTTP and session tests can run without a real provider.
type FakeAuthenticator struct {
	mu    sync.RWMutex
	users map[string]FakeUser // keyed by identifier
	// factorStates holds the mutable security-factor state (TOTP/passkey
	// lifecycle) per stable user ID; lazily initialized by the factor
	// methods (fake_factors.go).
	factorStates map[identity.UserID]*fakeFactorState
}

// NewFakeAuthenticator creates an empty FakeAuthenticator.
func NewFakeAuthenticator() *FakeAuthenticator {
	return &FakeAuthenticator{
		users: make(map[string]FakeUser),
	}
}

// AddUser registers a user on the fake authenticator for testing.
func (f *FakeAuthenticator) AddUser(u FakeUser) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[u.Identifier] = u
}

// fakeSessionToken derives the deterministic fake provider session token of
// a session reference. Authenticated results carry it so the session
// service seals a Version-2 provider session credential exactly like the
// real provider path (ADR-0005 §3).
func fakeSessionToken(sessionRef string) string {
	if sessionRef == "" {
		return ""
	}
	return "fake-token-" + sessionRef
}

// BeginPasswordAuthentication checks the identifier and password against
// configured fake users. If MFA is required, it returns an MFARequired result
// whose ProviderSessionID references the fake provider session; the HTTP layer
// generates the opaque MFA token returned to the browser.
func (f *FakeAuthenticator) BeginPasswordAuthentication(
	ctx context.Context,
	input PasswordAuthenticationInput,
) (AuthenticationResult, error) {
	f.mu.RLock()
	user, ok := f.users[input.Identifier]
	f.mu.RUnlock()

	if !ok || user.Password != input.Password {
		return AuthenticationResult{Status: StatusInvalidCredentials}, nil
	}

	if !user.UserStatus.CanAuthenticate() {
		return AuthenticationResult{Status: StatusLocked}, nil
	}

	if user.RequiresMFA {
		return AuthenticationResult{
			Status:            StatusMFARequired,
			UserID:            user.UserID,
			Provider:          user.Provider,
			ProviderSessionID: user.SessionRef,
			AvailableMethods:  user.MFAMethods,
		}, nil
	}

	return AuthenticationResult{
		Status:                   StatusAuthenticated,
		UserID:                   user.UserID,
		Provider:                 user.Provider,
		ProviderSessionReference: user.SessionRef,
		ProviderSessionToken:     NewProviderSessionToken(fakeSessionToken(user.SessionRef)),
		AuthenticationMethods:    []AuthenticationMethod{MethodPassword},
	}, nil
}

// CompleteMFA verifies the MFA code against the configured fake user. The
// user is located by the provider session ID supplied from the stored
// challenge (never from the browser).
func (f *FakeAuthenticator) CompleteMFA(
	ctx context.Context,
	input MFAChallengeInput,
) (AuthenticationResult, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, user := range f.users {
		if !user.RequiresMFA {
			continue
		}
		if user.SessionRef != input.ProviderSessionID {
			continue
		}

		// Verify the code.
		if input.Method == MFAMethodTOTP {
			if input.Code != user.MFACode {
				return AuthenticationResult{Status: StatusInvalidCredentials}, nil
			}
		} else if input.Method == MFAMethodRecovery {
			if input.Code != user.MFACode {
				return AuthenticationResult{Status: StatusInvalidCredentials}, nil
			}
		}
		// Passkey always succeeds in the fake (no real WebAuthn verification).

		return AuthenticationResult{
			Status:                   StatusAuthenticated,
			UserID:                   user.UserID,
			Provider:                 user.Provider,
			ProviderSessionReference: user.SessionRef,
			ProviderSessionToken:     NewProviderSessionToken(fakeSessionToken(user.SessionRef)),
			AuthenticationMethods:    []AuthenticationMethod{MethodPassword, AuthenticationMethod(input.Method)},
		}, nil
	}

	return AuthenticationResult{Status: StatusExpired}, nil
}

// RevokeProviderSession is a no-op in the fake authenticator.
func (f *FakeAuthenticator) RevokeProviderSession(
	ctx context.Context,
	sessionReference string,
) error {
	return nil
}

// VerifyUserPassword verifies the password of an already-known user for
// reauthentication (ADR-0004 §7). The user is located by the stable United
// Pass user ID — never by a caller-supplied identifier — so a reauthenticating
// session can never be redirected against another account. Status semantics
// match BeginPasswordAuthentication.
func (f *FakeAuthenticator) VerifyUserPassword(
	ctx context.Context,
	userID identity.UserID,
	password string,
) (AuthenticationResult, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, user := range f.users {
		if user.UserID != userID {
			continue
		}
		if user.Password != password {
			return AuthenticationResult{Status: StatusInvalidCredentials}, nil
		}
		if !user.UserStatus.CanAuthenticate() {
			return AuthenticationResult{Status: StatusLocked}, nil
		}
		if user.RequiresMFA {
			return AuthenticationResult{
				Status:            StatusMFARequired,
				UserID:            user.UserID,
				Provider:          user.Provider,
				ProviderSessionID: user.SessionRef,
				AvailableMethods:  user.MFAMethods,
			}, nil
		}
		return AuthenticationResult{
			Status:                   StatusAuthenticated,
			UserID:                   user.UserID,
			Provider:                 user.Provider,
			ProviderSessionReference: user.SessionRef,
			ProviderSessionToken:     NewProviderSessionToken(fakeSessionToken(user.SessionRef)),
			AuthenticationMethods:    []AuthenticationMethod{MethodPassword},
		}, nil
	}

	// No fake user matches the session user: fail closed with a generic
	// credential error so no account state is revealed.
	return AuthenticationResult{Status: StatusInvalidCredentials}, nil
}
