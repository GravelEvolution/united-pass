// Package auth also provides a FakeAuthenticator for testing and local
// development when no real authentication provider is configured. This fake
// is NOT a production implementation and must never be used as one.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// BeginPasswordAuthentication checks the identifier and password against
// configured fake users. If MFA is required, it returns an MFARequired result
// with a deterministic MFA token derived from the user ID.
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
		mfaToken := generateFakeMFAToken(string(user.UserID))
		return AuthenticationResult{
			Status:           StatusMFARequired,
			UserID:           user.UserID,
			Provider:         user.Provider,
			MFAToken:         mfaToken,
			AvailableMethods: user.MFAMethods,
		}, nil
	}

	return AuthenticationResult{
		Status:                   StatusAuthenticated,
		UserID:                   user.UserID,
		Provider:                 user.Provider,
		ProviderSessionReference: user.SessionRef,
		AuthenticationMethods:    []AuthenticationMethod{MethodPassword},
	}, nil
}

// CompleteMFA verifies the MFA code against the configured fake user.
func (f *FakeAuthenticator) CompleteMFA(
	ctx context.Context,
	input MFAChallengeInput,
) (AuthenticationResult, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Find the user by matching the MFA token.
	for _, user := range f.users {
		if !user.RequiresMFA {
			continue
		}
		expectedToken := generateFakeMFAToken(string(user.UserID))
		if expectedToken != input.MFAToken {
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

// generateFakeMFAToken creates a deterministic MFA token from a user ID for
// the fake authenticator. This is NOT how real MFA tokens are generated —
// real tokens use crypto/rand.
func generateFakeMFAToken(userID string) string {
	h := sha256.Sum256([]byte("mfa:" + userID))
	return hex.EncodeToString(h[:])
}
