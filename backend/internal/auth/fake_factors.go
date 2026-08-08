//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: In-memory fake factor management for tests and development
//

package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// The FakeAuthenticator also implements FactorManager so development and
// HTTP tests can exercise the security-factor endpoints without a real
// provider. Factor state is kept in memory per user; login MFA behavior is
// intentionally unchanged (configured per FakeUser at setup time).
//
// SECURITY: test-only; never used in production.
var _ FactorManager = (*FakeAuthenticator)(nil)

// fakeFactorState is the in-memory factor state of one fake user.
type fakeFactorState struct {
	totpEnabled bool
	totpPending bool
	passkeys    []FakePasskey
	passkeySeq  int
}

// FakePasskey is one registered passkey of a fake user.
type FakePasskey struct {
	ID    string
	Name  string
	State PasskeyState
}

// factorState returns the mutable factor state of a configured fake user,
// creating it on first use. Callers must hold the write lock.
func (f *FakeAuthenticator) factorState(userID identity.UserID) (*fakeFactorState, bool) {
	if f.factorStates == nil {
		f.factorStates = make(map[identity.UserID]*fakeFactorState)
	}
	state, ok := f.factorStates[userID]
	if !ok {
		state = &fakeFactorState{}
		f.factorStates[userID] = state
	}
	return state, f.hasUser(userID)
}

// hasUser reports whether a configured fake user matches the stable user ID.
// Callers must hold at least the read lock.
func (f *FakeAuthenticator) hasUser(userID identity.UserID) bool {
	for _, user := range f.users {
		if user.UserID == userID {
			return true
		}
	}
	return false
}

// BeginTOTPEnrollment starts a pending TOTP enrollment and returns
// deterministic secret material for the enroll UI.
func (f *FakeAuthenticator) BeginTOTPEnrollment(_ context.Context, userID identity.UserID) (TOTPEnrollment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, known := f.factorState(userID)
	if !known {
		return TOTPEnrollment{}, ErrProviderUnavailable
	}
	if state.totpEnabled || state.totpPending {
		return TOTPEnrollment{}, ErrFactorAlreadySet
	}
	state.totpPending = true
	secret := "FAKETOTP" + string(userID)
	return TOTPEnrollment{
		Secret:     secret,
		OTPAuthURI: "otpauth://totp/UnitedPass:" + string(userID) + "?secret=" + secret + "&issuer=UnitedPass",
	}, nil
}

// ConfirmTOTPEnrollment activates the pending TOTP enrollment. The accepted
// code is the user's configured MFACode; any non-empty code is accepted when
// the user has no fixed code configured.
func (f *FakeAuthenticator) ConfirmTOTPEnrollment(_ context.Context, userID identity.UserID, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, known := f.factorState(userID)
	if !known {
		return ErrProviderUnavailable
	}
	if !state.totpPending {
		return ErrFactorNotSet
	}
	if code == "" {
		return ErrInvalidFactorCode
	}
	for _, user := range f.users {
		if user.UserID == userID && user.MFACode != "" && user.MFACode != code {
			return ErrInvalidFactorCode
		}
	}
	state.totpPending = false
	state.totpEnabled = true
	return nil
}

// RemoveTOTP removes the TOTP factor (also discards a pending enrollment).
func (f *FakeAuthenticator) RemoveTOTP(_ context.Context, userID identity.UserID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, known := f.factorState(userID)
	if !known {
		return ErrProviderUnavailable
	}
	if !state.totpEnabled && !state.totpPending {
		return ErrFactorNotSet
	}
	state.totpEnabled = false
	state.totpPending = false
	return nil
}

// BeginPasskeyEnrollment starts a pending passkey registration and returns
// deterministic creation options for the browser ceremony.
func (f *FakeAuthenticator) BeginPasskeyEnrollment(_ context.Context, userID identity.UserID) (PasskeyEnrollment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, known := f.factorState(userID)
	if !known {
		return PasskeyEnrollment{}, ErrProviderUnavailable
	}
	state.passkeySeq++
	passkeyID := fmt.Sprintf("fake-passkey-%s-%d", string(userID), state.passkeySeq)
	state.passkeys = append(state.passkeys, FakePasskey{ID: passkeyID, State: PasskeyStatePending})
	options := json.RawMessage(fmt.Sprintf(`{"challenge":"fake-challenge-%d","rp":{"id":"fake.local","name":"United Pass"}}`, state.passkeySeq))
	return PasskeyEnrollment{PasskeyID: passkeyID, CreationOptions: options}, nil
}

// ConfirmPasskeyEnrollment activates the pending registration identified by
// passkeyID. Any non-empty attestation JSON object is accepted.
func (f *FakeAuthenticator) ConfirmPasskeyEnrollment(_ context.Context, userID identity.UserID, passkeyID, name string, publicKeyCredential json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, known := f.factorState(userID)
	if !known {
		return ErrProviderUnavailable
	}
	if passkeyID == "" || len(publicKeyCredential) == 0 {
		return ErrInvalidFactorCode
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(publicKeyCredential, &decoded); err != nil {
		return ErrInvalidFactorCode
	}
	for i := range state.passkeys {
		if state.passkeys[i].ID == passkeyID && state.passkeys[i].State == PasskeyStatePending {
			state.passkeys[i].State = PasskeyStateActive
			state.passkeys[i].Name = name
			return nil
		}
	}
	return ErrFactorNotSet
}

// RemovePasskey deletes one registered passkey.
func (f *FakeAuthenticator) RemovePasskey(_ context.Context, userID identity.UserID, passkeyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, known := f.factorState(userID)
	if !known {
		return ErrProviderUnavailable
	}
	if passkeyID == "" {
		return ErrFactorNotSet
	}
	for i := range state.passkeys {
		if state.passkeys[i].ID == passkeyID {
			state.passkeys = append(state.passkeys[:i], state.passkeys[i+1:]...)
			return nil
		}
	}
	return ErrFactorNotSet
}

// ListPasskeys returns the user's registered passkeys.
func (f *FakeAuthenticator) ListPasskeys(_ context.Context, userID identity.UserID) ([]PasskeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, known := f.factorState(userID)
	if !known {
		return nil, ErrProviderUnavailable
	}
	passkeys := make([]PasskeyInfo, 0, len(state.passkeys))
	for _, key := range state.passkeys {
		passkeys = append(passkeys, PasskeyInfo{ID: key.ID, Name: key.Name, State: key.State})
	}
	return passkeys, nil
}

// FactorSummary returns the combined factor state for GET /me/security.
// Fake users always have a password configured, so PasswordSet is true for
// every known user.
func (f *FakeAuthenticator) FactorSummary(_ context.Context, userID identity.UserID) (FactorSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, known := f.factorState(userID)
	if !known {
		return FactorSummary{}, ErrProviderUnavailable
	}
	passkeys := make([]PasskeyInfo, 0, len(state.passkeys))
	for _, key := range state.passkeys {
		passkeys = append(passkeys, PasskeyInfo{ID: key.ID, Name: key.Name, State: key.State})
	}
	return FactorSummary{
		PasswordSet: true,
		TOTPEnabled: state.totpEnabled,
		Passkeys:    passkeys,
	}, nil
}
