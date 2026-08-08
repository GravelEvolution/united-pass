//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the fake factor management seam
//

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func newFactorFake() (*FakeAuthenticator, identity.UserID) {
	f := NewFakeAuthenticator()
	userID := identity.UserID("user-factor")
	f.AddUser(FakeUser{
		UserID:     userID,
		Identifier: "factor@example.com",
		Password:   "pw",
		UserStatus: identity.UserStatusActive,
	})
	return f, userID
}

func TestFakeTOTP_Lifecycle(t *testing.T) {
	f, userID := newFactorFake()
	ctx := context.Background()

	enrollment, err := f.BeginTOTPEnrollment(ctx, userID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if enrollment.Secret == "" || enrollment.OTPAuthURI == "" {
		t.Fatalf("enrollment = %+v, want secret and otpauth URI", enrollment)
	}

	// Double begin fails closed while a pending enrollment exists.
	if _, err := f.BeginTOTPEnrollment(ctx, userID); !errors.Is(err, ErrFactorAlreadySet) {
		t.Fatalf("second begin err = %v, want ErrFactorAlreadySet", err)
	}

	if err := f.ConfirmTOTPEnrollment(ctx, userID, "123456"); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	// Enrolled: begin and confirm both refuse now.
	if _, err := f.BeginTOTPEnrollment(ctx, userID); !errors.Is(err, ErrFactorAlreadySet) {
		t.Fatalf("begin after enroll err = %v, want ErrFactorAlreadySet", err)
	}
	if err := f.ConfirmTOTPEnrollment(ctx, userID, "123456"); !errors.Is(err, ErrFactorNotSet) {
		t.Fatalf("confirm without pending err = %v, want ErrFactorNotSet", err)
	}

	summary, err := f.FactorSummary(ctx, userID)
	if err != nil || !summary.TOTPEnabled {
		t.Fatalf("summary = %+v err=%v, want TOTP enabled", summary, err)
	}

	if err := f.RemoveTOTP(ctx, userID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := f.RemoveTOTP(ctx, userID); !errors.Is(err, ErrFactorNotSet) {
		t.Fatalf("second remove err = %v, want ErrFactorNotSet", err)
	}
	summary, _ = f.FactorSummary(ctx, userID)
	if summary.TOTPEnabled {
		t.Error("TOTP must be disabled after removal")
	}
}

func TestFakeTOTP_FixedCodeEnforced(t *testing.T) {
	f := NewFakeAuthenticator()
	userID := identity.UserID("user-fixed")
	f.AddUser(FakeUser{
		UserID:     userID,
		Identifier: "fixed@example.com",
		Password:   "pw",
		UserStatus: identity.UserStatusActive,
		MFACode:    "654321",
	})
	ctx := context.Background()

	if _, err := f.BeginTOTPEnrollment(ctx, userID); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := f.ConfirmTOTPEnrollment(ctx, userID, "000000"); !errors.Is(err, ErrInvalidFactorCode) {
		t.Fatalf("wrong code err = %v, want ErrInvalidFactorCode", err)
	}
	// The pending enrollment survives a wrong code.
	if err := f.ConfirmTOTPEnrollment(ctx, userID, "654321"); err != nil {
		t.Fatalf("correct code err = %v, want success", err)
	}
}

func TestFakePasskey_Lifecycle(t *testing.T) {
	f, userID := newFactorFake()
	ctx := context.Background()

	enrollment, err := f.BeginPasskeyEnrollment(ctx, userID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if enrollment.PasskeyID == "" {
		t.Fatal("begin must return a passkeyId")
	}
	var options map[string]interface{}
	if err := json.Unmarshal(enrollment.CreationOptions, &options); err != nil {
		t.Fatalf("creation options must be a JSON object: %v", err)
	}

	// Multiple passkeys are independent registrations.
	second, err := f.BeginPasskeyEnrollment(ctx, userID)
	if err != nil {
		t.Fatalf("second begin: %v", err)
	}
	if second.PasskeyID == enrollment.PasskeyID {
		t.Fatal("each enrollment must mint a distinct passkeyId")
	}

	if err := f.ConfirmPasskeyEnrollment(ctx, userID, enrollment.PasskeyID, "MacBook", json.RawMessage(`{"id":"cred"}`)); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// Confirming again fails: the registration is no longer pending.
	if err := f.ConfirmPasskeyEnrollment(ctx, userID, enrollment.PasskeyID, "MacBook", json.RawMessage(`{"id":"cred"}`)); !errors.Is(err, ErrFactorNotSet) {
		t.Fatalf("re-confirm err = %v, want ErrFactorNotSet", err)
	}
	// Unknown passkey IDs fail closed.
	if err := f.ConfirmPasskeyEnrollment(ctx, userID, "pk-unknown", "", json.RawMessage(`{}`)); !errors.Is(err, ErrFactorNotSet) {
		t.Fatalf("unknown confirm err = %v, want ErrFactorNotSet", err)
	}
	// Malformed attestation fails closed.
	if err := f.ConfirmPasskeyEnrollment(ctx, userID, second.PasskeyID, "", json.RawMessage("not-json")); !errors.Is(err, ErrInvalidFactorCode) {
		t.Fatalf("bad attestation err = %v, want ErrInvalidFactorCode", err)
	}

	passkeys, err := f.ListPasskeys(ctx, userID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(passkeys) != 2 {
		t.Fatalf("passkeys = %d, want 2", len(passkeys))
	}
	if passkeys[0].ID != enrollment.PasskeyID || passkeys[0].State != PasskeyStateActive || passkeys[0].Name != "MacBook" {
		t.Errorf("passkeys[0] = %+v, want confirmed MacBook", passkeys[0])
	}

	if err := f.RemovePasskey(ctx, userID, enrollment.PasskeyID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := f.RemovePasskey(ctx, userID, enrollment.PasskeyID); !errors.Is(err, ErrFactorNotSet) {
		t.Fatalf("second remove err = %v, want ErrFactorNotSet", err)
	}
	passkeys, _ = f.ListPasskeys(ctx, userID)
	if len(passkeys) != 1 {
		t.Fatalf("passkeys after remove = %d, want 1", len(passkeys))
	}
}

func TestFakeFactors_UnknownUserFailsClosed(t *testing.T) {
	f := NewFakeAuthenticator()
	ctx := context.Background()

	if _, err := f.BeginTOTPEnrollment(ctx, "ghost"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("begin err = %v, want ErrProviderUnavailable", err)
	}
	if err := f.RemovePasskey(ctx, "ghost", "pk-1"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("remove err = %v, want ErrProviderUnavailable", err)
	}
	if _, err := f.FactorSummary(ctx, "ghost"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("summary err = %v, want ErrProviderUnavailable", err)
	}
}
