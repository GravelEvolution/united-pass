//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the ZITADEL password adapter (ADR-0006 §6)
//

package zitadel

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
)

// TestSetPassword_NewPasswordOnly pins the single frozen provider mode
// (ADR-0006 §6 step 3): the SA-privileged call carries newPassword only —
// never a current password and never a verification code — against the
// provider user resolved from the identity link.
func TestSetPassword_NewPasswordOnly(t *testing.T) {
	var got *userv2.SetPasswordRequest
	u := &fakeUserService{
		setPasswordFn: func(in *userv2.SetPasswordRequest) (*userv2.SetPasswordResponse, error) {
			got = in
			return &userv2.SetPasswordResponse{}, nil
		},
	}
	a := factorAuth(t, u, "")

	if err := a.SetPassword(context.Background(), "user-1", auth.NewSecretPassword("brand-new-secret")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if got == nil {
		t.Fatal("provider SetPassword was never called")
	}
	if got.UserId != factorSubject {
		t.Errorf("provider user = %q, want %q (resolved from identity link)", got.UserId, factorSubject)
	}
	if got.NewPassword == nil || got.NewPassword.Password != "brand-new-secret" {
		t.Fatal("request must carry the new password")
	}
	if got.NewPassword.ChangeRequired {
		t.Error("ChangeRequired must stay false")
	}
	if got.Verification != nil {
		t.Error("the frozen mode sends no Verification: no current password, no reset code")
	}
	if _, isCurrent := got.Verification.(*userv2.SetPasswordRequest_CurrentPassword); isCurrent {
		t.Error("currentPassword must never be threaded into the provider call")
	}
}

// TestSetPassword_ProviderErrorMapsToStableSentinel pins fail-closed error
// classification: every provider rejection collapses into the single stable
// sentinel — never provider detail, never a user-class error.
func TestSetPassword_ProviderErrorMapsToStableSentinel(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"policy rejection", grpcErr(codes.InvalidArgument, "COMMAND-x password policy violated")},
		{"sa permission fault", grpcErr(codes.NotFound, "AUTHZ-123 permission denied")},
		{"explicit forbidden", grpcErr(codes.PermissionDenied, "AUTHZ-456 forbidden")},
		{"unknown user", grpcErr(codes.NotFound, "USER-x not found")},
		{"transport failure", grpcErr(codes.Unavailable, "connection refused")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &fakeUserService{
				setPasswordFn: func(*userv2.SetPasswordRequest) (*userv2.SetPasswordResponse, error) {
					return nil, tc.err
				},
			}
			a := factorAuth(t, u, "")
			if err := a.SetPassword(context.Background(), "user-1", auth.NewSecretPassword("brand-new-secret")); !errors.Is(err, auth.ErrPasswordChangeFailed) {
				t.Fatalf("err = %v, want ErrPasswordChangeFailed", err)
			}
		})
	}
}

// TestSetPassword_UnresolvableLinkFailsClosed covers a session user without
// an identity link: the change fails closed with the stable sentinel and the
// provider is never called.
func TestSetPassword_UnresolvableLinkFailsClosed(t *testing.T) {
	called := false
	u := &fakeUserService{
		setPasswordFn: func(*userv2.SetPasswordRequest) (*userv2.SetPasswordResponse, error) {
			called = true
			return &userv2.SetPasswordResponse{}, nil
		},
	}
	linker := &fakeLinker{linkErr: identity.ErrUserNotFound}
	a := NewAuthenticator(&fakeSessionService{}, u, linker, "tenant-test", "", nil)

	if err := a.SetPassword(context.Background(), "user-1", auth.NewSecretPassword("brand-new-secret")); !errors.Is(err, auth.ErrPasswordChangeFailed) {
		t.Fatalf("err = %v, want ErrPasswordChangeFailed", err)
	}
	if called {
		t.Error("the provider must never be called when the identity link is missing")
	}
}

// TestSetPassword_EmptyPasswordFailsClosed covers the empty-password guard:
// the provider is never called.
func TestSetPassword_EmptyPasswordFailsClosed(t *testing.T) {
	called := false
	u := &fakeUserService{
		setPasswordFn: func(*userv2.SetPasswordRequest) (*userv2.SetPasswordResponse, error) {
			called = true
			return &userv2.SetPasswordResponse{}, nil
		},
	}
	a := factorAuth(t, u, "")

	if err := a.SetPassword(context.Background(), "user-1", auth.NewSecretPassword("")); !errors.Is(err, auth.ErrPasswordChangeFailed) {
		t.Fatalf("err = %v, want ErrPasswordChangeFailed", err)
	}
	if called {
		t.Error("the provider must never be called with an empty password")
	}
}
