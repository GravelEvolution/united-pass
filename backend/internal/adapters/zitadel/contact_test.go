//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Unit tests for ZITADEL verified-contact orchestration
//

package zitadel

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func contactTestAuthenticator(t *testing.T, users *fakeUserService) *Authenticator {
	t.Helper()
	return newTestAuth(t, &fakeSessionService{}, users, &fakeLinker{
		link: identity.IdentityLink{
			UserID:          "user-local-contact",
			Provider:        ProviderName,
			ProviderSubject: "provider-contact-user",
		},
	})
}

func TestBeginContactChangesUseExactLinkedProviderSubject(t *testing.T) {
	users := &fakeUserService{}
	users.setEmailFn = func(in *userv2.SetEmailRequest) (*userv2.SetEmailResponse, error) {
		if in.UserId != "provider-contact-user" || in.Email != "new@example.com" {
			t.Fatalf("email request = %+v", in)
		}
		if in.GetSendCode() == nil {
			t.Fatal("email change must ask the provider to send a verification code")
		}
		return &userv2.SetEmailResponse{}, nil
	}
	users.setPhoneFn = func(in *userv2.SetPhoneRequest) (*userv2.SetPhoneResponse, error) {
		if in.UserId != "provider-contact-user" || in.Phone != "+8613800138000" {
			t.Fatalf("phone request = %+v", in)
		}
		if in.GetSendCode() == nil {
			t.Fatal("phone change must ask the provider to send a verification code")
		}
		return &userv2.SetPhoneResponse{}, nil
	}
	authenticator := contactTestAuthenticator(t, users)

	if err := authenticator.BeginEmailChange(
		context.Background(), "user-local-contact", "new@example.com",
	); err != nil {
		t.Fatalf("begin email change: %v", err)
	}
	if err := authenticator.BeginPhoneChange(
		context.Background(), "user-local-contact", "+8613800138000",
	); err != nil {
		t.Fatalf("begin phone change: %v", err)
	}
}

func TestVerifyContactChangesMapInvalidCodes(t *testing.T) {
	users := &fakeUserService{
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
		verifyEmailFn: func(in *userv2.VerifyEmailRequest) (*userv2.VerifyEmailResponse, error) {
			if in.UserId != "provider-contact-user" || in.VerificationCode != "bad-code" {
				t.Fatalf("email verification request = %+v", in)
			}
			return nil, status.Error(codes.InvalidArgument, "invalid code")
		},
		verifyPhoneFn: func(in *userv2.VerifyPhoneRequest) (*userv2.VerifyPhoneResponse, error) {
			if in.UserId != "provider-contact-user" || in.VerificationCode != "bad-code" {
				t.Fatalf("phone verification request = %+v", in)
			}
			return nil, status.Error(codes.FailedPrecondition, "expired code")
		},
	}
	authenticator := contactTestAuthenticator(t, users)

	if err := authenticator.VerifyEmailChange(
		context.Background(), "user-local-contact", "new@example.com", "bad-code",
	); !errors.Is(err, identity.ErrContactCodeInvalid) {
		t.Fatalf("verify email error = %v, want invalid code", err)
	}
	if err := authenticator.VerifyPhoneChange(
		context.Background(), "user-local-contact", "+8613800138000", "bad-code",
	); !errors.Is(err, identity.ErrContactCodeInvalid) {
		t.Fatalf("verify phone error = %v, want invalid code", err)
	}
}

func TestVerifyContactChangesRepairLostProviderResponses(t *testing.T) {
	displayName := "Contact User"
	users := &fakeUserService{
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return &userv2.GetUserByIDResponse{User: &userv2.User{
				UserId: "provider-contact-user",
				Type: &userv2.User_Human{Human: &userv2.HumanUser{
					UserId:  "provider-contact-user",
					Profile: &userv2.HumanProfile{DisplayName: &displayName},
					Email:   &userv2.HumanEmail{Email: "new@example.com", IsVerified: true},
					Phone:   &userv2.HumanPhone{Phone: "+8613800138000", IsVerified: true},
				}},
			}}, nil
		},
		verifyEmailFn: func(*userv2.VerifyEmailRequest) (*userv2.VerifyEmailResponse, error) {
			return nil, context.DeadlineExceeded
		},
		verifyPhoneFn: func(*userv2.VerifyPhoneRequest) (*userv2.VerifyPhoneResponse, error) {
			return nil, context.DeadlineExceeded
		},
	}
	authenticator := contactTestAuthenticator(t, users)

	if err := authenticator.VerifyEmailChange(
		context.Background(), "user-local-contact", "new@example.com", "123456",
	); err != nil {
		t.Fatalf("email readback repair: %v", err)
	}
	if err := authenticator.VerifyPhoneChange(
		context.Background(), "user-local-contact", "+8613800138000", "123456",
	); err != nil {
		t.Fatalf("phone readback repair: %v", err)
	}
}
