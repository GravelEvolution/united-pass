//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: ZITADEL public account lifecycle adapter tests
//

package zitadel

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"

	managementv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	objectv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	projectv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type lifecycleUserServiceStub struct {
	createFn        func(*userv2.CreateUserRequest) (*userv2.CreateUserResponse, error)
	deleteFn        func(*userv2.DeleteUserRequest) (*userv2.DeleteUserResponse, error)
	listFn          func(*userv2.ListUsersRequest) (*userv2.ListUsersResponse, error)
	passwordResetFn func(*userv2.PasswordResetRequest) (*userv2.PasswordResetResponse, error)
	setPasswordFn   func(*userv2.SetPasswordRequest) (*userv2.SetPasswordResponse, error)
	verifyEmailFn   func(*userv2.VerifyEmailRequest) (*userv2.VerifyEmailResponse, error)
	getFn           func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error)
}

func (s *lifecycleUserServiceStub) CreateUser(_ context.Context, input *userv2.CreateUserRequest, _ ...grpc.CallOption) (*userv2.CreateUserResponse, error) {
	return s.createFn(input)
}
func (s *lifecycleUserServiceStub) DeleteUser(_ context.Context, input *userv2.DeleteUserRequest, _ ...grpc.CallOption) (*userv2.DeleteUserResponse, error) {
	if s.deleteFn == nil {
		return &userv2.DeleteUserResponse{}, nil
	}
	return s.deleteFn(input)
}
func (s *lifecycleUserServiceStub) ListUsers(_ context.Context, input *userv2.ListUsersRequest, _ ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
	return s.listFn(input)
}
func (s *lifecycleUserServiceStub) PasswordReset(_ context.Context, input *userv2.PasswordResetRequest, _ ...grpc.CallOption) (*userv2.PasswordResetResponse, error) {
	return s.passwordResetFn(input)
}
func (s *lifecycleUserServiceStub) SetPassword(_ context.Context, input *userv2.SetPasswordRequest, _ ...grpc.CallOption) (*userv2.SetPasswordResponse, error) {
	return s.setPasswordFn(input)
}
func (s *lifecycleUserServiceStub) VerifyEmail(_ context.Context, input *userv2.VerifyEmailRequest, _ ...grpc.CallOption) (*userv2.VerifyEmailResponse, error) {
	return s.verifyEmailFn(input)
}
func (s *lifecycleUserServiceStub) GetUserByID(_ context.Context, input *userv2.GetUserByIDRequest, _ ...grpc.CallOption) (*userv2.GetUserByIDResponse, error) {
	return s.getFn(input)
}

type lifecycleProjectServiceStub struct {
	calls int
	err   error
}

func (s *lifecycleProjectServiceStub) GetProjectByID(context.Context, *managementv1.GetProjectByIDRequest, ...grpc.CallOption) (*managementv1.GetProjectByIDResponse, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &managementv1.GetProjectByIDResponse{Project: &projectv1.Project{
		Id: "project_1", Details: &objectv1.ObjectDetails{ResourceOwner: "org_1"},
	}}, nil
}

func lifecycleHumanUser(subject, email string, verified bool) *userv2.User {
	displayName := "Test User"
	return &userv2.User{
		UserId: subject,
		Type: &userv2.User_Human{Human: &userv2.HumanUser{
			UserId:  subject,
			Profile: &userv2.HumanProfile{GivenName: "Test", FamilyName: "User", DisplayName: &displayName},
			Email:   &userv2.HumanEmail{Email: email, IsVerified: verified},
		}},
	}
}

func TestLifecycleRegisterUsesProjectOwnerAndCredentialInputs(t *testing.T) {
	projects := &lifecycleProjectServiceStub{}
	var captured *userv2.CreateUserRequest
	users := &lifecycleUserServiceStub{createFn: func(input *userv2.CreateUserRequest) (*userv2.CreateUserResponse, error) {
		captured = input
		return &userv2.CreateUserResponse{Id: "provider-user-1"}, nil
	}}
	provider := NewLifecycleProvider(users, projects, "project_1")
	input := auth.RegistrationInput{
		Username: "new.user", Email: "user@example.test",
		Password:             auth.NewSecretPassword("correct-horse-12"),
		EmailVerificationURL: "https://portal.example.test/verify-email?code={{.Code}}",
	}
	info, err := provider.Register(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if captured.GetOrganizationId() != "org_1" || captured.GetUsername() != "new.user" ||
		captured.GetHuman().GetPassword().GetPassword() != "correct-horse-12" ||
		captured.GetHuman().GetEmail().GetEmail() != "user@example.test" ||
		captured.GetHuman().GetEmail().GetSendCode().GetUrlTemplate() != input.EmailVerificationURL {
		t.Fatalf("unexpected create request: %+v", captured)
	}
	if info.Subject != "provider-user-1" || info.Email != "user@example.test" {
		t.Fatalf("unexpected provider info: %+v", info)
	}
	if _, err := provider.Register(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if projects.calls != 1 {
		t.Fatalf("project owner lookups = %d, want cached single lookup", projects.calls)
	}
}

func TestLifecycleFindPasswordResetRequiresOneVerifiedUser(t *testing.T) {
	projects := &lifecycleProjectServiceStub{}
	users := &lifecycleUserServiceStub{listFn: func(*userv2.ListUsersRequest) (*userv2.ListUsersResponse, error) {
		return &userv2.ListUsersResponse{Result: []*userv2.User{
			lifecycleHumanUser("provider-user-1", "user@example.test", true),
		}}, nil
	}}
	provider := NewLifecycleProvider(users, projects, "project_1")
	info, err := provider.FindPasswordResetIdentity(context.Background(), "USER@example.test")
	if err != nil || info.Subject != "provider-user-1" || !info.EmailVerified {
		t.Fatalf("info = %+v, err = %v", info, err)
	}

	users.listFn = func(*userv2.ListUsersRequest) (*userv2.ListUsersResponse, error) {
		return &userv2.ListUsersResponse{Result: []*userv2.User{
			lifecycleHumanUser("provider-user-1", "user@example.test", false),
		}}, nil
	}
	if _, err := provider.FindPasswordResetIdentity(context.Background(), "user@example.test"); !errors.Is(err, auth.ErrPublicAccountNotFound) {
		t.Fatalf("unverified user error = %v", err)
	}
}

func TestLifecycleResetPasswordMapsKnownAndAmbiguousOutcomes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "success"},
		{name: "policy rejection", err: status.Error(codes.InvalidArgument, "invalid"), want: auth.ErrLifecycleRejected},
		{name: "deadline ambiguous", err: context.DeadlineExceeded, want: auth.ErrPasswordChangeUnknown},
		{name: "provider unavailable ambiguous", err: status.Error(codes.Unavailable, "down"), want: auth.ErrPasswordChangeUnknown},
		{name: "permission", err: status.Error(codes.PermissionDenied, "denied"), want: auth.ErrProviderUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var captured *userv2.SetPasswordRequest
			users := &lifecycleUserServiceStub{setPasswordFn: func(input *userv2.SetPasswordRequest) (*userv2.SetPasswordResponse, error) {
				captured = input
				return &userv2.SetPasswordResponse{}, test.err
			}}
			provider := NewLifecycleProvider(users, &lifecycleProjectServiceStub{}, "project_1")
			err := provider.ResetPassword(context.Background(), "provider-user-1", "ABC123", auth.NewSecretPassword("new-password-123"))
			if !errors.Is(err, test.want) || (test.want == nil && err != nil) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if captured.GetUserId() != "provider-user-1" || captured.GetNewPassword().GetPassword() != "new-password-123" ||
				captured.GetVerificationCode() != "ABC123" {
				t.Fatalf("unexpected reset request: %+v", captured)
			}
		})
	}
}

func TestLifecycleEmailVerificationRepairsLostProviderResponse(t *testing.T) {
	users := &lifecycleUserServiceStub{
		verifyEmailFn: func(*userv2.VerifyEmailRequest) (*userv2.VerifyEmailResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "already verified")
		},
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return &userv2.GetUserByIDResponse{User: lifecycleHumanUser(
				"provider-user-1", "user@example.test", true,
			)}, nil
		},
	}
	provider := NewLifecycleProvider(users, &lifecycleProjectServiceStub{}, "project_1")
	if err := provider.VerifyRegistrationEmail(
		context.Background(), "provider-user-1", "USER@example.test", "ABC123",
	); err != nil {
		t.Fatalf("readback repair failed: %v", err)
	}
	if err := provider.VerifyRegistrationEmail(
		context.Background(), "provider-user-1", "other@example.test", "ABC123",
	); !errors.Is(err, auth.ErrLifecycleCodeInvalid) {
		t.Fatalf("mismatched verified email error = %v", err)
	}
}
