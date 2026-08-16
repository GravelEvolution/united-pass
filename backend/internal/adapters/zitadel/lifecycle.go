//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: ZITADEL registration, email-verification and password-reset adapter
//

package zitadel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	managementv1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	objectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type lifecycleUserService interface {
	CreateUser(context.Context, *userv2.CreateUserRequest, ...grpc.CallOption) (*userv2.CreateUserResponse, error)
	DeleteUser(context.Context, *userv2.DeleteUserRequest, ...grpc.CallOption) (*userv2.DeleteUserResponse, error)
	ListUsers(context.Context, *userv2.ListUsersRequest, ...grpc.CallOption) (*userv2.ListUsersResponse, error)
	PasswordReset(context.Context, *userv2.PasswordResetRequest, ...grpc.CallOption) (*userv2.PasswordResetResponse, error)
	SetPassword(context.Context, *userv2.SetPasswordRequest, ...grpc.CallOption) (*userv2.SetPasswordResponse, error)
	VerifyEmail(context.Context, *userv2.VerifyEmailRequest, ...grpc.CallOption) (*userv2.VerifyEmailResponse, error)
	GetUserByID(context.Context, *userv2.GetUserByIDRequest, ...grpc.CallOption) (*userv2.GetUserByIDResponse, error)
}

type lifecycleProjectService interface {
	GetProjectByID(context.Context, *managementv1.GetProjectByIDRequest, ...grpc.CallOption) (*managementv1.GetProjectByIDResponse, error)
}

// LifecycleProvider implements auth.PublicAccountProvider. The organization
// is derived from the configured provisioning project's resource owner, so a
// second independently configured organization ID cannot drift from the OAuth
// project used by this deployment.
type LifecycleProvider struct {
	users     lifecycleUserService
	projects  lifecycleProjectService
	projectID string

	organizationMu sync.Mutex
	organizationID string
}

var _ auth.PublicAccountProvider = (*LifecycleProvider)(nil)

func NewLifecycleProvider(
	users lifecycleUserService,
	projects lifecycleProjectService,
	projectID string,
) *LifecycleProvider {
	return &LifecycleProvider{users: users, projects: projects, projectID: projectID}
}

func (p *LifecycleProvider) Register(ctx context.Context, input auth.RegistrationInput) (identity.ProviderUserInfo, error) {
	organizationID, err := p.resolveOrganizationID(ctx)
	if err != nil {
		return identity.ProviderUserInfo{}, auth.ErrProviderUnavailable
	}
	displayName := input.Username
	verificationURL := input.EmailVerificationURL
	response, err := p.users.CreateUser(ctx, &userv2.CreateUserRequest{
		OrganizationId: organizationID,
		Username:       stringPointer(input.Username),
		UserType: &userv2.CreateUserRequest_Human_{Human: &userv2.CreateUserRequest_Human{
			Profile: &userv2.SetHumanProfile{
				GivenName:   input.Username,
				FamilyName:  input.Username,
				DisplayName: &displayName,
			},
			Email: &userv2.SetHumanEmail{
				Email: input.Email,
				Verification: &userv2.SetHumanEmail_SendCode{
					SendCode: &userv2.SendEmailVerificationCode{UrlTemplate: &verificationURL},
				},
			},
			PasswordType: &userv2.CreateUserRequest_Human_Password{
				Password: &userv2.Password{Password: input.Password.Password()},
			},
		}},
	})
	if err != nil {
		return identity.ProviderUserInfo{}, mapRegistrationError(err)
	}
	if response == nil || response.Id == "" {
		return identity.ProviderUserInfo{}, auth.ErrProviderUnavailable
	}
	return identity.ProviderUserInfo{
		Subject: response.Id, DisplayName: input.Username, Email: input.Email,
	}, nil
}

func (p *LifecycleProvider) DeleteRegisteredUser(ctx context.Context, providerSubject string) error {
	_, err := p.users.DeleteUser(ctx, &userv2.DeleteUserRequest{UserId: providerSubject})
	if providerStatus, ok := status.FromError(err); ok && providerStatus.Code() == codes.NotFound {
		return nil
	}
	if err != nil {
		return auth.ErrProviderUnavailable
	}
	return nil
}

func (p *LifecycleProvider) FindPasswordResetIdentity(ctx context.Context, identifier string) (identity.ProviderUserInfo, error) {
	organizationID, err := p.resolveOrganizationID(ctx)
	if err != nil {
		return identity.ProviderUserInfo{}, auth.ErrProviderUnavailable
	}
	response, err := p.users.ListUsers(ctx, &userv2.ListUsersRequest{
		Query: &objectv2.ListQuery{Limit: 2},
		Queries: []*userv2.SearchQuery{
			{Query: &userv2.SearchQuery_OrganizationIdQuery{OrganizationIdQuery: &userv2.OrganizationIdQuery{OrganizationId: organizationID}}},
			{Query: &userv2.SearchQuery_LoginNameQuery{LoginNameQuery: &userv2.LoginNameQuery{
				LoginName: identifier,
				Method:    objectv2.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE,
			}}},
		},
	})
	if err != nil {
		if isAuthZFailure(err) {
			return identity.ProviderUserInfo{}, auth.ErrProviderUnavailable
		}
		if providerStatus, ok := status.FromError(err); ok && providerStatus.Code() == codes.NotFound {
			return identity.ProviderUserInfo{}, auth.ErrPublicAccountNotFound
		}
		return identity.ProviderUserInfo{}, auth.ErrProviderUnavailable
	}
	if response == nil || len(response.Result) != 1 {
		return identity.ProviderUserInfo{}, auth.ErrPublicAccountNotFound
	}
	providerUser := response.Result[0]
	human := providerUser.GetHuman()
	if human == nil || human.Email == nil || !human.Email.IsVerified {
		return identity.ProviderUserInfo{}, auth.ErrPublicAccountNotFound
	}
	return providerUserInfo(providerUser), nil
}

func (p *LifecycleProvider) BeginPasswordReset(ctx context.Context, providerSubject, resetURL string) error {
	_, err := p.users.PasswordReset(ctx, &userv2.PasswordResetRequest{
		UserId: providerSubject,
		Medium: &userv2.PasswordResetRequest_SendLink{SendLink: &userv2.SendPasswordResetLink{
			NotificationType: userv2.NotificationType_NOTIFICATION_TYPE_Email,
			UrlTemplate:      &resetURL,
		}},
	})
	if err != nil {
		return auth.ErrProviderUnavailable
	}
	return nil
}

func (p *LifecycleProvider) ResetPassword(
	ctx context.Context,
	providerSubject, verificationCode string,
	password auth.SecretPassword,
) error {
	_, err := p.users.SetPassword(ctx, &userv2.SetPasswordRequest{
		UserId:      providerSubject,
		NewPassword: &userv2.Password{Password: password.Password()},
		Verification: &userv2.SetPasswordRequest_VerificationCode{
			VerificationCode: verificationCode,
		},
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return auth.ErrPasswordChangeUnknown
	}
	providerStatus, ok := status.FromError(err)
	if !ok {
		return auth.ErrPasswordChangeUnknown
	}
	switch providerStatus.Code() {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound, codes.AlreadyExists:
		return auth.ErrLifecycleRejected
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled, codes.ResourceExhausted:
		return auth.ErrPasswordChangeUnknown
	default:
		return auth.ErrProviderUnavailable
	}
}

func (p *LifecycleProvider) VerifyRegistrationEmail(
	ctx context.Context,
	providerSubject, expectedEmail, verificationCode string,
) error {
	_, err := p.users.VerifyEmail(ctx, &userv2.VerifyEmailRequest{
		UserId: providerSubject, VerificationCode: verificationCode,
	})
	if err == nil {
		return nil
	}
	// Repair the provider-committed / response-lost boundary by reading the
	// authoritative email state. The local pending user remains blocked until
	// this read confirms the exact expected email as verified.
	if p.emailVerified(ctx, providerSubject, expectedEmail) {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isAuthZFailure(err) {
		return auth.ErrProviderUnavailable
	}
	providerStatus, ok := status.FromError(err)
	if ok {
		switch providerStatus.Code() {
		case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound, codes.AlreadyExists:
			return auth.ErrLifecycleCodeInvalid
		}
	}
	return auth.ErrProviderUnavailable
}

func (p *LifecycleProvider) emailVerified(ctx context.Context, subject, expected string) bool {
	response, err := p.users.GetUserByID(ctx, &userv2.GetUserByIDRequest{UserId: subject})
	if err != nil || response == nil || response.User == nil || response.User.GetHuman() == nil || response.User.GetHuman().Email == nil {
		return false
	}
	email := response.User.GetHuman().Email
	return email.IsVerified && strings.EqualFold(email.Email, expected)
}

func (p *LifecycleProvider) resolveOrganizationID(ctx context.Context) (string, error) {
	p.organizationMu.Lock()
	defer p.organizationMu.Unlock()
	if p.organizationID != "" {
		return p.organizationID, nil
	}
	if p.projects == nil || p.projectID == "" {
		return "", errors.New("zitadel: lifecycle project is not configured")
	}
	response, err := p.projects.GetProjectByID(ctx, &managementv1.GetProjectByIDRequest{Id: p.projectID})
	if err != nil {
		return "", fmt.Errorf("zitadel: resolve lifecycle organization: %w", err)
	}
	if response == nil || response.Project == nil || response.Project.Details == nil || response.Project.Details.ResourceOwner == "" {
		return "", errors.New("zitadel: lifecycle project has no resource owner")
	}
	p.organizationID = response.Project.Details.ResourceOwner
	return p.organizationID, nil
}

func providerUserInfo(user *userv2.User) identity.ProviderUserInfo {
	info := identity.ProviderUserInfo{Subject: user.GetUserId()}
	human := user.GetHuman()
	if human == nil {
		return info
	}
	if human.Profile != nil {
		info.DisplayName = human.Profile.GetDisplayName()
		if info.DisplayName == "" {
			info.DisplayName = strings.TrimSpace(human.Profile.GivenName + " " + human.Profile.FamilyName)
		}
	}
	if human.Email != nil {
		info.Email = human.Email.Email
		info.EmailVerified = human.Email.IsVerified
	}
	if human.Phone != nil {
		info.Phone = human.Phone.Phone
		info.PhoneVerified = human.Phone.IsVerified
	}
	return info
}

func mapRegistrationError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isAuthZFailure(err) {
		return auth.ErrProviderUnavailable
	}
	providerStatus, ok := status.FromError(err)
	if !ok {
		return auth.ErrProviderUnavailable
	}
	switch providerStatus.Code() {
	case codes.AlreadyExists:
		return auth.ErrRegistrationConflict
	case codes.InvalidArgument, codes.FailedPrecondition:
		return auth.ErrLifecycleRejected
	default:
		return auth.ErrProviderUnavailable
	}
}

func stringPointer(value string) *string { return &value }
