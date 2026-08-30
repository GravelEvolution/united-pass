package zitadel

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	objectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type registrationUserService interface {
	// AddHumanUser is the UserService v2 creation API present in the pinned
	// ZITADEL 2.71 runtime. The newer CreateUser endpoint used by some SDK
	// versions is not implemented by that server and must not be called.
	AddHumanUser(context.Context, *userv2.AddHumanUserRequest, ...grpc.CallOption) (*userv2.AddHumanUserResponse, error)
	ResendEmailCode(context.Context, *userv2.ResendEmailCodeRequest, ...grpc.CallOption) (*userv2.ResendEmailCodeResponse, error)
	VerifyEmail(context.Context, *userv2.VerifyEmailRequest, ...grpc.CallOption) (*userv2.VerifyEmailResponse, error)
	DeleteUser(context.Context, *userv2.DeleteUserRequest, ...grpc.CallOption) (*userv2.DeleteUserResponse, error)
	GetUserByID(context.Context, *userv2.GetUserByIDRequest, ...grpc.CallOption) (*userv2.GetUserByIDResponse, error)
}

// RegistrationProvider uses UserService v2 and an organization ID. A project
// ID is intentionally not accepted here: ZITADEL user creation is scoped to
// an organization, while the project remains only the local identity-link
// tenant convention.
type RegistrationProvider struct {
	users          registrationUserService
	organizationID string
}

func NewRegistrationProvider(users registrationUserService, organizationID string) *RegistrationProvider {
	return &RegistrationProvider{users: users, organizationID: organizationID}
}

func (p *RegistrationProvider) CreateUser(ctx context.Context, input registration.ProviderUser) error {
	if p == nil || p.users == nil || p.organizationID == "" {
		return registration.ErrUnavailable
	}
	displayName := input.DisplayName
	urlTemplate := input.VerificationURLTemplate
	userID := input.UserID
	username := input.Username
	preferredLanguage := "zh"
	response, err := p.users.AddHumanUser(ctx, &userv2.AddHumanUserRequest{
		Organization: &objectv2.Organization{Org: &objectv2.Organization_OrgId{OrgId: p.organizationID}},
		UserId:       &userID,
		Username:     &username,
		Profile: &userv2.SetHumanProfile{
			GivenName:         input.DisplayName,
			FamilyName:        input.DisplayName,
			DisplayName:       &displayName,
			PreferredLanguage: &preferredLanguage,
		},
		Email: &userv2.SetHumanEmail{
			Email: input.Email,
			Verification: &userv2.SetHumanEmail_SendCode{SendCode: &userv2.SendEmailVerificationCode{
				UrlTemplate: &urlTemplate,
			}},
		},
		PasswordType: &userv2.AddHumanUserRequest_Password{Password: &userv2.Password{
			Password: input.Password, ChangeRequired: false,
		}},
	})
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return p.reconcileExistingUser(ctx, input)
		}
		return mapRegistrationCreateError(err)
	}
	if response.GetUserId() != input.UserID {
		if response.GetUserId() != "" {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_, _ = p.users.DeleteUser(cleanupCtx, &userv2.DeleteUserRequest{UserId: response.GetUserId()})
			cancel()
		}
		return registration.ErrUnavailable
	}
	return nil
}

// reconcileExistingUser turns the ambiguous "created upstream but response
// was lost" case into an idempotent retry. It accepts only the exact
// caller-controlled user ID, username, display name and email; the local
// reservation independently binds the non-readable password through a
// memory-hard request verifier. An unrelated collision remains generic.
func (p *RegistrationProvider) reconcileExistingUser(ctx context.Context, input registration.ProviderUser) error {
	response, err := p.users.GetUserByID(ctx, &userv2.GetUserByIDRequest{UserId: input.UserID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return registration.ErrConflict
		}
		return registration.ErrUnavailable
	}
	user := response.GetUser()
	human := user.GetHuman()
	if user.GetUserId() != input.UserID || user.GetUsername() != input.Username || human == nil || human.GetProfile() == nil || human.GetProfile().GetDisplayName() != input.DisplayName || !strings.EqualFold(strings.TrimSpace(human.GetEmail().GetEmail()), strings.TrimSpace(input.Email)) {
		return registration.ErrConflict
	}
	if human.GetEmail().GetIsVerified() {
		return nil
	}
	if err := p.ResendEmail(ctx, registration.ResendEmailInput{UserID: input.UserID, VerificationURLTemplate: input.VerificationURLTemplate}); err != nil {
		return registration.ErrUnavailable
	}
	return nil
}

func (p *RegistrationProvider) DeleteUser(ctx context.Context, userID string) error {
	if p == nil || p.users == nil || userID == "" {
		return registration.ErrUnavailable
	}
	_, err := p.users.DeleteUser(ctx, &userv2.DeleteUserRequest{UserId: userID})
	if err == nil || status.Code(err) == codes.NotFound {
		return nil
	}
	return registration.ErrUnavailable
}

func (p *RegistrationProvider) VerifyEmail(ctx context.Context, input registration.VerifyEmailInput) error {
	if p == nil || p.users == nil || input.UserID == "" || input.Code == "" {
		return registration.ErrVerificationFailed
	}
	_, err := p.users.VerifyEmail(ctx, &userv2.VerifyEmailRequest{
		UserId: input.UserID, VerificationCode: input.Code,
	})
	if err == nil {
		return nil
	}
	// Verification codes are one-time. A retry after the provider succeeded
	// but the local activation failed must still be able to finish, so read
	// back the provider email state before classifying the consumed code.
	response, readErr := p.users.GetUserByID(ctx, &userv2.GetUserByIDRequest{UserId: input.UserID})
	if readErr == nil && response.GetUser().GetHuman().GetEmail().GetIsVerified() {
		return nil
	}
	if isRegistrationUserError(err) {
		return registration.ErrVerificationFailed
	}
	return registration.ErrUnavailable
}

func (p *RegistrationProvider) ResendEmail(ctx context.Context, input registration.ResendEmailInput) error {
	if p == nil || p.users == nil || input.UserID == "" || input.VerificationURLTemplate == "" {
		return registration.ErrVerificationFailed
	}
	urlTemplate := input.VerificationURLTemplate
	_, err := p.users.ResendEmailCode(ctx, &userv2.ResendEmailCodeRequest{
		UserId: input.UserID,
		Verification: &userv2.ResendEmailCodeRequest_SendCode{SendCode: &userv2.SendEmailVerificationCode{
			UrlTemplate: &urlTemplate,
		}},
	})
	if err == nil {
		return nil
	}
	if isRegistrationUserError(err) {
		return registration.ErrVerificationFailed
	}
	return registration.ErrUnavailable
}

func mapRegistrationCreateError(err error) error {
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.AlreadyExists {
		return registration.ErrConflict
	}
	if status.Code(err) == codes.InvalidArgument {
		return registration.ErrInvalidInput
	}
	return registration.ErrUnavailable
}

func isRegistrationUserError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	switch status.Code(err) {
	case codes.InvalidArgument, codes.NotFound, codes.FailedPrecondition, codes.Aborted, codes.OutOfRange:
		return true
	default:
		return false
	}
}

var _ registration.Provider = (*RegistrationProvider)(nil)
