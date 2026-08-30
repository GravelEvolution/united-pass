package zitadel

import (
	"context"
	"errors"

	"github.com/GravelEvolution/united-pass/backend/internal/accountcontact"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type accountContactUserService interface {
	SetEmail(context.Context, *userv2.SetEmailRequest, ...grpc.CallOption) (*userv2.SetEmailResponse, error)
	VerifyEmail(context.Context, *userv2.VerifyEmailRequest, ...grpc.CallOption) (*userv2.VerifyEmailResponse, error)
	GetUserByID(context.Context, *userv2.GetUserByIDRequest, ...grpc.CallOption) (*userv2.GetUserByIDResponse, error)
}

// AccountContactProvider changes the provider-owned primary login email and
// only returns it after ZITADEL has verified the one-time code.
type AccountContactProvider struct{ users accountContactUserService }

func NewAccountContactProvider(users accountContactUserService) *AccountContactProvider {
	return &AccountContactProvider{users: users}
}

func (p *AccountContactProvider) BeginEmailChange(ctx context.Context, input accountcontact.BeginProviderInput) error {
	if p == nil || p.users == nil || input.UserID == "" || input.Email == "" || input.VerificationURLTemplate == "" {
		return accountcontact.ErrUnavailable
	}
	template := input.VerificationURLTemplate
	_, err := p.users.SetEmail(ctx, &userv2.SetEmailRequest{
		UserId: string(input.UserID),
		Email:  input.Email,
		Verification: &userv2.SetEmailRequest_SendCode{SendCode: &userv2.SendEmailVerificationCode{
			UrlTemplate: &template,
		}},
	})
	return mapAccountContactError(err)
}

func (p *AccountContactProvider) VerifyEmailChange(ctx context.Context, userID identity.UserID, code string) (string, error) {
	if p == nil || p.users == nil || userID == "" || !accountcontact.IsValidEmailVerificationCode(code) {
		return "", accountcontact.ErrVerificationFailed
	}
	_, verifyErr := p.users.VerifyEmail(ctx, &userv2.VerifyEmailRequest{UserId: string(userID), VerificationCode: code})
	response, readErr := p.users.GetUserByID(ctx, &userv2.GetUserByIDRequest{UserId: string(userID)})
	if readErr == nil {
		email := response.GetUser().GetHuman().GetEmail()
		if email.GetIsVerified() && email.GetEmail() != "" {
			return email.GetEmail(), nil
		}
	}
	if verifyErr != nil && isAccountContactUserError(verifyErr) {
		return "", accountcontact.ErrVerificationFailed
	}
	return "", accountcontact.ErrUnavailable
}

var _ accountcontact.Provider = (*AccountContactProvider)(nil)

func mapAccountContactError(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.AlreadyExists:
		return accountcontact.ErrConflict
	case codes.InvalidArgument, codes.NotFound, codes.FailedPrecondition:
		return accountcontact.ErrInvalidInput
	default:
		return accountcontact.ErrUnavailable
	}
}

func isAccountContactUserError(err error) bool {
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
