//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: ZITADEL verified email and phone mutation adapter
//

package zitadel

import (
	"context"
	"errors"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ identity.AccountContactProvider = (*Authenticator)(nil)

func (a *Authenticator) BeginEmailChange(ctx context.Context, userID identity.UserID, email string) error {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return identity.ErrAccountProvider
	}
	_, err = a.users.SetEmail(ctx, &userv2.SetEmailRequest{
		UserId: subject,
		Email:  email,
		Verification: &userv2.SetEmailRequest_SendCode{
			SendCode: &userv2.SendEmailVerificationCode{},
		},
	})
	return mapContactProviderError(err, false)
}

func (a *Authenticator) VerifyEmailChange(
	ctx context.Context,
	userID identity.UserID,
	email, code string,
) error {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return identity.ErrAccountProvider
	}
	_, err = a.users.VerifyEmail(ctx, &userv2.VerifyEmailRequest{
		UserId: subject, VerificationCode: code,
	})
	if err == nil {
		return nil
	}
	// The provider may have committed before the process lost the response.
	// Authoritative readback makes a retry settle that ambiguous boundary.
	if a.emailIsVerified(ctx, subject, email) {
		return nil
	}
	return mapContactProviderError(err, true)
}

func (a *Authenticator) BeginPhoneChange(ctx context.Context, userID identity.UserID, phone string) error {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return identity.ErrAccountProvider
	}
	_, err = a.users.SetPhone(ctx, &userv2.SetPhoneRequest{
		UserId: subject,
		Phone:  phone,
		Verification: &userv2.SetPhoneRequest_SendCode{
			SendCode: &userv2.SendPhoneVerificationCode{},
		},
	})
	return mapContactProviderError(err, false)
}

func (a *Authenticator) VerifyPhoneChange(
	ctx context.Context,
	userID identity.UserID,
	phone, code string,
) error {
	subject, err := a.resolveProviderUser(ctx, userID)
	if err != nil {
		return identity.ErrAccountProvider
	}
	_, err = a.users.VerifyPhone(ctx, &userv2.VerifyPhoneRequest{
		UserId: subject, VerificationCode: code,
	})
	if err == nil {
		return nil
	}
	if a.phoneIsVerified(ctx, subject, phone) {
		return nil
	}
	return mapContactProviderError(err, true)
}

func (a *Authenticator) emailIsVerified(ctx context.Context, subject, expected string) bool {
	resp, err := a.users.GetUserByID(ctx, &userv2.GetUserByIDRequest{UserId: subject})
	if err != nil || resp.User == nil || resp.User.GetHuman() == nil || resp.User.GetHuman().Email == nil {
		return false
	}
	email := resp.User.GetHuman().Email
	return email.IsVerified && strings.EqualFold(email.Email, expected)
}

func (a *Authenticator) phoneIsVerified(ctx context.Context, subject, expected string) bool {
	resp, err := a.users.GetUserByID(ctx, &userv2.GetUserByIDRequest{UserId: subject})
	if err != nil || resp.User == nil || resp.User.GetHuman() == nil || resp.User.GetHuman().Phone == nil {
		return false
	}
	phone := resp.User.GetHuman().Phone
	return phone.IsVerified && phone.Phone == expected
}

func mapContactProviderError(err error, verification bool) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isAuthZFailure(err) {
		return identity.ErrAccountProvider
	}
	providerStatus, ok := status.FromError(err)
	if !ok {
		return identity.ErrAccountProvider
	}
	switch providerStatus.Code() {
	case codes.AlreadyExists:
		return identity.ErrContactConflict
	case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound:
		if verification {
			return identity.ErrContactCodeInvalid
		}
		return identity.ErrContactConflict
	default:
		return identity.ErrAccountProvider
	}
}
