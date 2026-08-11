//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: ZITADEL provider-account deletion adapter for Phase 8
//

package zitadel

import (
	"context"
	"fmt"

	"github.com/GravelEvolution/united-pass/backend/internal/privacy"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type userDeletionService interface {
	DeleteUser(context.Context, *userv2.DeleteUserRequest, ...grpc.CallOption) (*userv2.DeleteUserResponse, error)
}

type AccountDeleter struct{ users userDeletionService }

func NewAccountDeleter(users userDeletionService) *AccountDeleter {
	return &AccountDeleter{users: users}
}

func (d *AccountDeleter) DeleteProviderUser(ctx context.Context, subject string) error {
	if d == nil || d.users == nil || subject == "" {
		return fmt.Errorf("%w: missing ZITADEL user deletion configuration", privacy.ErrProviderDelete)
	}
	_, err := d.users.DeleteUser(ctx, &userv2.DeleteUserRequest{UserId: subject})
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.NotFound {
		return privacy.ErrNotFound
	}
	return fmt.Errorf("%w: %s", privacy.ErrProviderDelete, provisioningErrorClass(err))
}
