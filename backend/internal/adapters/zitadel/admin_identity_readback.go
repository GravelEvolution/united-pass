package zitadel

import (
	"context"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"

	"github.com/GravelEvolution/united-pass/backend/internal/adminbootstrap"
)

type adminUserReadbackClient interface {
	GetUserByID(context.Context, *userv2.GetUserByIDRequest, ...grpc.CallOption) (*userv2.GetUserByIDResponse, error)
}

type AdminIdentityReadback struct {
	users    adminUserReadbackClient
	tenantID string
}

func NewAdminIdentityReadback(users adminUserReadbackClient, tenantID string) *AdminIdentityReadback {
	return &AdminIdentityReadback{users: users, tenantID: tenantID}
}

func (r *AdminIdentityReadback) ReadExact(ctx context.Context, tenantID, subject string) (adminbootstrap.ProviderIdentity, error) {
	if r == nil || r.users == nil || tenantID == "" || tenantID != r.tenantID || subject == "" {
		return adminbootstrap.ProviderIdentity{}, adminbootstrap.ErrIdentityMismatch
	}
	response, err := r.users.GetUserByID(ctx, &userv2.GetUserByIDRequest{UserId: subject})
	if err != nil || response.GetUser() == nil {
		return adminbootstrap.ProviderIdentity{}, adminbootstrap.ErrIdentityMismatch
	}
	user := response.GetUser()
	if user.GetUserId() != subject || user.GetHuman() == nil || user.GetUsername() == "" {
		return adminbootstrap.ProviderIdentity{}, adminbootstrap.ErrIdentityMismatch
	}
	return adminbootstrap.ProviderIdentity{Subject: user.GetUserId(), LoginName: user.GetUsername(), Enabled: user.GetState() == userv2.UserState_USER_STATE_ACTIVE}, nil
}

var _ adminbootstrap.ProviderIdentityReadback = (*AdminIdentityReadback)(nil)
