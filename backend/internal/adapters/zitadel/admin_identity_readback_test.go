package zitadel

import (
	"context"
	"testing"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
)

type adminUserReadbackStub struct{ response *userv2.GetUserByIDResponse }

func (s adminUserReadbackStub) GetUserByID(context.Context, *userv2.GetUserByIDRequest, ...grpc.CallOption) (*userv2.GetUserByIDResponse, error) {
	return s.response, nil
}

func TestAdminIdentityReadbackRequiresExactEnabledHuman(t *testing.T) {
	reader := NewAdminIdentityReadback(adminUserReadbackStub{&userv2.GetUserByIDResponse{User: &userv2.User{UserId: "subject_exact", Username: "El107t", State: userv2.UserState_USER_STATE_ACTIVE, Type: &userv2.User_Human{Human: &userv2.HumanUser{UserId: "subject_exact"}}}}}, "tenant_exact")
	result, err := reader.ReadExact(context.Background(), "tenant_exact", "subject_exact")
	if err != nil || !result.Enabled || result.LoginName != "El107t" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := reader.ReadExact(context.Background(), "other", "subject_exact"); err == nil {
		t.Fatal("cross-tenant readback accepted")
	}
}
