//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: ZITADEL account deletion adapter tests
//

package zitadel

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/privacy"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type deletionServiceStub struct {
	userID string
	err    error
}

func (s *deletionServiceStub) DeleteUser(_ context.Context, req *userv2.DeleteUserRequest, _ ...grpc.CallOption) (*userv2.DeleteUserResponse, error) {
	s.userID = req.GetUserId()
	return &userv2.DeleteUserResponse{}, s.err
}

func TestAccountDeleterDeletesExactSubjectAndTreatsNotFoundAsComplete(t *testing.T) {
	stub := &deletionServiceStub{}
	deleter := NewAccountDeleter(stub)
	if err := deleter.DeleteProviderUser(context.Background(), "provider-user-1"); err != nil || stub.userID != "provider-user-1" {
		t.Fatalf("user=%q err=%v", stub.userID, err)
	}
	stub.err = status.Error(codes.NotFound, "gone")
	if err := deleter.DeleteProviderUser(context.Background(), "provider-user-1"); !errors.Is(err, privacy.ErrNotFound) {
		t.Fatalf("err=%v", err)
	}
}
