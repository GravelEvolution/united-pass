package zitadel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type registrationUserServiceStub struct {
	createReq *userv2.AddHumanUserRequest
	resendReq *userv2.ResendEmailCodeRequest
	verifyReq *userv2.VerifyEmailRequest
	deleteReq *userv2.DeleteUserRequest
	createErr error
	createID  string
	verifyErr error
	getResp   *userv2.GetUserByIDResponse
	getErr    error
	getCalls  int
}

func (s *registrationUserServiceStub) AddHumanUser(_ context.Context, req *userv2.AddHumanUserRequest, _ ...grpc.CallOption) (*userv2.AddHumanUserResponse, error) {
	s.createReq = req
	id := s.createID
	if id == "" {
		id = req.GetUserId()
	}
	return &userv2.AddHumanUserResponse{UserId: id}, s.createErr
}

func TestRegistrationProviderRejectsAndDeletesDriftingProviderID(t *testing.T) {
	stub := &registrationUserServiceStub{createID: "provider-generated-wrong-id"}
	provider := NewRegistrationProvider(stub, "organization-id")
	err := provider.CreateUser(t.Context(), registration.ProviderUser{
		UserID: "user_0123456789abcdef0123456789abcdef", Username: "moonstone", DisplayName: "Moonstone",
		Email: "player@example.com", Password: "correct horse battery staple", VerificationURLTemplate: "https://example.test/#code={{.Code}}",
	})
	if !errors.Is(err, registration.ErrUnavailable) || stub.deleteReq == nil || stub.deleteReq.GetUserId() != "provider-generated-wrong-id" {
		deleted := ""
		if stub.deleteReq != nil {
			deleted = stub.deleteReq.GetUserId()
		}
		t.Fatalf("drifting ID error=%v deleted=%q", err, deleted)
	}
}
func (s *registrationUserServiceStub) ResendEmailCode(_ context.Context, req *userv2.ResendEmailCodeRequest, _ ...grpc.CallOption) (*userv2.ResendEmailCodeResponse, error) {
	s.resendReq = req
	return &userv2.ResendEmailCodeResponse{}, nil
}
func (s *registrationUserServiceStub) VerifyEmail(_ context.Context, req *userv2.VerifyEmailRequest, _ ...grpc.CallOption) (*userv2.VerifyEmailResponse, error) {
	s.verifyReq = req
	return &userv2.VerifyEmailResponse{}, s.verifyErr
}
func (s *registrationUserServiceStub) DeleteUser(_ context.Context, req *userv2.DeleteUserRequest, _ ...grpc.CallOption) (*userv2.DeleteUserResponse, error) {
	s.deleteReq = req
	return &userv2.DeleteUserResponse{}, nil
}
func (s *registrationUserServiceStub) GetUserByID(_ context.Context, _ *userv2.GetUserByIDRequest, _ ...grpc.CallOption) (*userv2.GetUserByIDResponse, error) {
	s.getCalls++
	return s.getResp, s.getErr
}

func TestRegistrationProviderCreatesUnverifiedHumanWithControlledID(t *testing.T) {
	stub := &registrationUserServiceStub{}
	provider := NewRegistrationProvider(stub, "organization-id")
	input := registration.ProviderUser{
		UserID: "user_0123456789abcdef0123456789abcdef", Username: "moonstone",
		DisplayName: "月石选手", Email: "player@example.com", Password: "correct horse battery staple",
		VerificationURLTemplate: "https://auth.moonstone.org.cn/verify-email#userId={{.UserID}}&code={{.Code}}&requestId=req",
	}
	if err := provider.CreateUser(t.Context(), input); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	req := stub.createReq
	if req.GetOrganization().GetOrgId() != "organization-id" || req.GetUserId() != input.UserID || req.GetUsername() != input.Username {
		t.Fatalf("create request identity = %#v", req)
	}
	if req.GetProfile() == nil || req.GetProfile().GetDisplayName() != input.DisplayName || req.GetEmail().GetEmail() != input.Email {
		t.Fatalf("human request = %#v", req)
	}
	if req.GetEmail().GetIsVerified() || req.GetEmail().GetSendCode().GetUrlTemplate() != input.VerificationURLTemplate {
		t.Fatalf("email verification request = %#v", req.GetEmail())
	}
	if req.GetPassword().GetPassword() != input.Password || req.GetPassword().GetChangeRequired() {
		t.Fatalf("password request was not the requested permanent initial password")
	}
}

func TestRegistrationProviderTreatsVerifiedReadbackAsIdempotent(t *testing.T) {
	stub := &registrationUserServiceStub{
		verifyErr: status.Error(codes.InvalidArgument, "already consumed"),
		getResp:   &userv2.GetUserByIDResponse{User: &userv2.User{Type: &userv2.User_Human{Human: &userv2.HumanUser{Email: &userv2.HumanEmail{IsVerified: true}}}}},
	}
	provider := NewRegistrationProvider(stub, "organization-id")
	err := provider.VerifyEmail(t.Context(), registration.VerifyEmailInput{UserID: "user_0123456789abcdef0123456789abcdef", Code: "one-time-code"})
	if err != nil {
		t.Fatalf("verified readback should be idempotent: %v", err)
	}

	stub.getResp.GetUser().GetHuman().Email.IsVerified = false
	if err := provider.VerifyEmail(t.Context(), registration.VerifyEmailInput{UserID: "user_0123456789abcdef0123456789abcdef", Code: "bad-code"}); !errors.Is(err, registration.ErrVerificationFailed) {
		t.Fatalf("unverified readback error = %v", err)
	}
}

func TestRegistrationProviderDoesNotReadBackAfterProviderDeadline(t *testing.T) {
	stub := &registrationUserServiceStub{verifyErr: status.Error(codes.DeadlineExceeded, "provider timeout")}
	err := NewRegistrationProvider(stub, "organization-id").VerifyEmail(t.Context(), registration.VerifyEmailInput{
		UserID: "user_0123456789abcdef0123456789abcdef", Code: "one-time-code",
	})
	if !errors.Is(err, registration.ErrUnavailable) {
		t.Fatalf("deadline error = %v, want ErrUnavailable", err)
	}
	if stub.getCalls != 0 {
		t.Fatalf("GetUserByID calls after provider deadline = %d, want 0", stub.getCalls)
	}
}

func TestRegistrationProviderMapsCreateCollisionWithoutDetails(t *testing.T) {
	stub := &registrationUserServiceStub{createErr: status.Error(codes.AlreadyExists, "email exists")}
	err := NewRegistrationProvider(stub, "organization-id").CreateUser(t.Context(), registration.ProviderUser{
		UserID: "user_0123456789abcdef0123456789abcdef", Username: "moonstone", DisplayName: "Moonstone",
		Email: "player@example.com", Password: "correct horse battery staple", VerificationURLTemplate: "https://example.test/#code={{.Code}}",
	})
	if !errors.Is(err, registration.ErrConflict) || err.Error() != registration.ErrConflict.Error() {
		t.Fatalf("collision error leaked provider detail: %v", err)
	}
}

func TestRegistrationProviderReconcilesAmbiguousCreateForExactControlledUser(t *testing.T) {
	input := registration.ProviderUser{
		UserID: "user_0123456789abcdef0123456789abcdef", Username: "moonstone", DisplayName: "Moonstone",
		Email: "player@example.com", Password: "correct horse battery staple", VerificationURLTemplate: "https://example.test/#code={{.Code}}",
	}
	stub := &registrationUserServiceStub{
		createErr: status.Error(codes.AlreadyExists, "request outcome unknown"),
		getResp: &userv2.GetUserByIDResponse{User: &userv2.User{
			UserId: input.UserID, Username: input.Username,
			Type: &userv2.User_Human{Human: &userv2.HumanUser{Profile: &userv2.HumanProfile{DisplayName: &input.DisplayName}, Email: &userv2.HumanEmail{Email: input.Email}}},
		}},
	}
	if err := NewRegistrationProvider(stub, "organization-id").CreateUser(t.Context(), input); err != nil {
		t.Fatalf("ambiguous create should reconcile: %v", err)
	}
	if stub.resendReq == nil || stub.resendReq.GetUserId() != input.UserID || stub.resendReq.GetSendCode().GetUrlTemplate() != input.VerificationURLTemplate {
		t.Fatalf("reconciled resend=%#v", stub.resendReq)
	}
}

func TestRegistrationProviderDoesNotReconcileDriftedDisplayName(t *testing.T) {
	input := registration.ProviderUser{
		UserID: "user_0123456789abcdef0123456789abcdef", Username: "moonstone", DisplayName: "Moonstone",
		Email: "player@example.com", Password: "correct horse battery staple", VerificationURLTemplate: "https://example.test/#code={{.Code}}",
	}
	driftedDisplayName := "Someone Else"
	stub := &registrationUserServiceStub{
		createErr: status.Error(codes.AlreadyExists, "request outcome unknown"),
		getResp: &userv2.GetUserByIDResponse{User: &userv2.User{
			UserId: input.UserID, Username: input.Username,
			Type: &userv2.User_Human{Human: &userv2.HumanUser{Profile: &userv2.HumanProfile{DisplayName: &driftedDisplayName}, Email: &userv2.HumanEmail{Email: input.Email}}},
		}},
	}
	if err := NewRegistrationProvider(stub, "organization-id").CreateUser(t.Context(), input); !errors.Is(err, registration.ErrConflict) {
		t.Fatalf("display-name drift error=%v", err)
	}
	if stub.resendReq != nil {
		t.Fatal("verification mail resent for a drifted provider profile")
	}
}

func TestRegistrationProviderDoesNotReconcileDifferentExistingIdentity(t *testing.T) {
	input := registration.ProviderUser{
		UserID: "user_0123456789abcdef0123456789abcdef", Username: "moonstone", DisplayName: "Moonstone",
		Email: "player@example.com", Password: "correct horse battery staple", VerificationURLTemplate: "https://example.test/#code={{.Code}}",
	}
	stub := &registrationUserServiceStub{
		createErr: status.Error(codes.AlreadyExists, "collision"),
		getResp: &userv2.GetUserByIDResponse{User: &userv2.User{
			UserId: input.UserID, Username: "someone-else",
			Type: &userv2.User_Human{Human: &userv2.HumanUser{Email: &userv2.HumanEmail{Email: input.Email}}},
		}},
	}
	if err := NewRegistrationProvider(stub, "organization-id").CreateUser(t.Context(), input); !errors.Is(err, registration.ErrConflict) {
		t.Fatalf("different identity error=%v", err)
	}
	if stub.resendReq != nil {
		t.Fatal("verification mail resent for a different provider identity")
	}
}

type blockingRegistrationUserService struct {
	operation         string
	deadlineRemaining time.Duration
	deadlineSeen      bool
	getCalls          int
}

func (s *blockingRegistrationUserService) block(ctx context.Context, operation string) error {
	if s.operation != operation {
		return nil
	}
	deadline, ok := ctx.Deadline()
	s.deadlineSeen = ok
	if ok {
		s.deadlineRemaining = time.Until(deadline)
	}
	<-ctx.Done()
	return ctx.Err()
}

func (s *blockingRegistrationUserService) AddHumanUser(ctx context.Context, req *userv2.AddHumanUserRequest, _ ...grpc.CallOption) (*userv2.AddHumanUserResponse, error) {
	if s.operation == "get" {
		return nil, status.Error(codes.AlreadyExists, "outcome unknown")
	}
	if err := s.block(ctx, "add"); err != nil {
		return nil, err
	}
	return &userv2.AddHumanUserResponse{UserId: req.GetUserId()}, nil
}

func (s *blockingRegistrationUserService) ResendEmailCode(ctx context.Context, _ *userv2.ResendEmailCodeRequest, _ ...grpc.CallOption) (*userv2.ResendEmailCodeResponse, error) {
	if err := s.block(ctx, "resend"); err != nil {
		return nil, err
	}
	return &userv2.ResendEmailCodeResponse{}, nil
}

func (s *blockingRegistrationUserService) VerifyEmail(ctx context.Context, _ *userv2.VerifyEmailRequest, _ ...grpc.CallOption) (*userv2.VerifyEmailResponse, error) {
	if err := s.block(ctx, "verify"); err != nil {
		return nil, err
	}
	return &userv2.VerifyEmailResponse{}, nil
}

func (s *blockingRegistrationUserService) DeleteUser(ctx context.Context, _ *userv2.DeleteUserRequest, _ ...grpc.CallOption) (*userv2.DeleteUserResponse, error) {
	if err := s.block(ctx, "delete"); err != nil {
		return nil, err
	}
	return &userv2.DeleteUserResponse{}, nil
}

func (s *blockingRegistrationUserService) GetUserByID(ctx context.Context, _ *userv2.GetUserByIDRequest, _ ...grpc.CallOption) (*userv2.GetUserByIDResponse, error) {
	s.getCalls++
	if err := s.block(ctx, "get"); err != nil {
		return nil, err
	}
	return &userv2.GetUserByIDResponse{}, nil
}

func TestRegistrationProviderBoundsEveryProviderRPC(t *testing.T) {
	const testTimeout = 25 * time.Millisecond
	input := registration.ProviderUser{
		UserID: "user_0123456789abcdef0123456789abcdef", Username: "moonstone", DisplayName: "Moonstone",
		Email: "player@example.com", Password: "correct horse battery staple", VerificationURLTemplate: "https://example.test/#code={{.Code}}",
	}
	tests := []struct {
		name               string
		operation          string
		invoke             func(context.Context, *RegistrationProvider, *blockingRegistrationUserService) error
		wantGetCalls       int
		assertGetCallCount bool
	}{
		{
			name: "AddHumanUser", operation: "add",
			invoke: func(ctx context.Context, provider *RegistrationProvider, _ *blockingRegistrationUserService) error {
				return provider.CreateUser(ctx, input)
			},
		},
		{
			name: "GetUserByID", operation: "get", wantGetCalls: 1, assertGetCallCount: true,
			invoke: func(ctx context.Context, provider *RegistrationProvider, _ *blockingRegistrationUserService) error {
				return provider.CreateUser(ctx, input)
			},
		},
		{
			name: "ResendEmailCode", operation: "resend",
			invoke: func(ctx context.Context, provider *RegistrationProvider, _ *blockingRegistrationUserService) error {
				return provider.ResendEmail(ctx, registration.ResendEmailInput{
					UserID: input.UserID, VerificationURLTemplate: input.VerificationURLTemplate,
				})
			},
		},
		{
			name: "VerifyEmail", operation: "verify", wantGetCalls: 0, assertGetCallCount: true,
			invoke: func(ctx context.Context, provider *RegistrationProvider, _ *blockingRegistrationUserService) error {
				return provider.VerifyEmail(ctx, registration.VerifyEmailInput{UserID: input.UserID, Code: "one-time-code"})
			},
		},
		{
			name: "DeleteUser", operation: "delete",
			invoke: func(ctx context.Context, provider *RegistrationProvider, _ *blockingRegistrationUserService) error {
				return provider.DeleteUser(ctx, input.UserID)
			},
		},
	}

	if got := NewRegistrationProvider(&blockingRegistrationUserService{}, "organization-id").rpcTimeout; got != registrationProviderRPCTimeout {
		t.Fatalf("default RPC timeout = %s, want %s", got, registrationProviderRPCTimeout)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &blockingRegistrationUserService{operation: test.operation}
			provider := newRegistrationProvider(stub, "organization-id", testTimeout)
			started := time.Now()
			err := test.invoke(t.Context(), provider, stub)
			if !errors.Is(err, registration.ErrUnavailable) {
				t.Fatalf("error = %v, want ErrUnavailable", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("provider call exceeded bounded test deadline: %s", elapsed)
			}
			if !stub.deadlineSeen || stub.deadlineRemaining <= 0 || stub.deadlineRemaining > testTimeout+5*time.Millisecond {
				t.Fatalf("provider deadline seen=%v remaining=%s, want (0, %s]", stub.deadlineSeen, stub.deadlineRemaining, testTimeout)
			}
			if test.assertGetCallCount && stub.getCalls != test.wantGetCalls {
				t.Fatalf("GetUserByID calls = %d, want %d", stub.getCalls, test.wantGetCalls)
			}
		})
	}
}
