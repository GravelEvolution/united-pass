package zitadel

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/accountcontact"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
)

type accountContactUserServiceStub struct {
	verifyReq *userv2.VerifyEmailRequest
	readCalls int
}

func (s *accountContactUserServiceStub) SetEmail(_ context.Context, _ *userv2.SetEmailRequest, _ ...grpc.CallOption) (*userv2.SetEmailResponse, error) {
	return &userv2.SetEmailResponse{}, nil
}

func (s *accountContactUserServiceStub) VerifyEmail(_ context.Context, req *userv2.VerifyEmailRequest, _ ...grpc.CallOption) (*userv2.VerifyEmailResponse, error) {
	s.verifyReq = req
	return &userv2.VerifyEmailResponse{}, nil
}

func (s *accountContactUserServiceStub) GetUserByID(_ context.Context, _ *userv2.GetUserByIDRequest, _ ...grpc.CallOption) (*userv2.GetUserByIDResponse, error) {
	s.readCalls++
	return &userv2.GetUserByIDResponse{User: &userv2.User{
		Type: &userv2.User_Human{Human: &userv2.HumanUser{
			Email: &userv2.HumanEmail{Email: "new@example.com", IsVerified: true},
		}},
	}}, nil
}

func TestAccountContactProviderForwardsCaseSensitiveAlphanumericCode(t *testing.T) {
	t.Parallel()

	stub := &accountContactUserServiceStub{}
	email, err := NewAccountContactProvider(stub).VerifyEmailChange(t.Context(), "user_1", "A1B2C3")
	if err != nil {
		t.Fatalf("VerifyEmailChange: %v", err)
	}
	if email != "new@example.com" {
		t.Fatalf("email = %q, want new@example.com", email)
	}
	if stub.verifyReq == nil || stub.verifyReq.GetVerificationCode() != "A1B2C3" {
		t.Fatalf("verification request = %#v, want exact code A1B2C3", stub.verifyReq)
	}
}

func TestAccountContactProviderRejectsInvalidCodeBeforeRPC(t *testing.T) {
	t.Parallel()

	for _, code := range []string{"a1B2C3", "A1B2C", "A1B2C!"} {
		code := code
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			stub := &accountContactUserServiceStub{}
			_, err := NewAccountContactProvider(stub).VerifyEmailChange(t.Context(), "user_1", code)
			if !errors.Is(err, accountcontact.ErrVerificationFailed) {
				t.Fatalf("VerifyEmailChange(%q) error = %v, want ErrVerificationFailed", code, err)
			}
			if stub.verifyReq != nil || stub.readCalls != 0 {
				t.Fatalf("invalid code caused provider RPCs: verify=%#v reads=%d", stub.verifyReq, stub.readCalls)
			}
		})
	}
}
