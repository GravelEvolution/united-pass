//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the ZITADEL authenticator adapter
//

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	sessionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type fakeSessionService struct {
	createFn func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error)
	setFn    func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error)
	getFn    func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error)
	listFn   func(*sessionv2.ListSessionsRequest) (*sessionv2.ListSessionsResponse, error)
	delFn    func(*sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error)
	delCtxFn func(context.Context, *sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error)
}

func (f *fakeSessionService) CreateSession(_ context.Context, in *sessionv2.CreateSessionRequest, _ ...grpc.CallOption) (*sessionv2.CreateSessionResponse, error) {
	return f.createFn(in)
}
func (f *fakeSessionService) SetSession(_ context.Context, in *sessionv2.SetSessionRequest, _ ...grpc.CallOption) (*sessionv2.SetSessionResponse, error) {
	return f.setFn(in)
}
func (f *fakeSessionService) GetSession(_ context.Context, in *sessionv2.GetSessionRequest, _ ...grpc.CallOption) (*sessionv2.GetSessionResponse, error) {
	return f.getFn(in)
}
func (f *fakeSessionService) ListSessions(_ context.Context, in *sessionv2.ListSessionsRequest, _ ...grpc.CallOption) (*sessionv2.ListSessionsResponse, error) {
	return f.listFn(in)
}

func (f *fakeSessionService) DeleteSession(ctx context.Context, in *sessionv2.DeleteSessionRequest, _ ...grpc.CallOption) (*sessionv2.DeleteSessionResponse, error) {
	if f.delCtxFn != nil {
		return f.delCtxFn(ctx, in)
	}
	return f.delFn(in)
}

type fakeUserService struct {
	getFn             func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error)
	listUsersFn       func(*userv2.ListUsersRequest) (*userv2.ListUsersResponse, error)
	methodsFn         func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error)
	registerTOTPFn    func(*userv2.RegisterTOTPRequest) (*userv2.RegisterTOTPResponse, error)
	verifyTOTPFn      func(*userv2.VerifyTOTPRegistrationRequest) (*userv2.VerifyTOTPRegistrationResponse, error)
	removeTOTPFn      func(*userv2.RemoveTOTPRequest) (*userv2.RemoveTOTPResponse, error)
	registerPasskeyFn func(*userv2.RegisterPasskeyRequest) (*userv2.RegisterPasskeyResponse, error)
	verifyPasskeyFn   func(*userv2.VerifyPasskeyRegistrationRequest) (*userv2.VerifyPasskeyRegistrationResponse, error)
	listPasskeysFn    func(*userv2.ListPasskeysRequest) (*userv2.ListPasskeysResponse, error)
	removePasskeyFn   func(*userv2.RemovePasskeyRequest) (*userv2.RemovePasskeyResponse, error)
	setPasswordFn     func(*userv2.SetPasswordRequest) (*userv2.SetPasswordResponse, error)
	passwordResetFn   func(*userv2.PasswordResetRequest) (*userv2.PasswordResetResponse, error)
}

func (f *fakeUserService) GetUserByID(_ context.Context, in *userv2.GetUserByIDRequest, _ ...grpc.CallOption) (*userv2.GetUserByIDResponse, error) {
	return f.getFn(in)
}
func (f *fakeUserService) ListUsers(_ context.Context, in *userv2.ListUsersRequest, _ ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
	if f.listUsersFn == nil {
		return &userv2.ListUsersResponse{}, nil
	}
	return f.listUsersFn(in)
}
func (f *fakeUserService) ListAuthenticationMethodTypes(_ context.Context, in *userv2.ListAuthenticationMethodTypesRequest, _ ...grpc.CallOption) (*userv2.ListAuthenticationMethodTypesResponse, error) {
	return f.methodsFn(in)
}
func (f *fakeUserService) RegisterTOTP(_ context.Context, in *userv2.RegisterTOTPRequest, _ ...grpc.CallOption) (*userv2.RegisterTOTPResponse, error) {
	return f.registerTOTPFn(in)
}
func (f *fakeUserService) VerifyTOTPRegistration(_ context.Context, in *userv2.VerifyTOTPRegistrationRequest, _ ...grpc.CallOption) (*userv2.VerifyTOTPRegistrationResponse, error) {
	return f.verifyTOTPFn(in)
}
func (f *fakeUserService) RemoveTOTP(_ context.Context, in *userv2.RemoveTOTPRequest, _ ...grpc.CallOption) (*userv2.RemoveTOTPResponse, error) {
	return f.removeTOTPFn(in)
}
func (f *fakeUserService) RegisterPasskey(_ context.Context, in *userv2.RegisterPasskeyRequest, _ ...grpc.CallOption) (*userv2.RegisterPasskeyResponse, error) {
	return f.registerPasskeyFn(in)
}
func (f *fakeUserService) VerifyPasskeyRegistration(_ context.Context, in *userv2.VerifyPasskeyRegistrationRequest, _ ...grpc.CallOption) (*userv2.VerifyPasskeyRegistrationResponse, error) {
	return f.verifyPasskeyFn(in)
}
func (f *fakeUserService) ListPasskeys(_ context.Context, in *userv2.ListPasskeysRequest, _ ...grpc.CallOption) (*userv2.ListPasskeysResponse, error) {
	return f.listPasskeysFn(in)
}
func (f *fakeUserService) RemovePasskey(_ context.Context, in *userv2.RemovePasskeyRequest, _ ...grpc.CallOption) (*userv2.RemovePasskeyResponse, error) {
	return f.removePasskeyFn(in)
}
func (f *fakeUserService) SetPassword(_ context.Context, in *userv2.SetPasswordRequest, _ ...grpc.CallOption) (*userv2.SetPasswordResponse, error) {
	if f.setPasswordFn == nil {
		return &userv2.SetPasswordResponse{}, nil
	}
	return f.setPasswordFn(in)
}
func (f *fakeUserService) PasswordReset(_ context.Context, in *userv2.PasswordResetRequest, _ ...grpc.CallOption) (*userv2.PasswordResetResponse, error) {
	if f.passwordResetFn == nil {
		return &userv2.PasswordResetResponse{}, nil
	}
	return f.passwordResetFn(in)
}

type fakeLinker struct {
	user     identity.User
	err      error
	lastInfo identity.ProviderUserInfo
	calls    int
	link     identity.IdentityLink
	linkErr  error
}

func (f *fakeLinker) GetOrCreateUserByProviderSubject(_ context.Context, _, _ string, info identity.ProviderUserInfo) (identity.User, error) {
	f.calls++
	f.lastInfo = info
	return f.user, f.err
}

func (f *fakeLinker) GetIdentityLinkByUserID(_ context.Context, _, _ string, _ identity.UserID) (identity.IdentityLink, error) {
	if f.linkErr != nil {
		return identity.IdentityLink{}, f.linkErr
	}
	if f.link == (identity.IdentityLink{}) {
		return identity.IdentityLink{}, identity.ErrUserNotFound
	}
	return f.link, nil
}

func newTestAuth(t *testing.T, s *fakeSessionService, u *fakeUserService, l *fakeLinker) *Authenticator {
	t.Helper()
	return NewAuthenticator(s, u, l, "tenant-test", "login.example.com", nil)
}

func sessionWithUser(userID string) *sessionv2.GetSessionResponse {
	return &sessionv2.GetSessionResponse{
		Session: &sessionv2.Session{
			Factors: &sessionv2.Factors{
				User: &sessionv2.UserFactor{Id: userID},
			},
		},
	}
}

func humanProfileResponse(userID string) *userv2.GetUserByIDResponse {
	display := "Zhixing Lin"
	return &userv2.GetUserByIDResponse{
		User: &userv2.User{
			UserId: userID,
			Type: &userv2.User_Human{
				Human: &userv2.HumanUser{
					UserId: userID,
					Profile: &userv2.HumanProfile{
						DisplayName: &display,
					},
					Email: &userv2.HumanEmail{
						Email:      "zhixing@example.com",
						IsVerified: true,
					},
					Phone: &userv2.HumanPhone{
						Phone:      "+8613800000000",
						IsVerified: false,
					},
				},
			},
		},
	}
}

func passwordOnlyCreate(t *testing.T, calls *int) func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
	t.Helper()
	return func(in *sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
		(*calls)++
		if in.Challenges != nil {
			t.Fatal("CreateSession must not request challenges")
		}
		if in.Checks == nil || in.Checks.User == nil || in.Checks.Password == nil || in.Checks.Password.Password != "secret" {
			t.Fatalf("CreateSession must contain exactly the user and expected password checks: %+v", in.Checks)
		}
		return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
	}
}

func passwordSessionService(t *testing.T, createCalls *int) *fakeSessionService {
	t.Helper()
	return &fakeSessionService{
		createFn: passwordOnlyCreate(t, createCalls),
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return sessionWithUser("user-zitadel-1"), nil
		},
	}
}

func TestBeginPasswordAuthenticationSuccess(t *testing.T) {
	createCalls := 0
	s := passwordSessionService(t, &createCalls)
	s.setFn = func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
		t.Fatal("password-only account must not request a WebAuthN challenge")
		return nil, nil
	}
	u := &fakeUserService{
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return humanProfileResponse("user-zitadel-1"), nil
		},
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return &userv2.ListAuthenticationMethodTypesResponse{AuthMethodTypes: []userv2.AuthenticationMethodType{
				userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSWORD,
			}}, nil
		},
	}
	l := &fakeLinker{user: identity.User{ID: "user_local_1", Status: identity.UserStatusActive}}

	res, err := newTestAuth(t, s, u, l).BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "zhixing.lin@example.com",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if createCalls != 1 {
		t.Fatalf("CreateSession calls = %d, want exactly 1 password check", createCalls)
	}
	if res.Status != auth.StatusAuthenticated || res.UserID != "user_local_1" {
		t.Fatalf("result = %+v, want authenticated local user", res)
	}
	if res.ProviderSessionReference != "s1" {
		t.Errorf("session reference = %q, want s1", res.ProviderSessionReference)
	}
	if len(res.AuthenticationMethods) != 1 || res.AuthenticationMethods[0] != auth.MethodPassword {
		t.Errorf("methods = %v, want [password]", res.AuthenticationMethods)
	}
	if l.calls != 1 || l.lastInfo.Subject != "user-zitadel-1" || l.lastInfo.Email != "zhixing@example.com" || !l.lastInfo.EmailVerified {
		t.Errorf("linked profile = %+v calls=%d", l.lastInfo, l.calls)
	}
}

func TestBeginPasswordAuthenticationRequiresTOTP(t *testing.T) {
	createCalls := 0
	s := passwordSessionService(t, &createCalls)
	s.setFn = func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
		t.Fatal("TOTP account must not request a WebAuthN challenge")
		return nil, nil
	}
	u := &fakeUserService{methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
		return &userv2.ListAuthenticationMethodTypesResponse{AuthMethodTypes: []userv2.AuthenticationMethodType{
			userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSWORD,
			userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_TOTP,
		}}, nil
	}}
	l := &fakeLinker{}

	res, err := newTestAuth(t, s, u, l).BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "zhixing.lin@example.com", Password: "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if createCalls != 1 {
		t.Fatalf("CreateSession calls = %d, want 1", createCalls)
	}
	if res.Status != auth.StatusMFARequired || len(res.AvailableMethods) != 1 || res.AvailableMethods[0] != auth.MFAMethodTOTP {
		t.Fatalf("result = %+v, want TOTP challenge", res)
	}
	if res.ProviderSessionID != "s1" || l.calls != 0 {
		t.Errorf("provider session = %q linker calls=%d, want s1 and 0", res.ProviderSessionID, l.calls)
	}
}

func TestBeginPasswordAuthenticationTOTPPreferredOverPasskey(t *testing.T) {
	createCalls := 0
	s := passwordSessionService(t, &createCalls)
	s.setFn = func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
		t.Fatal("TOTP must take precedence without requesting WebAuthN")
		return nil, nil
	}
	u := &fakeUserService{methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
		return &userv2.ListAuthenticationMethodTypesResponse{AuthMethodTypes: []userv2.AuthenticationMethodType{
			userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSKEY,
			userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_TOTP,
		}}, nil
	}}

	res, err := newTestAuth(t, s, u, &fakeLinker{}).BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com", Password: "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if createCalls != 1 || res.Status != auth.StatusMFARequired || len(res.AvailableMethods) != 1 || res.AvailableMethods[0] != auth.MFAMethodTOTP {
		t.Fatalf("CreateSession calls=%d result=%+v, want one password check and TOTP", createCalls, res)
	}
}

func TestBeginPasswordAuthenticationPasskeyChallengeUsesExistingSession(t *testing.T) {
	createCalls, setCalls := 0, 0
	options := &structpb.Struct{Fields: map[string]*structpb.Value{
		"challenge": structpb.NewStringValue("abc123"),
		"rpId":      structpb.NewStringValue("login.example.com"),
	}}
	s := passwordSessionService(t, &createCalls)
	s.setFn = func(in *sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
		setCalls++
		if in.SessionId != "s1" || in.SessionToken != "" {
			t.Fatalf("SetSession identity = (%q, token=%q), want (s1, empty)", in.SessionId, in.SessionToken)
		}
		if in.Checks != nil {
			t.Fatalf("SetSession must never repeat password or other checks: %+v", in.Checks)
		}
		if in.Challenges == nil || in.Challenges.WebAuthN == nil || in.Challenges.WebAuthN.Domain != "login.example.com" {
			t.Fatalf("SetSession WebAuthN challenge = %+v", in.Challenges)
		}
		return &sessionv2.SetSessionResponse{Challenges: &sessionv2.Challenges{
			WebAuthN: &sessionv2.Challenges_WebAuthN{PublicKeyCredentialRequestOptions: options},
		}}, nil
	}
	u := &fakeUserService{methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
		return &userv2.ListAuthenticationMethodTypesResponse{AuthMethodTypes: []userv2.AuthenticationMethodType{
			userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSKEY,
		}}, nil
	}}

	res, err := newTestAuth(t, s, u, &fakeLinker{}).BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com", Password: "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if createCalls != 1 || setCalls != 1 {
		t.Fatalf("CreateSession calls=%d SetSession calls=%d, want 1 and 1", createCalls, setCalls)
	}
	if res.Status != auth.StatusMFARequired || len(res.AvailableMethods) != 1 || res.AvailableMethods[0] != auth.MFAMethodPasskey {
		t.Fatalf("result = %+v, want passkey challenge", res)
	}
	var decoded structpb.Struct
	if err := json.Unmarshal(res.PasskeyRequestOptions, &decoded); err != nil || decoded.Fields["challenge"].GetStringValue() != "abc123" {
		t.Fatalf("passkey request options = %s, err=%v", res.PasskeyRequestOptions, err)
	}
}

func TestBeginPasswordAuthenticationPasskeyChallengeFailureFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		set  func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error)
	}{
		{name: "provider challenge error", set: func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			return nil, status.Error(codes.Internal, "WebAuthN begin login failed (WEBAU-4G8sw)")
		}},
		{name: "unrelated provider error", set: func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			return nil, status.Error(codes.Unavailable, "provider unavailable")
		}},
		{name: "nil response", set: func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			return nil, nil
		}},
		{name: "empty challenges", set: func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			return &sessionv2.SetSessionResponse{}, nil
		}},
		{name: "missing webauthn", set: func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			return &sessionv2.SetSessionResponse{Challenges: &sessionv2.Challenges{}}, nil
		}},
		{name: "missing request options", set: func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			return &sessionv2.SetSessionResponse{Challenges: &sessionv2.Challenges{WebAuthN: &sessionv2.Challenges_WebAuthN{}}}, nil
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			createCalls, deleted := 0, ""
			s := passwordSessionService(t, &createCalls)
			s.setFn = func(in *sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
				if in.Checks != nil || in.SessionToken != "" {
					t.Fatalf("challenge SetSession repeated credentials: %+v", in)
				}
				return test.set(in)
			}
			s.delFn = func(in *sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error) {
				deleted = in.SessionId
				return &sessionv2.DeleteSessionResponse{}, nil
			}
			u := &fakeUserService{methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
				return &userv2.ListAuthenticationMethodTypesResponse{AuthMethodTypes: []userv2.AuthenticationMethodType{
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSKEY,
				}}, nil
			}}
			l := &fakeLinker{}
			res, err := newTestAuth(t, s, u, l).BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
				Identifier: "u@example.com", Password: "secret",
			})
			if err != nil {
				t.Fatalf("BeginPasswordAuthentication: %v", err)
			}
			if createCalls != 1 || res.Status != auth.StatusProviderUnavailable || deleted != "s1" || l.calls != 0 {
				t.Fatalf("calls=%d status=%q deleted=%q linker=%d; want 1, unavailable, s1, 0", createCalls, res.Status, deleted, l.calls)
			}
		})
	}
}

func TestBeginPasswordAuthenticationWebAuthnDomainEmptyFailsClosed(t *testing.T) {
	for _, method := range []userv2.AuthenticationMethodType{
		userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSKEY,
		userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_U2F,
	} {
		t.Run(method.String(), func(t *testing.T) {
			createCalls, deleted := 0, ""
			s := passwordSessionService(t, &createCalls)
			s.setFn = func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
				t.Fatal("domain-empty flow must not call SetSession")
				return nil, nil
			}
			s.delFn = func(in *sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error) {
				deleted = in.SessionId
				return &sessionv2.DeleteSessionResponse{}, nil
			}
			u := &fakeUserService{methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
				return &userv2.ListAuthenticationMethodTypesResponse{AuthMethodTypes: []userv2.AuthenticationMethodType{method}}, nil
			}}
			a := NewAuthenticator(s, u, &fakeLinker{}, "tenant-test", "", nil)
			res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{Identifier: "u@example.com", Password: "secret"})
			if err != nil {
				t.Fatalf("BeginPasswordAuthentication: %v", err)
			}
			if createCalls != 1 || res.Status != auth.StatusProviderUnavailable || deleted != "s1" {
				t.Fatalf("calls=%d status=%q deleted=%q; want 1, unavailable, s1", createCalls, res.Status, deleted)
			}
		})
	}
}

func TestBeginPasswordAuthenticationNoFallbackOnOtherErrors(t *testing.T) {
	createCalls := 0
	s := &fakeSessionService{createFn: func(in *sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
		createCalls++
		if in.Challenges != nil || in.Checks == nil || in.Checks.Password == nil {
			t.Fatalf("unexpected CreateSession request: %+v", in)
		}
		return nil, status.Error(codes.Internal, "some other internal failure")
	}}
	res, err := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{}).BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com", Password: "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if createCalls != 1 || res.Status != auth.StatusProviderUnavailable {
		t.Fatalf("CreateSession calls=%d status=%q, want 1 and unavailable", createCalls, res.Status)
	}
}

// TestBeginPasswordAuthenticationAuthZFailure verifies a service-account
// permission failure while reading the user's authentication methods
// (NotFound + AUTHZ-*, e.g. "membership not found") is classified as
// provider_unavailable, not as invalid_credentials: a server-side
// configuration fault must never masquerade as a wrong password.
func TestBeginPasswordAuthenticationAuthZFailure(t *testing.T) {
	var deleted string
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return sessionWithUser("user-1"), nil
		},
		delFn: func(in *sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error) {
			deleted = in.SessionId
			return &sessionv2.DeleteSessionResponse{}, nil
		},
	}
	u := &fakeUserService{
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return nil, status.Error(codes.NotFound, "membership not found (AUTHZ-cdgFk)")
		},
	}
	a := newTestAuth(t, s, u, &fakeLinker{})
	res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusProviderUnavailable {
		t.Fatalf("status = %q, want %q (SA permission fault)", res.Status, auth.StatusProviderUnavailable)
	}
	if deleted != "s1" {
		t.Fatalf("deleted session = %q, want s1", deleted)
	}
}

// TestBeginPasswordAuthenticationSessionAuthZFailure verifies the same
// AUTHZ-* classification at the GetSession boundary.
func TestBeginPasswordAuthenticationSessionAuthZFailure(t *testing.T) {
	var deleted string
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return nil, status.Error(codes.NotFound, "membership not found (AUTHZ-cdgFk)")
		},
		delFn: func(in *sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error) {
			deleted = in.SessionId
			return &sessionv2.DeleteSessionResponse{}, nil
		},
	}
	a := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{})
	res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusProviderUnavailable {
		t.Fatalf("status = %q, want %q (SA permission fault)", res.Status, auth.StatusProviderUnavailable)
	}
	if deleted != "s1" {
		t.Fatalf("deleted session = %q, want s1", deleted)
	}
}

func TestBeginPasswordAuthenticationCleanupSurvivesCanceledRequest(t *testing.T) {
	deleteCalled := false
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return nil, status.Error(codes.Unavailable, "provider unavailable")
		},
		delCtxFn: func(ctx context.Context, in *sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error) {
			deleteCalled = true
			if in.SessionId != "s1" {
				t.Fatalf("deleted session = %q, want s1", in.SessionId)
			}
			if err := ctx.Err(); err != nil {
				t.Fatalf("cleanup inherited canceled request context: %v", err)
			}
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("cleanup context must have an independent deadline")
			}
			remaining := time.Until(deadline)
			if remaining <= 0 || remaining > providerSessionCleanupTimeout {
				t.Fatalf("cleanup deadline remaining = %s, want (0, %s]", remaining, providerSessionCleanupTimeout)
			}
			return &sessionv2.DeleteSessionResponse{}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{}).BeginPasswordAuthentication(ctx, auth.PasswordAuthenticationInput{
		Identifier: "u@example.com",
		Password:   "secret",
	})
	if err == nil {
		t.Fatal("BeginPasswordAuthentication error = nil, want provider failure")
	}
	if !deleteCalled {
		t.Fatal("provider session cleanup was not attempted")
	}
}

func TestCompleteMFAPasskeySuccess(t *testing.T) {
	var received *sessionv2.CheckWebAuthN
	s := &fakeSessionService{
		setFn: func(in *sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			if in.Checks == nil || in.Checks.WebAuthN == nil {
				return nil, errors.New("expected webauthn check")
			}
			received = in.Checks.WebAuthN
			return &sessionv2.SetSessionResponse{SessionToken: "tok2"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return sessionWithUser("user-zitadel-1"), nil
		},
	}
	u := &fakeUserService{
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return humanProfileResponse("user-zitadel-1"), nil
		},
	}
	l := &fakeLinker{user: identity.User{ID: "user_local_1", Status: identity.UserStatusActive}}

	a := newTestAuth(t, s, u, l)
	res, err := a.CompleteMFA(context.Background(), auth.MFAChallengeInput{
		ProviderSessionID: "s1",
		Method:            auth.MFAMethodPasskey,
		PasskeyAssertion:  json.RawMessage(`{"id":"assertion-1","response":{"authenticatorData":"abc"}}`),
	})
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.Status != auth.StatusAuthenticated {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusAuthenticated)
	}
	if res.ProviderSessionToken.Token() != "tok2" {
		t.Fatalf("provider session token = %q, want the final SetSession token", res.ProviderSessionToken)
	}
	// The assertion must have been parsed into the WebAuthn check struct.
	if received == nil || received.CredentialAssertionData == nil {
		t.Fatal("webauthn check must carry the parsed assertion")
	}
	id, ok := received.CredentialAssertionData.Fields["id"]
	if !ok || id.GetStringValue() != "assertion-1" {
		t.Errorf("assertion id not forwarded, got %v", received.CredentialAssertionData.Fields)
	}
	wantMethods := []auth.AuthenticationMethod{auth.MethodPassword, auth.MethodPasskey}
	if len(res.AuthenticationMethods) != 2 || res.AuthenticationMethods[0] != wantMethods[0] || res.AuthenticationMethods[1] != wantMethods[1] {
		t.Errorf("methods = %v, want %v", res.AuthenticationMethods, wantMethods)
	}
}

func TestCompleteMFABadPasskeyAssertion(t *testing.T) {
	s := &fakeSessionService{
		setFn: func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			return nil, errors.New("should not be called")
		},
	}
	a := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{})
	res, err := a.CompleteMFA(context.Background(), auth.MFAChallengeInput{
		ProviderSessionID: "s1",
		Method:            auth.MFAMethodPasskey,
		PasskeyAssertion:  json.RawMessage(`{not valid json`),
	})
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.Status != auth.StatusInvalidCredentials {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusInvalidCredentials)
	}
}

func TestBeginPasswordAuthenticationInvalidCredentials(t *testing.T) {
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "password invalid")
		},
	}
	a := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{})
	res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com",
		Password:   "wrong",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusInvalidCredentials {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusInvalidCredentials)
	}
}

func TestBeginPasswordAuthenticationProviderUnavailable(t *testing.T) {
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return nil, status.Error(codes.Unavailable, "connection refused")
		},
	}
	a := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{})
	res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusProviderUnavailable {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusProviderUnavailable)
	}
}

func TestCompleteMFATOTPSuccess(t *testing.T) {
	var receivedSessionID string
	s := &fakeSessionService{
		setFn: func(in *sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			receivedSessionID = in.SessionId
			if in.Checks == nil || in.Checks.Totp == nil || in.Checks.Totp.Code != "123456" {
				return nil, errors.New("expected totp check")
			}
			return &sessionv2.SetSessionResponse{SessionToken: "tok2"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return sessionWithUser("user-zitadel-1"), nil
		},
	}
	u := &fakeUserService{
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return humanProfileResponse("user-zitadel-1"), nil
		},
	}
	l := &fakeLinker{user: identity.User{ID: "user_local_1", Status: identity.UserStatusActive}}

	a := newTestAuth(t, s, u, l)
	res, err := a.CompleteMFA(context.Background(), auth.MFAChallengeInput{
		ProviderSessionID: "s1",
		Method:            auth.MFAMethodTOTP,
		Code:              "123456",
	})
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.Status != auth.StatusAuthenticated {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusAuthenticated)
	}
	if receivedSessionID != "s1" {
		t.Errorf("set session used id %q, want s1", receivedSessionID)
	}
	// The session reference stores the session ID only.
	if res.ProviderSessionReference != "s1" {
		t.Errorf("session reference = %q, want s1", res.ProviderSessionReference)
	}
	wantMethods := []auth.AuthenticationMethod{auth.MethodPassword, auth.MethodTOTP}
	if len(res.AuthenticationMethods) != 2 || res.AuthenticationMethods[0] != wantMethods[0] || res.AuthenticationMethods[1] != wantMethods[1] {
		t.Errorf("methods = %v, want %v", res.AuthenticationMethods, wantMethods)
	}
}

func TestCompleteMFAWrongTOTP(t *testing.T) {
	s := &fakeSessionService{
		setFn: func(*sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "totp invalid")
		},
	}
	a := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{})
	res, err := a.CompleteMFA(context.Background(), auth.MFAChallengeInput{
		ProviderSessionID: "s1",
		Method:            auth.MFAMethodTOTP,
		Code:              "000000",
	})
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.Status != auth.StatusInvalidCredentials {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusInvalidCredentials)
	}
}

func TestCompleteMFAInvalidProviderSession(t *testing.T) {
	a := newTestAuth(t, &fakeSessionService{}, &fakeUserService{}, &fakeLinker{})
	res, err := a.CompleteMFA(context.Background(), auth.MFAChallengeInput{
		ProviderSessionID: "",
		Method:            auth.MFAMethodTOTP,
		Code:              "123456",
	})
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.Status != auth.StatusExpired {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusExpired)
	}
}

func TestRevokeProviderSession(t *testing.T) {
	var deletedID string
	s := &fakeSessionService{
		delFn: func(in *sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error) {
			deletedID = in.SessionId
			return &sessionv2.DeleteSessionResponse{}, nil
		},
	}
	a := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{})
	if err := a.RevokeProviderSession(context.Background(), "s1"); err != nil {
		t.Fatalf("RevokeProviderSession: %v", err)
	}
	if deletedID != "s1" {
		t.Errorf("deleted session id = %q, want s1", deletedID)
	}
}

func TestRevokeProviderSessionNotFoundIsIdempotentButFailuresRemainVisible(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{name: "ordinary not found", err: status.Error(codes.NotFound, "session gone")},
		{name: "authz disguised as not found", err: status.Error(codes.NotFound, "membership not found (AUTHZ-cdgFk)"), wantErr: true},
		{name: "permission denied", err: status.Error(codes.PermissionDenied, "forbidden"), wantErr: true},
		{name: "transport unavailable", err: status.Error(codes.Unavailable, "connection refused"), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &fakeSessionService{
				delFn: func(*sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error) {
					return nil, test.err
				},
			}
			a := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{})
			err := a.RevokeProviderSession(context.Background(), "s1")
			if (err != nil) != test.wantErr {
				t.Fatalf("RevokeProviderSession error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestAuthenticatorCheck(t *testing.T) {
	s := &fakeSessionService{
		listFn: func(*sessionv2.ListSessionsRequest) (*sessionv2.ListSessionsResponse, error) {
			return &sessionv2.ListSessionsResponse{}, nil
		},
	}
	a := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{})
	if err := a.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if a.Name() != "auth_provider" {
		t.Errorf("name = %q, want auth_provider", a.Name())
	}
}

func TestMapAuthError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want auth.AuthenticationStatus
	}{
		{"nil", nil, auth.StatusAuthenticated},
		{"context deadline", context.DeadlineExceeded, auth.StatusProviderUnavailable},
		{"unavailable", status.Error(codes.Unavailable, "down"), auth.StatusProviderUnavailable},
		{"deadline", status.Error(codes.DeadlineExceeded, "slow"), auth.StatusProviderUnavailable},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad token"), auth.StatusProviderUnavailable},
		{"permission denied", status.Error(codes.PermissionDenied, "forbidden"), auth.StatusProviderUnavailable},
		{"authz disguised as not found", status.Error(codes.NotFound, "membership not found (AUTHZ-cdgFk)"), auth.StatusProviderUnavailable},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad password"), auth.StatusInvalidCredentials},
		{"not found", status.Error(codes.NotFound, "session gone"), auth.StatusInvalidCredentials},
		{"failed precondition", status.Error(codes.FailedPrecondition, "user locked"), auth.StatusInvalidCredentials},
		{"internal", status.Error(codes.Internal, "boom"), auth.StatusProviderUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapAuthError(tc.err); got != tc.want {
				t.Errorf("mapAuthError = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- Reauthentication password verification (ADR-0004 §7) ---

func TestVerifyUserPassword_RequiresIdentityLink(t *testing.T) {
	providerCalls := 0
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			providerCalls++
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
	}
	a := newTestAuth(t, s, &fakeUserService{}, &fakeLinker{})

	res, err := a.VerifyUserPassword(context.Background(), identity.UserID("user_local_1"), "secret")
	if err != nil {
		t.Fatalf("VerifyUserPassword: %v", err)
	}
	if res.Status != auth.StatusInvalidCredentials {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusInvalidCredentials)
	}
	// Without an identity link the provider must never be contacted.
	if providerCalls != 0 {
		t.Errorf("provider calls = %d, want 0", providerCalls)
	}
}

func TestVerifyUserPassword_SuccessUsesLinkedSubject(t *testing.T) {
	var gotUserID, gotPassword string
	s := &fakeSessionService{
		createFn: func(in *sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			if search, ok := in.Checks.User.Search.(*sessionv2.CheckUser_UserId); ok {
				gotUserID = search.UserId
			}
			if in.Checks.Password != nil {
				gotPassword = in.Checks.Password.Password
			}
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return sessionWithUser("user-zitadel-1"), nil
		},
	}
	u := &fakeUserService{
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return humanProfileResponse("user-zitadel-1"), nil
		},
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return &userv2.ListAuthenticationMethodTypesResponse{
				AuthMethodTypes: []userv2.AuthenticationMethodType{
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSWORD,
				},
			}, nil
		},
	}
	l := &fakeLinker{
		user: identity.User{ID: "user_local_1", Status: identity.UserStatusActive},
		link: identity.IdentityLink{
			UserID:          identity.UserID("user_local_1"),
			Provider:        ProviderName,
			ProviderSubject: "user-zitadel-1",
		},
	}
	a := newTestAuth(t, s, u, l)

	res, err := a.VerifyUserPassword(context.Background(), identity.UserID("user_local_1"), "secret")
	if err != nil {
		t.Fatalf("VerifyUserPassword: %v", err)
	}
	if res.Status != auth.StatusAuthenticated {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusAuthenticated)
	}
	// The provider user is resolved from the identity link — never from a
	// caller-supplied identifier.
	if gotUserID != "user-zitadel-1" {
		t.Errorf("provider user id = %q, want user-zitadel-1", gotUserID)
	}
	if gotPassword != "secret" {
		t.Errorf("password check = %q, want secret", gotPassword)
	}
}

func TestVerifyUserPassword_LinkLookupErrorPropagates(t *testing.T) {
	lookupErr := errors.New("db down")
	a := newTestAuth(t, &fakeSessionService{}, &fakeUserService{}, &fakeLinker{linkErr: lookupErr})

	if _, err := a.VerifyUserPassword(context.Background(), identity.UserID("user_local_1"), "secret"); !errors.Is(err, lookupErr) {
		t.Fatalf("err = %v, want lookup error propagated", err)
	}
}
