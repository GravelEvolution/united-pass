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
func (f *fakeSessionService) DeleteSession(_ context.Context, in *sessionv2.DeleteSessionRequest, _ ...grpc.CallOption) (*sessionv2.DeleteSessionResponse, error) {
	return f.delFn(in)
}

type fakeUserService struct {
	getFn             func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error)
	methodsFn         func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error)
	registerTOTPFn    func(*userv2.RegisterTOTPRequest) (*userv2.RegisterTOTPResponse, error)
	verifyTOTPFn      func(*userv2.VerifyTOTPRegistrationRequest) (*userv2.VerifyTOTPRegistrationResponse, error)
	removeTOTPFn      func(*userv2.RemoveTOTPRequest) (*userv2.RemoveTOTPResponse, error)
	registerPasskeyFn func(*userv2.RegisterPasskeyRequest) (*userv2.RegisterPasskeyResponse, error)
	verifyPasskeyFn   func(*userv2.VerifyPasskeyRegistrationRequest) (*userv2.VerifyPasskeyRegistrationResponse, error)
	listPasskeysFn    func(*userv2.ListPasskeysRequest) (*userv2.ListPasskeysResponse, error)
	removePasskeyFn   func(*userv2.RemovePasskeyRequest) (*userv2.RemovePasskeyResponse, error)
	setPasswordFn     func(*userv2.SetPasswordRequest) (*userv2.SetPasswordResponse, error)
	setEmailFn        func(*userv2.SetEmailRequest) (*userv2.SetEmailResponse, error)
	verifyEmailFn     func(*userv2.VerifyEmailRequest) (*userv2.VerifyEmailResponse, error)
	setPhoneFn        func(*userv2.SetPhoneRequest) (*userv2.SetPhoneResponse, error)
	verifyPhoneFn     func(*userv2.VerifyPhoneRequest) (*userv2.VerifyPhoneResponse, error)
}

func (f *fakeUserService) GetUserByID(_ context.Context, in *userv2.GetUserByIDRequest, _ ...grpc.CallOption) (*userv2.GetUserByIDResponse, error) {
	return f.getFn(in)
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
func (f *fakeUserService) SetEmail(_ context.Context, in *userv2.SetEmailRequest, _ ...grpc.CallOption) (*userv2.SetEmailResponse, error) {
	if f.setEmailFn == nil {
		return &userv2.SetEmailResponse{}, nil
	}
	return f.setEmailFn(in)
}
func (f *fakeUserService) VerifyEmail(_ context.Context, in *userv2.VerifyEmailRequest, _ ...grpc.CallOption) (*userv2.VerifyEmailResponse, error) {
	if f.verifyEmailFn == nil {
		return &userv2.VerifyEmailResponse{}, nil
	}
	return f.verifyEmailFn(in)
}
func (f *fakeUserService) SetPhone(_ context.Context, in *userv2.SetPhoneRequest, _ ...grpc.CallOption) (*userv2.SetPhoneResponse, error) {
	if f.setPhoneFn == nil {
		return &userv2.SetPhoneResponse{}, nil
	}
	return f.setPhoneFn(in)
}
func (f *fakeUserService) VerifyPhone(_ context.Context, in *userv2.VerifyPhoneRequest, _ ...grpc.CallOption) (*userv2.VerifyPhoneResponse, error) {
	if f.verifyPhoneFn == nil {
		return &userv2.VerifyPhoneResponse{}, nil
	}
	return f.verifyPhoneFn(in)
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

func TestBeginPasswordAuthenticationSuccess(t *testing.T) {
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
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
	l := &fakeLinker{user: identity.User{ID: "user_local_1", Status: identity.UserStatusActive}}

	a := newTestAuth(t, s, u, l)
	res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "zhixing.lin@example.com",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusAuthenticated {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusAuthenticated)
	}
	if res.UserID != "user_local_1" {
		t.Errorf("user id = %q, want user_local_1", res.UserID)
	}
	if res.Provider != ProviderName {
		t.Errorf("provider = %q, want %q", res.Provider, ProviderName)
	}
	// Provider session reference must be the session ID only — the token is
	// discarded and must never be persisted or returned.
	if res.ProviderSessionReference != "s1" {
		t.Errorf("session reference = %q, want s1 (session ID only)", res.ProviderSessionReference)
	}
	if len(res.AuthenticationMethods) != 1 || res.AuthenticationMethods[0] != auth.MethodPassword {
		t.Errorf("methods = %v, want [password]", res.AuthenticationMethods)
	}

	// The profile must be synchronized into the identity linker.
	if l.calls != 1 {
		t.Fatalf("linker calls = %d, want 1", l.calls)
	}
	if l.lastInfo.Subject != "user-zitadel-1" {
		t.Errorf("linked subject = %q, want user-zitadel-1", l.lastInfo.Subject)
	}
	if l.lastInfo.DisplayName != "Zhixing Lin" {
		t.Errorf("linked display name = %q, want Zhixing Lin", l.lastInfo.DisplayName)
	}
	if l.lastInfo.Email != "zhixing@example.com" || !l.lastInfo.EmailVerified {
		t.Errorf("linked email = %q verified=%v, want zhixing@example.com verified=true", l.lastInfo.Email, l.lastInfo.EmailVerified)
	}
	if l.lastInfo.Phone != "+8613800000000" {
		t.Errorf("linked phone = %q, want +8613800000000", l.lastInfo.Phone)
	}
}

func TestBeginPasswordAuthenticationRequiresTOTP(t *testing.T) {
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return sessionWithUser("user-zitadel-1"), nil
		},
	}
	u := &fakeUserService{
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return &userv2.ListAuthenticationMethodTypesResponse{
				AuthMethodTypes: []userv2.AuthenticationMethodType{
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSWORD,
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_TOTP,
				},
			}, nil
		},
	}
	l := &fakeLinker{}

	a := newTestAuth(t, s, u, l)
	res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "zhixing.lin@example.com",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusMFARequired {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusMFARequired)
	}
	if len(res.AvailableMethods) != 1 || res.AvailableMethods[0] != auth.MFAMethodTOTP {
		t.Errorf("available methods = %v, want [totp]", res.AvailableMethods)
	}
	// The provider session ID is server-side only; it must NOT be returned as
	// an MFA token. There is no MFAToken field on the result at all.
	if res.ProviderSessionID != "s1" {
		t.Errorf("provider session id = %q, want s1", res.ProviderSessionID)
	}
	// The linker must not have been called before MFA completes.
	if l.calls != 0 {
		t.Errorf("linker calls before MFA = %d, want 0", l.calls)
	}
}

func TestBeginPasswordAuthenticationPasskeyChallenge(t *testing.T) {
	options := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"challenge": structpb.NewStringValue("abc123"),
			"rpId":      structpb.NewStringValue("login.example.com"),
		},
	}
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return &sessionv2.CreateSessionResponse{
				SessionId:    "s1",
				SessionToken: "tok1",
				Challenges: &sessionv2.Challenges{
					WebAuthN: &sessionv2.Challenges_WebAuthN{
						PublicKeyCredentialRequestOptions: options,
					},
				},
			}, nil
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
	if res.Status != auth.StatusMFARequired {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusMFARequired)
	}
	if len(res.AvailableMethods) != 1 || res.AvailableMethods[0] != auth.MFAMethodPasskey {
		t.Errorf("available methods = %v, want [passkey]", res.AvailableMethods)
	}
	// The WebAuthn request options must reach the HTTP layer as a JSON object.
	if len(res.PasskeyRequestOptions) == 0 {
		t.Fatal("passkey request options must be set for the browser ceremony")
	}
	var decoded structpb.Struct
	if err := json.Unmarshal(res.PasskeyRequestOptions, &decoded); err != nil {
		t.Fatalf("passkey request options must be valid JSON: %v", err)
	}
	if decoded.Fields["challenge"].GetStringValue() != "abc123" {
		t.Errorf("passkey request options challenge = %q, want abc123", decoded.Fields["challenge"].GetStringValue())
	}
	if res.ProviderSessionID != "s1" {
		t.Errorf("provider session id = %q, want s1", res.ProviderSessionID)
	}
}

// TestBeginPasswordAuthenticationPasskeyChallengeFallback verifies that a
// WebAuthN challenge issuance failure (ZITADEL internal error, e.g. no
// passkeys registered or RP not configured) does not block password login:
// the adapter retries without challenges and the user can continue with TOTP.
func TestBeginPasswordAuthenticationPasskeyChallengeFallback(t *testing.T) {
	var calls int
	var retriedWithoutChallenge bool
	s := &fakeSessionService{
		createFn: func(in *sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			calls++
			if in.Challenges != nil {
				// First call requests a WebAuthN challenge and ZITADEL fails.
				return nil, status.Error(codes.Internal, "WebAuthN begin login failed (WEBAU-4G8sw)")
			}
			retriedWithoutChallenge = true
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return sessionWithUser("user-1"), nil
		},
	}
	u := &fakeUserService{
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return &userv2.ListAuthenticationMethodTypesResponse{
				AuthMethodTypes: []userv2.AuthenticationMethodType{
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_TOTP,
				},
			}, nil
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
	if calls != 2 {
		t.Errorf("CreateSession calls = %d, want 2 (challenge + fallback)", calls)
	}
	if !retriedWithoutChallenge {
		t.Error("expected a retry without WebAuthN challenges")
	}
	if res.Status != auth.StatusMFARequired {
		t.Fatalf("status = %q, want %q (TOTP fallback)", res.Status, auth.StatusMFARequired)
	}
	if len(res.AvailableMethods) != 1 || res.AvailableMethods[0] != auth.MFAMethodTOTP {
		t.Errorf("available methods = %v, want [totp]", res.AvailableMethods)
	}
}

// TestBeginPasswordAuthenticationNoFallbackOnOtherErrors verifies the retry
// only happens for WebAuthN challenge failures, not for arbitrary internal
// errors (which must not mask provider problems).
func TestBeginPasswordAuthenticationNoFallbackOnOtherErrors(t *testing.T) {
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return nil, status.Error(codes.Internal, "some other internal failure")
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

// challengeFailureSessionService returns a fake whose CreateSession fails
// with the real ZITADEL WebAuthN challenge error on the first call and
// succeeds without challenges on the retry.
func challengeFailureSessionService(deleted *string, getFn func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error)) *fakeSessionService {
	return &fakeSessionService{
		createFn: func(in *sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			if in.Challenges != nil {
				return nil, status.Error(codes.Internal, "WebAuthN begin login failed (WEBAU-4G8sw)")
			}
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
		getFn: func(in *sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			if getFn != nil {
				return getFn(in)
			}
			return sessionWithUser("user-1"), nil
		},
		delFn: func(in *sessionv2.DeleteSessionRequest) (*sessionv2.DeleteSessionResponse, error) {
			if deleted != nil {
				*deleted = in.SessionId
			}
			return &sessionv2.DeleteSessionResponse{}, nil
		},
	}
}

// TestBeginPasswordAuthenticationPasskeyChallengeFallbackFailClosed verifies
// that a passkey-only user (no TOTP) is NEVER downgraded to password-only
// login when the WebAuthN challenge cannot be issued: the adapter deletes the
// just-created provider session, returns provider_unavailable and must not
// create a local user/session.
func TestBeginPasswordAuthenticationPasskeyChallengeFallbackFailClosed(t *testing.T) {
	var deleted string
	s := challengeFailureSessionService(&deleted, nil)
	u := &fakeUserService{
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return &userv2.ListAuthenticationMethodTypesResponse{
				AuthMethodTypes: []userv2.AuthenticationMethodType{
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSKEY,
				},
			}, nil
		},
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return humanProfileResponse("user-1"), nil
		},
	}
	l := &fakeLinker{user: identity.User{ID: "user_local_1", Status: identity.UserStatusActive}}
	a := newTestAuth(t, s, u, l)
	res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusProviderUnavailable {
		t.Fatalf("status = %q, want %q (fail closed)", res.Status, auth.StatusProviderUnavailable)
	}
	if deleted != "s1" {
		t.Errorf("provider session deleted = %q, want s1 (fail closed must revoke the session)", deleted)
	}
	if l.calls != 0 {
		t.Errorf("linker calls = %d, want 0 (no local user/session may be created)", l.calls)
	}
	if res.UserID != "" {
		t.Errorf("user id = %q, want empty", res.UserID)
	}
}

// TestBeginPasswordAuthenticationPasskeyChallengeFallbackU2F verifies U2F
// security keys are treated like passkeys for the fail-closed decision.
func TestBeginPasswordAuthenticationPasskeyChallengeFallbackU2F(t *testing.T) {
	var deleted string
	s := challengeFailureSessionService(&deleted, nil)
	u := &fakeUserService{
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return &userv2.ListAuthenticationMethodTypesResponse{
				AuthMethodTypes: []userv2.AuthenticationMethodType{
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_U2F,
				},
			}, nil
		},
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return humanProfileResponse("user-1"), nil
		},
	}
	l := &fakeLinker{user: identity.User{ID: "user_local_1", Status: identity.UserStatusActive}}
	a := newTestAuth(t, s, u, l)
	res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusProviderUnavailable {
		t.Fatalf("status = %q, want %q (fail closed)", res.Status, auth.StatusProviderUnavailable)
	}
	if deleted != "s1" {
		t.Errorf("provider session deleted = %q, want s1", deleted)
	}
	if l.calls != 0 {
		t.Errorf("linker calls = %d, want 0", l.calls)
	}
}

// TestBeginPasswordAuthenticationPasskeyChallengeFallbackPasskeyAndTOTP
// verifies a user with both passkey and TOTP can fall back to TOTP when the
// passkey challenge cannot be issued.
func TestBeginPasswordAuthenticationPasskeyChallengeFallbackPasskeyAndTOTP(t *testing.T) {
	var deleted string
	s := challengeFailureSessionService(&deleted, nil)
	u := &fakeUserService{
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return &userv2.ListAuthenticationMethodTypesResponse{
				AuthMethodTypes: []userv2.AuthenticationMethodType{
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSKEY,
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_TOTP,
				},
			}, nil
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
	if res.Status != auth.StatusMFARequired {
		t.Fatalf("status = %q, want %q (TOTP fallback)", res.Status, auth.StatusMFARequired)
	}
	if len(res.AvailableMethods) != 1 || res.AvailableMethods[0] != auth.MFAMethodTOTP {
		t.Errorf("available methods = %v, want [totp]", res.AvailableMethods)
	}
	if deleted != "" {
		t.Errorf("provider session deleted = %q, want none (TOTP fallback keeps the session)", deleted)
	}
}

// TestBeginPasswordAuthenticationPasskeyChallengeFallbackNoMFA verifies a
// user with no second factor at all (password only) can authenticate with
// just the password after the challenge fallback.
func TestBeginPasswordAuthenticationPasskeyChallengeFallbackNoMFA(t *testing.T) {
	s := challengeFailureSessionService(nil, nil)
	u := &fakeUserService{
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return &userv2.ListAuthenticationMethodTypesResponse{
				AuthMethodTypes: []userv2.AuthenticationMethodType{
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSWORD,
				},
			}, nil
		},
		getFn: func(*userv2.GetUserByIDRequest) (*userv2.GetUserByIDResponse, error) {
			return humanProfileResponse("user-1"), nil
		},
	}
	l := &fakeLinker{user: identity.User{ID: "user_local_1", Status: identity.UserStatusActive}}
	a := newTestAuth(t, s, u, l)
	res, err := a.BeginPasswordAuthentication(context.Background(), auth.PasswordAuthenticationInput{
		Identifier: "u@example.com",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusAuthenticated {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusAuthenticated)
	}
	if l.calls != 1 {
		t.Errorf("linker calls = %d, want 1", l.calls)
	}
	if res.UserID != "user_local_1" {
		t.Errorf("user id = %q, want user_local_1", res.UserID)
	}
}

// TestBeginPasswordAuthenticationAuthZFailure verifies a service-account
// permission failure while reading the user's authentication methods
// (NotFound + AUTHZ-*, e.g. "membership not found") is classified as
// provider_unavailable, not as invalid_credentials: a server-side
// configuration fault must never masquerade as a wrong password.
func TestBeginPasswordAuthenticationAuthZFailure(t *testing.T) {
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return sessionWithUser("user-1"), nil
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
}

// TestBeginPasswordAuthenticationSessionAuthZFailure verifies the same
// AUTHZ-* classification at the GetSession boundary.
func TestBeginPasswordAuthenticationSessionAuthZFailure(t *testing.T) {
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return &sessionv2.CreateSessionResponse{SessionId: "s1", SessionToken: "tok1"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return nil, status.Error(codes.NotFound, "membership not found (AUTHZ-cdgFk)")
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
