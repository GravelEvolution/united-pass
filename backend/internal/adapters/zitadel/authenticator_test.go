package zitadel

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	sessionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	methodsFn func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error)
}

func (f *fakeUserService) ListAuthenticationMethodTypes(_ context.Context, in *userv2.ListAuthenticationMethodTypesRequest, _ ...grpc.CallOption) (*userv2.ListAuthenticationMethodTypesResponse, error) {
	return f.methodsFn(in)
}

type fakeLinker struct {
	user identity.User
	err  error
}

func (f *fakeLinker) GetOrCreateUserByProviderSubject(_ context.Context, _, _ string, _ identity.ProviderUserInfo) (identity.User, error) {
	return f.user, f.err
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
	if res.ProviderSessionReference != "s1:tok1" {
		t.Errorf("session reference = %q, want s1:tok1", res.ProviderSessionReference)
	}
	if len(res.AuthenticationMethods) != 1 || res.AuthenticationMethods[0] != auth.MethodPassword {
		t.Errorf("methods = %v, want [password]", res.AuthenticationMethods)
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
	if res.MFAToken != "s1:tok1" {
		t.Errorf("mfa token = %q, want s1:tok1", res.MFAToken)
	}
}

func TestBeginPasswordAuthenticationPasskeyChallenge(t *testing.T) {
	s := &fakeSessionService{
		createFn: func(*sessionv2.CreateSessionRequest) (*sessionv2.CreateSessionResponse, error) {
			return &sessionv2.CreateSessionResponse{
				SessionId:    "s1",
				SessionToken: "tok1",
				Challenges: &sessionv2.Challenges{
					WebAuthN: &sessionv2.Challenges_WebAuthN{},
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
	var receivedToken string
	s := &fakeSessionService{
		setFn: func(in *sessionv2.SetSessionRequest) (*sessionv2.SetSessionResponse, error) {
			receivedToken = in.SessionToken
			if in.Checks == nil || in.Checks.Totp == nil || in.Checks.Totp.Code != "123456" {
				return nil, errors.New("expected totp check")
			}
			return &sessionv2.SetSessionResponse{SessionToken: "tok2"}, nil
		},
		getFn: func(*sessionv2.GetSessionRequest) (*sessionv2.GetSessionResponse, error) {
			return sessionWithUser("user-zitadel-1"), nil
		},
	}
	l := &fakeLinker{user: identity.User{ID: "user_local_1", Status: identity.UserStatusActive}}

	a := newTestAuth(t, s, &fakeUserService{}, l)
	res, err := a.CompleteMFA(context.Background(), auth.MFAChallengeInput{
		MFAToken: "s1:tok1",
		Method:   auth.MFAMethodTOTP,
		Code:     "123456",
	})
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.Status != auth.StatusAuthenticated {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusAuthenticated)
	}
	if receivedToken != "tok1" {
		t.Errorf("set session used token %q, want tok1", receivedToken)
	}
	// The new session token becomes the provider session reference.
	if res.ProviderSessionReference != "s1:tok2" {
		t.Errorf("session reference = %q, want s1:tok2", res.ProviderSessionReference)
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
		MFAToken: "s1:tok1",
		Method:   auth.MFAMethodTOTP,
		Code:     "000000",
	})
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.Status != auth.StatusInvalidCredentials {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusInvalidCredentials)
	}
}

func TestCompleteMFAInvalidTokenFormat(t *testing.T) {
	a := newTestAuth(t, &fakeSessionService{}, &fakeUserService{}, &fakeLinker{})
	res, err := a.CompleteMFA(context.Background(), auth.MFAChallengeInput{
		MFAToken: "not-a-valid-token",
		Method:   auth.MFAMethodTOTP,
		Code:     "123456",
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
	if err := a.RevokeProviderSession(context.Background(), "s1:tok1"); err != nil {
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

func TestSessionRefRoundTrip(t *testing.T) {
	ref := encodeSessionRef("session-123", "token-abc")
	sid, tok, err := decodeSessionRef(ref)
	if err != nil {
		t.Fatalf("decodeSessionRef: %v", err)
	}
	if sid != "session-123" || tok != "token-abc" {
		t.Errorf("decoded = (%q, %q), want (session-123, token-abc)", sid, tok)
	}
}

func TestDecodeSessionRefInvalid(t *testing.T) {
	for _, ref := range []string{"", "no-separator", ":empty-parts", "a:"} {
		if _, _, err := decodeSessionRef(ref); err == nil {
			t.Errorf("decodeSessionRef(%q) should fail", ref)
		}
	}
}
