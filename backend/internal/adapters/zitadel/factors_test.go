//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the ZITADEL security factor adapter
//

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const factorSubject = "provider-user-1"

func factorLinker() *fakeLinker {
	return &fakeLinker{link: identity.IdentityLink{
		UserID:          identity.UserID("user-1"),
		ProviderSubject: factorSubject,
	}}
}

func factorAuth(t *testing.T, u *fakeUserService, domain string) *Authenticator {
	t.Helper()
	return NewAuthenticator(&fakeSessionService{}, u, factorLinker(), "tenant-test", domain, nil)
}

func grpcErr(code codes.Code, msg string) error {
	return status.Error(code, msg)
}

// --- TOTP lifecycle ---

func TestFactorBeginTOTP_Success(t *testing.T) {
	var got *userv2.RegisterTOTPRequest
	u := &fakeUserService{
		registerTOTPFn: func(in *userv2.RegisterTOTPRequest) (*userv2.RegisterTOTPResponse, error) {
			got = in
			return &userv2.RegisterTOTPResponse{Uri: "otpauth://totp/x?secret=S", Secret: "S"}, nil
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	enrollment, err := a.BeginTOTPEnrollment(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("begin TOTP: %v", err)
	}
	if got.UserId != factorSubject {
		t.Errorf("provider user = %q, want %q (resolved from identity link)", got.UserId, factorSubject)
	}
	if enrollment.Secret != "S" || enrollment.OTPAuthURI != "otpauth://totp/x?secret=S" {
		t.Errorf("enrollment = %+v, want secret and otpauth URI", enrollment)
	}
}

func TestFactorBeginTOTP_AlreadySet(t *testing.T) {
	u := &fakeUserService{
		registerTOTPFn: func(*userv2.RegisterTOTPRequest) (*userv2.RegisterTOTPResponse, error) {
			return nil, grpcErr(codes.AlreadyExists, "COMMAND-4o1x TOTP already exists")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if _, err := a.BeginTOTPEnrollment(context.Background(), "user-1"); !errors.Is(err, auth.ErrFactorAlreadySet) {
		t.Fatalf("err = %v, want ErrFactorAlreadySet", err)
	}
}

func TestFactorBeginTOTP_EmptySecretFailsClosed(t *testing.T) {
	u := &fakeUserService{
		registerTOTPFn: func(*userv2.RegisterTOTPRequest) (*userv2.RegisterTOTPResponse, error) {
			return &userv2.RegisterTOTPResponse{}, nil // no secret material
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if _, err := a.BeginTOTPEnrollment(context.Background(), "user-1"); !errors.Is(err, auth.ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
}

func TestFactorConfirmTOTP_WrongCode(t *testing.T) {
	u := &fakeUserService{
		verifyTOTPFn: func(*userv2.VerifyTOTPRegistrationRequest) (*userv2.VerifyTOTPRegistrationResponse, error) {
			return nil, grpcErr(codes.InvalidArgument, "EVENT-8isk2 invalid code")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if err := a.ConfirmTOTPEnrollment(context.Background(), "user-1", "000000"); !errors.Is(err, auth.ErrInvalidFactorCode) {
		t.Fatalf("err = %v, want ErrInvalidFactorCode", err)
	}
}

func TestFactorConfirmTOTP_NoPendingEnrollment(t *testing.T) {
	u := &fakeUserService{
		verifyTOTPFn: func(*userv2.VerifyTOTPRegistrationRequest) (*userv2.VerifyTOTPRegistrationResponse, error) {
			return nil, grpcErr(codes.NotFound, "COMMAND-4o2x TOTP not found")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if err := a.ConfirmTOTPEnrollment(context.Background(), "user-1", "123456"); !errors.Is(err, auth.ErrFactorNotSet) {
		t.Fatalf("err = %v, want ErrFactorNotSet", err)
	}
}

func TestFactorRemoveTOTP_NotEnrolled(t *testing.T) {
	u := &fakeUserService{
		removeTOTPFn: func(*userv2.RemoveTOTPRequest) (*userv2.RemoveTOTPResponse, error) {
			return nil, grpcErr(codes.NotFound, "COMMAND-4o3x TOTP not found")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if err := a.RemoveTOTP(context.Background(), "user-1"); !errors.Is(err, auth.ErrFactorNotSet) {
		t.Fatalf("err = %v, want ErrFactorNotSet", err)
	}
}

func TestFactorWrite_InvalidArgumentIsProviderUnavailable(t *testing.T) {
	// On begin/remove paths there is no user-controlled input, so an
	// InvalidArgument rejection is a server-side fault and fails closed to
	// provider unavailable (never a user-facing input error).
	u := &fakeUserService{
		removeTOTPFn: func(*userv2.RemoveTOTPRequest) (*userv2.RemoveTOTPResponse, error) {
			return nil, grpcErr(codes.InvalidArgument, "COMMAND-xyz state fault")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if err := a.RemoveTOTP(context.Background(), "user-1"); !errors.Is(err, auth.ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
}

// --- Passkey lifecycle ---

func passkeyCreationOptions(t *testing.T) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(map[string]interface{}{
		"challenge": "abc",
		"rp":        map[string]interface{}{"id": "rp.example.com"},
	})
	if err != nil {
		t.Fatalf("build struct: %v", err)
	}
	return s
}

func TestFactorBeginPasskey_Success(t *testing.T) {
	var got *userv2.RegisterPasskeyRequest
	u := &fakeUserService{
		registerPasskeyFn: func(in *userv2.RegisterPasskeyRequest) (*userv2.RegisterPasskeyResponse, error) {
			got = in
			return &userv2.RegisterPasskeyResponse{
				PasskeyId:                          "pk-1",
				PublicKeyCredentialCreationOptions: passkeyCreationOptions(t),
			}, nil
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	enrollment, err := a.BeginPasskeyEnrollment(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("begin passkey: %v", err)
	}
	if got.UserId != factorSubject || got.Domain != "rp.example.com" {
		t.Errorf("request user/domain = %q/%q, want %q/rp.example.com", got.UserId, got.Domain, factorSubject)
	}
	if enrollment.PasskeyID != "pk-1" {
		t.Errorf("passkeyID = %q, want pk-1", enrollment.PasskeyID)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(enrollment.CreationOptions, &decoded); err != nil {
		t.Fatalf("creation options must be a JSON object: %v", err)
	}
	if decoded["challenge"] != "abc" {
		t.Errorf("creation options = %v, want verbatim challenge", decoded)
	}
}

func TestFactorBeginPasskey_NoDomainFailsClosed(t *testing.T) {
	u := &fakeUserService{}
	a := factorAuth(t, u, "") // no relying-party domain configured

	if _, err := a.BeginPasskeyEnrollment(context.Background(), "user-1"); !errors.Is(err, auth.ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
}

func TestFactorConfirmPasskey_BadAttestation(t *testing.T) {
	a := factorAuth(t, &fakeUserService{}, "rp.example.com")

	if err := a.ConfirmPasskeyEnrollment(context.Background(), "user-1", "pk-1", "key", json.RawMessage("not-json")); !errors.Is(err, auth.ErrInvalidFactorCode) {
		t.Fatalf("err = %v, want ErrInvalidFactorCode", err)
	}
}

func TestFactorConfirmPasskey_Rejected(t *testing.T) {
	u := &fakeUserService{
		verifyPasskeyFn: func(*userv2.VerifyPasskeyRegistrationRequest) (*userv2.VerifyPasskeyRegistrationResponse, error) {
			return nil, grpcErr(codes.FailedPrecondition, "COMMAND-WebAuthN verification failed")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	err := a.ConfirmPasskeyEnrollment(context.Background(), "user-1", "pk-1", "key", json.RawMessage(`{"id":"cred"}`))
	if !errors.Is(err, auth.ErrInvalidFactorCode) {
		t.Fatalf("err = %v, want ErrInvalidFactorCode", err)
	}
}

func TestFactorRemovePasskey_NotFound(t *testing.T) {
	u := &fakeUserService{
		removePasskeyFn: func(*userv2.RemovePasskeyRequest) (*userv2.RemovePasskeyResponse, error) {
			return nil, grpcErr(codes.NotFound, "COMMAND-pk not found")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if err := a.RemovePasskey(context.Background(), "user-1", "pk-unknown"); !errors.Is(err, auth.ErrFactorNotSet) {
		t.Fatalf("err = %v, want ErrFactorNotSet", err)
	}
}

// --- Listing and summary ---

func factorPasskeyList() *userv2.ListPasskeysResponse {
	return &userv2.ListPasskeysResponse{
		Result: []*userv2.Passkey{
			{Id: "pk-ready", Name: "MacBook", State: userv2.AuthFactorState_AUTH_FACTOR_STATE_READY},
			{Id: "pk-pending", State: userv2.AuthFactorState_AUTH_FACTOR_STATE_NOT_READY},
			{Id: "pk-removed", State: userv2.AuthFactorState_AUTH_FACTOR_STATE_REMOVED},
		},
	}
}

func TestFactorListPasskeys_StateMapping(t *testing.T) {
	u := &fakeUserService{
		listPasskeysFn: func(*userv2.ListPasskeysRequest) (*userv2.ListPasskeysResponse, error) {
			return factorPasskeyList(), nil
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	passkeys, err := a.ListPasskeys(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("list passkeys: %v", err)
	}
	if len(passkeys) != 2 {
		t.Fatalf("passkeys = %d, want 2 (removed must be filtered)", len(passkeys))
	}
	if passkeys[0].ID != "pk-ready" || passkeys[0].State != auth.PasskeyStateActive || passkeys[0].Name != "MacBook" {
		t.Errorf("passkeys[0] = %+v, want pk-ready active MacBook", passkeys[0])
	}
	if passkeys[1].ID != "pk-pending" || passkeys[1].State != auth.PasskeyStatePending {
		t.Errorf("passkeys[1] = %+v, want pk-pending pending", passkeys[1])
	}
}

func TestFactorSummary(t *testing.T) {
	u := &fakeUserService{
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return &userv2.ListAuthenticationMethodTypesResponse{
				AuthMethodTypes: []userv2.AuthenticationMethodType{
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_PASSWORD,
					userv2.AuthenticationMethodType_AUTHENTICATION_METHOD_TYPE_TOTP,
				},
			}, nil
		},
		listPasskeysFn: func(*userv2.ListPasskeysRequest) (*userv2.ListPasskeysResponse, error) {
			return factorPasskeyList(), nil
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	summary, err := a.FactorSummary(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("factor summary: %v", err)
	}
	if !summary.PasswordSet || !summary.TOTPEnabled {
		t.Errorf("summary = %+v, want password set and TOTP enabled", summary)
	}
	if len(summary.Passkeys) != 2 {
		t.Errorf("summary passkeys = %d, want 2", len(summary.Passkeys))
	}
}

// --- Fail-closed seams ---

func TestFactor_NoIdentityLinkFailsClosed(t *testing.T) {
	// A session user without a provider link can never reach the factor
	// surface: fail closed as provider unavailable, never reveal state.
	u := &fakeUserService{}
	a := NewAuthenticator(&fakeSessionService{}, u, &fakeLinker{}, "tenant-test", "rp.example.com", nil)

	if _, err := a.BeginTOTPEnrollment(context.Background(), "user-1"); !errors.Is(err, auth.ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
}

func TestFactor_SAPermissionFaultFailsClosed(t *testing.T) {
	// ZITADEL surfaces insufficient SA permission as NotFound + AUTHZ-*:
	// provider.forbidden, never a user-facing factor error (ADR-0006 §10).
	u := &fakeUserService{
		registerTOTPFn: func(*userv2.RegisterTOTPRequest) (*userv2.RegisterTOTPResponse, error) {
			return nil, grpcErr(codes.NotFound, "AUTHZ-404 permission denied")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if _, err := a.BeginTOTPEnrollment(context.Background(), "user-1"); !errors.Is(err, auth.ErrProviderForbidden) {
		t.Fatalf("err = %v, want ErrProviderForbidden", err)
	}
}

func TestFactor_SummarySAPermissionForbidden(t *testing.T) {
	// The read-only summary path must preserve the distinct provider.forbidden
	// class for SA authorization failures, never collapsing it into
	// provider.unavailable (ADR-0006 §10).
	u := &fakeUserService{
		methodsFn: func(*userv2.ListAuthenticationMethodTypesRequest) (*userv2.ListAuthenticationMethodTypesResponse, error) {
			return nil, grpcErr(codes.NotFound, "AUTHZ-404 permission denied")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if _, err := a.FactorSummary(context.Background(), "user-1"); !errors.Is(err, auth.ErrProviderForbidden) {
		t.Fatalf("err = %v, want ErrProviderForbidden", err)
	}
}

func TestFactor_TransportFailureIsProviderUnavailable(t *testing.T) {
	u := &fakeUserService{
		listPasskeysFn: func(*userv2.ListPasskeysRequest) (*userv2.ListPasskeysResponse, error) {
			return nil, grpcErr(codes.Unavailable, "connection refused")
		},
	}
	a := factorAuth(t, u, "rp.example.com")

	if _, err := a.ListPasskeys(context.Background(), "user-1"); !errors.Is(err, auth.ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
}

func TestMapFactorError_Classification(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		confirm bool
		want    error
	}{
		{"nil", nil, false, nil},
		{"already exists", grpcErr(codes.AlreadyExists, "COMMAND-x"), false, auth.ErrFactorAlreadySet},
		{"not found", grpcErr(codes.NotFound, "COMMAND-x"), false, auth.ErrFactorNotSet},
		{"authz permission", grpcErr(codes.NotFound, "AUTHZ-403"), false, auth.ErrProviderForbidden},
		{"write invalid argument", grpcErr(codes.InvalidArgument, "COMMAND-x"), false, auth.ErrProviderUnavailable},
		{"confirm invalid argument", grpcErr(codes.InvalidArgument, "EVENT-x"), true, auth.ErrInvalidFactorCode},
		{"confirm failed precondition", grpcErr(codes.FailedPrecondition, "COMMAND-x"), true, auth.ErrInvalidFactorCode},
		{"unavailable", grpcErr(codes.Unavailable, "down"), false, auth.ErrProviderUnavailable},
		{"permission denied", grpcErr(codes.PermissionDenied, "no"), false, auth.ErrProviderForbidden},
		{"internal", grpcErr(codes.Internal, "boom"), true, auth.ErrProviderUnavailable},
		{"non-grpc", errors.New("network reset"), false, auth.ErrProviderUnavailable},
	}
	for _, tc := range cases {
		if got := mapFactorError(tc.err, tc.confirm); !errors.Is(got, tc.want) && got != tc.want {
			t.Errorf("%s: mapFactorError = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFactorSecretNeverInErrorText(t *testing.T) {
	// Guard: sentinel errors must not carry provider detail or secret
	// material into logs or responses.
	for _, sentinel := range []error{auth.ErrFactorAlreadySet, auth.ErrFactorNotSet, auth.ErrInvalidFactorCode, auth.ErrProviderUnavailable, auth.ErrProviderForbidden} {
		if strings.Contains(sentinel.Error(), "secret") || strings.Contains(sentinel.Error(), "otpauth") {
			t.Errorf("sentinel %q leaks secret-bearing wording", sentinel.Error())
		}
	}
}
