//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the authorization request adapter
//

package zitadel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/consent"

	oidcv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// stubOIDCService is a scripted oidc.v2 OIDCService for adapter tests.
type stubOIDCService struct {
	getResp *oidcv2.GetAuthRequestResponse
	getErr  error
	cbResp  *oidcv2.CreateCallbackResponse
	cbErr   error

	lastGet *oidcv2.GetAuthRequestRequest
	lastCB  *oidcv2.CreateCallbackRequest
	calls   int
}

func (s *stubOIDCService) GetAuthRequest(_ context.Context, in *oidcv2.GetAuthRequestRequest, _ ...grpc.CallOption) (*oidcv2.GetAuthRequestResponse, error) {
	s.lastGet = in
	s.calls++
	return s.getResp, s.getErr
}

func (s *stubOIDCService) CreateCallback(_ context.Context, in *oidcv2.CreateCallbackRequest, _ ...grpc.CallOption) (*oidcv2.CreateCallbackResponse, error) {
	s.lastCB = in
	s.calls++
	return s.cbResp, s.cbErr
}

func TestGetAuthRequestMapsProtoFields(t *testing.T) {
	created := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	maxAge := 45 * time.Second
	loginHint := "user@example.com"
	stub := &stubOIDCService{
		getResp: &oidcv2.GetAuthRequestResponse{
			AuthRequest: &oidcv2.AuthRequest{
				Id:           "V2-request-id",
				CreationDate: timestamppb.New(created),
				ClientId:     "client-1",
				Scope:        []string{"openid", "offline_access"},
				RedirectUri:  "https://rp.example/callback",
				Prompt:       []oidcv2.Prompt{oidcv2.Prompt_PROMPT_CONSENT, oidcv2.Prompt(99)},
				LoginHint:    &loginHint,
				MaxAge:       durationpb.New(maxAge),
			},
		},
	}
	adapter := NewAuthRequestAdapter(nil)
	adapter.svc = stub

	view, err := adapter.GetAuthRequest(context.Background(), "V2-request-id")
	if err != nil {
		t.Fatalf("GetAuthRequest: %v", err)
	}
	if stub.lastGet.GetAuthRequestId() != "V2-request-id" {
		t.Fatalf("request id not forwarded: %v", stub.lastGet)
	}
	if view.ID != "V2-request-id" || view.ClientID != "client-1" ||
		view.RedirectURI != "https://rp.example/callback" ||
		!view.CreatedAt.Equal(created) || view.LoginHint != "user@example.com" ||
		view.HintUserID != "" {
		t.Fatalf("view mismatch: %+v", view)
	}
	if len(view.Scopes) != 2 || view.Scopes[1] != "offline_access" {
		t.Fatalf("scopes mismatch: %v", view.Scopes)
	}
	if view.MaxAge == nil || *view.MaxAge != maxAge {
		t.Fatalf("maxAge mismatch: %v", view.MaxAge)
	}
	if !view.HasPrompt(consent.PromptConsent) || !view.HasPrompt(consent.PromptUnspecified) {
		t.Fatalf("prompts mismatch: %v", view.Prompts)
	}
}

func TestGetAuthRequestOptionalFieldsAbsent(t *testing.T) {
	stub := &stubOIDCService{
		getResp: &oidcv2.GetAuthRequestResponse{
			AuthRequest: &oidcv2.AuthRequest{Id: "V2-x", ClientId: "c"},
		},
	}
	adapter := &AuthRequestAdapter{svc: stub}

	view, err := adapter.GetAuthRequest(context.Background(), "V2-x")
	if err != nil {
		t.Fatalf("GetAuthRequest: %v", err)
	}
	if view.MaxAge != nil || view.LoginHint != "" || view.HintUserID != "" || !view.CreatedAt.IsZero() {
		t.Fatalf("absent fields must stay zero: %+v", view)
	}

	// Provider returned an empty envelope: treat as not_found.
	stub.getResp = &oidcv2.GetAuthRequestResponse{}
	if _, err := adapter.GetAuthRequest(context.Background(), "V2-x"); !consent.IsClass(err, consent.ClassNotFound) {
		t.Fatalf("empty envelope: want not_found, got %v", err)
	}
}

func TestAdapterValidatesInputsBeforeCallingProvider(t *testing.T) {
	stub := &stubOIDCService{}
	adapter := &AuthRequestAdapter{svc: stub}
	ctx := context.Background()

	if _, err := adapter.GetAuthRequest(ctx, ""); !consent.IsClass(err, consent.ClassNotFound) {
		t.Fatalf("empty id: want not_found, got %v", err)
	}
	if _, err := adapter.GetAuthRequest(ctx, strings.Repeat("x", consent.MaxAuthRequestIDLen+1)); !consent.IsClass(err, consent.ClassNotFound) {
		t.Fatalf("oversized id: want not_found, got %v", err)
	}
	if _, err := adapter.CompleteWithSession(ctx, "V2-x", consent.SessionHandle{}); !consent.IsClass(err, consent.ClassInternal) {
		t.Fatalf("invalid session handle: want internal, got %v", err)
	}
	if _, err := adapter.CompleteWithError(ctx, "V2-x", consent.CallbackErrorReason(0)); !consent.IsClass(err, consent.ClassInternal) {
		t.Fatalf("unknown reason: want internal, got %v", err)
	}
	if stub.calls != 0 {
		t.Fatalf("validation failures must not reach the provider, calls = %d", stub.calls)
	}
}

func TestCompleteWithSessionBuildsSessionCallback(t *testing.T) {
	stub := &stubOIDCService{
		cbResp: &oidcv2.CreateCallbackResponse{CallbackUrl: "https://rp.example/callback?code=c&state=s"},
	}
	adapter := &AuthRequestAdapter{svc: stub}

	handle, err := consent.NewSessionHandle("sess-1", "tok-1")
	if err != nil {
		t.Fatalf("NewSessionHandle: %v", err)
	}
	result, err := adapter.CompleteWithSession(context.Background(), "V2-x", handle)
	if err != nil {
		t.Fatalf("CompleteWithSession: %v", err)
	}
	if result.Raw() != "https://rp.example/callback?code=c&state=s" {
		t.Fatalf("callback mismatch: %q", result.Raw())
	}
	session := stub.lastCB.GetSession()
	if session.GetSessionId() != "sess-1" || session.GetSessionToken() != "tok-1" {
		t.Fatalf("session not forwarded: %v", session)
	}
	if stub.lastCB.GetAuthRequestId() != "V2-x" {
		t.Fatalf("request id not forwarded: %v", stub.lastCB)
	}

	// Empty provider callback URL is an internal fault, never a success.
	stub.cbResp = &oidcv2.CreateCallbackResponse{}
	retry, err := consent.NewSessionHandle("s", "t")
	if err != nil {
		t.Fatalf("NewSessionHandle: %v", err)
	}
	if _, err := adapter.CompleteWithSession(context.Background(), "V2-x", retry); !consent.IsClass(err, consent.ClassInternal) {
		t.Fatalf("empty callback url: want internal, got %v", err)
	}
}

func TestCompleteWithErrorMapsReasons(t *testing.T) {
	cases := map[consent.CallbackErrorReason]oidcv2.ErrorReason{
		consent.ReasonAccessDenied:             oidcv2.ErrorReason_ERROR_REASON_ACCESS_DENIED,
		consent.ReasonLoginRequired:            oidcv2.ErrorReason_ERROR_REASON_LOGIN_REQUIRED,
		consent.ReasonConsentRequired:          oidcv2.ErrorReason_ERROR_REASON_CONSENT_REQUIRED,
		consent.ReasonAccountSelectionRequired: oidcv2.ErrorReason_ERROR_REASON_ACCOUNT_SELECTION_REQUIRED,
		consent.ReasonServerError:              oidcv2.ErrorReason_ERROR_REASON_SERVER_ERROR,
		consent.ReasonTemporarilyUnavailable:   oidcv2.ErrorReason_ERROR_REASON_TEMPORARY_UNAVAILABLE,
		consent.ReasonRequestNotSupported:      oidcv2.ErrorReason_ERROR_REASON_REQUEST_NOT_SUPPORTED,
	}
	for reason, want := range cases {
		stub := &stubOIDCService{
			cbResp: &oidcv2.CreateCallbackResponse{CallbackUrl: "https://rp.example/callback?error=x"},
		}
		adapter := &AuthRequestAdapter{svc: stub}
		if _, err := adapter.CompleteWithError(context.Background(), "V2-x", reason); err != nil {
			t.Fatalf("CompleteWithError(%s): %v", reason, err)
		}
		if got := stub.lastCB.GetError().GetError(); got != want {
			t.Fatalf("reason %s mapped to %v, want %v", reason, got, want)
		}
	}
}

func TestErrorClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want consent.ErrorClass
	}{
		{"plain not found", status.Error(codes.NotFound, "V2-request not found"), consent.ClassNotFound},
		{"sa permission masquerading as not found", status.Error(codes.NotFound, "AUTHZ-xyz permission denied"), consent.ClassProviderUnavailable},
		{"expired wording", status.Error(codes.NotFound, "auth request expired"), consent.ClassExpired},
		{"one-shot second call", status.Error(codes.AlreadyExists, "V2-D6Fv2 auth request already completed"), consent.ClassAlreadyCompleted},
		{"precondition already", status.Error(codes.FailedPrecondition, "auth request already finalized"), consent.ClassAlreadyCompleted},
		{"precondition other", status.Error(codes.FailedPrecondition, "session invalid"), consent.ClassProviderConflict},
		{"aborted", status.Error(codes.Aborted, "conflicting update"), consent.ClassProviderConflict},
		{"project check denial", status.Error(codes.PermissionDenied, "OIDC-foSyH49RvL user is not project allowed"), consent.ClassUserNotEligible},
		{"other permission denied", status.Error(codes.PermissionDenied, "transport authz"), consent.ClassProviderUnavailable},
		{"invalid redirect", status.Error(codes.InvalidArgument, "redirect_uri is not registered"), consent.ClassInvalidRedirect},
		{"invalid scope", status.Error(codes.InvalidArgument, "scope offline_access not allowed"), consent.ClassInvalidScope},
		{"other invalid argument", status.Error(codes.InvalidArgument, "callback kind required"), consent.ClassProviderConflict},
		{"rate limited", status.Error(codes.ResourceExhausted, "too many requests"), consent.ClassRateLimited},
		{"unavailable", status.Error(codes.Unavailable, "connection refused"), consent.ClassProviderUnavailable},
		{"unauthenticated sa", status.Error(codes.Unauthenticated, "token expired"), consent.ClassProviderUnavailable},
		{"grpc deadline", status.Error(codes.DeadlineExceeded, "deadline"), consent.ClassProviderUnavailable},
		{"internal", status.Error(codes.Internal, "boom"), consent.ClassInternal},
		{"unknown", status.Error(codes.Unknown, "boom"), consent.ClassInternal},
		{"unimplemented", status.Error(codes.Unimplemented, "no"), consent.ClassInternal},
		{"non grpc", errors.New("dial tcp: connection refused"), consent.ClassProviderUnavailable},
		{"context deadline", context.DeadlineExceeded, consent.ClassProviderUnavailable},
		{"context canceled", context.Canceled, consent.ClassProviderUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := consent.ErrorClassOf(classifyAuthRequestError(tc.err))
			if !ok || class != tc.want {
				t.Fatalf("classify(%v) = %v, %v; want %v", tc.err, class, ok, tc.want)
			}
		})
	}
	if classifyAuthRequestError(nil) != nil {
		t.Fatal("nil must classify to nil")
	}
}

func TestClassificationNeverLeaksRawMessage(t *testing.T) {
	raw := status.Error(codes.PermissionDenied, "OIDC-foSyH49RvL secret detail")
	err := classifyAuthRequestError(raw)
	if strings.Contains(err.Error(), "secret detail") || strings.Contains(err.Error(), "OIDC-") {
		t.Fatalf("classified error leaks provider detail: %q", err.Error())
	}
	if !errors.Is(err, raw) {
		t.Fatal("classified error must unwrap to the transport error")
	}
}

func TestUserNotEligibleIsNeverUnavailable(t *testing.T) {
	// The deterministic admission failure must stay stable across retries:
	// it is not a transport fault (ADR-0005 §8).
	err := classifyAuthRequestError(status.Error(codes.PermissionDenied, "OIDC-foSyH49RvL"))
	if consent.IsClass(err, consent.ClassProviderUnavailable) {
		t.Fatal("user_not_eligible must never be provider_unavailable")
	}
	if !consent.IsClass(err, consent.ClassUserNotEligible) {
		t.Fatalf("want user_not_eligible, got %v", err)
	}
}
