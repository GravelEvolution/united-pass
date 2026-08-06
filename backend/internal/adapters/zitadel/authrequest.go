package zitadel

// Authorization-request orchestration adapter for ZITADEL's oidc.v2
// OIDCService (GetAuthRequest / CreateCallback), implementing the
// consent.AuthRequestProvider seam (ADR-0005 §8, §12).
//
// Verified against ZITADEL v2.71.0 sources: both methods require only the
// "authenticated" permission (the existing JWT-profile service account is
// sufficient); CreateCallback is one-shot per auth request; the session
// path runs CheckProjectPermissionByClientID (PermissionDenied
// OIDC-foSyH49RvL ⇒ user_not_eligible) while the error path does not; the
// returned callback_url is credential-grade and is wrapped in
// consent.CallbackResult so it is never logged or persisted by callers.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/GravelEvolution/united-pass/backend/internal/consent"

	oidcv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/oidc/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// oidcService is the subset of the ZITADEL oidc.v2 OIDCService the adapter
// uses. It is an interface so tests can substitute a stub.
type oidcService interface {
	GetAuthRequest(ctx context.Context, in *oidcv2.GetAuthRequestRequest, opts ...grpc.CallOption) (*oidcv2.GetAuthRequestResponse, error)
	CreateCallback(ctx context.Context, in *oidcv2.CreateCallbackRequest, opts ...grpc.CallOption) (*oidcv2.CreateCallbackResponse, error)
}

// AuthRequestAdapter implements consent.AuthRequestProvider against ZITADEL.
type AuthRequestAdapter struct {
	svc oidcService
}

// NewAuthRequestAdapter builds the adapter on the SDK's generated
// OIDCService client.
func NewAuthRequestAdapter(client oidcv2.OIDCServiceClient) *AuthRequestAdapter {
	return &AuthRequestAdapter{svc: client}
}

var _ consent.AuthRequestProvider = (*AuthRequestAdapter)(nil)

// GetAuthRequest reads the provider auth request (idempotent, side-effect
// free).
func (a *AuthRequestAdapter) GetAuthRequest(ctx context.Context, authRequestID string) (*consent.AuthRequestView, error) {
	if err := consent.ValidateAuthRequestID(authRequestID); err != nil {
		return nil, consent.NewProviderError(consent.ClassNotFound, err)
	}
	resp, err := a.svc.GetAuthRequest(ctx, &oidcv2.GetAuthRequestRequest{
		AuthRequestId: authRequestID,
	})
	if err != nil {
		return nil, classifyAuthRequestError(err)
	}
	ar := resp.GetAuthRequest()
	if ar == nil {
		return nil, consent.NewProviderError(consent.ClassNotFound, nil)
	}
	return authRequestViewFromProto(ar), nil
}

// CompleteWithSession links the verified provider session (Allow) and
// returns the code/token callback URL. One-shot per auth request.
func (a *AuthRequestAdapter) CompleteWithSession(ctx context.Context, authRequestID string, session consent.SessionHandle) (consent.CallbackResult, error) {
	if err := consent.ValidateAuthRequestID(authRequestID); err != nil {
		return consent.CallbackResult{}, consent.NewProviderError(consent.ClassNotFound, err)
	}
	if err := session.Validate(); err != nil {
		return consent.CallbackResult{}, consent.NewProviderError(consent.ClassInternal, err)
	}
	resp, err := a.svc.CreateCallback(ctx, &oidcv2.CreateCallbackRequest{
		AuthRequestId: authRequestID,
		CallbackKind: &oidcv2.CreateCallbackRequest_Session{
			Session: &oidcv2.Session{
				SessionId:    session.SessionID,
				SessionToken: session.SessionToken,
			},
		},
	})
	if err != nil {
		return consent.CallbackResult{}, classifyAuthRequestError(err)
	}
	return callbackResultFromResponse(resp)
}

// CompleteWithError fails the auth request with an OIDC error callback
// (Deny / login_required / consent_required / account_selection_required /
// gateway faults) and returns the provider-verified error callback URL.
// One-shot per auth request; the error path performs no project permission
// check on v2.71.
func (a *AuthRequestAdapter) CompleteWithError(ctx context.Context, authRequestID string, reason consent.CallbackErrorReason) (consent.CallbackResult, error) {
	if err := consent.ValidateAuthRequestID(authRequestID); err != nil {
		return consent.CallbackResult{}, consent.NewProviderError(consent.ClassNotFound, err)
	}
	mapped, ok := callbackErrorReasonToProto(reason)
	if !ok {
		return consent.CallbackResult{}, consent.NewProviderError(
			consent.ClassInternal, fmt.Errorf("zitadel: unsupported callback error reason %d", int(reason)))
	}
	resp, err := a.svc.CreateCallback(ctx, &oidcv2.CreateCallbackRequest{
		AuthRequestId: authRequestID,
		CallbackKind: &oidcv2.CreateCallbackRequest_Error{
			Error: &oidcv2.AuthorizationError{Error: mapped},
		},
	})
	if err != nil {
		return consent.CallbackResult{}, classifyAuthRequestError(err)
	}
	return callbackResultFromResponse(resp)
}

func callbackResultFromResponse(resp *oidcv2.CreateCallbackResponse) (consent.CallbackResult, error) {
	if resp == nil {
		return consent.CallbackResult{}, consent.NewProviderError(consent.ClassInternal, nil)
	}
	result, err := consent.NewCallbackResult(resp.GetCallbackUrl())
	if err != nil {
		return consent.CallbackResult{}, consent.NewProviderError(consent.ClassInternal, err)
	}
	return result, nil
}

func callbackErrorReasonToProto(reason consent.CallbackErrorReason) (oidcv2.ErrorReason, bool) {
	switch reason {
	case consent.ReasonAccessDenied:
		return oidcv2.ErrorReason_ERROR_REASON_ACCESS_DENIED, true
	case consent.ReasonLoginRequired:
		return oidcv2.ErrorReason_ERROR_REASON_LOGIN_REQUIRED, true
	case consent.ReasonConsentRequired:
		return oidcv2.ErrorReason_ERROR_REASON_CONSENT_REQUIRED, true
	case consent.ReasonAccountSelectionRequired:
		return oidcv2.ErrorReason_ERROR_REASON_ACCOUNT_SELECTION_REQUIRED, true
	case consent.ReasonServerError:
		return oidcv2.ErrorReason_ERROR_REASON_SERVER_ERROR, true
	case consent.ReasonTemporarilyUnavailable:
		return oidcv2.ErrorReason_ERROR_REASON_TEMPORARY_UNAVAILABLE, true
	default:
		return oidcv2.ErrorReason_ERROR_REASON_UNSPECIFIED, false
	}
}

func authRequestViewFromProto(ar *oidcv2.AuthRequest) *consent.AuthRequestView {
	view := &consent.AuthRequestView{
		ID:          ar.GetId(),
		ClientID:    ar.GetClientId(),
		Scopes:      append([]string(nil), ar.GetScope()...),
		RedirectURI: ar.GetRedirectUri(),
		LoginHint:   ar.GetLoginHint(),
		HintUserID:  ar.GetHintUserId(),
	}
	if ts := ar.GetCreationDate(); ts != nil {
		view.CreatedAt = ts.AsTime()
	}
	if ma := ar.GetMaxAge(); ma != nil {
		d := ma.AsDuration()
		view.MaxAge = &d
	}
	for _, p := range ar.GetPrompt() {
		view.Prompts = append(view.Prompts, promptFromProto(p))
	}
	return view
}

func promptFromProto(p oidcv2.Prompt) consent.Prompt {
	switch p {
	case oidcv2.Prompt_PROMPT_NONE:
		return consent.PromptNone
	case oidcv2.Prompt_PROMPT_LOGIN:
		return consent.PromptLogin
	case oidcv2.Prompt_PROMPT_CONSENT:
		return consent.PromptConsent
	case oidcv2.Prompt_PROMPT_SELECT_ACCOUNT:
		return consent.PromptSelectAccount
	case oidcv2.Prompt_PROMPT_CREATE:
		return consent.PromptCreate
	default:
		// Unknown values are preserved as unspecified so the resolution
		// domain applies its invalid-combination rules instead of silently
		// accepting them (ADR-0005 §9).
		return consent.PromptUnspecified
	}
}

// classifyAuthRequestError maps a ZITADEL gRPC error from the oidc.v2
// OIDCService onto the stable consent error classes (contract §8,
// ADR-0005 §8). Raw messages influence only the narrow, documented
// disambiguations below; they never leave the adapter.
//
// CALIBRATION NOTE: the exact gRPC code ZITADEL v2.71 returns for a second
// CreateCallback and for expired auth requests is confirmed against the
// sources for AlreadyExists/NotFound only; message-based disambiguations
// are re-verified during the P3.9 real acceptance.
func classifyAuthRequestError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return consent.NewProviderError(consent.ClassProviderUnavailable, err)
	}
	st, ok := status.FromError(err)
	if !ok {
		// Non-gRPC failure (network layer, client construction): transport.
		return consent.NewProviderError(consent.ClassProviderUnavailable, err)
	}
	msg := st.Message()
	switch st.Code() {
	case codes.NotFound:
		if strings.Contains(msg, "AUTHZ-") {
			// Service-account permission fault is a configuration error,
			// never a user or request condition (P2 precedent).
			return consent.NewProviderError(consent.ClassProviderUnavailable, err)
		}
		if strings.Contains(strings.ToLower(msg), "expired") {
			return consent.NewProviderError(consent.ClassExpired, err)
		}
		// Unknown, expired and consumed-by-CreateCallback are externally
		// indistinguishable on v2.71; the class is evidence only for
		// terminating the request, never for a grant (ADR-0005 §4).
		return consent.NewProviderError(consent.ClassNotFound, err)
	case codes.AlreadyExists:
		return consent.NewProviderError(consent.ClassAlreadyCompleted, err)
	case codes.FailedPrecondition:
		if strings.Contains(strings.ToLower(msg), "already") {
			return consent.NewProviderError(consent.ClassAlreadyCompleted, err)
		}
		return consent.NewProviderError(consent.ClassProviderConflict, err)
	case codes.Aborted:
		return consent.NewProviderError(consent.ClassProviderConflict, err)
	case codes.PermissionDenied:
		// Both OIDCService methods only require "authenticated", so a
		// PermissionDenied here is the conditional project check of the
		// Allow path (OIDC-foSyH49RvL): a deterministic user-admission
		// failure, never provider_unavailable (ADR-0005 §8).
		if strings.Contains(msg, "OIDC-") {
			return consent.NewProviderError(consent.ClassUserNotEligible, err)
		}
		return consent.NewProviderError(consent.ClassProviderUnavailable, err)
	case codes.InvalidArgument:
		lower := strings.ToLower(msg)
		switch {
		case strings.Contains(lower, "redirect"):
			return consent.NewProviderError(consent.ClassInvalidRedirect, err)
		case strings.Contains(lower, "scope"):
			return consent.NewProviderError(consent.ClassInvalidScope, err)
		default:
			return consent.NewProviderError(consent.ClassProviderConflict, err)
		}
	case codes.ResourceExhausted:
		return consent.NewProviderError(consent.ClassRateLimited, err)
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled, codes.Unauthenticated:
		return consent.NewProviderError(consent.ClassProviderUnavailable, err)
	default:
		// Internal, Unknown, DataLoss, Unimplemented, ... are server-side
		// faults; details never surface.
		return consent.NewProviderError(consent.ClassInternal, err)
	}
}
