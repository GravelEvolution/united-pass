package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
)

const (
	codeWeChatOnboardingExpired          = "wechat.onboarding_expired"
	codeWeChatOnboardingPasswordMismatch = "wechat.onboarding_email_password_mismatch"
	codeWeChatOnboardingConflict         = "wechat.onboarding_conflict"
	codeWeChatPhoneRequired              = "wechat.phone_required"
	codeWeChatPhoneConflict              = "wechat.phone_conflict"
)

type WeChatOnboardingService interface {
	Begin(context.Context, wechatonboarding.BeginInput) (wechatonboarding.BeginResult, error)
	Complete(context.Context, wechatonboarding.CompleteInput) (wechatonboarding.CompleteResult, error)
	CompleteMFA(context.Context, wechatonboarding.MFAInput) (wechatonboarding.CompleteResult, error)
}

type WeChatOnboardingBeginRateChecker interface {
	CheckWeChatLogin(context.Context, string, string, int, time.Duration) (bool, time.Duration, error)
}

type WeChatOnboardingProviderSessionRevoker interface {
	RevokeProviderSession(context.Context, string) error
}

type WeChatOnboardingSessionService interface {
	CreateSession(context.Context, session.CreateSessionInput) (session.CreateSessionResult, error)
	DeleteSession(context.Context, string) error
}

// WeChatOnboardingProviderSessionPromotion closes the process-loss window
// between consuming an MFA challenge and durably creating the native session.
// The store keeps an encrypted cleanup obligation under a short lease until
// CompleteProviderSessionPromotion succeeds.
type WeChatOnboardingProviderSessionPromotion interface {
	CompleteProviderSessionPromotion(context.Context, string) error
	ScheduleProviderSessionCleanup(context.Context, string) error
}

type WeChatOnboardingHandlers struct {
	service        WeChatOnboardingService
	sessions       WeChatOnboardingSessionService
	beginRate      WeChatOnboardingBeginRateChecker
	revoker        WeChatOnboardingProviderSessionRevoker
	promotion      WeChatOnboardingProviderSessionPromotion
	completePolicy registration.CreateRatePolicy
	beginLimit     int
	beginWindow    time.Duration
	logger         *slog.Logger
}

func NewWeChatOnboardingHandlers(service WeChatOnboardingService, sessions WeChatOnboardingSessionService, beginRate WeChatOnboardingBeginRateChecker, revoker WeChatOnboardingProviderSessionRevoker, promotion WeChatOnboardingProviderSessionPromotion, completePolicy registration.CreateRatePolicy, beginLimit int, beginWindow time.Duration, logger *slog.Logger) *WeChatOnboardingHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &WeChatOnboardingHandlers{service: service, sessions: sessions, beginRate: beginRate, revoker: revoker, promotion: promotion, completePolicy: completePolicy, beginLimit: beginLimit, beginWindow: beginWindow, logger: logger}
}

func (h *WeChatOnboardingHandlers) Mount(router chi.Router) {
	router.With(RequireMiniProgramClient(), RequireJSONMutation()).Post("/auth/wechat/onboarding", h.Begin)
	router.With(RequireMiniProgramClient(), RequireJSONMutation()).Post("/auth/wechat/onboarding/complete", h.Complete)
	router.With(RequireMiniProgramClient(), RequireJSONMutation()).Post("/auth/wechat/onboarding/mfa", h.CompleteMFA)
}

// Begin accepts only provider one-time codes. Both wx.login and getPhoneNumber
// proofs are required before this route may create an onboarding challenge or
// issue a WeChat-authenticated session.
func (h *WeChatOnboardingHandlers) Begin(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	var body struct {
		LoginCode string `json:"loginCode"`
		PhoneCode string `json:"phoneCode"`
	}
	if !decodeWeChatBody(w, r, &body) {
		return
	}
	if wechat.ValidateCode(body.LoginCode) != nil {
		WriteValidation(w, r, "微信授权信息无效，请重试。", nil)
		return
	}
	if wechat.ValidateCode(body.PhoneCode) != nil {
		writeError(w, r, http.StatusUnprocessableEntity, codeWeChatPhoneRequired, "微信登录需要授权手机号，请重新发起。", nil)
		return
	}
	allowed, retryAfter, err := h.beginRate.CheckWeChatLogin(r.Context(), clientIP(r), hashIdentifier(body.LoginCode), h.beginLimit, h.beginWindow)
	if err != nil || !allowed {
		if retryAfter <= 0 {
			retryAfter = h.beginWindow
		}
		WriteRateLimited(w, r, retrySeconds(retryAfter))
		return
	}
	result, err := h.service.Begin(r.Context(), wechatonboarding.BeginInput{LoginCode: body.LoginCode, PhoneCode: body.PhoneCode})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	switch result.Status {
	case wechatonboarding.StatusAuthenticated:
		h.createFederatedSession(w, r, result.UserID)
	case wechatonboarding.StatusOnboardingRequired:
		writeJSONNoStore(w, r, http.StatusAccepted, struct {
			Status          string    `json:"status"`
			OnboardingToken string    `json:"onboardingToken"`
			ExpiresAt       time.Time `json:"expiresAt"`
		}{Status: string(result.Status), OnboardingToken: result.OnboardingToken, ExpiresAt: result.ExpiresAt})
	default:
		WriteInternalError(w, r)
	}
}

func (h *WeChatOnboardingHandlers) Complete(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	var body struct {
		OnboardingToken string `json:"onboardingToken"`
		Email           string `json:"email"`
		Password        string `json:"password"`
		Username        string `json:"username,omitempty"`
		DisplayName     string `json:"displayName,omitempty"`
		AcceptedTerms   bool   `json:"acceptedTerms"`
		RequestID       string `json:"requestId,omitempty"`
	}
	if !decodeWeChatBody(w, r, &body) {
		return
	}
	client := clientIP(r)
	result, err := h.service.Complete(r.Context(), wechatonboarding.CompleteInput{
		OnboardingToken: body.OnboardingToken, Email: body.Email, Password: body.Password,
		Username: body.Username, DisplayName: body.DisplayName, AcceptedTerms: body.AcceptedTerms,
		RequestID: body.RequestID, ClientIP: client, ClientNetwork: clientNetwork(client, h.completePolicy.IPv4NetBits, h.completePolicy.IPv6NetBits),
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeCompleteResult(w, r, result, "")
}

func (h *WeChatOnboardingHandlers) CompleteMFA(w http.ResponseWriter, r *http.Request) {
	if !h.ready() {
		WriteNotFound(w, r)
		return
	}
	var body struct {
		MFAToken         string          `json:"mfaToken"`
		Method           string          `json:"method"`
		Code             string          `json:"code,omitempty"`
		PasskeyAssertion json.RawMessage `json:"passkeyAssertion,omitempty"`
	}
	if !decodeWeChatBody(w, r, &body) {
		return
	}
	result, err := h.service.CompleteMFA(r.Context(), wechatonboarding.MFAInput{
		MFAToken: body.MFAToken, Method: auth.MFAMethod(body.Method), Code: body.Code,
		PasskeyAssertion: body.PasskeyAssertion, ClientIP: clientIP(r),
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeCompleteResult(w, r, result, body.MFAToken)
}

func (h *WeChatOnboardingHandlers) writeCompleteResult(w http.ResponseWriter, r *http.Request, result wechatonboarding.CompleteResult, mfaToken string) {
	switch result.Status {
	case wechatonboarding.StatusAuthenticated:
		h.createAuthenticatedSession(w, r, result.Authentication, mfaToken)
	case wechatonboarding.StatusMFARequired:
		methods := make([]string, len(result.AvailableMethods))
		for i, method := range result.AvailableMethods {
			methods[i] = string(method)
		}
		writeJSONNoStore(w, r, http.StatusAccepted, struct {
			Status                string          `json:"status"`
			MFAToken              string          `json:"mfaToken"`
			AvailableMethods      []string        `json:"availableMethods"`
			PasskeyRequestOptions json.RawMessage `json:"passkeyRequestOptions,omitempty"`
			ExpiresAt             time.Time       `json:"expiresAt"`
		}{Status: string(result.Status), MFAToken: result.MFAToken, AvailableMethods: methods, PasskeyRequestOptions: result.PasskeyRequestOptions, ExpiresAt: result.ExpiresAt})
	case wechatonboarding.StatusVerificationNeeded:
		writeJSONNoStore(w, r, http.StatusCreated, struct {
			Status            string    `json:"status"`
			RegistrationToken string    `json:"registrationToken"`
			ExpiresAt         time.Time `json:"expiresAt"`
		}{Status: string(result.Status), RegistrationToken: result.RegistrationToken, ExpiresAt: result.ExpiresAt})
	default:
		WriteInternalError(w, r)
	}
}

func (h *WeChatOnboardingHandlers) createFederatedSession(w http.ResponseWriter, r *http.Request, userID identity.UserID) {
	h.createSession(w, r, session.CreateSessionInput{
		UserID: userID, ClientKind: session.ClientKindMiniProgram, Provider: wechat.ProviderName,
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodFederated, auth.MethodWeChatPhoneVerified}, UserAgent: r.UserAgent(), ClientIP: clientIP(r),
	}, "")
}

func (h *WeChatOnboardingHandlers) createAuthenticatedSession(w http.ResponseWriter, r *http.Request, result auth.AuthenticationResult, mfaToken string) {
	if mfaToken != "" && result.ProviderSessionReference == "" {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		_ = h.promotion.ScheduleProviderSessionCleanup(cleanupCtx, mfaToken)
		cancel()
		h.logger.Error("wechat onboarding MFA result missing provider session reference", "requestId", requestID(r))
		WriteInternalError(w, r)
		return
	}
	methods := append([]auth.AuthenticationMethod(nil), result.AuthenticationMethods...)
	if !hasAuthenticationMethod(methods, auth.MethodFederated) {
		methods = append(methods, auth.MethodFederated)
	}
	if !hasAuthenticationMethod(methods, auth.MethodWeChatPhoneVerified) {
		methods = append(methods, auth.MethodWeChatPhoneVerified)
	}
	provider := result.Provider
	if provider == "" {
		provider = wechat.ProviderName
	}
	h.createSession(w, r, session.CreateSessionInput{
		UserID: result.UserID, ClientKind: session.ClientKindMiniProgram, Provider: provider,
		ProviderSessionReference: result.ProviderSessionReference, ProviderSessionToken: result.ProviderSessionToken,
		AuthenticationMethods: methods, UserAgent: r.UserAgent(), ClientIP: clientIP(r),
	}, mfaToken)
}

func (h *WeChatOnboardingHandlers) createSession(w http.ResponseWriter, r *http.Request, input session.CreateSessionInput, mfaToken string) {
	created, err := h.sessions.CreateSession(r.Context(), input)
	if err != nil {
		if mfaToken != "" {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			_ = h.promotion.ScheduleProviderSessionCleanup(cleanupCtx, mfaToken)
			cancel()
		}
		if input.ProviderSessionReference != "" {
			revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			_ = h.revoker.RevokeProviderSession(revokeCtx, input.ProviderSessionReference)
			cancel()
		}
		h.logger.Error("wechat onboarding session creation failed", "requestId", requestID(r))
		WriteInternalError(w, r)
		return
	}
	if mfaToken != "" {
		promotionCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		promotionErr := h.promotion.CompleteProviderSessionPromotion(promotionCtx, mfaToken)
		cancel()
		if promotionErr != nil {
			// Do not expose the newly minted bearer unless the cleanup
			// obligation was atomically retired. The unreachable local session
			// is deleted, promotion is abandoned and provider revocation remains
			// both immediate and worker-backed.
			scheduleCtx, scheduleCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			_ = h.promotion.ScheduleProviderSessionCleanup(scheduleCtx, mfaToken)
			scheduleCancel()
			rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			_ = h.sessions.DeleteSession(rollbackCtx, created.SessionToken)
			rollbackCancel()
			if input.ProviderSessionReference != "" {
				revokeCtx, revokeCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
				_ = h.revoker.RevokeProviderSession(revokeCtx, input.ProviderSessionReference)
				revokeCancel()
			}
			h.logger.Error("wechat onboarding provider-session promotion failed", "requestId", requestID(r))
			WriteInternalError(w, r)
			return
		}
	}
	writeJSONNoStore(w, r, http.StatusOK, authenticatedResponse{Status: "authenticated", SessionBearer: created.SessionToken, ExpiresAt: created.Record.ExpiresAt})
}

func (h *WeChatOnboardingHandlers) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var rateErr *wechatonboarding.RateLimitError
	switch {
	case errors.As(err, &rateErr):
		WriteRateLimited(w, r, retrySeconds(rateErr.RetryAfter))
	case errors.Is(err, wechatonboarding.ErrChallengeClaimed), errors.Is(err, wechatonboarding.ErrMaxAttempts):
		WriteRateLimited(w, r, retrySeconds(h.beginWindow))
	case errors.Is(err, wechatonboarding.ErrChallengeNotFound):
		writeError(w, r, http.StatusUnauthorized, codeWeChatOnboardingExpired, "微信登录流程已过期，请重新发起。", nil)
	case errors.Is(err, wechatonboarding.ErrPasswordMismatch):
		writeError(w, r, http.StatusUnauthorized, codeWeChatOnboardingPasswordMismatch, "此邮箱已存在账号，请设定原始密码以进行绑定", nil)
	case errors.Is(err, wechatonboarding.ErrPhoneRequired):
		writeError(w, r, http.StatusUnprocessableEntity, codeWeChatPhoneRequired, "微信登录需要授权手机号，请重新发起。", nil)
	case errors.Is(err, wechatonboarding.ErrInvalidInput):
		WriteValidation(w, r, "请检查账户信息后重试。", nil)
	case errors.Is(err, wechatonboarding.ErrPhoneConflict):
		writeError(w, r, http.StatusConflict, codeWeChatPhoneConflict, "该手机号已绑定其他统一账户，或与当前账户信息冲突；系统未自动合并，请使用原账户登录或联系支持。", nil)
	case errors.Is(err, wechatonboarding.ErrIdentityConflict), errors.Is(err, wechatonboarding.ErrEmailAmbiguous):
		writeError(w, r, http.StatusConflict, codeWeChatOnboardingConflict, "无法安全绑定该账户，请检查信息或联系支持。", nil)
	case errors.Is(err, wechatonboarding.ErrAccountInactive), errors.Is(err, wechatonboarding.ErrAuthenticationFail):
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "账户验证失败，请重试。", nil)
	default:
		h.logger.Error("wechat onboarding failed", "requestId", requestID(r))
		WriteProviderUnavailable(w, r)
	}
}

func (h *WeChatOnboardingHandlers) ready() bool {
	return h != nil && h.service != nil && h.sessions != nil && h.beginRate != nil && h.revoker != nil && h.promotion != nil && h.beginLimit > 0 && h.beginWindow > 0
}

func retrySeconds(value time.Duration) int {
	seconds := int((value + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func hasAuthenticationMethod(methods []auth.AuthenticationMethod, target auth.AuthenticationMethod) bool {
	for _, method := range methods {
		if method == target {
			return true
		}
	}
	return false
}
