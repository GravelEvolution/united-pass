package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

// WeChatRegistrationService creates only pending accounts after server-side
// verification of Mini Program identity and phone proofs.
type WeChatRegistrationService interface {
	VerifyRegistration(context.Context, string, string) (wechat.IdentityProof, error)
	CreateVerified(context.Context, wechatregistration.CreateVerifiedInput) (registration.CreateResult, error)
}

type WeChatRegistrationRateChecker interface {
	CheckRegistrationCreate(context.Context, string, string, string, registration.CreateRatePolicy) (bool, time.Duration, error)
	ClaimWeChatRegistrationProofs(context.Context, string, string, string, int, time.Duration) (bool, time.Duration, error)
}

type WeChatRegistrationHandlers struct {
	service WeChatRegistrationService
	rate    WeChatRegistrationRateChecker
	policy  registration.CreateRatePolicy
	logger  *slog.Logger
}

func NewWeChatRegistrationHandlers(service WeChatRegistrationService, rate WeChatRegistrationRateChecker, policy registration.CreateRatePolicy, logger *slog.Logger) *WeChatRegistrationHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &WeChatRegistrationHandlers{service: service, rate: rate, policy: policy, logger: logger}
}

func (h *WeChatRegistrationHandlers) Mount(router chi.Router) {
	router.With(RequireMiniProgramClient(), RequireJSONMutation()).Post("/registrations/wechat", h.Create)
}

func (h *WeChatRegistrationHandlers) Create(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil || h.rate == nil {
		writeError(w, r, http.StatusNotFound, codeRegistrationClosed, "注册暂未开放。", nil)
		return
	}
	var body struct {
		Username      string `json:"username"`
		DisplayName   string `json:"displayName"`
		Email         string `json:"email"`
		Password      string `json:"password"`
		AcceptedTerms bool   `json:"acceptedTerms"`
		RequestID     string `json:"requestId"`
		LoginCode     string `json:"loginCode"`
		PhoneCode     string `json:"phoneCode"`
	}
	if !decodeWeChatBody(w, r, &body) {
		return
	}
	registrationInput := registration.CreateInput{Username: body.Username, DisplayName: body.DisplayName, Email: body.Email, Password: body.Password, AcceptedTerms: body.AcceptedTerms, RequestID: body.RequestID}
	if err := registration.ValidateCreate(registrationInput); err != nil || wechat.ValidateCode(body.LoginCode) != nil || wechat.ValidateCode(body.PhoneCode) != nil {
		h.writeServiceError(w, r, registration.ErrInvalidInput)
		return
	}
	if !h.claimProofs(w, r, body.LoginCode, body.PhoneCode) {
		return
	}
	proof, err := h.service.VerifyRegistration(r.Context(), body.LoginCode, body.PhoneCode)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if !h.checkRate(w, r, strings.ToLower(strings.TrimSpace(body.Email))) {
		return
	}
	result, err := h.service.CreateVerified(r.Context(), wechatregistration.CreateVerifiedInput{Registration: registrationInput, Proof: proof})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, struct {
		Status            string    `json:"status"`
		RegistrationToken string    `json:"registrationToken"`
		ExpiresAt         time.Time `json:"expiresAt"`
	}{Status: "verification_required", RegistrationToken: result.RegistrationToken, ExpiresAt: result.ExpiresAt})
}

func (h *WeChatRegistrationHandlers) claimProofs(w http.ResponseWriter, r *http.Request, loginCode, phoneCode string) bool {
	allowed, retryAfter, err := h.rate.ClaimWeChatRegistrationProofs(
		r.Context(),
		clientIP(r),
		hashIdentifier(loginCode),
		hashIdentifier(phoneCode),
		h.policy.ClientIP.Max,
		h.policy.ClientIP.Window,
	)
	if err != nil || !allowed {
		seconds := int((retryAfter + time.Second - 1) / time.Second)
		if seconds <= 0 {
			seconds = int(h.policy.ClientIP.Window.Seconds())
		}
		WriteRateLimited(w, r, seconds)
		return false
	}
	return true
}

func (h *WeChatRegistrationHandlers) checkRate(w http.ResponseWriter, r *http.Request, email string) bool {
	client := clientIP(r)
	allowed, retryAfter, err := h.rate.CheckRegistrationCreate(
		r.Context(), client, clientNetwork(client, h.policy.IPv4NetBits, h.policy.IPv6NetBits), hashIdentifier(email), h.policy,
	)
	if err != nil || !allowed {
		seconds := int((retryAfter + time.Second - 1) / time.Second)
		if seconds <= 0 {
			seconds = int(h.policy.ClientIP.Window.Seconds())
		}
		WriteRateLimited(w, r, seconds)
		return false
	}
	return true
}

func (h *WeChatRegistrationHandlers) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, registration.ErrInvalidInput):
		WriteValidation(w, r, "请检查注册及微信授权信息后重试。", nil)
	case errors.Is(err, registration.ErrConflict):
		writeError(w, r, http.StatusConflict, codeRegistrationConflict, "无法完成注册，请检查信息或稍后重试。", nil)
	default:
		h.logger.Error("wechat registration failed", "requestId", requestID(r))
		WriteProviderUnavailable(w, r)
	}
}
