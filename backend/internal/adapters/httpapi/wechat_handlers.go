package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
)

const maxWeChatBodyBytes = 16 << 10

type WeChatLoginService interface {
	ResolveLogin(context.Context, string) (identity.User, error)
	BindVerifiedPhone(context.Context, identity.UserID, string, string) error
}

type WeChatSessionService interface {
	CreateSession(context.Context, session.CreateSessionInput) (session.CreateSessionResult, error)
}

type WeChatRateChecker interface {
	CheckWeChatLogin(context.Context, string, string, int, time.Duration) (bool, time.Duration, error)
	CheckWeChatPhone(context.Context, string, string, int, time.Duration) (bool, time.Duration, error)
}

// WeChatHandlers exposes the Mini Program-specific login and verified-phone
// operations. It does not accept caller-supplied WeChat identity values.
type WeChatHandlers struct {
	service  WeChatLoginService
	sessions WeChatSessionService
	rate     WeChatRateChecker
	limit    int
	window   time.Duration
	logger   *slog.Logger
}

func NewWeChatHandlers(service WeChatLoginService, sessions WeChatSessionService, rate WeChatRateChecker, limit int, window time.Duration, logger *slog.Logger) *WeChatHandlers {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &WeChatHandlers{service: service, sessions: sessions, rate: rate, limit: limit, window: window, logger: logger}
}

// Login establishes a short-lived native bearer only after a fresh wx.login
// code resolves to an existing explicit WeChat binding. The raw bearer is
// returned once for Mini Program process memory; only its hash is persisted.
func (h *WeChatHandlers) Login(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil || h.sessions == nil || h.rate == nil {
		WriteNotFound(w, r)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decodeWeChatBody(w, r, &body) {
		return
	}
	if err := wechat.ValidateCode(body.Code); err != nil {
		WriteValidation(w, r, "微信授权信息无效，请重试。", nil)
		return
	}
	if !h.allow(w, r, body.Code, false) {
		return
	}
	user, err := h.service.ResolveLogin(r.Context(), body.Code)
	if err != nil {
		h.writeLoginError(w, r, err)
		return
	}
	created, err := h.sessions.CreateSession(r.Context(), session.CreateSessionInput{
		UserID: user.ID, Provider: wechat.ProviderName, ClientKind: session.ClientKindMiniProgram,
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodFederated},
		UserAgent:             r.UserAgent(), ClientIP: clientIP(r),
	})
	if err != nil {
		h.logger.Error("wechat session creation failed", "requestId", requestID(r))
		WriteInternalError(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, authenticatedResponse{
		Status:        "authenticated",
		SessionBearer: created.SessionToken,
		ExpiresAt:     created.Record.ExpiresAt,
	})
}

// BindPhone requires an authenticated native bearer at route composition.
// The login code is replayed against the current user's durable WeChat link;
// the independent phone code proves that WeChat authorized disclosure of the
// returned number for this AppID. WeChat's getPhoneNumber response exposes no
// OpenID, so it cannot cryptographically assert that both codes share a user.
func (h *WeChatHandlers) BindPhone(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if h == nil || h.service == nil || h.rate == nil {
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
	if wechat.ValidateCode(body.LoginCode) != nil || wechat.ValidateCode(body.PhoneCode) != nil {
		WriteValidation(w, r, "微信授权信息无效，请重试。", nil)
		return
	}
	if !h.allow(w, r, body.LoginCode, false) || !h.allow(w, r, body.PhoneCode, true) {
		return
	}
	if err := h.service.BindVerifiedPhone(r.Context(), principal.UserID, body.LoginCode, body.PhoneCode); err != nil {
		switch {
		case errors.Is(err, wechat.ErrInvalidCode), errors.Is(err, wechat.ErrRejected), errors.Is(err, wechat.ErrBindingMismatch):
			WriteValidation(w, r, "微信身份或手机号授权无效，请重新验证。", nil)
		case errors.Is(err, wechat.ErrPhoneConflict):
			writeError(w, r, http.StatusConflict, codeWeChatPhoneConflict, "该手机号已绑定其他统一账户，或与当前账户信息冲突；系统未自动合并，请使用原账户登录或联系支持。", nil)
		case errors.Is(err, wechat.ErrNotRegistered):
			WriteUnauthorized(w, r)
		default:
			h.logger.Error("wechat phone binding failed", "requestId", requestID(r))
			WriteProviderUnavailable(w, r)
		}
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]string{"status": "verified"})
}

func (h *WeChatHandlers) allow(w http.ResponseWriter, r *http.Request, code string, phone bool) bool {
	var allowed bool
	var retryAfter time.Duration
	var err error
	if phone {
		allowed, retryAfter, err = h.rate.CheckWeChatPhone(r.Context(), clientIP(r), hashIdentifier(code), h.limit, h.window)
	} else {
		allowed, retryAfter, err = h.rate.CheckWeChatLogin(r.Context(), clientIP(r), hashIdentifier(code), h.limit, h.window)
	}
	if err != nil || !allowed {
		seconds := int((retryAfter + time.Second - 1) / time.Second)
		if seconds <= 0 {
			seconds = int(h.window.Seconds())
		}
		WriteRateLimited(w, r, seconds)
		return false
	}
	return true
}

func (h *WeChatHandlers) writeLoginError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, wechat.ErrInvalidCode), errors.Is(err, wechat.ErrRejected), errors.Is(err, wechat.ErrNotRegistered):
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "微信授权未完成，请重新验证。", nil)
	default:
		h.logger.Error("wechat login failed", "requestId", requestID(r))
		WriteProviderUnavailable(w, r)
	}
}

func decodeWeChatBody(w http.ResponseWriter, r *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, codeUnsupportedMediaType, "请求必须使用 JSON 格式。", nil)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWeChatBodyBytes)
	return decodeJSONBody(w, r, target, "wechat proof") == nil
}
