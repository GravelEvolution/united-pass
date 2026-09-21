package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	app "github.com/GravelEvolution/united-pass/backend/internal/dreamupadmin"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
)

// DreamUPNativeReauthenticationService performs the authority-side role,
// event, target and security-generation checks before a native grant exists.
type DreamUPNativeReauthenticationService interface {
	AuthorizeNativeReauthentication(context.Context, app.Actor, app.NativeReauthenticationRequest) (app.NativeReauthenticationAuthorization, error)
}

// DreamUPNativeReauthHandlers exchanges a fresh, one-use wx.login proof for
// an exact action-and-target-bound administrator grant. The Mini Program can
// obtain the wx.login code without exposing a security-question ceremony;
// possession of an old API bearer alone is insufficient.
type DreamUPNativeReauthHandlers struct {
	service    DreamUPNativeReauthenticationService
	identities WeChatLoginService
	grants     ReauthGrantStore
	rate       WeChatRateChecker
	auditor    ReauthEventRecorder
	grantTTL   time.Duration
	rateLimit  int
	rateWindow time.Duration
	logger     *slog.Logger
}

func NewDreamUPNativeReauthHandlers(
	service DreamUPNativeReauthenticationService,
	identities WeChatLoginService,
	grants ReauthGrantStore,
	rate WeChatRateChecker,
	auditor ReauthEventRecorder,
	grantTTL time.Duration,
	rateLimit int,
	rateWindow time.Duration,
	logger *slog.Logger,
) (*DreamUPNativeReauthHandlers, error) {
	if service == nil || identities == nil || grants == nil || rate == nil || auditor == nil || grantTTL <= 0 || rateLimit <= 0 || rateWindow <= 0 {
		return nil, app.ErrInvalidRequest
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &DreamUPNativeReauthHandlers{
		service: service, identities: identities, grants: grants, rate: rate, auditor: auditor,
		grantTTL: grantTTL, rateLimit: rateLimit, rateWindow: rateWindow, logger: logger,
	}, nil
}

func (h *DreamUPNativeReauthHandlers) Request(w http.ResponseWriter, r *http.Request) {
	actor, ok := dreamUPActor(r)
	if !ok || actor.AuthenticationTransport != app.AuthenticationTransportNativeMiniProgramBearer {
		WriteUnauthorized(w, r)
		return
	}
	var body struct {
		LoginCode string `json:"loginCode"`
		EventID   string `json:"eventId"`
		Action    string `json:"action"`
		Target    string `json:"target"`
	}
	if !decodeWeChatBody(w, r, &body) {
		return
	}
	if wechat.ValidateCode(body.LoginCode) != nil {
		WriteValidation(w, r, "微信身份确认信息无效，请重试。", nil)
		return
	}
	allowed, retryAfter, err := h.rate.CheckWeChatLogin(r.Context(), clientIP(r), hashIdentifier(body.LoginCode), h.rateLimit, h.rateWindow)
	if err != nil || !allowed {
		if retryAfter <= 0 {
			retryAfter = h.rateWindow
		}
		WriteRateLimited(w, r, retrySeconds(retryAfter))
		return
	}
	action := permissions.Action(body.Action)
	if _, valid := permissions.ParseDreamUPReauthenticationTarget(body.EventID, action, body.Target); !valid {
		WriteValidation(w, r, "活动管理授权目标无效，请刷新后重试。", nil)
		return
	}
	if err := h.record(r, applications.EventReauthenticationRequested, actor.UserID, body.Action, applications.SecurityEventSuccess, ""); err != nil {
		h.logger.Error("native DreamUP reauthentication request audit failed", "requestId", requestID(r), "errorClass", observability.ClassifyError(err))
		WriteInternalError(w, r)
		return
	}
	user, err := h.identities.ResolveLogin(r.Context(), body.LoginCode)
	if err != nil || user.ID != actor.UserID {
		failureClass := "identity_mismatch"
		if err != nil {
			failureClass = string(observability.ClassifyError(err))
		}
		h.recordFailure(r, actor.UserID, body.Action, failureClass)
		switch {
		case errors.Is(err, wechat.ErrUnavailable):
			WriteProviderUnavailable(w, r)
		default:
			writeError(w, r, http.StatusUnauthorized, CodeReauthenticationReq, "请重新确认当前微信身份。", nil)
		}
		return
	}
	authorization, err := h.service.AuthorizeNativeReauthentication(r.Context(), actor, app.NativeReauthenticationRequest{
		EventID: body.EventID, Action: action, Target: body.Target,
	})
	if err != nil {
		h.recordFailure(r, actor.UserID, body.Action, string(observability.ClassifyError(err)))
		h.writeServiceError(w, r, err)
		return
	}
	record, ok := SessionRecordFromContext(r.Context())
	if !ok || record.UserID != actor.UserID || string(record.SessionID) != actor.SessionID || record.SecurityEpoch != authorization.SecurityEpoch {
		h.recordFailure(r, actor.UserID, body.Action, "session_generation_mismatch")
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "登录状态已变化，请重新登录。", nil)
		return
	}
	token, err := session.GenerateToken()
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	grantIDToken, err := session.GenerateToken()
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	now := time.Now().UTC()
	data := auth.ReauthGrantData{
		GrantID: "rgr_" + grantIDToken[:24], UserID: actor.UserID, SessionID: actor.SessionID,
		Action: string(authorization.Action), Target: authorization.Target, CreatedAt: now,
		SecurityEpoch: authorization.SecurityEpoch, ChallengeVersion: authorization.ChallengeVersion,
	}
	tokenHash := session.HashToken(token)
	if err := h.grants.CreateGrant(r.Context(), tokenHash, data, h.grantTTL); err != nil {
		h.logger.Error("native DreamUP reauthentication grant creation failed", "requestId", requestID(r), "errorClass", observability.ClassifyError(err))
		WriteInternalError(w, r)
		return
	}
	if err := h.record(r, applications.EventReauthenticationSucceeded, actor.UserID, body.Action, applications.SecurityEventSuccess, ""); err != nil {
		_, cleanupErr := h.grants.ConsumeGrant(r.Context(), tokenHash)
		h.logger.Error("native DreamUP reauthentication success audit failed", "requestId", requestID(r), "errorClass", observability.ClassifyError(err), "grantCleanupErrorClass", observability.ClassifyError(cleanupErr))
		WriteInternalError(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, reauthGrantResponse{Status: "granted", ReauthToken: token, ExpiresAt: now.Add(h.grantTTL)})
}

func (h *DreamUPNativeReauthHandlers) record(r *http.Request, event string, userID identity.UserID, action string, result applications.SecurityEventResult, failureClass string) error {
	return h.auditor.RecordEvent(r.Context(), event, userID, "", "", request.ID(r.Context()), action, result, failureClass)
}

func (h *DreamUPNativeReauthHandlers) recordFailure(r *http.Request, userID identity.UserID, action, failureClass string) {
	if err := h.record(r, applications.EventReauthenticationFailed, userID, action, applications.SecurityEventDenied, failureClass); err != nil {
		h.logger.Error("native DreamUP reauthentication failure audit failed", "requestId", requestID(r), "errorClass", observability.ClassifyError(err))
	}
}

func (h *DreamUPNativeReauthHandlers) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, app.ErrInvalidRequest):
		WriteValidation(w, r, "活动管理授权目标无效，请刷新后重试。", nil)
	case errors.Is(err, app.ErrForbidden):
		WriteForbidden(w, r)
	case errors.Is(err, app.ErrNotFound):
		WriteNotFound(w, r)
	case errors.Is(err, app.ErrStepUpRequired):
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "登录状态已变化，请重新登录。", nil)
	default:
		WriteProviderUnavailable(w, r)
	}
}
