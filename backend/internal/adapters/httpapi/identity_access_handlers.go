package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type IdentityAccessService interface {
	CreateRequest(context.Context, identityaccess.CreateRequestInput) (identityaccess.CreateRequestResult, error)
	Decide(context.Context, identityaccess.DecideInput) (identityaccess.DecideResult, error)
	Claim(context.Context, identityaccess.ClaimInput) (identityaccess.ClaimResult, error)
	ListOwn(context.Context, identity.UserID, adminpagination.Query) (identityaccess.Page, error)
	ListApprovalQueue(context.Context, identity.UserID, adminpagination.Query) (identityaccess.Page, error)
	GetOwn(context.Context, identity.UserID, string, string) (identityaccess.Request, error)
	GetForApproval(context.Context, identity.UserID, string, string) (identityaccess.Request, error)
}

type IdentityAccessReauthVerifier interface {
	VerifyAndConsumeData(context.Context, string, string, string, string, applications.ApplicationID, applications.OAuthClientID) (auth.ReauthGrantData, error)
}

type IdentityAccessHandlers struct {
	service        IdentityAccessService
	reauth         IdentityAccessReauthVerifier
	expectedOrigin string
	now            func() time.Time
}

func NewIdentityAccessHandlers(service IdentityAccessService, reauth IdentityAccessReauthVerifier, expectedOrigin string, now func() time.Time) *IdentityAccessHandlers {
	expectedOrigin = normalizeIdentityAccessOrigin(expectedOrigin)
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &IdentityAccessHandlers{service: service, reauth: reauth, expectedOrigin: expectedOrigin, now: now}
}

type identityAccessCreateBody struct {
	TargetType identityaccess.TargetType `json:"targetType"`
	TargetID   string                    `json:"targetId"`
	Fields     []identityaccess.Field    `json:"fields"`
	Reason     string                    `json:"reason"`
}

type identityAccessDecisionBody struct {
	Fields []identityaccess.Field `json:"fields,omitempty"`
}

type identityAccessRequestView struct {
	ID         string                    `json:"requestId"`
	EventID    string                    `json:"eventId"`
	TargetType identityaccess.TargetType `json:"targetType"`
	TargetID   string                    `json:"targetId"`
	Fields     []identityaccess.Field    `json:"fields"`
	Status     identityaccess.Status     `json:"status"`
	Version    int64                     `json:"version"`
	CreatedAt  time.Time                 `json:"createdAt,omitempty"`
	UpdatedAt  time.Time                 `json:"updatedAt,omitempty"`
	ExpiresAt  time.Time                 `json:"expiresAt,omitempty"`
}

type identityAccessPageView struct {
	Items []identityAccessRequestView `json:"items"`
	Page  struct {
		NextCursor *string `json:"nextCursor"`
		HasMore    bool    `json:"hasMore"`
	} `json:"page"`
}

type identityAccessDecisionView struct {
	RequestID string                `json:"requestId"`
	Status    identityaccess.Status `json:"status"`
	Version   int64                 `json:"version"`
	Replayed  bool                  `json:"replayed,omitempty"`
}

type identityAccessClaimView struct {
	GrantID  string `json:"grantId"`
	Status   string `json:"status"`
	Version  int64  `json:"version"`
	Replayed bool   `json:"replayed,omitempty"`
}

func (h *IdentityAccessHandlers) Create(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.requireMutation(w, r)
	if !ok {
		return
	}
	var body identityAccessCreateBody
	if err := decodeJSONBody(w, r, &body, "identity access request"); err != nil {
		return
	}
	result, err := h.service.CreateRequest(r.Context(), identityaccess.CreateRequestInput{
		ActorID: principal.UserID, EventID: chi.URLParam(r, "eventId"), Target: identityaccess.TargetRef{Type: body.TargetType, ID: body.TargetID},
		Fields: body.Fields, Reason: body.Reason, CorrelationID: request.ID(r.Context()), IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteIdentityAccessVersion(result.Request.Version))
	writeJSONNoStore(w, r, http.StatusCreated, identityAccessRequestResponse(result.Request))
}

func (h *IdentityAccessHandlers) ListOwn(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.requireRead(w, r)
	if !ok {
		return
	}
	query, ok := identityAccessListQuery(w, r)
	if !ok {
		return
	}
	page, err := h.service.ListOwn(r.Context(), principal.UserID, query)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, identityAccessPageResponse(page))
}

func (h *IdentityAccessHandlers) GetOwn(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.requireRead(w, r)
	if !ok {
		return
	}
	item, err := h.service.GetOwn(r.Context(), principal.UserID, chi.URLParam(r, "eventId"), chi.URLParam(r, "requestId"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteIdentityAccessVersion(item.Version))
	writeJSONNoStore(w, r, http.StatusOK, identityAccessRequestResponse(item))
}

func (h *IdentityAccessHandlers) ListApprovalQueue(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.requireRead(w, r)
	if !ok {
		return
	}
	query, ok := identityAccessListQuery(w, r)
	if !ok {
		return
	}
	page, err := h.service.ListApprovalQueue(r.Context(), principal.UserID, query)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, identityAccessPageResponse(page))
}

func (h *IdentityAccessHandlers) GetForApproval(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.requireRead(w, r)
	if !ok {
		return
	}
	item, err := h.service.GetForApproval(r.Context(), principal.UserID, chi.URLParam(r, "eventId"), chi.URLParam(r, "requestId"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteIdentityAccessVersion(item.Version))
	writeJSONNoStore(w, r, http.StatusOK, identityAccessRequestResponse(item))
}

func (h *IdentityAccessHandlers) Approve(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, true)
}
func (h *IdentityAccessHandlers) Reject(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, false)
}

func (h *IdentityAccessHandlers) decide(w http.ResponseWriter, r *http.Request, approved bool) {
	principal, record, ok := h.requireMutation(w, r)
	if !ok {
		return
	}
	expected, err := parseChallengeIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeError(w, r, http.StatusPreconditionRequired, CodeConflict, "请刷新申请状态后重试。", nil)
		return
	}
	body := identityAccessDecisionBody{}
	if r.ContentLength != 0 {
		if err := decodeJSONBody(w, r, &body, "identity access decision"); err != nil {
			return
		}
	}
	accessRequestID := chi.URLParam(r, "requestId")
	base := identityaccess.DecideInput{ActorID: principal.UserID, EventID: chi.URLParam(r, "eventId"), AccessRequestID: accessRequestID, Approved: approved, Fields: body.Fields, ExpectedVersion: expected, CorrelationID: request.ID(r.Context()), IdempotencyKey: r.Header.Get("Idempotency-Key")}
	var verifyErr error
	if h.reauth == nil || r.Header.Get("X-Reauthentication-Token") == "" {
		verifyErr = errors.New("identity access reauthentication unavailable")
	} else {
		base.StepUp, verifyErr = h.reauth.VerifyAndConsumeData(r.Context(), r.Header.Get("X-Reauthentication-Token"), auth.ReauthActionAdminOAApproval, string(record.SessionID), accessRequestID, "", "")
	}
	result, serviceErr := h.service.Decide(r.Context(), base)
	if verifyErr != nil && serviceErr != nil {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "审批身份信息查阅申请需要重新验证管理员身份。", nil)
		return
	}
	if serviceErr != nil {
		h.writeError(w, r, serviceErr)
		return
	}
	if verifyErr != nil && !result.Replayed {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "审批身份信息查阅申请需要重新验证管理员身份。", nil)
		return
	}
	w.Header().Set("ETag", quoteIdentityAccessVersion(result.Request.Version))
	writeJSONNoStore(w, r, http.StatusOK, identityAccessDecisionView{RequestID: result.Request.ID, Status: result.Request.Status, Version: result.Request.Version, Replayed: result.Replayed})
}

func (h *IdentityAccessHandlers) Claim(w http.ResponseWriter, r *http.Request) {
	principal, _, ok := h.requireMutation(w, r)
	if !ok {
		return
	}
	expected, err := parseChallengeIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeError(w, r, http.StatusPreconditionRequired, CodeConflict, "请刷新授权状态后重试。", nil)
		return
	}
	result, err := h.service.Claim(r.Context(), identityaccess.ClaimInput{ActorID: principal.UserID, EventID: chi.URLParam(r, "eventId"), GrantID: chi.URLParam(r, "grantId"), ExpectedVersion: expected, CorrelationID: request.ID(r.Context()), IdempotencyKey: r.Header.Get("Idempotency-Key")})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, identityAccessClaimView{GrantID: result.Claim.GrantID, Status: string(identityaccess.GrantClaimed), Version: result.Claim.Version, Replayed: result.Replayed})
}

func (h *IdentityAccessHandlers) requireRead(w http.ResponseWriter, r *http.Request) (session.Principal, session.SessionRecord, bool) {
	principal, principalOK := PrincipalFromContext(r.Context())
	record, recordOK := SessionRecordFromContext(r.Context())
	if h == nil || h.service == nil || !principalOK || !recordOK || principal.UserID == "" || principal.SessionID == "" || principal.UserID != record.UserID || principal.SessionID != record.SessionID {
		WriteUnauthorized(w, r)
		return session.Principal{}, session.SessionRecord{}, false
	}
	return principal, record, true
}

func (h *IdentityAccessHandlers) requireMutation(w http.ResponseWriter, r *http.Request) (session.Principal, session.SessionRecord, bool) {
	principal, record, ok := h.requireRead(w, r)
	if !ok {
		return session.Principal{}, session.SessionRecord{}, false
	}
	if h.expectedOrigin == "" || strings.TrimSuffix(strings.TrimSpace(r.Header.Get("Origin")), "/") != h.expectedOrigin {
		WriteForbidden(w, r)
		return session.Principal{}, session.SessionRecord{}, false
	}
	return principal, record, true
}

func identityAccessListQuery(w http.ResponseWriter, r *http.Request) (adminpagination.Query, bool) {
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > adminpagination.MaxPageSize {
			WriteValidation(w, r, "分页参数无效。", nil)
			return adminpagination.Query{}, false
		}
		limit = value
	}
	filters := map[string]string{}
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		filters["status"] = status
	}
	return adminpagination.Query{EventID: chi.URLParam(r, "eventId"), Cursor: r.URL.Query().Get("cursor"), Limit: limit, Sort: r.URL.Query().Get("sort"), Filters: filters}, true
}

func identityAccessRequestResponse(item identityaccess.Request) identityAccessRequestView {
	return identityAccessRequestView{ID: item.ID, EventID: item.EventID, TargetType: item.TargetType, TargetID: item.TargetID, Fields: append([]identityaccess.Field(nil), item.Fields...), Status: item.Status, Version: item.Version, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt, ExpiresAt: item.ExpiresAt}
}

func identityAccessPageResponse(page identityaccess.Page) identityAccessPageView {
	result := identityAccessPageView{Items: make([]identityAccessRequestView, len(page.Items))}
	for index, item := range page.Items {
		result.Items[index] = identityAccessRequestResponse(item)
	}
	result.Page.HasMore = page.HasMore
	if page.NextCursor != "" {
		next := page.NextCursor
		result.Page.NextCursor = &next
	}
	return result
}

func quoteIdentityAccessVersion(version int64) string {
	return `"` + strconv.FormatInt(version, 10) + `"`
}

func normalizeIdentityAccessOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
}

func (h *IdentityAccessHandlers) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, identityaccess.ErrNotFound):
		WriteNotFound(w, r)
	case errors.Is(err, identityaccess.ErrForbidden):
		WriteForbidden(w, r)
	case errors.Is(err, identityaccess.ErrStepUpRequired):
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新验证管理员身份。", nil)
	case errors.Is(err, identityaccess.ErrConflict), errors.Is(err, identityaccess.ErrIdempotencyConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "状态已发生变化，请刷新后重试。", nil)
	case errors.Is(err, identityaccess.ErrIfMatchRequired):
		writeError(w, r, http.StatusPreconditionRequired, CodeConflict, "请刷新资源版本后重试。", nil)
	case errors.Is(err, identityaccess.ErrInvalidRequest), errors.Is(err, identityaccess.ErrInvalidDecision), errors.Is(err, identityaccess.ErrInvalidReason), errors.Is(err, identityaccess.ErrInvalidIdempotencyKey), errors.Is(err, adminpagination.ErrInvalidCursor):
		WriteValidation(w, r, "请检查提交内容。", nil)
	default:
		WriteInternalError(w, r)
	}
}
