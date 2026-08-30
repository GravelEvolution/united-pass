package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	app "github.com/GravelEvolution/united-pass/backend/internal/dreamupadmin"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

const maxDreamUPAdminBodyBytes = 64 << 10

var (
	contactSubmissionLimitPattern  = regexp.MustCompile(`^[1-9][0-9]{0,2}$`)
	contactSubmissionCursorPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
)

type DreamUPAdminService interface {
	Eligible(context.Context, app.Actor) (bool, error)
	ListEvents(context.Context, app.Actor) ([]app.EventSummary, error)
	OperationStatus(context.Context, app.Actor, string, string) (app.MutationStatus, error)
	Proxy(context.Context, app.Actor, app.ProxyRequest) (app.ProxyResponse, error)
}

type DreamUPAdminHandlers struct {
	service          DreamUPAdminService
	expectedOrigin   string
	allowMiniProgram bool
}

func NewDreamUPAdminHandlers(service DreamUPAdminService, expectedOrigin string, allowMiniProgram ...bool) (*DreamUPAdminHandlers, error) {
	parsed, err := url.Parse(expectedOrigin)
	if service == nil || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || expectedOrigin != strings.TrimRight(expectedOrigin, "/") {
		return nil, app.ErrInvalidRequest
	}
	allowed := len(allowMiniProgram) == 1 && allowMiniProgram[0]
	return &DreamUPAdminHandlers{service: service, expectedOrigin: expectedOrigin, allowMiniProgram: allowed}, nil
}

func (h *DreamUPAdminHandlers) Mount(router chi.Router) {
	router.Get("/session", h.session)
	router.Get("/eligibility", h.eligibility)
	router.Get("/events", h.events)
	router.Get("/events/{eventId}/operations/status", h.operationStatus)
	router.Get("/events/{eventId}/content", h.content)
	router.Put("/events/{eventId}/content/intro", h.contentIntro)
	router.Post("/events/{eventId}/announcements", h.createAnnouncement)
	router.Patch("/events/{eventId}/announcements/{contentId}", h.updateAnnouncement)
	router.Get("/events/{eventId}/applications", h.applications)
	router.Get("/events/{eventId}/teams", h.teams)
	router.Get("/events/{eventId}/contact-submissions", h.contactSubmissions)
	router.Get("/events/{eventId}/contact-submissions/{submissionId}", h.contactSubmissionDetail)
	router.Post("/events/{eventId}/contact-submissions/{submissionId}/resolution", h.contactSubmissionResolution)
	router.Get("/events/{eventId}/applications/{applicationId}", h.applicationDetail)
	router.Put("/events/{eventId}/applications/{applicationId}/reviews/me", h.review)
	router.Get("/events/{eventId}/applications/{applicationId}/admission-consensus", h.consensus)
	router.Put("/events/{eventId}/applications/{applicationId}/admission-consensus/approval", h.approval)
	router.Delete("/events/{eventId}/applications/{applicationId}/admission-consensus/approval", h.approval)
	router.Post("/events/{eventId}/applications/{applicationId}/decision", h.decision)
	router.Post("/events/{eventId}/checkins/scan", h.scanCheckin)
}

// CORS exposes only this constrained BFF to the DreamUP first-party origin.
// Credentials remain host-only cookies and every mutation still passes the
// existing CSRF and exact-origin checks.
func (h *DreamUPAdminHandlers) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == h.expectedOrigin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, X-Reauthentication-Token, If-Match, Idempotency-Key, X-Request-ID")
			w.Header().Set("Access-Control-Expose-Headers", "ETag, X-Request-ID")
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			if origin != h.expectedOrigin {
				writeError(w, r, http.StatusForbidden, "origin_mismatch", "请求来源无效。", nil)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *DreamUPAdminHandlers) session(w http.ResponseWriter, r *http.Request) {
	actor, ok := dreamUPActor(r)
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	if IsNativeBearerSession(r.Context()) {
		writeJSONNoStore(w, r, http.StatusOK, map[string]any{"authenticated": true, "userId": actor.UserID})
		return
	}
	csrfToken := ReadCSRFCookie(r)
	if csrfToken == "" {
		WriteForbidden(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]any{
		"authenticated": true,
		"userId":        actor.UserID,
		"csrfToken":     csrfToken,
	})
}

func (h *DreamUPAdminHandlers) eligibility(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	actor, ok := dreamUPActor(r)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "authentication_required", "请先登录。", nil)
		return
	}
	eligible, err := h.service.Eligible(r.Context(), actor)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, struct {
		Eligible bool `json:"eligible"`
	}{Eligible: eligible})
}

func (h *DreamUPAdminHandlers) events(w http.ResponseWriter, r *http.Request) {
	actor, ok := dreamUPActor(r)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "authentication_required", "请先登录。", nil)
		return
	}
	events, err := h.service.ListEvents(r.Context(), actor)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, struct {
		Events []app.EventSummary `json:"events"`
	}{Events: events})
}

func (h *DreamUPAdminHandlers) operationStatus(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	actor, ok := dreamUPActor(r)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "authentication_required", "请先登录。", nil)
		return
	}
	status, err := h.service.OperationStatus(r.Context(), actor, chi.URLParam(r, "eventId"), r.Header.Get("Idempotency-Key"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, struct {
		Operation app.MutationStatus `json:"operation"`
	}{Operation: status})
}

func (h *DreamUPAdminHandlers) content(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContentManage, kind: "event_content", upstreamMethod: http.MethodGet, suffix: "/content"})
}

func (h *DreamUPAdminHandlers) contentIntro(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContentManage, kind: "event_content", upstreamMethod: http.MethodPut, suffix: "/content/intro", mutation: true})
}

func (h *DreamUPAdminHandlers) createAnnouncement(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContentManage, kind: "event_content", upstreamMethod: http.MethodPost, suffix: "/announcements", mutation: true})
}

func (h *DreamUPAdminHandlers) updateAnnouncement(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContentManage, kind: "event_content", resourceParam: "contentId", upstreamMethod: http.MethodPatch, suffix: "/announcements/" + url.PathEscape(chi.URLParam(r, "contentId")), mutation: true})
}

func (h *DreamUPAdminHandlers) applications(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	for key := range query {
		if key != "status" && key != "limit" && key != "sort" {
			writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
			return
		}
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionApplicationReadBasic, kind: "event", upstreamMethod: http.MethodGet, suffix: "/applications", query: query})
}

func (h *DreamUPAdminHandlers) teams(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) != 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionDashboardRead, kind: "event", upstreamMethod: http.MethodGet, suffix: "/teams"})
}

func (h *DreamUPAdminHandlers) contactSubmissions(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	for key, values := range query {
		if (key != "kind" && key != "limit" && key != "cursor") || len(values) != 1 {
			writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
			return
		}
	}
	if kind := query.Get("kind"); kind != "" && kind != "feedback" && kind != "sponsorship" {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
		return
	}
	if limit := query.Get("limit"); limit != "" && (!contactSubmissionLimitPattern.MatchString(limit) || (len(limit) == 3 && limit > "100")) {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
		return
	}
	if values, present := query["cursor"]; present {
		if !contactSubmissionCursorPattern.MatchString(values[0]) {
			writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
			return
		}
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContactSubmissionManage, kind: "event", upstreamMethod: http.MethodGet, suffix: "/contact-submissions", query: query})
}

func (h *DreamUPAdminHandlers) contactSubmissionResolution(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContactSubmissionManage, kind: "contact_submission", resourceParam: "submissionId", upstreamMethod: http.MethodPatch, suffix: "/contact-submissions/" + url.PathEscape(chi.URLParam(r, "submissionId")) + "/resolution", mutation: true})
}

func (h *DreamUPAdminHandlers) contactSubmissionDetail(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContactSubmissionManage, kind: "contact_submission", resourceParam: "submissionId", upstreamMethod: http.MethodGet, suffix: "/contact-submissions/" + url.PathEscape(chi.URLParam(r, "submissionId"))})
}

func (h *DreamUPAdminHandlers) applicationDetail(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, proxyRoute{capability: permissions.ActionApplicationReadBasic, kind: "application", resourceParam: "applicationId", upstreamMethod: http.MethodGet, suffix: "/applications/" + url.PathEscape(chi.URLParam(r, "applicationId")), addOwnReview: true})
}

func (h *DreamUPAdminHandlers) review(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, proxyRoute{capability: permissions.ActionApplicationReview, kind: "application", resourceParam: "applicationId", upstreamMethod: http.MethodPut, suffix: "/applications/" + url.PathEscape(chi.URLParam(r, "applicationId")) + "/reviews/me", mutation: true})
}

func (h *DreamUPAdminHandlers) consensus(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, proxyRoute{capability: permissions.ActionApplicationApproveAdmission, kind: "application", resourceParam: "applicationId", upstreamMethod: http.MethodGet, suffix: "/applications/" + url.PathEscape(chi.URLParam(r, "applicationId")) + "/admission-consensus"})
}

func (h *DreamUPAdminHandlers) approval(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, proxyRoute{capability: permissions.ActionApplicationApproveAdmission, kind: "application", resourceParam: "applicationId", upstreamMethod: r.Method, suffix: "/applications/" + url.PathEscape(chi.URLParam(r, "applicationId")) + "/admission-consensus/approval", mutation: true, allowEmptyBody: r.Method == http.MethodDelete})
}

func (h *DreamUPAdminHandlers) decision(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, proxyRoute{capability: permissions.ActionApplicationDecide, kind: "application", resourceParam: "applicationId", upstreamMethod: http.MethodPatch, suffix: "/applications/" + url.PathEscape(chi.URLParam(r, "applicationId")) + "/decision", mutation: true, addOwnReview: true})
}

func (h *DreamUPAdminHandlers) scanCheckin(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, proxyRoute{capability: permissions.ActionCheckinScan, kind: "event", upstreamMethod: http.MethodPost, suffix: "/checkins/scan", mutation: true})
}

type proxyRoute struct {
	capability     permissions.Action
	kind           string
	resourceParam  string
	upstreamMethod string
	suffix         string
	query          url.Values
	mutation       bool
	allowEmptyBody bool
	addOwnReview   bool
}

func (h *DreamUPAdminHandlers) proxy(w http.ResponseWriter, r *http.Request, route proxyRoute) {
	actor, ok := dreamUPActor(r)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "authentication_required", "请先登录。", nil)
		return
	}
	if route.mutation && !h.trustedMutation(r) {
		writeError(w, r, http.StatusForbidden, "origin_mismatch", "请求来源无效。", nil)
		return
	}
	eventID := chi.URLParam(r, "eventId")
	resourceID := eventID
	if route.resourceParam != "" {
		resourceID = chi.URLParam(r, route.resourceParam)
	}
	var body json.RawMessage
	if route.mutation {
		var err error
		if route.allowEmptyBody {
			body, err = readOptionalDreamUPAdminBody(r)
		} else {
			body, err = readDreamUPAdminBody(r)
		}
		if err != nil {
			writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求内容无效。", nil)
			return
		}
	}
	requestID := request.ID(r.Context())
	result, err := h.service.Proxy(r.Context(), actor, app.ProxyRequest{
		EventID: eventID, Capability: route.capability, ResourceKind: route.kind, ResourceID: resourceID,
		Method: route.upstreamMethod, Path: "/internal/v1/events/" + url.PathEscape(eventID) + route.suffix,
		Query: cloneURLValues(route.query), Body: body, RequestID: requestID,
		IdempotencyKey: r.Header.Get("Idempotency-Key"), IfMatch: r.Header.Get("If-Match"),
		ReauthenticationToken: r.Header.Get("X-Reauthentication-Token"),
	})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	responseBody := result.Body
	if route.addOwnReview {
		responseBody = ensureOwnReview(responseBody)
	}
	if result.ETag != "" {
		w.Header().Set("ETag", result.ETag)
	}
	if result.RequestID != "" {
		w.Header().Set("X-Request-ID", result.RequestID)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.StatusCode)
	_, _ = w.Write(responseBody)
}

func rejectDreamUPAdminQuery(w http.ResponseWriter, r *http.Request) bool {
	if len(r.URL.Query()) == 0 {
		return false
	}
	writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
	return true
}

func (h *DreamUPAdminHandlers) trustedMutation(r *http.Request) bool {
	if r.Header.Get("Origin") == h.expectedOrigin {
		return true
	}
	return h.allowMiniProgram && IsNativeBearerSession(r.Context()) && isMiniProgramClientRequest(r)
}

func dreamUPActor(r *http.Request) (app.Actor, bool) {
	principal, principalOK := PrincipalFromContext(r.Context())
	record, recordOK := SessionRecordFromContext(r.Context())
	if !principalOK || !recordOK || principal.UserID == "" || record.UserID != principal.UserID || record.SessionID != principal.SessionID || record.AuthenticationTime.IsZero() {
		return app.Actor{}, false
	}
	nativeBearer := IsNativeBearerSession(r.Context())
	miniProgram := isMiniProgramClientRequest(r)
	var transport app.AuthenticationTransport
	switch {
	case nativeBearer && miniProgram:
		transport = app.AuthenticationTransportNativeMiniProgramBearer
	case !nativeBearer && !miniProgram:
		transport = app.AuthenticationTransportBrowserCookie
	default:
		// A native credential without the authenticated Mini Program request
		// shape, or a cookie request claiming that shape, is ambiguous and must
		// not gain either transport's authorization behavior.
		return app.Actor{}, false
	}
	return app.Actor{UserID: principal.UserID, SessionID: string(principal.SessionID), AuthenticatedAt: record.AuthenticationTime, SecurityEpoch: record.SecurityEpoch, AuthenticationTransport: transport}, true
}

func readDreamUPAdminBody(r *http.Request) (json.RawMessage, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, app.ErrInvalidRequest
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxDreamUPAdminBodyBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxDreamUPAdminBodyBytes || !json.Valid(raw) || bytes.TrimSpace(raw)[0] != '{' {
		return nil, app.ErrInvalidRequest
	}
	return append(json.RawMessage(nil), raw...), nil
}

func readOptionalDreamUPAdminBody(r *http.Request) (json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxDreamUPAdminBodyBytes+1))
	if err != nil || len(raw) > maxDreamUPAdminBodyBytes {
		return nil, app.ErrInvalidRequest
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, nil
	}
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" || !json.Valid(raw) || raw[0] != '{' {
		return nil, app.ErrInvalidRequest
	}
	return append(json.RawMessage(nil), raw...), nil
}

func ensureOwnReview(raw json.RawMessage) json.RawMessage {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object["application"] == nil || object["ownReview"] != nil {
		return raw
	}
	object["ownReview"] = json.RawMessage("null")
	encoded, err := json.Marshal(object)
	if err != nil {
		return raw
	}
	return encoded
}

func (h *DreamUPAdminHandlers) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, app.ErrInvalidRequest):
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求内容无效。", nil)
	case errors.Is(err, app.ErrForbidden):
		writeError(w, r, http.StatusForbidden, "permission_denied", "没有执行此操作的权限。", nil)
	case errors.Is(err, app.ErrStepUpRequired):
		writeError(w, r, http.StatusUnauthorized, "admin_stepup.required", "请先完成管理员二次验证。", nil)
	case errors.Is(err, app.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "resource_not_found", "资源不存在。", nil)
	case errors.Is(err, app.ErrConflict):
		writeError(w, r, http.StatusConflict, "state_conflict", "状态已变化，请刷新后重试。", nil)
	default:
		writeError(w, r, http.StatusBadGateway, "upstream_unavailable", "活动服务暂时不可用。", nil)
	}
}

func cloneURLValues(values url.Values) url.Values {
	result := make(url.Values, len(values))
	for key, entries := range values {
		result[key] = append([]string(nil), entries...)
	}
	return result
}
