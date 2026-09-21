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
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	app "github.com/GravelEvolution/united-pass/backend/internal/dreamupadmin"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

const (
	maxDreamUPAdminBodyBytes               = 64 << 10
	maxDreamUPOperationsCursorBytes        = 2048
	maxDreamUPOperationsCursorPayloadBytes = 1536
)

var (
	contactSubmissionLimitPattern  = regexp.MustCompile(`^[1-9][0-9]{0,2}$`)
	contactSubmissionCursorPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
	dreamUPOperationsCursorPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`)
	dreamUPAdminFilterPattern      = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,255}$`)
	dreamUPRequestIDPattern        = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
	dreamUPIdempotencyPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,160}$`)
	dreamUPReceiptHashPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	redactedReviewStringKeys       = map[string]struct{}{
		"city": {}, "affiliation_type": {}, "affiliation_name": {}, "primary_role": {}, "experience_level": {},
		"problem_to_solve": {}, "first_build_step": {}, "what_you_bring": {}, "collaboration_goal": {},
		"vibe_coding_foundation": {}, "last_word_to_moonstone": {}, "view_on_tech_democratization": {},
		"when_tech_singularity": {}, "ai_human_relationship": {}, "team_preference": {}, "existing_team_details": {},
		"affiliationType": {}, "affiliationName": {}, "primaryRole": {}, "experienceLevel": {},
		"problemToSolve": {}, "firstBuildStep": {}, "whatYouBring": {}, "collaborationGoal": {},
		"vibeCodingFoundation": {}, "lastWordToMoonstone": {}, "viewOnTechDemocratization": {},
		"whenTechSingularity": {}, "aiHumanRelationship": {}, "teamPreference": {}, "existingTeamDetails": {},
		"organization": {}, "role_skills": {}, "motivation": {},
	}
	redactedReviewArrayLimits = map[string]int{
		"skill_tags": 5, "portfolio_urls": 3, "skillTags": 5, "portfolioUrls": 3,
	}
)

type DreamUPAdminService interface {
	Eligible(context.Context, app.Actor) (bool, error)
	ListEvents(context.Context, app.Actor) ([]app.EventSummary, error)
	OperationStatus(context.Context, app.Actor, string, string) (app.MutationStatus, error)
	Proxy(context.Context, app.Actor, app.ProxyRequest) (app.ProxyResponse, error)
}

type DreamUPAdminHandlers struct {
	service                    DreamUPAdminService
	personalAssetOwnerResolver app.PersonalAssetOwnerResolver
	reviewIdentityResolver     app.ReviewIdentityResolver
	expectedOrigin             string
	allowMiniProgram           bool
}

type DreamUPAdminHandlerConfig struct {
	PersonalAssetOwnerResolver app.PersonalAssetOwnerResolver
	ReviewIdentityResolver     app.ReviewIdentityResolver
	AllowMiniProgram           bool
}

func NewDreamUPAdminHandlers(service DreamUPAdminService, expectedOrigin string, config DreamUPAdminHandlerConfig) (*DreamUPAdminHandlers, error) {
	parsed, err := url.Parse(expectedOrigin)
	if service == nil || config.PersonalAssetOwnerResolver == nil || config.ReviewIdentityResolver == nil || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || expectedOrigin != strings.TrimRight(expectedOrigin, "/") {
		return nil, app.ErrInvalidRequest
	}
	return &DreamUPAdminHandlers{
		service: service, personalAssetOwnerResolver: config.PersonalAssetOwnerResolver,
		reviewIdentityResolver: config.ReviewIdentityResolver,
		expectedOrigin:         expectedOrigin, allowMiniProgram: config.AllowMiniProgram,
	}, nil
}

func (h *DreamUPAdminHandlers) Mount(router chi.Router) {
	router.Get("/session", h.session)
	router.Get("/eligibility", h.eligibility)
	router.Get("/events", h.events)
	router.Get("/events/{eventId}/operations/status", h.operationStatus)
	router.Get("/events/{eventId}/content", h.content)
	router.Get("/events/{eventId}/splash-ad", h.splashPoster)
	router.Post("/events/{eventId}/splash-poster-image-upload-intents", h.createSplashPosterImageUploadIntent)
	router.Post("/events/{eventId}/announcement-background-image-upload-intents", h.createAnnouncementBackgroundImageUploadIntent)
	router.Put("/events/{eventId}/splash-ad", h.updateSplashPoster)
	router.Put("/events/{eventId}/content/intro", h.contentIntro)
	router.Post("/events/{eventId}/announcements", h.createAnnouncement)
	router.Patch("/events/{eventId}/announcements/{contentId}", h.updateAnnouncement)
	router.Get("/events/{eventId}/applications", h.applications)
	router.Get("/events/{eventId}/teams", h.teams)
	router.Get("/events/{eventId}/contact-submissions", h.contactSubmissions)
	router.Get("/events/{eventId}/contact-submissions/{submissionId}", h.contactSubmissionDetail)
	router.Post("/events/{eventId}/contact-submissions/{submissionId}/resolution", h.contactSubmissionResolution)
	router.Get("/events/{eventId}/applications/{applicationId}", h.applicationDetail)
	router.Post("/events/{eventId}/applications/{applicationId}/review-identity", h.applicationReviewIdentity)
	router.Put("/events/{eventId}/applications/{applicationId}/reviews/me", h.review)
	router.Get("/events/{eventId}/applications/{applicationId}/admission-consensus", h.consensus)
	router.Put("/events/{eventId}/applications/{applicationId}/admission-consensus/approval", h.approval)
	router.Delete("/events/{eventId}/applications/{applicationId}/admission-consensus/approval", h.approval)
	router.Post("/events/{eventId}/applications/{applicationId}/decision", h.decision)
	router.Post("/events/{eventId}/checkins/scan", h.scanCheckin)
	router.Get("/events/{eventId}/inspection-points", h.inspectionPoints)
	router.Post("/events/{eventId}/inspection-points", h.createInspectionPoint)
	router.Post("/events/{eventId}/inspection-point-image-upload-intents", h.createInspectionPointImageUploadIntent)
	router.Get("/events/{eventId}/inspection-points/{pointId}", h.inspectionPointDetail)
	router.Patch("/events/{eventId}/inspection-points/{pointId}", h.updateInspectionPoint)
	router.Post("/events/{eventId}/inspection-points/{pointId}/code-rotations", h.rotateInspectionPointCode)
	router.Post("/events/{eventId}/inspection-points/{pointId}/inspections", h.createInspection)
	router.Get("/events/{eventId}/inspections", h.inspections)
	router.Get("/events/{eventId}/inspections/{inspectionId}", h.inspectionDetail)
	router.Post("/events/{eventId}/inspection-photo-uploads/{uploadId}/finalize", h.finalizeInspectionPhotoUpload)
	router.Get("/events/{eventId}/assets", h.assets)
	router.Post("/events/{eventId}/assets", h.createAsset)
	router.Post("/events/{eventId}/asset-image-upload-intents", h.createAssetImageUploadIntent)
	router.Get("/events/{eventId}/assets/{assetId}", h.assetDetail)
	router.Patch("/events/{eventId}/assets/{assetId}", h.updateAsset)
	router.Post("/events/{eventId}/asset-units/{unitId}/code-rotations", h.rotateAssetCode)
	router.Post("/events/{eventId}/asset-units/{unitId}/inventory-adjustments", h.adjustAssetInventory)
	router.Get("/events/{eventId}/asset-reservations", h.assetReservations)
	router.Patch("/events/{eventId}/asset-reservations/{reservationId}", h.decideAssetReservation)
	router.Post("/events/{eventId}/asset-units/{unitId}/checkout", h.checkoutAssetUnit)
	router.Post("/events/{eventId}/asset-units/{unitId}/checkin", h.checkinAssetUnit)
	router.Post("/events/{eventId}/asset-units/{unitId}/transfers", h.transferAssetUnit)
	router.Get("/events/{eventId}/personal-asset-assignments", h.personalAssetAssignments)
	router.Post("/events/{eventId}/personal-asset-assignments", h.createPersonalAssetAssignment)
	router.Post("/events/{eventId}/personal-asset-image-upload-intents", h.createPersonalAssetImageUploadIntent)
	router.Patch("/events/{eventId}/personal-asset-assignments/{assignmentId}", h.updatePersonalAssetAssignment)
	router.Post("/events/{eventId}/personal-asset-assignments/{assignmentId}/code-rotations", h.rotatePersonalAssetCode)
	router.Post("/events/{eventId}/entity-codes/{codeId}/print-jobs", h.createSingleQRPrintJob)
	router.Post("/events/{eventId}/qr-print-jobs/bulk", h.createBulkQRPrintJob)
	router.Get("/events/{eventId}/qr-print-jobs/{printJobId}", h.qrPrintJob)
	router.Get("/events/{eventId}/qr-print-jobs/{printJobId}/bulk", h.bulkQRPrintJob)
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
	query, ok := validatedDreamUPListQuery(w, r, "limit", "cursor")
	if !ok {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContentManage, kind: "event_content", upstreamMethod: http.MethodGet, suffix: "/content", query: query})
}

func (h *DreamUPAdminHandlers) splashPoster(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContentManage, kind: "splash_poster", upstreamMethod: http.MethodGet, suffix: "/splash-ad"})
}

func (h *DreamUPAdminHandlers) createSplashPosterImageUploadIntent(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContentManage, kind: "splash_poster", upstreamMethod: http.MethodPost, suffix: "/splash-poster-image-upload-intents", mutation: true})
}

func (h *DreamUPAdminHandlers) createAnnouncementBackgroundImageUploadIntent(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContentManage, kind: "event_content", upstreamMethod: http.MethodPost, suffix: "/announcement-background-image-upload-intents", mutation: true})
}

func (h *DreamUPAdminHandlers) updateSplashPoster(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionContentManage, kind: "splash_poster", upstreamMethod: http.MethodPut, suffix: "/splash-ad", mutation: true})
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
	query, ok := validatedDreamUPListQuery(w, r, "status", "limit", "sort", "cursor")
	if !ok {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionApplicationReadBasic, kind: "event", upstreamMethod: http.MethodGet, suffix: "/applications", query: query, requireRedactedApplicationPage: true})
}

func (h *DreamUPAdminHandlers) teams(w http.ResponseWriter, r *http.Request) {
	query, ok := validatedDreamUPListQuery(w, r, "limit", "cursor")
	if !ok {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionDashboardRead, kind: "event", upstreamMethod: http.MethodGet, suffix: "/teams", query: query})
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
	h.proxy(w, r, proxyRoute{capability: permissions.ActionApplicationReadBasic, kind: "application", resourceParam: "applicationId", upstreamMethod: http.MethodGet, suffix: "/applications/" + url.PathEscape(chi.URLParam(r, "applicationId")), addOwnReview: true, requireRedactedApplication: true})
}

func (h *DreamUPAdminHandlers) applicationReviewIdentity(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	applicationID := chi.URLParam(r, "applicationId")
	h.proxy(w, r, proxyRoute{
		capability: permissions.ActionIdentityReadRestricted, kind: "application", resourceParam: "applicationId",
		upstreamMethod: http.MethodPost, suffix: "/applications/" + url.PathEscape(applicationID) + "/review-identity",
		mutation: true, rewriteBody: rewriteApplicationReviewIdentityBody, transformReviewIdentity: true,
	})
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
	h.proxy(w, r, proxyRoute{capability: permissions.ActionApplicationDecide, kind: "application", resourceParam: "applicationId", upstreamMethod: http.MethodPatch, suffix: "/applications/" + url.PathEscape(chi.URLParam(r, "applicationId")) + "/decision", mutation: true, addOwnReview: true, requireRedactedApplication: true})
}

func (h *DreamUPAdminHandlers) scanCheckin(w http.ResponseWriter, r *http.Request) {
	h.proxy(w, r, proxyRoute{capability: permissions.ActionCheckinScan, kind: "event", upstreamMethod: http.MethodPost, suffix: "/checkins/scan", mutation: true})
}

func (h *DreamUPAdminHandlers) inspectionPoints(w http.ResponseWriter, r *http.Request) {
	query, ok := validatedDreamUPListQuery(w, r, "status", "limit", "cursor")
	if !ok {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionInspectionPointRead, kind: "event", upstreamMethod: http.MethodGet, suffix: "/inspection-points", query: query})
}

func (h *DreamUPAdminHandlers) createInspectionPoint(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionInspectionPointManage, kind: "event", upstreamMethod: http.MethodPost, suffix: "/inspection-points", mutation: true})
}

func (h *DreamUPAdminHandlers) createInspectionPointImageUploadIntent(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionInspectionPointManage, kind: "event", upstreamMethod: http.MethodPost, suffix: "/inspection-point-image-upload-intents", mutation: true})
}

func (h *DreamUPAdminHandlers) inspectionPointDetail(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionInspectionPointRead, "inspection_point", "pointId", http.MethodGet, "/inspection-points/"+url.PathEscape(chi.URLParam(r, "pointId")), false))
}

func (h *DreamUPAdminHandlers) updateInspectionPoint(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionInspectionPointManage, "inspection_point", "pointId", http.MethodPatch, "/inspection-points/"+url.PathEscape(chi.URLParam(r, "pointId")), true))
}

func (h *DreamUPAdminHandlers) rotateInspectionPointCode(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionInspectionPointManage, "inspection_point", "pointId", http.MethodPost, "/inspection-points/"+url.PathEscape(chi.URLParam(r, "pointId"))+"/code-rotations", true))
}

func (h *DreamUPAdminHandlers) createInspection(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionInspectionPerform, "inspection_point", "pointId", http.MethodPost, "/inspection-points/"+url.PathEscape(chi.URLParam(r, "pointId"))+"/inspections", true))
}

func (h *DreamUPAdminHandlers) inspections(w http.ResponseWriter, r *http.Request) {
	query, ok := validatedDreamUPListQuery(w, r, "status", "pointId", "limit", "cursor")
	if !ok {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionInspectionReview, kind: "event", upstreamMethod: http.MethodGet, suffix: "/inspections", query: query})
}

func (h *DreamUPAdminHandlers) inspectionDetail(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionInspectionReview, "inspection_record", "inspectionId", http.MethodGet, "/inspections/"+url.PathEscape(chi.URLParam(r, "inspectionId")), false))
}

func (h *DreamUPAdminHandlers) finalizeInspectionPhotoUpload(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionInspectionPerform, "inspection_photo_upload", "uploadId", http.MethodPost, "/inspection-photo-uploads/"+url.PathEscape(chi.URLParam(r, "uploadId"))+"/finalize", true))
}

func (h *DreamUPAdminHandlers) assets(w http.ResponseWriter, r *http.Request) {
	query, ok := validatedDreamUPListQuery(w, r, "status", "kind", "limit", "cursor")
	if !ok {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionAssetRead, kind: "event", upstreamMethod: http.MethodGet, suffix: "/assets", query: query})
}

func (h *DreamUPAdminHandlers) createAsset(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionAssetManage, kind: "event", upstreamMethod: http.MethodPost, suffix: "/assets", mutation: true})
}

func (h *DreamUPAdminHandlers) createAssetImageUploadIntent(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionAssetManage, kind: "event", upstreamMethod: http.MethodPost, suffix: "/asset-image-upload-intents", mutation: true})
}

func (h *DreamUPAdminHandlers) assetDetail(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionAssetRead, "event_asset", "assetId", http.MethodGet, "/assets/"+url.PathEscape(chi.URLParam(r, "assetId")), false))
}

func (h *DreamUPAdminHandlers) updateAsset(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionAssetManage, "event_asset", "assetId", http.MethodPatch, "/assets/"+url.PathEscape(chi.URLParam(r, "assetId")), true))
}

func (h *DreamUPAdminHandlers) rotateAssetCode(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionAssetCodeRotate, "asset_unit", "unitId", http.MethodPost, "/asset-units/"+url.PathEscape(chi.URLParam(r, "unitId"))+"/code-rotations", true))
}

func (h *DreamUPAdminHandlers) adjustAssetInventory(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionAssetInventoryAdjust, "asset_unit", "unitId", http.MethodPost, "/asset-units/"+url.PathEscape(chi.URLParam(r, "unitId"))+"/inventory-adjustments", true))
}

func (h *DreamUPAdminHandlers) assetReservations(w http.ResponseWriter, r *http.Request) {
	query, ok := validatedDreamUPListQuery(w, r, "status", "assetId", "limit", "cursor")
	if !ok {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionAssetReservationManage, kind: "event", upstreamMethod: http.MethodGet, suffix: "/asset-reservations", query: query})
}

func (h *DreamUPAdminHandlers) decideAssetReservation(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionAssetReservationManage, "asset_reservation", "reservationId", http.MethodPatch, "/asset-reservations/"+url.PathEscape(chi.URLParam(r, "reservationId")), true))
}

func (h *DreamUPAdminHandlers) checkoutAssetUnit(w http.ResponseWriter, r *http.Request) {
	h.assetUnitMutation(w, r, "checkout")
}
func (h *DreamUPAdminHandlers) checkinAssetUnit(w http.ResponseWriter, r *http.Request) {
	h.assetUnitMutation(w, r, "checkin")
}
func (h *DreamUPAdminHandlers) transferAssetUnit(w http.ResponseWriter, r *http.Request) {
	h.assetUnitMutation(w, r, "transfers")
}

func (h *DreamUPAdminHandlers) assetUnitMutation(w http.ResponseWriter, r *http.Request, action string) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	unitID := url.PathEscape(chi.URLParam(r, "unitId"))
	h.proxy(w, r, objectProxyRoute(permissions.ActionAssetCustodyTransfer, "asset_unit", "unitId", http.MethodPost, "/asset-units/"+unitID+"/"+action, true))
}

func (h *DreamUPAdminHandlers) personalAssetAssignments(w http.ResponseWriter, r *http.Request) {
	query, ok := validatedDreamUPListQuery(w, r, "status", "limit", "cursor")
	if !ok {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionPersonalAssetAssignment, kind: "event", upstreamMethod: http.MethodGet, suffix: "/personal-asset-assignments", query: query})
}

func (h *DreamUPAdminHandlers) createPersonalAssetAssignment(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{
		capability: permissions.ActionPersonalAssetAssignment, kind: "event", upstreamMethod: http.MethodPost,
		suffix: "/personal-asset-assignments", mutation: true, rewriteBody: h.rewritePersonalAssetCreationBody,
	})
}

func (h *DreamUPAdminHandlers) createPersonalAssetImageUploadIntent(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionPersonalAssetAssignment, kind: "event", upstreamMethod: http.MethodPost, suffix: "/personal-asset-image-upload-intents", mutation: true})
}

func (h *DreamUPAdminHandlers) updatePersonalAssetAssignment(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionPersonalAssetAssignment, "personal_asset_assignment", "assignmentId", http.MethodPatch, "/personal-asset-assignments/"+url.PathEscape(chi.URLParam(r, "assignmentId")), true))
}

func (h *DreamUPAdminHandlers) rotatePersonalAssetCode(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionPersonalAssetAssignment, "personal_asset_assignment", "assignmentId", http.MethodPost, "/personal-asset-assignments/"+url.PathEscape(chi.URLParam(r, "assignmentId"))+"/code-rotations", true))
}

func (h *DreamUPAdminHandlers) createSingleQRPrintJob(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionQRPrintSingle, "entity_code", "codeId", http.MethodPost, "/entity-codes/"+url.PathEscape(chi.URLParam(r, "codeId"))+"/print-jobs", true))
}

func (h *DreamUPAdminHandlers) createBulkQRPrintJob(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, proxyRoute{capability: permissions.ActionQRPrintBulk, kind: "event", upstreamMethod: http.MethodPost, suffix: "/qr-print-jobs/bulk", mutation: true})
}

func (h *DreamUPAdminHandlers) qrPrintJob(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionQRPrintSingle, "qr_print_job", "printJobId", http.MethodGet, "/qr-print-jobs/"+url.PathEscape(chi.URLParam(r, "printJobId")), false))
}

// bulkQRPrintJob deliberately has its own capability-bound route instead of a
// generic print-job read permission. The Worker compares this assertion with
// the immutable capability and role-binding snapshot stored on the job before
// it decrypts any QR token material.
func (h *DreamUPAdminHandlers) bulkQRPrintJob(w http.ResponseWriter, r *http.Request) {
	if rejectDreamUPAdminQuery(w, r) {
		return
	}
	h.proxy(w, r, objectProxyRoute(permissions.ActionQRPrintBulk, "qr_print_job", "printJobId", http.MethodGet, "/qr-print-jobs/"+url.PathEscape(chi.URLParam(r, "printJobId"))+"/bulk", false))
}

func objectProxyRoute(capability permissions.Action, kind, resourceParam, method, suffix string, mutation bool) proxyRoute {
	return proxyRoute{capability: capability, kind: kind, resourceParam: resourceParam, upstreamMethod: method, suffix: suffix, mutation: mutation}
}

func validatedDreamUPListQuery(w http.ResponseWriter, r *http.Request, allowedKeys ...string) (url.Values, bool) {
	allowed := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = struct{}{}
	}
	query := r.URL.Query()
	for key, values := range query {
		if _, ok := allowed[key]; !ok || len(values) != 1 {
			writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
			return nil, false
		}
		value := values[0]
		switch key {
		case "limit":
			if !contactSubmissionLimitPattern.MatchString(value) || (len(value) == 3 && value > "100") {
				writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
				return nil, false
			}
		case "cursor":
			separator := strings.IndexByte(value, '.')
			if len(value) > maxDreamUPOperationsCursorBytes || separator < 1 || separator > maxDreamUPOperationsCursorPayloadBytes || !dreamUPOperationsCursorPattern.MatchString(value) {
				writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
				return nil, false
			}
		default:
			if !dreamUPAdminFilterPattern.MatchString(value) {
				writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求参数无效。", nil)
				return nil, false
			}
		}
	}
	return query, true
}

type proxyRoute struct {
	capability                     permissions.Action
	kind                           string
	resourceParam                  string
	upstreamMethod                 string
	suffix                         string
	query                          url.Values
	mutation                       bool
	allowEmptyBody                 bool
	addOwnReview                   bool
	requireRedactedApplication     bool
	requireRedactedApplicationPage bool
	transformReviewIdentity        bool
	rewriteBody                    func(context.Context, json.RawMessage) (json.RawMessage, error)
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
		if route.rewriteBody != nil {
			body, err = route.rewriteBody(r.Context(), body)
			if err != nil {
				h.writeError(w, r, err)
				return
			}
			// Restore the request body to the final canonical bytes, then pass it
			// through the ordinary bounded JSON reader. This keeps the existing
			// operation fingerprint and delegation signature bound to exactly the
			// payload that is proxied upstream.
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			body, err = readDreamUPAdminBody(r)
			if err != nil {
				writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求内容无效。", nil)
				return
			}
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
	if route.transformReviewIdentity && result.StatusCode >= http.StatusOK && result.StatusCode < http.StatusMultipleChoices {
		responseBody, err = h.transformReviewIdentityResponse(r.Context(), responseBody, r.Header.Get("Idempotency-Key"))
		if err != nil {
			writeError(w, r, http.StatusBadGateway, "upstream_contract_violation", "活动服务返回了无效数据。", nil)
			return
		}
	}
	if route.addOwnReview {
		responseBody = ensureOwnReview(responseBody)
	}
	if route.requireRedactedApplicationPage && result.StatusCode >= http.StatusOK && result.StatusCode < http.StatusMultipleChoices {
		if err := validateRedactedApplicationPage(responseBody, eventID); err != nil {
			writeError(w, r, http.StatusBadGateway, "upstream_contract_violation", "活动服务返回了无效数据。", nil)
			return
		}
	}
	if route.requireRedactedApplication && result.StatusCode >= http.StatusOK && result.StatusCode < http.StatusMultipleChoices {
		if err := validateRedactedApplicationDetail(responseBody, eventID, resourceID); err != nil {
			writeError(w, r, http.StatusBadGateway, "upstream_contract_violation", "活动服务返回了无效数据。", nil)
			return
		}
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

func rewriteApplicationReviewIdentityBody(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	body, err := closedJSONObject(raw, map[string]struct{}{}, nil)
	if err != nil || len(body) != 0 {
		return nil, app.ErrInvalidRequest
	}
	requestID := request.ID(ctx)
	if !dreamUPRequestIDPattern.MatchString(requestID) {
		return nil, app.ErrInvalidRequest
	}
	return json.Marshal(struct {
		ProtectedReasonID string `json:"protectedReasonId"`
	}{ProtectedReasonID: app.ReviewIdentityProtectedReasonID(requestID)})
}

func (h *DreamUPAdminHandlers) transformReviewIdentityResponse(ctx context.Context, raw json.RawMessage, expectedOperationID string) (json.RawMessage, error) {
	envelope, err := closedJSONObject(raw, map[string]struct{}{`identity`: {}, `receipt`: {}}, []string{"identity", "receipt"})
	if err != nil {
		return nil, err
	}
	identityObject, err := closedJSONObject(envelope["identity"], map[string]struct{}{
		`providerSubject`: {}, `legalName`: {}, `email`: {}, `mobile`: {},
	}, []string{"providerSubject", "legalName", "email", "mobile"})
	if err != nil {
		return nil, err
	}
	var providerSubject string
	if json.Unmarshal(identityObject["providerSubject"], &providerSubject) != nil || !validBoundedIdentityText(providerSubject, 255, false) {
		return nil, errors.New("invalid review identity provider subject")
	}
	legalName, err := nullableBoundedIdentityText(identityObject["legalName"], 120)
	if err != nil {
		return nil, err
	}
	email, err := nullableBoundedIdentityText(identityObject["email"], 320)
	if err != nil {
		return nil, err
	}
	mobile, err := nullableBoundedIdentityText(identityObject["mobile"], 40)
	if err != nil {
		return nil, err
	}
	receiptObject, err := closedJSONObject(envelope["receipt"], map[string]struct{}{
		`operationId`: {}, `receiptHash`: {}, `consumedAt`: {},
	}, []string{"operationId", "receiptHash", "consumedAt"})
	if err != nil {
		return nil, err
	}
	var operationID, receiptHash string
	var consumedAt int64
	if !dreamUPIdempotencyPattern.MatchString(expectedOperationID) ||
		json.Unmarshal(receiptObject["operationId"], &operationID) != nil || operationID != expectedOperationID ||
		!dreamUPIdempotencyPattern.MatchString(operationID) ||
		json.Unmarshal(receiptObject["receiptHash"], &receiptHash) != nil || !dreamUPReceiptHashPattern.MatchString(receiptHash) ||
		json.Unmarshal(receiptObject["consumedAt"], &consumedAt) != nil || consumedAt <= 0 {
		return nil, errors.New("invalid review identity receipt")
	}
	userID, err := h.reviewIdentityResolver.ResolveReviewIdentityUser(ctx, providerSubject)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Identity struct {
			UserID    string  `json:"userId"`
			LegalName *string `json:"legalName"`
			Email     *string `json:"email"`
			Mobile    *string `json:"mobile"`
		} `json:"identity"`
		Receipt struct {
			OperationID string `json:"operationId"`
			ReceiptHash string `json:"receiptHash"`
			ConsumedAt  int64  `json:"consumedAt"`
		} `json:"receipt"`
	}{Identity: struct {
		UserID    string  `json:"userId"`
		LegalName *string `json:"legalName"`
		Email     *string `json:"email"`
		Mobile    *string `json:"mobile"`
	}{UserID: string(userID), LegalName: legalName, Email: email, Mobile: mobile}, Receipt: struct {
		OperationID string `json:"operationId"`
		ReceiptHash string `json:"receiptHash"`
		ConsumedAt  int64  `json:"consumedAt"`
	}{OperationID: operationID, ReceiptHash: receiptHash, ConsumedAt: consumedAt}})
}

func nullableBoundedIdentityText(raw json.RawMessage, maxBytes int) (*string, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || !validBoundedIdentityText(value, maxBytes, true) {
		return nil, errors.New("invalid review identity value")
	}
	return &value, nil
}

func validBoundedIdentityText(value string, maxCharacters int, allowEmpty bool) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxCharacters || strings.TrimSpace(value) != value || (!allowEmpty && value == "") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || (character >= 0x202a && character <= 0x202e) || (character >= 0x2066 && character <= 0x2069) {
			return false
		}
	}
	return true
}

func validateRedactedApplicationDetail(raw json.RawMessage, expectedEventID, expectedApplicationID string) error {
	envelope, err := closedJSONObject(raw,
		map[string]struct{}{`application`: {}, `ownReview`: {}},
		[]string{"application", "ownReview"},
	)
	if err != nil {
		return err
	}
	if err = validateRedactedBasicApplication(envelope["application"], expectedEventID, expectedApplicationID); err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(envelope["ownReview"]), []byte("null")) {
		return nil
	}
	review, err := closedJSONObject(envelope["ownReview"], map[string]struct{}{
		`recommendation`: {}, `note`: {}, `version`: {},
	}, []string{"recommendation", "note", "version"})
	if err != nil {
		return err
	}
	var recommendation, note string
	var version int64
	if json.Unmarshal(review["recommendation"], &recommendation) != nil || !validReviewRecommendation(recommendation) ||
		json.Unmarshal(review["note"], &note) != nil || len(note) > 2000 ||
		json.Unmarshal(review["version"], &version) != nil || version < 1 {
		return errors.New("invalid redacted application own review")
	}
	return nil
}

func validateRedactedApplicationPage(raw json.RawMessage, expectedEventID string) error {
	envelope, err := closedJSONObject(raw,
		map[string]struct{}{`applications`: {}, `nextCursor`: {}},
		[]string{"applications", "nextCursor"},
	)
	if err != nil {
		return err
	}
	var applications []json.RawMessage
	if err = json.Unmarshal(envelope["applications"], &applications); err != nil || applications == nil || len(applications) > 100 {
		return errors.New("invalid redacted application page")
	}
	for _, application := range applications {
		if err = validateRedactedBasicApplication(application, expectedEventID, ""); err != nil {
			return err
		}
	}
	cursorRaw := bytes.TrimSpace(envelope["nextCursor"])
	if bytes.Equal(cursorRaw, []byte("null")) {
		return nil
	}
	var cursor string
	separator := -1
	if json.Unmarshal(cursorRaw, &cursor) == nil {
		separator = strings.IndexByte(cursor, '.')
	}
	if len(cursor) > maxDreamUPOperationsCursorBytes || separator < 1 || separator > maxDreamUPOperationsCursorPayloadBytes || !dreamUPOperationsCursorPattern.MatchString(cursor) {
		return errors.New("invalid redacted application page cursor")
	}
	return nil
}

func validateRedactedBasicApplication(raw json.RawMessage, expectedEventID, expectedApplicationID string) error {
	application, err := closedJSONObject(raw, map[string]struct{}{
		`id`: {}, `eventId`: {}, `displayHandle`: {}, `status`: {}, `version`: {},
		`reviewAnswers`: {}, `submittedAt`: {}, `updatedAt`: {},
	}, []string{"id", "eventId", "displayHandle", "status", "version", "reviewAnswers", "submittedAt", "updatedAt"})
	if err != nil {
		return err
	}
	var id, eventID, displayHandle, status string
	var version, updatedAt int64
	if json.Unmarshal(application["id"], &id) != nil || !dreamUPAdminFilterPattern.MatchString(id) ||
		json.Unmarshal(application["eventId"], &eventID) != nil || eventID != expectedEventID ||
		json.Unmarshal(application["displayHandle"], &displayHandle) != nil || len(displayHandle) < 8 || len(displayHandle) > 80 ||
		json.Unmarshal(application["status"], &status) != nil || !validRedactedApplicationStatus(status) ||
		json.Unmarshal(application["version"], &version) != nil || version < 1 ||
		json.Unmarshal(application["updatedAt"], &updatedAt) != nil || updatedAt < 0 {
		return errors.New("invalid redacted application")
	}
	if expectedApplicationID != "" && id != expectedApplicationID {
		return errors.New("redacted application identifier mismatch")
	}
	if submittedAt := bytes.TrimSpace(application["submittedAt"]); !bytes.Equal(submittedAt, []byte("null")) {
		var value int64
		if json.Unmarshal(submittedAt, &value) != nil || value < 0 {
			return errors.New("invalid redacted application submission time")
		}
	}
	return validateRedactedReviewAnswers(application["reviewAnswers"])
}

func validateRedactedReviewAnswers(raw json.RawMessage) error {
	var answers map[string]json.RawMessage
	if err := json.Unmarshal(raw, &answers); err != nil || answers == nil {
		return errors.New("invalid redacted application review answers")
	}
	for key, value := range answers {
		if limit, ok := redactedReviewArrayLimits[key]; ok {
			var items []string
			if json.Unmarshal(value, &items) != nil || items == nil || len(items) > limit {
				return errors.New("invalid redacted application review answer")
			}
			continue
		}
		if _, ok := redactedReviewStringKeys[key]; !ok {
			return errors.New("unexpected redacted application review answer")
		}
		var text string
		if json.Unmarshal(value, &text) != nil {
			return errors.New("invalid redacted application review answer")
		}
	}
	return nil
}

func validRedactedApplicationStatus(status string) bool {
	switch status {
	case "submitted", "under_review", "accepted", "waitlisted", "rejected", "withdrawn":
		return true
	default:
		return false
	}
}

func validReviewRecommendation(recommendation string) bool {
	switch recommendation {
	case "accept", "waitlist", "reject", "needs_discussion":
		return true
	default:
		return false
	}
}

func closedJSONObject(raw json.RawMessage, allowed map[string]struct{}, required []string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errors.New("expected JSON object")
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return nil, errors.New("unexpected JSON property")
		}
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return nil, errors.New("missing JSON property")
		}
	}
	return object, nil
}

func (h *DreamUPAdminHandlers) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, app.ErrInvalidRequest):
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "请求内容无效。", nil)
	case errors.Is(err, app.ErrAuthenticationRequired):
		writeError(w, r, http.StatusUnauthorized, "authentication_required", "登录状态已过期，请重新登录。", nil)
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
