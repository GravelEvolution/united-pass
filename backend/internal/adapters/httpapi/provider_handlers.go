//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 6 Provider administration HTTP API
//

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/providers"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type providerCapability int

const (
	providerRead providerCapability = iota
	providerManage
)

type ProviderHandlers struct {
	service     *providers.Service
	permissions permissions.Resolver
	reauth      ReauthVerifier
	logger      *slog.Logger
}

func NewProviderHandlers(service *providers.Service, resolver permissions.Resolver, reauth ReauthVerifier, logger *slog.Logger) *ProviderHandlers {
	return &ProviderHandlers{service: service, permissions: resolver, reauth: reauth, logger: logger}
}

func (h *ProviderHandlers) authorize(w http.ResponseWriter, r *http.Request, required providerCapability, targetKey, targetID, eventType, operation string) (session.Principal, bool) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return session.Principal{}, false
	}
	caps, err := h.permissions.Resolve(r.Context(), principal.UserID)
	if err != nil {
		WriteInternalError(w, r)
		return session.Principal{}, false
	}
	if (required == providerRead && !caps.ProviderRead) || (required == providerManage && !caps.ProviderManage) {
		h.service.RecordAuthorizationDenied(context.WithoutCancel(r.Context()), principal.UserID,
			targetKey, targetID, eventType, operation, request.ID(r.Context()))
		WriteForbidden(w, r)
		return session.Principal{}, false
	}
	return principal, true
}

func providerIDParam(r *http.Request) (providers.ProviderID, bool) {
	value := chi.URLParam(r, "providerId")
	return providers.ProviderID(value), providers.HasProviderIDPrefix(value)
}

func conflictIDParam(r *http.Request) (providers.ConflictID, bool) {
	value := chi.URLParam(r, "conflictId")
	return providers.ConflictID(value), providers.HasConflictIDPrefix(value)
}

func (h *ProviderHandlers) ListProviders(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, providerRead, "", "", "", "provider.list"); !ok {
		return
	}
	query := providers.ListQuery{Cursor: r.URL.Query().Get("cursor"), Query: r.URL.Query().Get("query"), Status: r.URL.Query().Get("status")}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			WriteBadRequest(w, r, "limit 参数必须为 1 至 100 的整数。")
			return
		}
		query.Limit = limit
	}
	page, err := h.service.ListProviders(r.Context(), query)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	items := make([]providerSummaryResponse, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, toProviderSummaryResponse(item))
	}
	writeJSONNoStore(w, r, http.StatusOK, cursorResponse[providerSummaryResponse]{Items: items, Page: cursorPageResponse{NextCursor: nullableString(page.NextCursor), HasMore: page.HasMore}})
}

type providerSummaryResponse struct {
	ProviderID       string    `json:"providerId"`
	DisplayName      string    `json:"displayName"`
	Vendor           string    `json:"vendor"`
	IntegrationLabel string    `json:"integrationLabel"`
	Status           string    `json:"status"`
	LoginEnabled     bool      `json:"loginEnabled"`
	LinkedUserCount  int       `json:"linkedUserCount"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

func toProviderSummaryResponse(item providers.ProviderSummary) providerSummaryResponse {
	return providerSummaryResponse{ProviderID: string(item.ProviderID), DisplayName: item.DisplayName, Vendor: item.Vendor, IntegrationLabel: item.IntegrationLabel, Status: string(item.Status), LoginEnabled: item.LoginEnabled, LinkedUserCount: item.LinkedUserCount, UpdatedAt: item.UpdatedAt}
}

func (h *ProviderHandlers) GetProvider(w http.ResponseWriter, r *http.Request) {
	providerID, ok := providerIDParam(r)
	if !ok {
		WriteNotFound(w, r)
		return
	}
	if _, ok := h.authorize(w, r, providerRead, "provider_id", string(providerID), "", "provider.read"); !ok {
		return
	}
	detail, err := h.service.GetProvider(r.Context(), providerID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, toProviderDetailResponse(detail))
}

type providerDetailResponse struct {
	providerSummaryResponse
	AppID            string                 `json:"appId"`
	SecretConfigured bool                   `json:"secretConfigured"`
	CallbackURL      string                 `json:"callbackUrl"`
	ContactScope     string                 `json:"contactScope"`
	LastValidatedAt  *time.Time             `json:"lastValidatedAt"`
	LastSyncAt       *time.Time             `json:"lastSyncAt"`
	LastSyncResult   *directorySyncResponse `json:"lastSyncResult"`
}

func toProviderDetailResponse(detail providers.ProviderDetail) providerDetailResponse {
	response := providerDetailResponse{providerSummaryResponse: toProviderSummaryResponse(detail.ProviderSummary), AppID: detail.AppID, SecretConfigured: detail.SecretConfigured, CallbackURL: detail.CallbackURL, ContactScope: detail.ContactScope, LastValidatedAt: detail.LastValidatedAt, LastSyncAt: detail.LastSyncAt}
	if detail.LastSyncResult != nil {
		value := toDirectorySyncResponse(*detail.LastSyncResult)
		response.LastSyncResult = &value
	}
	return response
}

func (h *ProviderHandlers) EnableProvider(w http.ResponseWriter, r *http.Request) {
	h.setEnabled(w, r, true)
}
func (h *ProviderHandlers) DisableProvider(w http.ResponseWriter, r *http.Request) {
	h.setEnabled(w, r, false)
}

func (h *ProviderHandlers) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	providerID, valid := providerIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	eventType := providers.EventProviderDisabled
	if enabled {
		eventType = providers.EventProviderEnabled
	}
	principal, ok := h.authorize(w, r, providerManage, "provider_id", string(providerID), eventType, "provider.state.update")
	if !ok {
		return
	}
	action := auth.ReauthActionProviderDisable
	if enabled {
		action = auth.ReauthActionProviderEnable
	}
	if !h.requireReauth(w, r, principal, action, string(providerID)) {
		return
	}
	detail, err := h.service.SetProviderEnabled(r.Context(), principal.UserID, providerID, enabled, request.ID(r.Context()))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, toProviderDetailResponse(detail))
}

func (h *ProviderHandlers) StartDirectorySync(w http.ResponseWriter, r *http.Request) {
	providerID, valid := providerIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, providerManage, "provider_id", string(providerID), providers.EventDirectorySyncRequested, "provider.directory.sync")
	if !ok {
		return
	}
	job, err := h.service.EnqueueSync(r.Context(), principal.UserID, providerID, request.ID(r.Context()))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, toDirectorySyncResponse(job))
}

func (h *ProviderHandlers) ListSyncHistory(w http.ResponseWriter, r *http.Request) {
	providerID, valid := providerIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	if _, ok := h.authorize(w, r, providerRead, "provider_id", string(providerID), "", "provider.directory.history"); !ok {
		return
	}
	items, err := h.service.ListSyncHistory(r.Context(), providerID, 25)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	response := make([]syncHistoryResponse, 0, len(items))
	for _, item := range items {
		response = append(response, syncHistoryResponse{directorySyncResponse: toDirectorySyncResponse(item.SyncJob), Summary: item.Summary})
	}
	writeJSONNoStore(w, r, http.StatusOK, response)
}

type directorySyncResponse struct {
	SyncID              string     `json:"syncId"`
	ProviderID          string     `json:"providerId"`
	StartedAt           time.Time  `json:"startedAt"`
	CompletedAt         *time.Time `json:"completedAt"`
	Status              string     `json:"status"`
	DepartmentsAdded    int        `json:"departmentsAdded"`
	DepartmentsUpdated  int        `json:"departmentsUpdated"`
	EmployeesAdded      int        `json:"employeesAdded"`
	EmployeesUpdated    int        `json:"employeesUpdated"`
	EmployeesOffboarded int        `json:"employeesOffboarded"`
	ConflictsDetected   int        `json:"conflictsDetected"`
}

func toDirectorySyncResponse(job providers.SyncJob) directorySyncResponse {
	return directorySyncResponse{SyncID: string(job.SyncID), ProviderID: string(job.ProviderID), StartedAt: job.StartedAt, CompletedAt: job.CompletedAt, Status: string(job.Status), DepartmentsAdded: job.DepartmentsAdded, DepartmentsUpdated: job.DepartmentsUpdated, EmployeesAdded: job.EmployeesAdded, EmployeesUpdated: job.EmployeesUpdated, EmployeesOffboarded: job.EmployeesOffboarded, ConflictsDetected: job.ConflictsDetected}
}

type syncHistoryResponse struct {
	directorySyncResponse
	Summary string `json:"summary"`
}

func (h *ProviderHandlers) ListConflicts(w http.ResponseWriter, r *http.Request) {
	providerID, valid := providerIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	if _, ok := h.authorize(w, r, providerRead, "provider_id", string(providerID), "", "provider.conflict.list"); !ok {
		return
	}
	items, err := h.service.ListConflicts(r.Context(), providerID, 100)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	response := make([]syncConflictResponse, 0, len(items))
	for _, item := range items {
		response = append(response, toSyncConflictResponse(item))
	}
	writeJSONNoStore(w, r, http.StatusOK, response)
}

type syncConflictResponse struct {
	ConflictID      string    `json:"conflictId"`
	ProviderID      string    `json:"providerId"`
	ExternalSubject string    `json:"externalSubject"`
	ExternalName    string    `json:"externalName"`
	ExternalEmail   string    `json:"externalEmail"`
	MatchedUserID   *string   `json:"matchedUserId"`
	MatchedUserName *string   `json:"matchedUserName"`
	MatchReason     string    `json:"matchReason"`
	Status          string    `json:"status"`
	DetectedAt      time.Time `json:"detectedAt"`
}

func toSyncConflictResponse(item providers.SyncConflict) syncConflictResponse {
	return syncConflictResponse{ConflictID: string(item.ConflictID), ProviderID: string(item.ProviderID), ExternalSubject: item.ExternalSubject, ExternalName: item.ExternalName, ExternalEmail: item.ExternalEmail, MatchedUserID: nullableString(string(item.MatchedUserID)), MatchedUserName: nullableString(item.MatchedUserName), MatchReason: string(item.MatchReason), Status: string(item.Status), DetectedAt: item.DetectedAt}
}

type resolveConflictRequest struct {
	UserID string `json:"userId"`
}

func (h *ProviderHandlers) ResolveConflict(w http.ResponseWriter, r *http.Request) {
	conflictID, valid := conflictIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, providerManage, "conflict_id", string(conflictID), providers.EventIdentityConflictResolved, "provider.identity.link")
	if !ok {
		return
	}
	if !h.requireReauth(w, r, principal, auth.ReauthActionProviderIdentityLink, string(conflictID)) {
		return
	}
	var body resolveConflictRequest
	if err := decodeJSONBody(w, r, &body, "resolve provider conflict"); err != nil {
		return
	}
	if body.UserID == "" || len(body.UserID) > 128 {
		WriteBadRequest(w, r, "userId 格式不正确。")
		return
	}
	if err := h.service.ResolveConflict(r.Context(), principal.UserID, conflictID, identity.UserID(body.UserID), request.ID(r.Context())); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ProviderHandlers) IgnoreConflict(w http.ResponseWriter, r *http.Request) {
	conflictID, valid := conflictIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, providerManage, "conflict_id", string(conflictID), providers.EventIdentityConflictIgnored, "provider.identity.ignore")
	if !ok {
		return
	}
	if err := h.service.IgnoreConflict(r.Context(), principal.UserID, conflictID, request.ID(r.Context())); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ProviderHandlers) requireReauth(w http.ResponseWriter, r *http.Request, principal session.Principal, action, target string) bool {
	if h.reauth == nil {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	if err := h.reauth.VerifyAndConsume(r.Context(), r.Header.Get("X-Reauthentication-Token"), action, string(principal.SessionID), target, "", ""); err != nil {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	return true
}

func (h *ProviderHandlers) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, providers.ErrNotFound):
		WriteNotFound(w, r)
	case errors.Is(err, providers.ErrInvalidInput):
		WriteBadRequest(w, r, "请求参数不正确。")
	case errors.Is(err, providers.ErrConflict), errors.Is(err, providers.ErrNotConfigured):
		writeError(w, r, http.StatusConflict, CodeConflict, "Provider 状态冲突或服务端凭据尚未配置。", nil)
	case errors.Is(err, providers.ErrProviderFailure):
		WriteProviderUnavailable(w, r)
	default:
		WriteInternalError(w, r)
	}
}
