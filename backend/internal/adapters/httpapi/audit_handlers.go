//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 7 audit search and export HTTP API
//

package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/audit"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type AuditHandlers struct {
	service     *audit.Service
	permissions permissions.Resolver
	reauth      ReauthVerifier
}

func NewAuditHandlers(service *audit.Service, resolver permissions.Resolver, reauth ReauthVerifier) *AuditHandlers {
	return &AuditHandlers{service: service, permissions: resolver, reauth: reauth}
}

func (h *AuditHandlers) authorize(w http.ResponseWriter, r *http.Request, export bool) (session.Principal, bool) {
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
	granted := caps.AuditRead
	if export {
		granted = caps.AuditExport
	}
	if !granted {
		action := "audit.read"
		if export {
			action = "audit.export"
		}
		h.service.RecordAuthorizationDenied(context.WithoutCancel(r.Context()), principal.UserID, action, request.ID(r.Context()))
		WriteForbidden(w, r)
		return session.Principal{}, false
	}
	return principal, true
}

func parseAuditQuery(r *http.Request) (audit.Query, error) {
	query := audit.Query{Cursor: r.URL.Query().Get("cursor"), Query: r.URL.Query().Get("query"), EventType: r.URL.Query().Get("eventType"), Result: r.URL.Query().Get("result"), ActorName: r.URL.Query().Get("actorName"), RequestID: r.URL.Query().Get("requestId")}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return query, audit.ErrValidation
		}
		query.Limit = value
	}
	for key, target := range map[string]**time.Time{"from": &query.From, "to": &query.To} {
		if raw := r.URL.Query().Get(key); raw != "" {
			value, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return query, audit.ErrValidation
			}
			*target = &value
		}
	}
	return query, audit.ValidateQuery(query)
}

func (h *AuditHandlers) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, false); !ok {
		return
	}
	query, err := parseAuditQuery(r)
	if err != nil {
		WriteBadRequest(w, r, "审计筛选参数不正确。")
		return
	}
	page, err := h.service.List(r.Context(), query)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, cursorResponse[audit.Event]{Items: page.Items, Page: cursorPageResponse{NextCursor: nullableString(page.NextCursor), HasMore: page.HasMore}})
}

func (h *AuditHandlers) CreateExport(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r, true)
	if !ok {
		return
	}
	var query audit.Query
	if err := decodeJSONBody(w, r, &query, "create audit export"); err != nil {
		return
	}
	if !h.requireReauth(w, r, principal) {
		return
	}
	result, err := h.service.CreateExport(r.Context(), principal.UserID, request.ID(r.Context()), query)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, result)
}

func exportIDParam(r *http.Request) (audit.ExportID, bool) {
	value := chi.URLParam(r, "exportId")
	return audit.ExportID(value), len(value) > 12 && len(value) < 80 && value[:4] == "exp_"
}

func (h *AuditHandlers) GetExport(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r, true)
	if !ok {
		return
	}
	id, valid := exportIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	result, err := h.service.GetExport(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if result.ActorID != principal.UserID {
		WriteNotFound(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, result)
}

func (h *AuditHandlers) Download(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r, true)
	if !ok {
		return
	}
	id, valid := exportIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	metadata, err := h.service.GetExport(r.Context(), id)
	if err != nil || metadata.ActorID != principal.UserID {
		WriteNotFound(w, r)
		return
	}
	content, err := h.service.Download(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-%s.csv"`, id))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (h *AuditHandlers) requireReauth(w http.ResponseWriter, r *http.Request, principal session.Principal) bool {
	if h.reauth == nil {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	if err := h.reauth.VerifyAndConsume(r.Context(), r.Header.Get("X-Reauthentication-Token"), auth.ReauthActionAuditExport, string(principal.SessionID), "audit", "", ""); err != nil {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	return true
}
func (h *AuditHandlers) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, audit.ErrNotFound):
		WriteNotFound(w, r)
	case errors.Is(err, audit.ErrValidation):
		WriteBadRequest(w, r, "审计筛选参数不正确。")
	case errors.Is(err, audit.ErrNotReady):
		writeError(w, r, http.StatusConflict, CodeConflict, "导出任务尚未完成。", nil)
	case errors.Is(err, audit.ErrExpired):
		WriteNotFound(w, r)
	default:
		WriteInternalError(w, r)
	}
}
