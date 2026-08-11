//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 8 personal-data export, deletion and public legal status HTTP API
//

package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/privacy"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type PrivacyHandlers struct {
	service *privacy.Service
	reauth  ReauthVerifier
}

func NewPrivacyHandlers(service *privacy.Service, reauth ReauthVerifier) *PrivacyHandlers {
	return &PrivacyHandlers{service: service, reauth: reauth}
}

func (h *PrivacyHandlers) principal(w http.ResponseWriter, r *http.Request) (session.Principal, bool) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return session.Principal{}, false
	}
	return principal, true
}

func (h *PrivacyHandlers) requireReauth(w http.ResponseWriter, r *http.Request, principal session.Principal, action string) bool {
	if h.reauth == nil {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	if err := h.reauth.VerifyAndConsume(r.Context(), r.Header.Get("X-Reauthentication-Token"), action,
		string(principal.SessionID), string(principal.UserID), applications.ApplicationID(""), applications.OAuthClientID("")); err != nil {
		writeError(w, r, http.StatusForbidden, CodeReauthenticationReq, "该操作需要重新认证。", nil)
		return false
	}
	return true
}

func (h *PrivacyHandlers) BeginExport(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok || !h.requireReauth(w, r, principal, auth.ReauthActionPersonalDataExport) {
		return
	}
	result, err := h.service.BeginExport(r.Context(), principal.UserID, request.ID(r.Context()))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, result)
}

func personalExportID(r *http.Request) (privacy.ExportID, bool) {
	value := chi.URLParam(r, "exportId")
	return privacy.ExportID(value), len(value) > 17 && len(value) < 80 && len(value) >= 5 && value[:5] == "pexp_"
}

func (h *PrivacyHandlers) GetExport(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	id, valid := personalExportID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	result, err := h.service.GetExport(r.Context(), principal.UserID, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, result)
}

func (h *PrivacyHandlers) Download(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	id, valid := personalExportID(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	content, err := h.service.Download(r.Context(), principal.UserID, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="personal-data-%s.json"`, id))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

type noDeletionResponse struct {
	Status string `json:"status"`
}

func (h *PrivacyHandlers) GetDeletion(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	result, err := h.service.GetDeletion(r.Context(), principal.UserID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if result == nil {
		writeJSONNoStore(w, r, http.StatusOK, noDeletionResponse{Status: "none"})
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, result)
}

func (h *PrivacyHandlers) RequestDeletion(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok || !h.requireReauth(w, r, principal, auth.ReauthActionAccountDelete) {
		return
	}
	result, err := h.service.RequestDeletion(r.Context(), principal.UserID, request.ID(r.Context()))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusAccepted, result)
}

func (h *PrivacyHandlers) CancelDeletion(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	result, err := h.service.CancelDeletion(r.Context(), principal.UserID, request.ID(r.Context()))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, result)
}

func (h *PrivacyHandlers) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, privacy.ErrNotFound), errors.Is(err, privacy.ErrExpired):
		WriteNotFound(w, r)
	case errors.Is(err, privacy.ErrConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "当前账户已有冲突的隐私权利请求。", nil)
	case errors.Is(err, privacy.ErrNotReady):
		writeError(w, r, http.StatusConflict, CodeConflict, "数据导出尚未完成。", nil)
	case errors.Is(err, privacy.ErrValidation):
		WriteBadRequest(w, r, "请求参数不正确。")
	default:
		WriteInternalError(w, r)
	}
}

type LegalHandlers struct {
	service *privacy.Service
	now     func() time.Time
}

func NewLegalHandlers(service *privacy.Service) *LegalHandlers {
	return &LegalHandlers{service: service, now: func() time.Time { return time.Now().UTC() }}
}

type publicLegalPublication struct {
	DocumentKind  string    `json:"documentKind"`
	Version       string    `json:"version"`
	ContentSHA256 string    `json:"contentSha256"`
	EffectiveAt   time.Time `json:"effectiveAt"`
	PublishedAt   time.Time `json:"publishedAt"`
	Status        string    `json:"status"`
}

func (h *LegalHandlers) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.service.ListLegalPublications(r.Context())
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	result := make([]publicLegalPublication, 0, len(items))
	for _, item := range items {
		status := "scheduled"
		if !h.now().Before(item.EffectiveAt) {
			status = "effective"
		}
		result = append(result, publicLegalPublication{DocumentKind: item.DocumentKind,
			Version: item.Version, ContentSHA256: item.ContentSHA256, EffectiveAt: item.EffectiveAt,
			PublishedAt: item.PublishedAt, Status: status})
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]any{"items": result})
}
