//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 7 policy management HTTP API
//

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type PolicyHandlers struct {
	service     *policies.Service
	permissions permissions.Resolver
	reauth      ReauthVerifier
}

func NewPolicyHandlers(service *policies.Service, resolver permissions.Resolver, reauth ReauthVerifier) *PolicyHandlers {
	return &PolicyHandlers{service: service, permissions: resolver, reauth: reauth}
}

func (h *PolicyHandlers) authorize(w http.ResponseWriter, r *http.Request, capability string) (session.Principal, bool) {
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
	granted := (capability == "read" && caps.PolicyRead) || (capability == "manage" && caps.PolicyManage) || (capability == "publish" && caps.PolicyPublish)
	if !granted {
		h.service.RecordAuthorizationDenied(context.WithoutCancel(r.Context()), principal.UserID, "policy."+capability, request.ID(r.Context()))
		WriteForbidden(w, r)
		return session.Principal{}, false
	}
	return principal, true
}

func policyIDParam(r *http.Request) (policies.PolicyID, bool) {
	value := chi.URLParam(r, "policyId")
	return policies.PolicyID(value), policies.HasPolicyIDPrefix(value)
}

func (h *PolicyHandlers) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, "read"); !ok {
		return
	}
	query := policies.ListQuery{Cursor: r.URL.Query().Get("cursor"), Query: r.URL.Query().Get("query"), Status: policies.Status(r.URL.Query().Get("status"))}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			WriteBadRequest(w, r, "limit 参数不正确。")
			return
		}
		query.Limit = limit
	}
	page, err := h.service.List(r.Context(), query)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, cursorResponse[policies.Summary]{Items: page.Items, Page: cursorPageResponse{NextCursor: nullableString(page.NextCursor), HasMore: page.HasMore}})
}

func (h *PolicyHandlers) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := policyIDParam(r)
	if !ok {
		WriteNotFound(w, r)
		return
	}
	if _, ok := h.authorize(w, r, "read"); !ok {
		return
	}
	detail, err := h.service.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, detail)
}

func (h *PolicyHandlers) Create(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r, "manage")
	if !ok {
		return
	}
	var input policies.DraftInput
	if err := decodeJSONBody(w, r, &input, "create policy"); err != nil {
		return
	}
	id, version, err := h.service.Create(r.Context(), principal.UserID, input)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusCreated, map[string]any{"policyId": id, "version": version})
}

type policyUpdateRequest struct {
	ExpectedVersion int               `json:"expectedVersion"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Resource        string            `json:"resource"`
	Action          string            `json:"action"`
	Effect          policies.Effect   `json:"effect"`
	Principals      []policies.Clause `json:"principals"`
	Conditions      []policies.Clause `json:"conditions"`
}

func (h *PolicyHandlers) Update(w http.ResponseWriter, r *http.Request) {
	id, valid := policyIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, "manage")
	if !ok {
		return
	}
	var input policyUpdateRequest
	if err := decodeJSONBody(w, r, &input, "update policy"); err != nil {
		return
	}
	version, err := h.service.Update(r.Context(), principal.UserID, id, input.ExpectedVersion, policies.DraftInput{Name: input.Name, Description: input.Description, Resource: input.Resource, Action: input.Action, Effect: input.Effect, Principals: input.Principals, Conditions: input.Conditions})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]any{"policyId": id, "version": version})
}

type policyPublishRequest struct {
	Version int `json:"version"`
}

func (h *PolicyHandlers) Publish(w http.ResponseWriter, r *http.Request) {
	id, valid := policyIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	principal, ok := h.authorize(w, r, "publish")
	if !ok {
		return
	}
	var input policyPublishRequest
	if err := decodeJSONBody(w, r, &input, "publish policy"); err != nil {
		return
	}
	if !h.requireReauth(w, r, principal, auth.ReauthActionPolicyPublish, string(id)) {
		return
	}
	version, err := h.service.Publish(r.Context(), principal.UserID, id, input.Version, request.ID(r.Context()))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, map[string]any{"version": version})
}

func (h *PolicyHandlers) Simulate(w http.ResponseWriter, r *http.Request) {
	id, valid := policyIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	if _, ok := h.authorize(w, r, "read"); !ok {
		return
	}
	var input policies.SimulationInput
	if err := decodeJSONBody(w, r, &input, "simulate policy"); err != nil {
		return
	}
	result, err := h.service.Simulate(r.Context(), id, input)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, result)
}

func (h *PolicyHandlers) Versions(w http.ResponseWriter, r *http.Request) {
	id, valid := policyIDParam(r)
	if !valid {
		WriteNotFound(w, r)
		return
	}
	if _, ok := h.authorize(w, r, "read"); !ok {
		return
	}
	detail, err := h.service.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, detail.VersionHistory)
}

func (h *PolicyHandlers) requireReauth(w http.ResponseWriter, r *http.Request, principal session.Principal, action, target string) bool {
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

func (h *PolicyHandlers) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, policies.ErrNotFound):
		WriteNotFound(w, r)
	case errors.Is(err, policies.ErrValidation):
		WriteValidation(w, r, "策略参数校验失败。", nil)
	case errors.Is(err, policies.ErrConflict), errors.Is(err, policies.ErrDuplicateName):
		writeError(w, r, http.StatusConflict, CodeConflict, "策略版本或名称发生冲突，请刷新后重试。", nil)
	case errors.Is(err, policies.ErrPublisher):
		WriteProviderUnavailable(w, r)
	default:
		WriteInternalError(w, r)
	}
}
