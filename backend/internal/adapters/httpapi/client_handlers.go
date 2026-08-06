package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

// Client handlers for the OAuth client management plane (ADR-0004 §7).
// They live on ApplicationHandlers so capability checks, error mapping and
// response rendering stay shared with the application endpoints.

// clientIDFromPath reads and shape-checks the clientId path parameter.
// Malformed IDs yield ok=false; callers respond 404 so resource existence is
// never revealed (anti-enumeration).
func clientIDFromPath(r *http.Request) (applications.OAuthClientID, bool) {
	raw := chi.URLParam(r, "clientId")
	if !applications.HasOAuthClientIDPrefix(raw) {
		return "", false
	}
	return applications.OAuthClientID(raw), true
}

// clientPathIDs extracts both path identifiers. Any shape-invalid ID is
// answered with the same 404 as a missing resource.
func clientPathIDs(w http.ResponseWriter, r *http.Request) (applications.ApplicationID, applications.OAuthClientID, bool) {
	appID, ok := applicationIDFromPath(r)
	if !ok {
		WriteNotFound(w, r)
		return "", "", false
	}
	clientID, ok := clientIDFromPath(r)
	if !ok {
		WriteNotFound(w, r)
		return "", "", false
	}
	return appID, clientID, true
}

type clientCreationResponse struct {
	ClientID string `json:"clientId"`
	// ClientSecret is present exactly once for confidential clients and is
	// never persisted; omitempty keeps it absent for public clients.
	ClientSecret string `json:"clientSecret,omitempty"`
}

// CreateClient handles POST /api/v1/admin/applications/{applicationId}/clients.
// The confidential secret is returned exactly once in the 201 response with
// Cache-Control: no-store.
func (h *ApplicationHandlers) CreateClient(w http.ResponseWriter, r *http.Request) {
	appID, ok := applicationIDFromPath(r)
	if !ok {
		WriteNotFound(w, r)
		return
	}
	actor, granted := h.checkCapability(w, r, true,
		applications.EventOAuthClientCreated, "client.create", appID)
	if !granted {
		return
	}

	var req clientCreateInput
	if err := decodeJSONBody(w, r, &req, "create client"); err != nil {
		return
	}

	clientIn := applications.ClientInput{
		Name:         req.Name,
		Profile:      applications.ClientProfile(req.Profile),
		RedirectURIs: req.RedirectURIs,
		LogoutURI:    req.LogoutURI,
		Scopes:       req.AllowedScopes,
		ConsentMode:  applications.ConsentMode(req.ConsentMode),
	}
	if err := applications.ValidateClientInput(clientIn); err != nil {
		WriteValidation(w, r, "请求参数校验失败。", prefixFieldErrors(err, ""))
		return
	}

	result, err := h.svc.CreateClient(r.Context(), actor, appID, request.ID(r.Context()), clientIn)
	if err != nil {
		h.writeMutationError(w, r, err, nil, "客户端名称已存在。")
		return
	}

	writeJSONNoStore(w, r, http.StatusCreated, clientCreationResponse{
		ClientID:     string(result.ClientID),
		ClientSecret: result.ClientSecret,
	})
}

// GetClient handles GET /api/v1/admin/applications/{applicationId}/clients/{clientId}.
// Secret values are never returned; only secret metadata is listed.
func (h *ApplicationHandlers) GetClient(w http.ResponseWriter, r *http.Request) {
	appID, clientID, ok := clientPathIDs(w, r)
	if !ok {
		return
	}
	if _, granted := h.checkCapability(w, r, false, "", "client.read", appID); !granted {
		return
	}

	client, err := h.svc.GetClient(r.Context(), appID, clientID)
	if err != nil {
		writeApplicationLookupError(w, r, err)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, clientJSON(client))
}

type clientUpdateRequest struct {
	Name          *string   `json:"name"`
	RedirectURIs  *[]string `json:"redirectUris"`
	LogoutURI     *string   `json:"logoutUri"`
	AllowedScopes *[]string `json:"allowedScopes"`
	ConsentMode   *string   `json:"consentMode"`
}

// UpdateClient handles PATCH /api/v1/admin/applications/{applicationId}/clients/{clientId}.
// The profile is immutable; redirect and logout URIs use exact-match
// semantics (no normalization, no wildcards).
func (h *ApplicationHandlers) UpdateClient(w http.ResponseWriter, r *http.Request) {
	appID, clientID, ok := clientPathIDs(w, r)
	if !ok {
		return
	}
	actor, granted := h.checkCapability(w, r, true,
		applications.EventOAuthClientUpdated, "client.update", appID)
	if !granted {
		return
	}

	var req clientUpdateRequest
	if err := decodeJSONBody(w, r, &req, "update client"); err != nil {
		return
	}
	if req.Name == nil && req.RedirectURIs == nil && req.LogoutURI == nil &&
		req.AllowedScopes == nil && req.ConsentMode == nil {
		WriteBadRequest(w, r, "至少需要提交一个更新字段。")
		return
	}

	patch := applications.ClientPatch{
		Name:          req.Name,
		RedirectURIs:  req.RedirectURIs,
		LogoutURI:     req.LogoutURI,
		AllowedScopes: req.AllowedScopes,
	}
	if req.ConsentMode != nil {
		mode := applications.ConsentMode(*req.ConsentMode)
		patch.ConsentMode = &mode
	}

	client, err := h.svc.UpdateClient(r.Context(), actor, appID, clientID, request.ID(r.Context()), patch)
	if err != nil {
		h.writeMutationError(w, r, err, nil, "客户端名称已存在。")
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, clientJSON(client))
}

// EnableClient handles POST /api/v1/admin/applications/{applicationId}/clients/{clientId}/enable.
func (h *ApplicationHandlers) EnableClient(w http.ResponseWriter, r *http.Request) {
	h.setClientStatus(w, r, true)
}

// DisableClient handles POST /api/v1/admin/applications/{applicationId}/clients/{clientId}/disable.
func (h *ApplicationHandlers) DisableClient(w http.ResponseWriter, r *http.Request) {
	h.setClientStatus(w, r, false)
}

func (h *ApplicationHandlers) setClientStatus(w http.ResponseWriter, r *http.Request, enable bool) {
	appID, clientID, ok := clientPathIDs(w, r)
	if !ok {
		return
	}
	eventType := applications.EventOAuthClientDisabled
	operation := "client.disable"
	if enable {
		eventType = applications.EventOAuthClientEnabled
		operation = "client.enable"
	}
	actor, granted := h.checkCapability(w, r, true, eventType, operation, appID)
	if !granted {
		return
	}

	client, err := h.svc.SetClientStatus(r.Context(), actor, appID, clientID, request.ID(r.Context()), enable)
	if err != nil {
		h.writeMutationError(w, r, err, nil, "客户端名称已存在。")
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, clientJSON(client))
}

// DeleteClient handles DELETE /api/v1/admin/applications/{applicationId}/clients/{clientId}.
// Deleting a client is a high-risk operation and requires a fresh
// reauthentication token (ADR-0004 §6.7).
func (h *ApplicationHandlers) DeleteClient(w http.ResponseWriter, r *http.Request) {
	appID, clientID, ok := clientPathIDs(w, r)
	if !ok {
		return
	}
	actor, granted := h.checkCapability(w, r, true,
		applications.EventOAuthClientDeleted, "client.delete", appID)
	if !granted {
		return
	}

	if !h.verifyReauthentication(w, r, actor, applications.EventOAuthClientDeleted, "client.delete", appID, clientID) {
		return
	}

	if err := h.svc.DeleteClient(r.Context(), actor, appID, clientID, request.ID(r.Context())); err != nil {
		h.writeMutationError(w, r, err, nil, "客户端名称已存在。")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type secretRotationResponse struct {
	SecretID string `json:"secretId"`
	// ClientSecret appears exactly once and is never persisted; the response
	// is no-store + no-cache (ADR-0004 §6).
	ClientSecret            string    `json:"clientSecret"`
	PreviousSecretExpiresAt time.Time `json:"previousSecretExpiresAt"`
}

// RotateClientSecret handles POST
// /api/v1/admin/applications/{applicationId}/clients/{clientId}/secret-rotations.
// It requires the applicationSecretRotate capability, passes the rotation
// rate limit and consumes a single-use reauthentication grant bound to
// exactly this action and client. The new secret is returned exactly once.
func (h *ApplicationHandlers) RotateClientSecret(w http.ResponseWriter, r *http.Request) {
	appID, clientID, ok := clientPathIDs(w, r)
	if !ok {
		return
	}

	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	caps, err := h.permResolver.Resolve(r.Context(), principal.UserID)
	if err != nil {
		WriteInternalError(w, r)
		return
	}
	if !caps.ApplicationSecretRotate {
		h.svc.RecordEvent(r.Context(), applications.EventSecretRotationFailed, principal.UserID, appID, clientID,
			request.ID(r.Context()), "client.secret.rotate", applications.SecurityEventDenied, "authorization")
		WriteForbidden(w, r)
		return
	}

	// Rotation rate limit keyed on IP + hashed client ID. Fail closed.
	if h.rotationRates == nil {
		WriteRateLimited(w, r, int(h.rotationWindow.Seconds()))
		return
	}
	allowed, retryAfter, err := h.rotationRates.CheckRotation(r.Context(), clientIP(r),
		hashIdentifier(string(clientID)), h.rotationLimit, h.rotationWindow)
	if err != nil {
		h.logger.Error("secret rotation rate limit check failed",
			"requestId", request.ID(r.Context()),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteRateLimited(w, r, int(h.rotationWindow.Seconds()))
		return
	}
	if !allowed {
		WriteRateLimited(w, r, int(retryAfter.Seconds()))
		return
	}

	if !h.verifyReauthentication(w, r, principal.UserID, applications.EventSecretRotationFailed,
		"client.secret.rotate", appID, clientID) {
		return
	}

	result, err := h.svc.RotateClientSecret(r.Context(), principal.UserID, appID, clientID, request.ID(r.Context()))
	if err != nil {
		h.writeRotationError(w, r, err)
		return
	}

	w.Header().Set("Pragma", "no-cache")
	writeJSONNoStore(w, r, http.StatusOK, secretRotationResponse{
		SecretID:                string(result.SecretID),
		ClientSecret:            result.ClientSecret,
		PreviousSecretExpiresAt: result.PreviousSecretExpiresAt.UTC(),
	})
}

// writeRotationError maps rotation use-case errors onto the frozen error
// contract. Public or non-active clients yield 422; concurrent rotations
// yield the standard 409.
func (h *ApplicationHandlers) writeRotationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, applications.ErrNotFound):
		WriteNotFound(w, r)
	case errors.Is(err, applications.ErrSecretRotationNotAllowed):
		WriteValidation(w, r, "请求参数校验失败。", []FieldError{{
			Field:   "clientId",
			Message: "该客户端不支持轮转 Secret（公开客户端无 Secret，非活跃客户端不允许变更）。",
		}})
	case errors.Is(err, applications.ErrInvalidStateTransition), errors.Is(err, applications.ErrConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "资源当前状态不允许该操作。", nil)
	case errors.Is(err, applications.ErrSecretRotationOutcomeUnknown):
		writeError(w, r, http.StatusConflict, CodeConflict, "上一次轮转结果未知（提供方响应超时），客户端已锁定待对账，请先完成对账再重试。", nil)
	case errors.Is(err, applications.ErrParentApplicationDisabled):
		writeError(w, r, http.StatusConflict, CodeConflict, "所属应用已停用，无法轮转客户端 Secret；请先启用应用。", nil)
	case errors.Is(err, applications.ErrProviderConflict):
		writeError(w, r, http.StatusConflict, CodeConflict, "身份提供方报告冲突，请稍后重试。", nil)
	case errors.Is(err, applications.ErrProviderUnavailable):
		WriteProviderUnavailable(w, r)
	default:
		WriteInternalError(w, r)
	}
}
