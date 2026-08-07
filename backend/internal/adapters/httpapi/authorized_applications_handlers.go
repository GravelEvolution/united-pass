package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

// CodeGrantNotFound: the grant does not exist or does not belong to the
// current user. Foreign and unknown grants are indistinguishable (no
// ownership enumeration, ADR-0005 §6).
const CodeGrantNotFound = "consent.grant_not_found"

// AuthorizedApplicationService serves the current user's authorized
// application list and the owner-bound grant revocation. The
// consent.GrantManagementService satisfies it; the interface is defined
// here (close to the consumer) per AGENTS.md §8.
type AuthorizedApplicationService interface {
	ListAuthorizedApplications(ctx context.Context, userID identity.UserID) ([]consent.AuthorizedApplication, error)
	RevokeGrant(ctx context.Context, userID identity.UserID, grantID consent.GrantID) error
}

// AuthorizedApplicationHandlers serves the frozen account endpoints:
// GET /api/v1/me/authorized-applications and
// DELETE /api/v1/me/authorized-applications/{grantId}. Both run behind
// RequireSession; the DELETE additionally passes RequireCSRF (safe
// methods skip the token check). Revocation is a purely local consent
// action: provider-issued tokens are not invalidated by United Pass and
// no such claim is made anywhere in the response (ADR-0005 §6).
type AuthorizedApplicationHandlers struct {
	svc    AuthorizedApplicationService
	logger *slog.Logger
}

// NewAuthorizedApplicationHandlers builds the authorized application
// handlers.
func NewAuthorizedApplicationHandlers(svc AuthorizedApplicationService, logger *slog.Logger) *AuthorizedApplicationHandlers {
	return &AuthorizedApplicationHandlers{svc: svc, logger: logger}
}

// authorizedApplicationJSON is one frozen row of the authorized
// application list (contract: AuthorizedApplication). lastUsedAt has no
// true signal on provider v2.71 and serializes as null (ADR-0005 §6);
// status is always "active" because the list is the live consent surface.
type authorizedApplicationJSON struct {
	GrantID          string   `json:"grantId"`
	ApplicationID    string   `json:"applicationId"`
	ApplicationName  string   `json:"applicationName"`
	ApplicationOwner string   `json:"applicationOwner"`
	ClientType       string   `json:"clientType"`
	GrantedAt        string   `json:"grantedAt"`
	LastUsedAt       *string  `json:"lastUsedAt"`
	Scopes           []string `json:"scopes"`
	HasOfflineAccess bool     `json:"hasOfflineAccess"`
	Status           string   `json:"status"`
}

// ListAuthorizedApplications handles GET /api/v1/me/authorized-applications.
func (h *AuthorizedApplicationHandlers) ListAuthorizedApplications(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	apps, err := h.svc.ListAuthorizedApplications(r.Context(), principal.UserID)
	if err != nil {
		h.logger.Error("authorized application listing failed",
			"errorClass", observability.ClassifyError(err),
		)
		WriteInternalError(w, r)
		return
	}

	out := make([]authorizedApplicationJSON, 0, len(apps))
	for _, app := range apps {
		out = append(out, authorizedApplicationJSON{
			GrantID:          string(app.GrantID),
			ApplicationID:    string(app.ApplicationID),
			ApplicationName:  app.ApplicationName,
			ApplicationOwner: app.ApplicationOwner,
			ClientType:       string(app.ClientType),
			GrantedAt:        app.GrantedAt.UTC().Format(time.RFC3339),
			LastUsedAt:       nil, // no true usage signal on provider v2.71 (ADR-0005 §6)
			Scopes:           app.Scopes,
			HasOfflineAccess: app.HasOfflineAccess,
			Status:           string(consent.GrantActive),
		})
	}
	writeJSONNoStore(w, r, http.StatusOK, out)
}

// RevokeGrant handles DELETE /api/v1/me/authorized-applications/{grantId}.
// Idempotent: repeat calls return the same stable 204 outcome (ADR-0005
// §6). The effect is local consent revocation only — the next
// authorization request for this client requires fresh consent; already
// issued tokens are not invalidated by United Pass.
func (h *AuthorizedApplicationHandlers) RevokeGrant(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	grantID := chi.URLParam(r, "grantId")
	if !consent.HasGrantIDPrefix(grantID) {
		writeError(w, r, http.StatusNotFound, CodeGrantNotFound,
			"未找到该应用授权。", nil)
		return
	}

	err := h.svc.RevokeGrant(r.Context(), principal.UserID, consent.GrantID(grantID))
	if err != nil {
		if errors.Is(err, consent.ErrGrantNotFound) {
			writeError(w, r, http.StatusNotFound, CodeGrantNotFound,
				"未找到该应用授权。", nil)
			return
		}
		h.logger.Error("grant revocation failed",
			"errorClass", observability.ClassifyError(err),
		)
		WriteInternalError(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
