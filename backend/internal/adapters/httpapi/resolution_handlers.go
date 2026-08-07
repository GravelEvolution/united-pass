//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: HTTP handlers for the authorization request resolution endpoint
//

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

// CodeInteractionNotSupported: the auth request cannot proceed through
// the interactive consent UI (prompt=create, prompt=select_account, an
// invalid prompt combination, or prompt=none without a silently reusable
// grant). The interaction gateway owns those executions (ADR-0005 §9, §12).
const CodeInteractionNotSupported = "authorization.interaction_not_supported"

// ConsentResolutionService derives the ConsentResolution for one auth
// request side-effect free. The consent.ResolutionService satisfies it; it
// is defined here (close to the consumer) per AGENTS.md §8.
type ConsentResolutionService interface {
	Resolve(ctx context.Context, input consent.ResolutionInput) (consent.Resolution, error)
}

// AuthorizationHandlers serves the frozen consent-resolution endpoint:
// GET /api/v1/authorization/requests/{requestId}. The handler never
// claims operations, never calls provider completions, never writes
// grants and never writes audit rows — resolution is derived on read
// (ADR-0005 §2, §12).
type AuthorizationHandlers struct {
	resolver ConsentResolutionService
	logger   *slog.Logger
}

// NewAuthorizationHandlers builds the resolution handler.
func NewAuthorizationHandlers(resolver ConsentResolutionService, logger *slog.Logger) *AuthorizationHandlers {
	return &AuthorizationHandlers{resolver: resolver, logger: logger}
}

// ConsentResolution JSON shapes mirror the frozen frontend union exactly
// (frontend/src/features/authorization/types.ts); no new members may be
// introduced (ADR-0005 §12).
type (
	consentScopeJSON struct {
		Scope       string `json:"scope"`
		Label       string `json:"label"`
		Description string `json:"description"`
	}

	consentRequestJSON struct {
		RequestID              string             `json:"requestId"`
		ApplicationName        string             `json:"applicationName"`
		ApplicationDescription string             `json:"applicationDescription"`
		ApplicationOwner       string             `json:"applicationOwner"`
		RedirectHost           string             `json:"redirectHost"`
		Scopes                 []consentScopeJSON `json:"scopes"`
	}

	consentValidJSON struct {
		Status  string             `json:"status"`
		Request consentRequestJSON `json:"request"`
	}

	consentExpiredJSON struct {
		Status    string `json:"status"`
		RequestID string `json:"requestId"`
		ExpiredAt string `json:"expiredAt"`
	}

	consentClientNotFoundJSON struct {
		Status    string `json:"status"`
		RequestID string `json:"requestId"`
	}

	consentRedirectMismatchJSON struct {
		Status            string `json:"status"`
		RequestID         string `json:"requestId"`
		AttemptedRedirect string `json:"attemptedRedirect"`
	}

	consentUnauthenticatedJSON struct {
		Status    string `json:"status"`
		RequestID string `json:"requestId"`
	}

	consentScopeNotAllowedJSON struct {
		Status           string   `json:"status"`
		RequestID        string   `json:"requestId"`
		DisallowedScopes []string `json:"disallowedScopes"`
	}

	consentAlreadyAuthorizedJSON struct {
		Status          string `json:"status"`
		RequestID       string `json:"requestId"`
		ApplicationName string `json:"applicationName"`
		RedirectHost    string `json:"redirectHost"`
	}
)

// ResolveRequest handles GET /api/v1/authorization/requests/{requestId}.
// The route runs behind OptionalSession: an absent or invalid session
// resolves to the unauthenticated outcome instead of a 401, matching the
// frozen union. The response carries no-store through the global security
// headers (ADR-0005 §11).
func (h *AuthorizationHandlers) ResolveRequest(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	if err := consent.ValidateAuthRequestID(requestID); err != nil {
		WriteBadRequest(w, r, "授权请求标识无效。")
		return
	}

	input := consent.ResolutionInput{AuthRequestID: requestID}
	if principal, ok := PrincipalFromContext(r.Context()); ok {
		input.Session = &consent.ResolutionSession{
			UserID:             principal.UserID,
			AuthenticationTime: principal.AuthenticationTime,
		}
	}

	resolution, err := h.resolver.Resolve(r.Context(), input)
	if err != nil {
		h.writeResolutionError(w, r, err)
		return
	}

	body, ok := consentResolutionJSON(resolution)
	if !ok {
		// Unreachable: the service only returns known statuses. Fail
		// closed rather than serialize an unknown union member.
		WriteInternalError(w, r)
		return
	}
	writeJSONNoStore(w, r, http.StatusOK, body)
}

// consentResolutionJSON maps the domain resolution onto the frozen
// frontend union. It reports false for unknown statuses.
func consentResolutionJSON(res consent.Resolution) (any, bool) {
	switch res.Status {
	case consent.ResolutionValid:
		scopes := make([]consentScopeJSON, 0, len(res.Scopes))
		for _, scope := range res.Scopes {
			scopes = append(scopes, consentScopeJSON{
				Scope:       scope.Scope,
				Label:       scope.Label,
				Description: scope.Description,
			})
		}
		return consentValidJSON{
			Status: string(res.Status),
			Request: consentRequestJSON{
				RequestID:              res.AuthRequestID,
				ApplicationName:        res.ApplicationName,
				ApplicationDescription: res.ApplicationDescription,
				ApplicationOwner:       res.ApplicationOwner,
				RedirectHost:           res.RedirectHost,
				Scopes:                 scopes,
			},
		}, true
	case consent.ResolutionExpired:
		return consentExpiredJSON{
			Status:    string(res.Status),
			RequestID: res.AuthRequestID,
			ExpiredAt: res.ExpiredAt.UTC().Format(time.RFC3339),
		}, true
	case consent.ResolutionClientNotFound:
		return consentClientNotFoundJSON{Status: string(res.Status), RequestID: res.AuthRequestID}, true
	case consent.ResolutionRedirectMismatch:
		return consentRedirectMismatchJSON{
			Status:            string(res.Status),
			RequestID:         res.AuthRequestID,
			AttemptedRedirect: res.AttemptedRedirectHost,
		}, true
	case consent.ResolutionUnauthenticated:
		return consentUnauthenticatedJSON{Status: string(res.Status), RequestID: res.AuthRequestID}, true
	case consent.ResolutionScopeNotAllowed:
		disallowed := res.DisallowedScopes
		if disallowed == nil {
			disallowed = []string{}
		}
		return consentScopeNotAllowedJSON{
			Status:           string(res.Status),
			RequestID:        res.AuthRequestID,
			DisallowedScopes: disallowed,
		}, true
	case consent.ResolutionAlreadyAuthorized:
		return consentAlreadyAuthorizedJSON{
			Status:          string(res.Status),
			RequestID:       res.AuthRequestID,
			ApplicationName: res.ApplicationName,
			RedirectHost:    res.RedirectHost,
		}, true
	default:
		return nil, false
	}
}

// writeResolutionError maps resolution failures to stable HTTP outcomes.
// Provider transport failures surface as provider unavailable; unsupported
// interaction modes surface as a stable 400; everything else is the safe
// internal fallback. Stable classes only ever reach logs and responses —
// never raw provider detail (ADR-0005 §8).
func (h *AuthorizationHandlers) writeResolutionError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, consent.ErrResolutionNotInteractive) {
		writeError(w, r, http.StatusBadRequest, CodeInteractionNotSupported,
			"该授权请求无法通过当前交互方式继续。", nil)
		return
	}

	if class, ok := consent.ErrorClassOf(err); ok {
		switch class {
		case consent.ClassProviderUnavailable, consent.ClassRateLimited:
			WriteProviderUnavailable(w, r)
		default:
			h.logger.Error("authorization resolution provider failure",
				"requestId", request.ID(r.Context()),
				"errorClass", string(class),
			)
			WriteInternalError(w, r)
		}
		return
	}

	if errors.Is(err, identity.ErrUserNotFound) {
		// A user that disappeared mid-resolution degrades to the anonymous
		// outcome inside the frozen union; a 401 error body would escape
		// the ConsentResolution contract. OptionalSession normally already
		// downgrades such sessions, so this is defense in depth for future
		// seams.
		writeJSONNoStore(w, r, http.StatusOK, consentUnauthenticatedJSON{
			Status:    string(consent.ResolutionUnauthenticated),
			RequestID: chi.URLParam(r, "requestId"),
		})
		return
	}

	h.logger.Error("authorization resolution failed",
		"requestId", request.ID(r.Context()),
		"errorClass", observability.ClassifyError(err),
		"errorDetail", observability.RedactedError(err, 256),
	)
	WriteInternalError(w, r)
}
