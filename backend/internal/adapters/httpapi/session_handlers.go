//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-08
// Description: Session inventory handlers (list and revoke own sessions)
//

package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// Session inventory error codes (ADR-0006 §2). They are stable and
// non-enumerating: 404 never distinguishes unknown, foreign or already-gone
// targets; 409 identifies the caller's own current session only.
const (
	CodeSessionNotFound = "session.not_found"
	CodeSessionCurrent  = "session.current"
)

// SessionHandlers serves the account-security session inventory
// (ADR-0006 §1/§2): listing the caller's live sessions and revoking other
// sessions. All routes are strictly current-user-scoped by the Principal
// placed by RequireSession; no user ID ever comes from the request.
type SessionHandlers struct {
	sessionSvc *session.Service
	logger     *slog.Logger
}

// NewSessionHandlers builds the session inventory handlers.
func NewSessionHandlers(sessionSvc *session.Service, logger *slog.Logger) *SessionHandlers {
	return &SessionHandlers{sessionSvc: sessionSvc, logger: logger}
}

// sessionView is the frozen wire shape of one inventory entry (ADR-0006 §3).
// ApproximateLocation is always null server-side (no GeoIP dependency);
// IsCurrent is computed from the caller's principal, never client-supplied.
type sessionView struct {
	SessionID             string    `json:"sessionId"`
	DeviceName            string    `json:"deviceName"`
	ClientName            string    `json:"clientName"`
	ApproximateLocation   *string   `json:"approximateLocation"`
	IPAddressMasked       string    `json:"ipAddressMasked"`
	LastActiveAt          time.Time `json:"lastActiveAt"`
	CreatedAt             time.Time `json:"createdAt"`
	AuthenticationMethods []string  `json:"authenticationMethods"`
	IsCurrent             bool      `json:"isCurrent"`
}

// ListSessions handles GET /api/v1/me/sessions. It returns the caller's live
// sessions as a JSON array of sessionView (200). Expired sessions are never
// listed; the current session is included and flagged isCurrent.
func (h *SessionHandlers) ListSessions(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	records, err := h.sessionSvc.ListUserSessions(r.Context(), principal.UserID)
	if err != nil {
		h.logger.Error("session list failed",
			"requestId", request.ID(r.Context()),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}

	views := make([]sessionView, 0, len(records))
	for i := range records {
		views = append(views, toSessionView(records[i], principal.SessionID))
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(views)
}

// RevokeSession handles DELETE /api/v1/me/sessions/{sessionId}. It revokes
// exactly one other session of the caller:
//   - 204 on success;
//   - 409 session.current when the target is the caller's current session;
//   - 404 session.not_found for unknown, foreign or already-gone targets
//     (the cases are intentionally indistinguishable).
//
// No reauthentication is required (session + CSRF is the gate, ADR-0006 §2).
func (h *SessionHandlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	targetID := session.SessionID(chi.URLParam(r, "sessionId"))
	if targetID == "" {
		writeError(w, r, http.StatusNotFound, CodeSessionNotFound, "会话不存在或已被撤销。", nil)
		return
	}

	err := h.sessionSvc.RevokeSession(r.Context(), principal.UserID, principal.SessionID, targetID)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, session.ErrSessionIsCurrent):
		writeError(w, r, http.StatusConflict, CodeSessionCurrent, "不能撤销当前会话，请使用退出登录。", nil)
	case errors.Is(err, session.ErrSessionNotFound):
		writeError(w, r, http.StatusNotFound, CodeSessionNotFound, "会话不存在或已被撤销。", nil)
	default:
		h.logger.Error("session revoke failed",
			"requestId", request.ID(r.Context()),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
	}
}

// RevokeAllOthers handles DELETE /api/v1/me/sessions. It revokes every other
// session of the caller; the current session is always preserved. The 200
// body carries the revoked count (204 must not carry a body, ADR-0006 §2).
func (h *SessionHandlers) RevokeAllOthers(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	count, err := h.sessionSvc.RevokeAllOtherSessions(r.Context(), principal.UserID, principal.SessionID)
	if err != nil {
		h.logger.Error("session revoke-all failed",
			"requestId", request.ID(r.Context()),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		WriteInternalError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		Revoked int `json:"revoked"`
	}{Revoked: count})
}

// toSessionView maps a record into the frozen wire shape. Display metadata is
// stored normalized at creation time; empty strings reach the frontend as-is
// and render as 未知… there.
func toSessionView(record session.SessionRecord, currentSessionID session.SessionID) sessionView {
	methods := make([]string, len(record.AuthenticationMethods))
	for i, m := range record.AuthenticationMethods {
		methods[i] = string(m)
	}
	return sessionView{
		SessionID:             string(record.SessionID),
		DeviceName:            record.DeviceDisplay,
		ClientName:            record.ClientDisplay,
		ApproximateLocation:   nil,
		IPAddressMasked:       record.IPAddressMasked,
		LastActiveAt:          record.LastSeenAt,
		CreatedAt:             record.CreatedAt,
		AuthenticationMethods: methods,
		IsCurrent:             record.SessionID == currentSessionID,
	}
}
