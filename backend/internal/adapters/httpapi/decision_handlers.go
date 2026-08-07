//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: HTTP handlers for the consent decision endpoints (allow/deny)
//

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// Stable decision error codes (frozen surface classes, ADR-0005 §3, §5,
// §8). The callback URL of a successful decision is exposed exclusively
// as redirectUrl and consumed via same-window navigation (ADR-0005 §11).
const (
	CodeRequestExpired        = "authorization.request_expired"
	CodeRequestAlreadyDecided = "authorization.request_already_decided"
	CodeCredentialRequired    = "authorization.session_credential_required"
	CodeUserNotEligible       = "authorization.user_not_eligible"
)

// ConsentDecisionService executes one interactive consent decision end to
// end. The consent.DecisionService satisfies it; the interface is defined
// here (close to the consumer) per AGENTS.md §8. The credential reader
// travels per request: decryption is keyed by the currently valid session
// of THIS request and released after use (ADR-0005 §3).
type ConsentDecisionService interface {
	Decide(ctx context.Context, input consent.DecisionInput, credentials consent.ProviderSessionCredentialReader) (consent.DecisionOutcome, error)
}

// ProviderSessionCredentialDecrypter decrypts sealed provider session
// credentials. The session service satisfies it; only the decision path
// ever receives an implementation (ADR-0005 §3).
type ProviderSessionCredentialDecrypter interface {
	DecryptProviderSessionCredential(ctx context.Context, encrypted session.EncryptedProviderSessionCredential) (session.ProviderSessionCredential, error)
}

// AuthorizationDecisionHandlers serves the frozen decision endpoint:
// POST /api/v1/authorization/requests/{requestId}/decision. The route
// runs behind RequireSession + RequireCSRF; the response carries
// no-store through the global security headers and the callback URL is
// returned exclusively as the frozen redirectUrl field (ADR-0005 §11).
type AuthorizationDecisionHandlers struct {
	decider   ConsentDecisionService
	decrypter ProviderSessionCredentialDecrypter
	logger    *slog.Logger
}

// NewAuthorizationDecisionHandlers builds the decision handler.
func NewAuthorizationDecisionHandlers(
	decider ConsentDecisionService,
	decrypter ProviderSessionCredentialDecrypter,
	logger *slog.Logger,
) *AuthorizationDecisionHandlers {
	return &AuthorizationDecisionHandlers{decider: decider, decrypter: decrypter, logger: logger}
}

// decisionRequestJSON is the frozen request body: {"decision":"allow"|"deny"}.
type decisionRequestJSON struct {
	Decision string `json:"decision"`
}

// decisionResponseJSON is the frozen success body: the provider-verified
// callback URL as redirectUrl. Deny also completes through the provider
// and therefore returns the access_denied callback URL, never a local
// fallback page (contract: OAuth 授权与同意).
type decisionResponseJSON struct {
	RedirectURL string `json:"redirectUrl"`
}

// sessionRecordCredentialReader binds the credential read to the session
// record authenticated on THIS request: the sealed credential is taken
// from the record placed by RequireSession, and only after the requested
// session ID matches it. Credentials of any other session are never
// reachable through this seam (ADR-0005 §3).
type sessionRecordCredentialReader struct {
	record    session.SessionRecord
	decrypter ProviderSessionCredentialDecrypter
}

// NewSessionCredentialReader builds the per-request credential reader for
// one authenticated session record.
func NewSessionCredentialReader(record session.SessionRecord, decrypter ProviderSessionCredentialDecrypter) consent.ProviderSessionCredentialReader {
	return sessionRecordCredentialReader{record: record, decrypter: decrypter}
}

// ReadProviderSessionCredential implements
// consent.ProviderSessionCredentialReader. A missing or mismatched
// session binding fails closed as a missing credential; legacy sessions
// (no sealed credential) surface the missing sentinel so the decision
// flow routes the user agent into re-login (ADR-0005 §3).
func (r sessionRecordCredentialReader) ReadProviderSessionCredential(
	ctx context.Context,
	sessionID session.SessionID,
) (session.ProviderSessionCredential, error) {
	if sessionID == "" || sessionID != r.record.SessionID {
		return session.ProviderSessionCredential{}, session.ErrProviderSessionCredentialMissing
	}
	if r.record.ProviderSessionCredential == "" {
		return session.ProviderSessionCredential{}, session.ErrProviderSessionCredentialMissing
	}
	return r.decrypter.DecryptProviderSessionCredential(ctx, r.record.ProviderSessionCredential)
}

// DecideRequest handles POST /api/v1/authorization/requests/{requestId}/decision.
// The handler never trusts the earlier resolution GET: the decision
// service re-enforces every condition server-side before any provider
// call (ADR-0005 §5, §12).
func (h *AuthorizationDecisionHandlers) DecideRequest(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	if err := consent.ValidateAuthRequestID(requestID); err != nil {
		WriteBadRequest(w, r, "授权请求标识无效。")
		return
	}

	var body decisionRequestJSON
	if err := decodeDecisionBody(r, &body); err != nil {
		WriteBadRequest(w, r, "授权决定请求格式无效。")
		return
	}
	kind := consent.DecisionKind(body.Decision)
	if !kind.Valid() {
		WriteBadRequest(w, r, "授权决定取值无效。")
		return
	}

	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}
	record, ok := SessionRecordFromContext(r.Context())
	if !ok {
		WriteUnauthorized(w, r)
		return
	}

	outcome, err := h.decider.Decide(r.Context(), consent.DecisionInput{
		AuthRequestID: requestID,
		Decision:      kind,
		Session: &consent.DecisionSession{
			UserID:             principal.UserID,
			AuthenticationTime: principal.AuthenticationTime,
			SessionID:          principal.SessionID,
		},
	}, NewSessionCredentialReader(record, h.decrypter))
	if err != nil {
		h.writeDecisionError(w, r, err)
		return
	}

	writeJSONNoStore(w, r, http.StatusOK, decisionResponseJSON{RedirectURL: outcome.RedirectURL()})
}

// decodeDecisionBody reads the JSON body exactly once, rejecting unknown
// fields and any trailing content after the first JSON value (a
// state-changing endpoint must parse strictly); the body size is already
// bounded by the global MaxBodyBytes middleware.
func decodeDecisionBody(r *http.Request, body *decisionRequestJSON) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(body); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("httpapi: unexpected trailing JSON after decision body")
	}
	return nil
}

// writeDecisionError maps decision failures onto stable HTTP outcomes.
// Only stable classes ever reach logs and responses — never raw provider
// detail or the callback URL (ADR-0005 §8, §11).
func (h *AuthorizationDecisionHandlers) writeDecisionError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, consent.ErrResolutionNotInteractive):
		writeError(w, r, http.StatusBadRequest, CodeInteractionNotSupported,
			"该授权请求无法通过当前交互方式继续。", nil)
		return
	case errors.Is(err, consent.ErrDecisionCredentialRequired):
		// Legacy or unusable provider session credential: the flow fails
		// closed into interactive re-login, which upgrades the credential
		// to Version 2 (ADR-0005 §3).
		writeError(w, r, http.StatusUnauthorized, CodeCredentialRequired,
			"请重新登录后继续授权。", nil)
		return
	case errors.Is(err, consent.ErrDecisionRequestExpired):
		writeError(w, r, http.StatusGone, CodeRequestExpired,
			"该授权请求已失效，请从应用重新发起授权。", nil)
		return
	case errors.Is(err, consent.ErrDecisionAlreadyDecided):
		writeError(w, r, http.StatusConflict, CodeRequestAlreadyDecided,
			"该授权请求已被处理，请从应用重新发起授权。", nil)
		return
	}

	if class, ok := consent.ErrorClassOf(err); ok {
		switch class {
		case consent.ClassUserNotEligible:
			writeError(w, r, http.StatusForbidden, CodeUserNotEligible,
				"当前账户无权完成该授权。", nil)
		case consent.ClassProviderUnavailable, consent.ClassRateLimited:
			WriteProviderUnavailable(w, r)
		default:
			h.logger.Error("authorization decision provider failure",
				"requestId", request.ID(r.Context()),
				"errorClass", string(class),
			)
			WriteInternalError(w, r)
		}
		return
	}

	h.logger.Error("authorization decision failed",
		"requestId", request.ID(r.Context()),
		"errorClass", observability.ClassifyError(err),
		"errorDetail", observability.RedactedError(err, 256),
	)
	WriteInternalError(w, r)
}
