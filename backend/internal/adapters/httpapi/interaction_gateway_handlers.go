//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Authorization Interaction Gateway HTTP handler: GET /_interaction/login routing and 302 outcomes
//

package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

// InteractionGatewayPort is the narrow gateway seam this handler consumes
// (AGENTS.md §8). Route executes one arrival and never returns a bare
// callback URL — the outcome stays redacted until the Location header is
// written (ADR-0005 §3, §11).
type InteractionGatewayPort interface {
	Route(ctx context.Context, authRequestID string, sess *consent.DecisionSession, credentials consent.ProviderSessionCredentialReader) (consent.GatewayAction, error)
}

// InteractionGatewayHandlers serves GET /_interaction/login — the sole
// entry point ZITADEL generates for LoginV2 clients (ADR-0005 §1, §12). It
// runs behind OptionalSession: prompt=none must be executable without a
// session, while silent completion needs the authenticated one. The
// handler renders no UI; every outcome is a 302 or the fixed local failure
// page, and every response carries no-store + no-referrer (§11).
type InteractionGatewayHandlers struct {
	gateway   InteractionGatewayPort
	decrypter ProviderSessionCredentialDecrypter
	logger    *slog.Logger
}

// NewInteractionGatewayHandlers builds the gateway handler. The decrypter
// is only ever used to construct the per-request credential reader for a
// silent Allow (ADR-0005 §3).
func NewInteractionGatewayHandlers(
	gateway InteractionGatewayPort,
	decrypter ProviderSessionCredentialDecrypter,
	logger *slog.Logger,
) *InteractionGatewayHandlers {
	return &InteractionGatewayHandlers{gateway: gateway, decrypter: decrypter, logger: logger}
}

// interactionFailurePage is the fixed local failure page (ADR-0005 §12):
// no request input is ever reflected into it.
const interactionFailurePage = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>授权无法继续</title>
</head>
<body style="font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #f6f7f9; color: #1f2937;">
<div style="text-align: center; padding: 2rem;">
<h1 style="font-size: 1.25rem;">授权无法继续</h1>
<p>该授权请求无效或已失效。请返回应用重新发起授权。</p>
</div>
</body>
</html>
`

// InteractionLogin routes one provider-generated interaction entry. The
// authRequest parameter is validated strictly: the raw query is parsed
// with error propagation (r.URL.Query() would silently drop ParseQuery
// failures), exactly one occurrence is accepted, and the decoded value
// must fit the opaque-ID limits (ADR-0005 §2).
func (h *InteractionGatewayHandlers) InteractionLogin(w http.ResponseWriter, r *http.Request) {
	// §11: every gateway response is uncacheable and referrer-less.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		h.writeLocalFailure(w, consent.LocalFailureBadRequest)
		return
	}
	ids := values["authRequest"]
	if len(ids) != 1 {
		h.writeLocalFailure(w, consent.LocalFailureBadRequest)
		return
	}
	authRequestID := ids[0]
	if consent.ValidateAuthRequestID(authRequestID) != nil {
		h.writeLocalFailure(w, consent.LocalFailureBadRequest)
		return
	}

	// Optional session: present for silent completion candidates, absent
	// for the prompt=none login_required branch.
	var sess *consent.DecisionSession
	var credentials consent.ProviderSessionCredentialReader
	if principal, ok := PrincipalFromContext(r.Context()); ok {
		if record, ok := SessionRecordFromContext(r.Context()); ok {
			sess = &consent.DecisionSession{
				UserID:             principal.UserID,
				AuthenticationTime: principal.AuthenticationTime,
				SessionID:          principal.SessionID,
			}
			credentials = NewSessionCredentialReader(record, h.decrypter)
		}
	}

	action, err := h.gateway.Route(r.Context(), authRequestID, sess, credentials)
	if err != nil {
		h.logger.Error("interaction gateway routing failed",
			"requestId", request.ID(r.Context()),
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		h.writeLocalFailure(w, consent.LocalFailureInternal)
		return
	}

	switch action.Kind {
	case consent.ActionRedirectLogin:
		http.Redirect(w, r, "/login?"+requestIDQuery(authRequestID), http.StatusFound)
	case consent.ActionRedirectAuthorize:
		http.Redirect(w, r, "/authorize?"+requestIDQuery(authRequestID), http.StatusFound)
	case consent.ActionProviderCallback:
		// The provider callback URL is credential-grade: it appears only
		// in the Location header — never in logs, bodies or audit
		// (ADR-0005 §3, §11).
		w.Header().Set("Location", action.Outcome.RedirectURL())
		w.WriteHeader(http.StatusFound)
	default:
		h.writeLocalFailure(w, action.Failure)
	}
}

// requestIDQuery encodes the opaque auth request ID as the requestId query
// parameter through url.Values — never string concatenation.
func requestIDQuery(authRequestID string) string {
	return url.Values{"requestId": {authRequestID}}.Encode()
}

// writeLocalFailure renders the fixed local failure page with the status
// selected by the failure kind. The page never reflects request input.
func (h *InteractionGatewayHandlers) writeLocalFailure(w http.ResponseWriter, failure consent.LocalFailureKind) {
	status := http.StatusInternalServerError
	switch failure {
	case consent.LocalFailureBadRequest:
		status = http.StatusBadRequest
	case consent.LocalFailureExpired:
		status = http.StatusGone
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(interactionFailurePage))
}
