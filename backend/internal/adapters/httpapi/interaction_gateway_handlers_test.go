//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the authorization interaction gateway handlers
//

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// stubGateway records the routing inputs and returns the canned action.
type stubGateway struct {
	action consent.GatewayAction
	err    error

	lastID        string
	lastSession   *consent.DecisionSession
	hadCredential bool
	calls         int
}

func (s *stubGateway) Route(_ context.Context, authRequestID string, sess *consent.DecisionSession, credentials consent.ProviderSessionCredentialReader) (consent.GatewayAction, error) {
	s.lastID = authRequestID
	s.lastSession = sess
	s.hadCredential = credentials != nil
	s.calls++
	return s.action, s.err
}

func newGatewayHandlers(gateway *stubGateway) *InteractionGatewayHandlers {
	return NewInteractionGatewayHandlers(gateway, &stubDecrypter{}, testLogger())
}

func gatewayRequest(t *testing.T, target string, injectSession bool) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	ctx := r.Context()
	if injectSession {
		ctx = WithPrincipal(ctx, session.Principal{
			UserID:             identity.UserID("user_gw"),
			AuthenticationTime: time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC),
			SessionID:          session.SessionID("up-session-gw"),
		})
		ctx = WithSessionRecord(ctx, session.SessionRecord{
			SessionID: session.SessionID("up-session-gw"),
			UserID:    identity.UserID("user_gw"),
		})
	}
	return r.WithContext(ctx)
}

func TestInteractionLoginRedirectsToLogin(t *testing.T) {
	gateway := &stubGateway{action: consent.GatewayAction{Kind: consent.ActionRedirectLogin}}
	rec := httptest.NewRecorder()

	newGatewayHandlers(gateway).InteractionLogin(rec, gatewayRequest(t, "/_interaction/login?authRequest=V2-abc", false))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login?requestId=V2-abc" {
		t.Fatalf("Location = %q", loc)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if gateway.lastID != "V2-abc" || gateway.lastSession != nil {
		t.Fatalf("routing input: %+v", gateway)
	}
}

func TestInteractionLoginRedirectsToAuthorize(t *testing.T) {
	gateway := &stubGateway{action: consent.GatewayAction{Kind: consent.ActionRedirectAuthorize}}
	rec := httptest.NewRecorder()

	newGatewayHandlers(gateway).InteractionLogin(rec, gatewayRequest(t, "/_interaction/login?authRequest=V2-abc", true))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/authorize?requestId=V2-abc" {
		t.Fatalf("Location = %q", loc)
	}
	if gateway.lastSession == nil || gateway.lastSession.UserID != "user_gw" ||
		gateway.lastSession.SessionID != session.SessionID("up-session-gw") {
		t.Fatalf("session not forwarded: %+v", gateway.lastSession)
	}
	if !gateway.hadCredential {
		t.Fatal("authenticated arrival must carry the per-request credential reader")
	}
}

func TestInteractionLoginForwardsProviderCallbackOnlyAsLocation(t *testing.T) {
	callback, err := consent.NewCallbackResult("https://rp.example/callback?code=secret-code&state=s1")
	if err != nil {
		t.Fatalf("NewCallbackResult: %v", err)
	}
	gateway := &stubGateway{action: consent.GatewayAction{
		Kind:    consent.ActionProviderCallback,
		Outcome: consent.NewDecisionOutcome(callback),
	}}
	rec := httptest.NewRecorder()

	newGatewayHandlers(gateway).InteractionLogin(rec, gatewayRequest(t, "/_interaction/login?authRequest=V2-abc", false))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://rp.example/callback?code=secret-code&state=s1" {
		t.Fatalf("Location = %q", loc)
	}
	// The credential-grade URL must not leak into the body.
	if strings.Contains(rec.Body.String(), "secret-code") {
		t.Fatal("callback URL leaked into the response body")
	}
}

func TestInteractionLoginLocalFailureStatuses(t *testing.T) {
	cases := []struct {
		failure consent.LocalFailureKind
		want    int
	}{
		{consent.LocalFailureBadRequest, http.StatusBadRequest},
		{consent.LocalFailureExpired, http.StatusGone},
		{consent.LocalFailureInternal, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		gateway := &stubGateway{action: consent.GatewayAction{Kind: consent.ActionLocalFailure, Failure: tc.failure}}
		rec := httptest.NewRecorder()
		newGatewayHandlers(gateway).InteractionLogin(rec, gatewayRequest(t, "/_interaction/login?authRequest=V2-abc", false))
		if rec.Code != tc.want {
			t.Fatalf("failure %v: status = %d, want %d", tc.failure, rec.Code, tc.want)
		}
		if !strings.Contains(rec.Body.String(), "授权无法继续") {
			t.Fatalf("failure %v: fixed page missing", tc.failure)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("failure %v: no-store missing", tc.failure)
		}
	}
}

func TestInteractionLoginRoutingErrorRendersInternalFailure(t *testing.T) {
	gateway := &stubGateway{err: errors.New("provider blew up")}
	rec := httptest.NewRecorder()

	newGatewayHandlers(gateway).InteractionLogin(rec, gatewayRequest(t, "/_interaction/login?authRequest=V2-abc", false))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestInteractionLoginStrictParameterValidation(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"missing parameter", "/_interaction/login"},
		{"duplicate parameter", "/_interaction/login?authRequest=V2-a&authRequest=V2-b"},
		{"empty value", "/_interaction/login?authRequest="},
		{"oversized value", "/_interaction/login?authRequest=" + strings.Repeat("a", consent.MaxAuthRequestIDLen+1)},
		{"malformed percent-encoding", "/_interaction/login?authRequest=%zz"},
		{"malformed plus duplicate cleaned", "/_interaction/login?authRequest=%zz&authRequest=V2-ok"},
		{"unterminated escape", "/_interaction/login?authRequest=%2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gateway := &stubGateway{}
			rec := httptest.NewRecorder()
			newGatewayHandlers(gateway).InteractionLogin(rec, gatewayRequest(t, tc.target, false))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if gateway.calls != 0 {
				t.Fatal("invalid parameter must never reach the gateway")
			}
		})
	}
}

func TestInteractionLoginEncodesRequestID(t *testing.T) {
	gateway := &stubGateway{action: consent.GatewayAction{Kind: consent.ActionRedirectLogin}}
	rec := httptest.NewRecorder()

	// Space (encoded as +) and ampersand in the opaque ID must survive as
	// encoded query.
	newGatewayHandlers(gateway).InteractionLogin(rec, gatewayRequest(t, "/_interaction/login?authRequest=V2-a+b%26c", false))

	if gateway.lastID != "V2-a b&c" {
		t.Fatalf("decoded id = %q", gateway.lastID)
	}
	if loc := rec.Header().Get("Location"); loc != "/login?requestId=V2-a+b%26c" {
		t.Fatalf("Location = %q", loc)
	}
}
