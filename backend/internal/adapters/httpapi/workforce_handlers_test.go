//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 5 workforce HTTP authorization and target-bound reauth tests
//

package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

type workforceHTTPRepository struct {
	workforce.Repository
	statusMutation *workforce.UserStatusMutation
	offboardUser   identity.UserID
	deniedEvents   int
}

func (r *workforceHTTPRepository) ChangeUserStatus(_ context.Context, mutation workforce.UserStatusMutation) (*workforce.AccessRevocationJob, error) {
	r.statusMutation = &mutation
	return nil, nil
}

func (r *workforceHTTPRepository) OffboardEmployee(_ context.Context, _ identity.UserID, userID identity.UserID, _ string) (workforce.EmployeeProfile, workforce.AccessRevocationJob, error) {
	r.offboardUser = userID
	return workforce.EmployeeProfile{UserID: userID, Status: workforce.EmployeeStatusOffboarding},
		workforce.AccessRevocationJob{JobID: "arj_test", UserID: userID}, nil
}

func (r *workforceHTTPRepository) ResolveAccessRevocation(context.Context, workforce.AccessRevocationJob, int, string) error {
	return nil
}

func (r *workforceHTTPRepository) FailAccessRevocation(context.Context, workforce.AccessRevocationJob, string) error {
	return nil
}

func (r *workforceHTTPRepository) RecordAuthorizationDenied(context.Context, identity.UserID, string, string, string, string, string) error {
	r.deniedEvents++
	return nil
}

type workforceHTTPRevoker struct{}

func (workforceHTTPRevoker) RevokeUserSessionByAdmin(context.Context, identity.UserID, string) (string, error) {
	return "", nil
}

func (workforceHTTPRevoker) RevokeAllUserSessionsByAdmin(context.Context, identity.UserID) (int, string, error) {
	return 1, "", nil
}

type targetReauthVerifier struct {
	wantToken   string
	action      string
	sessionID   string
	target      string
	consumeCall int
}

func (v *targetReauthVerifier) VerifyAndConsume(_ context.Context, token, action, sessionID, target string, appID applications.ApplicationID, clientID applications.OAuthClientID) error {
	v.consumeCall++
	v.action, v.sessionID, v.target = action, sessionID, target
	if token != v.wantToken || appID != "" || clientID != "" {
		return errors.New("binding mismatch")
	}
	return nil
}

func newWorkforceHandlerForTest(repo *workforceHTTPRepository, caps permissions.Capabilities, reauth ReauthVerifier) *WorkforceHandlers {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service := workforce.NewService(repo, workforceHTTPRevoker{}, logger)
	return NewWorkforceHandlers(service, &stubPermResolver{caps: caps}, reauth, nil, logger)
}

func workforceRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithPrincipal(req.Context(), session.Principal{
		UserID: "user_actor", SessionID: "session_actor",
	})
	ctx = request.WithID(ctx, "req_workforce_test")
	return req.WithContext(ctx)
}

func routeWorkforceRequest(req *http.Request, pattern string) *http.Request {
	routeContext := chi.NewRouteContext()
	parts := strings.Split(strings.Trim(pattern, "/"), "/")
	actual := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	for index, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") && index < len(actual) {
			routeContext.URLParams.Add(strings.Trim(part, "{}"), actual[index])
		}
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))
}

func TestDisableUserRequiresTargetBoundReauthentication(t *testing.T) {
	repo := &workforceHTTPRepository{}
	verifier := &targetReauthVerifier{wantToken: "reauth-good"}
	handler := newWorkforceHandlerForTest(repo, permissions.AllCapabilities(), verifier)
	req := routeWorkforceRequest(
		workforceRequest(http.MethodPost, "/admin/users/user_target/disable", `{"revokeSessions":true}`),
		"/admin/users/{userId}/disable")
	rec := httptest.NewRecorder()
	handler.DisableUser(rec, req)
	if rec.Code != http.StatusForbidden || repo.statusMutation != nil {
		t.Fatalf("without grant status=%d mutation=%+v, want 403/no mutation", rec.Code, repo.statusMutation)
	}

	verifier = &targetReauthVerifier{wantToken: "reauth-good"}
	handler = newWorkforceHandlerForTest(repo, permissions.AllCapabilities(), verifier)
	req = routeWorkforceRequest(
		workforceRequest(http.MethodPost, "/admin/users/user_target/disable", `{"revokeSessions":true}`),
		"/admin/users/{userId}/disable")
	req.Header.Set("X-Reauthentication-Token", "reauth-good")
	rec = httptest.NewRecorder()
	handler.DisableUser(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("with grant status=%d body=%s", rec.Code, rec.Body.String())
	}
	if verifier.action != auth.ReauthActionUserDisable || verifier.target != "user_target" || verifier.sessionID != "session_actor" {
		t.Fatalf("reauth binding action=%q target=%q session=%q", verifier.action, verifier.target, verifier.sessionID)
	}
	if repo.statusMutation == nil || repo.statusMutation.TargetUserID != "user_target" || !repo.statusMutation.RevokeSessions {
		t.Fatalf("status mutation = %+v", repo.statusMutation)
	}
}

func TestOffboardingUsesIndependentCapabilityAndTargetBinding(t *testing.T) {
	repo := &workforceHTTPRepository{}
	caps := permissions.NoCapabilities()
	caps.EmployeeOffboard = true
	verifier := &targetReauthVerifier{wantToken: "reauth-offboard"}
	handler := newWorkforceHandlerForTest(repo, caps, verifier)
	req := routeWorkforceRequest(
		workforceRequest(http.MethodPost, "/admin/users/user_employee/offboarding", `{}`),
		"/admin/users/{userId}/offboarding")
	req.Header.Set("X-Reauthentication-Token", "reauth-offboard")
	rec := httptest.NewRecorder()
	handler.OffboardEmployee(rec, req)
	if rec.Code != http.StatusAccepted || repo.offboardUser != "user_employee" {
		t.Fatalf("status=%d offboardUser=%q body=%s", rec.Code, repo.offboardUser, rec.Body.String())
	}
	if verifier.action != auth.ReauthActionEmployeeOffboard || verifier.target != "user_employee" {
		t.Fatalf("offboard grant action=%q target=%q", verifier.action, verifier.target)
	}
}

func TestWorkforceCapabilityDenialIsAuditedAndDoesNotMutate(t *testing.T) {
	repo := &workforceHTTPRepository{}
	handler := newWorkforceHandlerForTest(repo, permissions.NoCapabilities(), nil)
	req := routeWorkforceRequest(
		workforceRequest(http.MethodPost, "/admin/users/user_target/disable", `{"revokeSessions":false}`),
		"/admin/users/{userId}/disable")
	rec := httptest.NewRecorder()
	handler.DisableUser(rec, req)
	if rec.Code != http.StatusForbidden || repo.statusMutation != nil || repo.deniedEvents != 1 {
		t.Fatalf("status=%d mutation=%+v denied=%d", rec.Code, repo.statusMutation, repo.deniedEvents)
	}
}
