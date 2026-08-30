package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type identityAccessServiceStub struct {
	createInput identityaccess.CreateRequestInput
	decideInput identityaccess.DecideInput
	claimInput  identityaccess.ClaimInput
}

func (s *identityAccessServiceStub) CreateRequest(_ context.Context, input identityaccess.CreateRequestInput) (identityaccess.CreateRequestResult, error) {
	s.createInput = input
	now := time.Date(2026, 8, 17, 8, 0, 0, 0, time.UTC)
	return identityaccess.CreateRequestResult{Request: identityaccess.Request{ID: "iar_1", EventID: input.EventID, RequesterID: input.ActorID, TargetType: input.Target.Type, TargetID: input.Target.ID, Fields: input.Fields, Status: identityaccess.StatusPending, ReasonID: "reason_secret", Version: 1, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}}, nil
}

func (s *identityAccessServiceStub) Decide(_ context.Context, input identityaccess.DecideInput) (identityaccess.DecideResult, error) {
	s.decideInput = input
	return identityaccess.DecideResult{Request: identityaccess.Request{ID: input.AccessRequestID, EventID: input.EventID, Status: identityaccess.StatusApproved, Version: 2}, Grant: &identityaccess.Grant{ID: "iag_secret", Version: 1, Authorization: identityaccess.GrantAuthorization{FieldSetHash: "secret_hash"}}}, nil
}

func (s *identityAccessServiceStub) Claim(_ context.Context, input identityaccess.ClaimInput) (identityaccess.ClaimResult, error) {
	s.claimInput = input
	return identityaccess.ClaimResult{Claim: identityaccess.Claim{GrantID: input.GrantID, ClaimNonce: "never-in-browser", FieldSetHash: "never-in-browser", Version: 2}}, nil
}

func (s *identityAccessServiceStub) ListOwn(context.Context, identity.UserID, adminpagination.Query) (identityaccess.Page, error) {
	return identityaccess.Page{}, nil
}
func (s *identityAccessServiceStub) ListApprovalQueue(context.Context, identity.UserID, adminpagination.Query) (identityaccess.Page, error) {
	return identityaccess.Page{}, nil
}
func (s *identityAccessServiceStub) GetOwn(context.Context, identity.UserID, string, string) (identityaccess.Request, error) {
	return identityaccess.Request{ID: "iar_1", Status: identityaccess.StatusPending, Version: 1}, nil
}
func (s *identityAccessServiceStub) GetForApproval(context.Context, identity.UserID, string, string) (identityaccess.Request, error) {
	return identityaccess.Request{ID: "iar_1", Status: identityaccess.StatusPending, Version: 1}, nil
}

type identityAccessReauthStub struct{ data auth.ReauthGrantData }

func (s identityAccessReauthStub) VerifyAndConsumeData(_ context.Context, _, _, _, _ string, _ applications.ApplicationID, _ applications.OAuthClientID) (auth.ReauthGrantData, error) {
	return s.data, nil
}

func withIdentityAccessSession(r *http.Request, user identity.UserID) *http.Request {
	principal := session.Principal{UserID: user, SessionID: "session_1"}
	record := session.SessionRecord{UserID: user, SessionID: "session_1"}
	ctx := WithPrincipal(r.Context(), principal)
	ctx = WithSessionRecord(ctx, record)
	return r.WithContext(ctx)
}

func TestIdentityAccessCreateRequiresSessionAndSameOriginAndDoesNotExposeReason(t *testing.T) {
	service := &identityAccessServiceStub{}
	handler := NewIdentityAccessHandlers(service, nil, "https://pass.example.test", nil)
	router := chi.NewRouter()
	router.Post("/admin/events/{eventId}/identity-access/requests", handler.Create)
	body := `{"targetType":"application","targetId":"app_1","fields":["legal_name"],"reason":"为了核对选手身份，确认现场签到信息与报名材料保持一致。"}`

	unauth := httptest.NewRequest(http.MethodPost, "/admin/events/evt_shanghai/identity-access/requests", strings.NewReader(body))
	unauth.Header.Set("Origin", "https://pass.example.test")
	unauth.Header.Set("Idempotency-Key", "abcdefghijklmnopqrstuvwxyzABCDEF")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, unauth)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	wrongOrigin := withIdentityAccessSession(httptest.NewRequest(http.MethodPost, "/admin/events/evt_shanghai/identity-access/requests", strings.NewReader(body)), "senior")
	wrongOrigin.Header.Set("Origin", "https://evil.example")
	wrongOrigin.Header.Set("Idempotency-Key", "abcdefghijklmnopqrstuvwxyzABCDEF")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, wrongOrigin)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("origin status=%d", recorder.Code)
	}

	request := withIdentityAccessSession(httptest.NewRequest(http.MethodPost, "/admin/events/evt_shanghai/identity-access/requests", strings.NewReader(body)), "senior")
	request.Header.Set("Origin", "https://pass.example.test")
	request.Header.Set("Idempotency-Key", "abcdefghijklmnopqrstuvwxyzABCDEF")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "reason") || strings.Contains(recorder.Body.String(), "核对选手") {
		t.Fatalf("reason leaked: %s", recorder.Body.String())
	}
	if service.createInput.ActorID != "senior" || service.createInput.EventID != "evt_shanghai" {
		t.Fatalf("input=%+v", service.createInput)
	}
}

func TestIdentityAccessApproveConsumesTargetBoundStepUpAndClaimResponseIsOpaque(t *testing.T) {
	service := &identityAccessServiceStub{}
	reauth := identityAccessReauthStub{data: auth.ReauthGrantData{GrantID: "reauth_1", UserID: "super", SessionID: "session_1", Action: auth.ReauthActionAdminOAApproval, Target: "iar_1", ChallengeVersion: 4, CreatedAt: time.Now().UTC()}}
	handler := NewIdentityAccessHandlers(service, reauth, "https://pass.example.test", nil)
	router := chi.NewRouter()
	router.Post("/admin/events/{eventId}/identity-access/requests/{requestId}/approve", handler.Approve)
	router.Post("/admin/events/{eventId}/identity-access/grants/{grantId}/claim", handler.Claim)

	approve := withIdentityAccessSession(httptest.NewRequest(http.MethodPost, "/admin/events/evt_shanghai/identity-access/requests/iar_1/approve", strings.NewReader(`{"fields":["legal_name"]}`)), "super")
	approve.Header.Set("Origin", "https://pass.example.test")
	approve.Header.Set("Idempotency-Key", "bcdefghijklmnopqrstuvwxyzABCDEFG")
	approve.Header.Set("If-Match", `"1"`)
	approve.Header.Set("X-Reauthentication-Token", "opaque")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, approve)
	if recorder.Code != http.StatusOK {
		t.Fatalf("approve=%d %s", recorder.Code, recorder.Body.String())
	}
	if service.decideInput.StepUp.GrantID != "reauth_1" || service.decideInput.AccessRequestID != "iar_1" {
		t.Fatalf("decision=%+v", service.decideInput)
	}
	if strings.Contains(recorder.Body.String(), "iag_secret") || strings.Contains(recorder.Body.String(), "secret_hash") {
		t.Fatalf("grant internals leaked: %s", recorder.Body.String())
	}

	claim := withIdentityAccessSession(httptest.NewRequest(http.MethodPost, "/admin/events/evt_shanghai/identity-access/grants/iag_1/claim", nil), "senior")
	claim.Header.Set("Origin", "https://pass.example.test")
	claim.Header.Set("Idempotency-Key", "cdefghijklmnopqrstuvwxyzABCDEFGH")
	claim.Header.Set("If-Match", `"1"`)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, claim)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("claim=%d %s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(recorder.Body.String(), "never-in-browser") || response["claimNonce"] != nil {
		t.Fatalf("claim leaked: %s", recorder.Body.String())
	}
}
