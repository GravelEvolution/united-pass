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

	app "github.com/GravelEvolution/united-pass/backend/internal/dreamupadmin"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type dreamUPBFFServiceStub struct {
	input            app.ProxyRequest
	actor            app.Actor
	eligible         bool
	eligibilityCalls int
	events           []app.EventSummary
	response         *app.ProxyResponse
	status           app.MutationStatus
	statusEventID    string
	statusKey        string
	statusErr        error
}

func (s *dreamUPBFFServiceStub) Eligible(_ context.Context, actor app.Actor) (bool, error) {
	s.actor = actor
	s.eligibilityCalls++
	return s.eligible, nil
}

func (s *dreamUPBFFServiceStub) ListEvents(_ context.Context, actor app.Actor) ([]app.EventSummary, error) {
	s.actor = actor
	return s.events, nil
}

func (s *dreamUPBFFServiceStub) OperationStatus(_ context.Context, actor app.Actor, eventID, key string) (app.MutationStatus, error) {
	s.actor, s.statusEventID, s.statusKey = actor, eventID, key
	return s.status, s.statusErr
}

func (s *dreamUPBFFServiceStub) Proxy(_ context.Context, actor app.Actor, input app.ProxyRequest) (app.ProxyResponse, error) {
	s.actor, s.input = actor, input
	if s.response != nil {
		return *s.response, nil
	}
	return app.ProxyResponse{StatusCode: http.StatusOK, Body: json.RawMessage(`{"review":{"recommendation":"accept","note":"ok","version":2,"updatedAt":1}}`), RequestID: input.RequestID, ETag: `"2"`}, nil
}

func dreamUPBFFRouter(t *testing.T, service DreamUPAdminService) http.Handler {
	t.Helper()
	handler, err := NewDreamUPAdminHandlers(service, "https://moonstone.org.cn")
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Use(RequestID)
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := session.Principal{UserID: identity.UserID("user_1"), SessionID: "session_1", AuthenticationTime: time.Now().Add(-time.Minute)}
			record := session.SessionRecord{UserID: principal.UserID, SessionID: principal.SessionID, AuthenticationTime: principal.AuthenticationTime}
			next.ServeHTTP(w, r.WithContext(WithSessionRecord(WithPrincipal(r.Context(), principal), record)))
		})
	})
	router.Route("/api/v1/admin/dreamup", handler.Mount)
	return router
}

func TestDreamUPAdminHandlersMapFrozenReviewRouteExactly(t *testing.T) {
	service := &dreamUPBFFServiceStub{}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_1/reviews/me", strings.NewReader(`{"recommendation":"accept","note":"ok"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://moonstone.org.cn")
	req.Header.Set("Idempotency-Key", "0123456789abcdef0123456789abcdef")
	req.Header.Set("If-Match", `"1"`)
	req.Header.Set("X-Reauthentication-Token", strings.Repeat("R", 43))
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.EventID != "evt_shanghai" || service.input.ResourceID != "app_1" || service.input.Path != "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me" || service.input.Method != http.MethodPut || service.input.ReauthenticationToken != strings.Repeat("R", 43) {
		t.Fatalf("input=%+v", service.input)
	}
	if service.actor.UserID != "user_1" || service.actor.SessionID != "session_1" || service.actor.AuthenticationTransport != app.AuthenticationTransportBrowserCookie {
		t.Fatalf("actor=%+v", service.actor)
	}
}

func TestDreamUPAdminHandlersClassifyOnlyMatchedNativeMiniProgramTransport(t *testing.T) {
	tests := []struct {
		name          string
		nativeBearer  bool
		miniHeader    bool
		wantStatus    int
		wantTransport app.AuthenticationTransport
	}{
		{name: "cookie website", wantStatus: http.StatusOK, wantTransport: app.AuthenticationTransportBrowserCookie},
		{name: "native Mini Program", nativeBearer: true, miniHeader: true, wantStatus: http.StatusOK, wantTransport: app.AuthenticationTransportNativeMiniProgramBearer},
		{name: "native credential without Mini Program shape", nativeBearer: true, wantStatus: http.StatusUnauthorized},
		{name: "cookie request claiming Mini Program shape", miniHeader: true, wantStatus: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{}
			handler, err := NewDreamUPAdminHandlers(service, "https://moonstone.org.cn", true)
			if err != nil {
				t.Fatal(err)
			}
			router := chi.NewRouter()
			router.Use(RequestID)
			router.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					principal := session.Principal{UserID: "user_1", SessionID: "session_1", AuthenticationTime: time.Now().Add(-time.Minute)}
					record := session.SessionRecord{UserID: principal.UserID, SessionID: principal.SessionID, AuthenticationTime: principal.AuthenticationTime, ClientKind: session.ClientKindMiniProgram, SecurityEpoch: 6}
					ctx := WithSessionRecord(WithPrincipal(r.Context(), principal), record)
					if test.nativeBearer {
						ctx = WithNativeBearerSession(ctx)
					}
					next.ServeHTTP(w, r.WithContext(ctx))
				})
			})
			router.Route("/api/v1/admin/dreamup", handler.Mount)
			request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/content", nil)
			if test.miniHeader {
				request.Header.Set("X-UnitedPass-Client", session.ClientKindMiniProgram)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if test.wantStatus == http.StatusOK && (service.actor.AuthenticationTransport != test.wantTransport || service.actor.SecurityEpoch != 6) {
				t.Fatalf("actor=%+v", service.actor)
			}
			if test.wantStatus != http.StatusOK && service.input.EventID != "" {
				t.Fatalf("ambiguous transport reached service: %+v", service.input)
			}
		})
	}
}

func TestDreamUPAdminHandlersRejectCrossOriginMutationBeforeService(t *testing.T) {
	service := &dreamUPBFFServiceStub{}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_1/admission-consensus/approval", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Idempotency-Key", "0123456789abcdef0123456789abcdef")
	req.Header.Set("If-Match", `"1"`)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.EventID != "" {
		t.Fatal("cross-origin request reached service")
	}
}

func TestDreamUPAdminHandlersAllowBodylessApprovalWithdrawal(t *testing.T) {
	service := &dreamUPBFFServiceStub{}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_1/admission-consensus/approval", nil)
	req.Header.Set("Origin", "https://moonstone.org.cn")
	req.Header.Set("Idempotency-Key", "0123456789abcdef0123456789abcdef")
	req.Header.Set("If-Match", `"1"`)
	req.Header.Set("X-Reauthentication-Token", strings.Repeat("R", 43))
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.Method != http.MethodDelete || len(service.input.Body) != 0 || service.input.IfMatch != `"1"` {
		t.Fatalf("input=%+v", service.input)
	}
}

func TestDreamUPAdminHandlersTranslateBrowserDecisionPOSTToWorkerPATCH(t *testing.T) {
	service := &dreamUPBFFServiceStub{}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_1/decision", strings.NewReader(`{"status":"rejected","reason":"not aligned"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://moonstone.org.cn")
	req.Header.Set("Idempotency-Key", "0123456789abcdef0123456789abcdef")
	req.Header.Set("If-Match", `"1"`)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.Method != http.MethodPatch || service.input.Path != "/internal/v1/events/evt_shanghai/applications/app_1/decision" {
		t.Fatalf("input=%+v", service.input)
	}
}

func TestDreamUPAdminHandlersUseDedicatedWriteCapabilityForContactResolution(t *testing.T) {
	responseBody := `{"resolution":{"status":"acknowledged","version":1,"note":"received","updatedAt":"2026-08-27T06:00:00Z"}}`
	service := &dreamUPBFFServiceStub{response: &app.ProxyResponse{StatusCode: http.StatusOK, Body: json.RawMessage(responseBody), RequestID: "req_contact_upstream", ETag: `"1"`}}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/contact-submissions/contact_1/resolution", strings.NewReader(`{"status":"acknowledged"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://moonstone.org.cn")
	req.Header.Set("Idempotency-Key", "0123456789abcdef0123456789abcdef")
	req.Header.Set("If-Match", `"0"`)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.Capability != permissions.ActionContactSubmissionManage || service.input.Capability == permissions.ActionAuditRead || service.input.Method != http.MethodPatch || service.input.ResourceKind != "contact_submission" || service.input.ResourceID != "contact_1" || service.input.Path != "/internal/v1/events/evt_shanghai/contact-submissions/contact_1/resolution" {
		t.Fatalf("input=%+v", service.input)
	}
	if recorder.Body.String() != responseBody || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("ETag") != `"1"` || recorder.Header().Get("X-Request-ID") != "req_contact_upstream" {
		t.Fatalf("response headers=%v body=%s", recorder.Header(), recorder.Body.String())
	}
}

func TestDreamUPAdminHandlersForwardOnlyBoundedContactCursor(t *testing.T) {
	responseBody := `{"submissions":[{"id":"contact_1","kind":"feedback","payload":{"content":"The application page is unavailable."},"createdAt":"2026-08-27T06:00:00Z","resolution":null}],"nextCursor":"bmV4dA"}`
	service := &dreamUPBFFServiceStub{response: &app.ProxyResponse{StatusCode: http.StatusOK, Body: json.RawMessage(responseBody), RequestID: "req_contact_list"}}
	router := dreamUPBFFRouter(t, service)
	cursor := strings.Repeat("A", 512)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/contact-submissions?kind=feedback&limit=25&cursor="+cursor, nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.Query.Get("cursor") != cursor || service.input.Query.Get("kind") != "feedback" || service.input.Query.Get("limit") != "25" {
		t.Fatalf("query=%v", service.input.Query)
	}
	if service.input.Capability != permissions.ActionContactSubmissionManage || service.input.Capability == permissions.ActionAuditRead {
		t.Fatalf("contact list capability=%q", service.input.Capability)
	}
	if recorder.Body.String() != responseBody || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-Request-ID") != "req_contact_list" {
		t.Fatalf("response headers=%v body=%s", recorder.Header(), recorder.Body.String())
	}

	for _, invalid := range []string{"", "padding=", "contains%20space", strings.Repeat("a", 513)} {
		service.input = app.ProxyRequest{}
		recorder = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/contact-submissions?cursor="+invalid, nil)
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnprocessableEntity || service.input.EventID != "" {
			t.Fatalf("cursor=%q status=%d input=%+v", invalid, recorder.Code, service.input)
		}
	}
}

func TestDreamUPAdminHandlersExposeOnlyBooleanEligibility(t *testing.T) {
	service := &dreamUPBFFServiceStub{eligible: true, events: []app.EventSummary{{EventID: "must_not_leak"}}}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/eligibility", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response) != 1 || response["eligible"] != true || service.eligibilityCalls != 1 || service.actor.UserID != "user_1" {
		t.Fatalf("response=%v calls=%d actor=%+v", response, service.eligibilityCalls, service.actor)
	}
}

func TestDreamUPAdminHandlersExposeOnlyDurableOperationStatusMetadata(t *testing.T) {
	now := time.Date(2026, 8, 27, 8, 30, 0, 0, time.UTC)
	responseStatus, resultVersion := http.StatusOK, int64(4)
	service := &dreamUPBFFServiceStub{status: app.MutationStatus{Status: "succeeded", RequestID: ":trace-admin_123", ResponseStatus: &responseStatus, ResultVersion: &resultVersion, UpdatedAt: now}}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/operations/status", nil)
	request.Header.Set("Idempotency-Key", "0123456789abcdef0123456789abcdef")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if service.statusEventID != "evt_shanghai" || service.statusKey != "0123456789abcdef0123456789abcdef" || service.actor.UserID != "user_1" {
		t.Fatalf("event=%q key=%q actor=%+v", service.statusEventID, service.statusKey, service.actor)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"status":"succeeded"`) || !strings.Contains(body, `"requestId":":trace-admin_123"`) || strings.Contains(body, service.statusKey) || strings.Contains(body, "receipt") {
		t.Fatalf("unsafe or incomplete status body=%s", body)
	}
}

func TestDreamUPAdminOperationStatusRequiresIdempotencyKey(t *testing.T) {
	service := &dreamUPBFFServiceStub{statusErr: app.ErrInvalidRequest}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/operations/status", nil))
	if recorder.Code != http.StatusUnprocessableEntity || service.statusKey != "" {
		t.Fatalf("status=%d key=%q body=%s", recorder.Code, service.statusKey, recorder.Body.String())
	}
}

func TestDreamUPAdminEligibilityRequiresAuthenticatedActor(t *testing.T) {
	service := &dreamUPBFFServiceStub{eligible: true}
	handler, err := NewDreamUPAdminHandlers(service, "https://moonstone.org.cn")
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Route("/api/v1/admin/dreamup", handler.Mount)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/eligibility", nil))
	if recorder.Code != http.StatusUnauthorized || service.eligibilityCalls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, service.eligibilityCalls, recorder.Body.String())
	}
}

func TestDreamUPAdminHandlersMapContentRoutesAndBindResources(t *testing.T) {
	body := `{"title":"向未来","summary":"一起创造","blocks":[],"action":"save_draft"}`
	tests := []struct {
		name, method, path, upstreamMethod, upstreamPath, resourceID string
		mutation                                                     bool
	}{
		{name: "read content", method: http.MethodGet, path: "/api/v1/admin/dreamup/events/evt_shanghai/content", upstreamMethod: http.MethodGet, upstreamPath: "/internal/v1/events/evt_shanghai/content", resourceID: "evt_shanghai"},
		{name: "save intro", method: http.MethodPut, path: "/api/v1/admin/dreamup/events/evt_shanghai/content/intro", upstreamMethod: http.MethodPut, upstreamPath: "/internal/v1/events/evt_shanghai/content/intro", resourceID: "evt_shanghai", mutation: true},
		{name: "create announcement", method: http.MethodPost, path: "/api/v1/admin/dreamup/events/evt_shanghai/announcements", upstreamMethod: http.MethodPost, upstreamPath: "/internal/v1/events/evt_shanghai/announcements", resourceID: "evt_shanghai", mutation: true},
		{name: "update announcement", method: http.MethodPatch, path: "/api/v1/admin/dreamup/events/evt_shanghai/announcements/content_1", upstreamMethod: http.MethodPatch, upstreamPath: "/internal/v1/events/evt_shanghai/announcements/content_1", resourceID: "content_1", mutation: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{}
			router := dreamUPBFFRouter(t, service)
			recorder := httptest.NewRecorder()
			var reader *strings.Reader
			if test.mutation {
				reader = strings.NewReader(body)
			} else {
				reader = strings.NewReader("")
			}
			req := httptest.NewRequest(test.method, test.path, reader)
			if test.mutation {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://moonstone.org.cn")
				req.Header.Set("Idempotency-Key", "0123456789abcdef0123456789abcdef")
				req.Header.Set("If-Match", `"0"`)
			}
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if service.input.Capability != permissions.ActionContentManage || service.input.ResourceKind != "event_content" || service.input.ResourceID != test.resourceID || service.input.Method != test.upstreamMethod || service.input.Path != test.upstreamPath {
				t.Fatalf("input=%+v", service.input)
			}
			if test.mutation && (string(service.input.Body) != body || service.input.IfMatch != `"0"` || service.input.IdempotencyKey == "") {
				t.Fatalf("mutation binding=%+v", service.input)
			}
		})
	}
}

func TestDreamUPAdminHandlersMapContactSubmissionDetail(t *testing.T) {
	service := &dreamUPBFFServiceStub{}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/contact-submissions/contact_1", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.Capability != permissions.ActionContactSubmissionManage || service.input.ResourceKind != "contact_submission" || service.input.ResourceID != "contact_1" || service.input.Method != http.MethodGet || service.input.Path != "/internal/v1/events/evt_shanghai/contact-submissions/contact_1" {
		t.Fatalf("input=%+v", service.input)
	}
}

func TestDreamUPAdminCORSAllowsExactPATCHMethod(t *testing.T) {
	handler, err := NewDreamUPAdminHandlers(&dreamUPBFFServiceStub{}, "https://moonstone.org.cn")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/admin/dreamup/events/evt_shanghai/announcements/content_1", nil)
	req.Header.Set("Origin", "https://moonstone.org.cn")
	handler.CORS(http.NotFoundHandler()).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent || !strings.Contains(recorder.Header().Get("Access-Control-Allow-Methods"), "PATCH") || !strings.Contains(recorder.Header().Get("Access-Control-Allow-Headers"), "X-Reauthentication-Token") {
		t.Fatalf("status=%d methods=%q headers=%q", recorder.Code, recorder.Header().Get("Access-Control-Allow-Methods"), recorder.Header().Get("Access-Control-Allow-Headers"))
	}
}

func TestDreamUPAdminHandlersRejectUnsignedQueryOnNewExactRoutes(t *testing.T) {
	for _, path := range []string{
		"/api/v1/admin/dreamup/eligibility?eventId=evt_shanghai",
		"/api/v1/admin/dreamup/events/evt_shanghai/content?status=draft",
		"/api/v1/admin/dreamup/events/evt_shanghai/contact-submissions/contact_1?expand=all",
	} {
		service := &dreamUPBFFServiceStub{eligible: true}
		router := dreamUPBFFRouter(t, service)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusUnprocessableEntity || service.eligibilityCalls != 0 || service.input.EventID != "" {
			t.Errorf("path=%s status=%d eligibilityCalls=%d input=%+v", path, recorder.Code, service.eligibilityCalls, service.input)
		}
	}
}
