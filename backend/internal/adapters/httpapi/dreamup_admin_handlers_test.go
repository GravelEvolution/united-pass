package httpapi

import (
	"context"
	"encoding/json"
	"errors"
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

type dreamUPPersonalAssetOwnerResolverStub struct {
	resolved app.PersonalAssetOwnerIdentity
	err      error
	userID   string
	calls    int
}

type dreamUPReviewIdentityResolverStub struct {
	userID  identity.UserID
	subject string
	err     error
	calls   int
}

func (s *dreamUPReviewIdentityResolverStub) ResolveReviewIdentityUser(_ context.Context, subject string) (identity.UserID, error) {
	s.subject = subject
	s.calls++
	if s.err != nil {
		return "", s.err
	}
	if s.userID == "" {
		return identity.UserID("user_applicant"), nil
	}
	return s.userID, nil
}

func (s *dreamUPPersonalAssetOwnerResolverStub) ResolvePersonalAssetOwner(_ context.Context, userID string) (app.PersonalAssetOwnerIdentity, error) {
	s.userID = userID
	s.calls++
	if s.err != nil {
		return app.PersonalAssetOwnerIdentity{}, s.err
	}
	if s.resolved.UserID == "" {
		return app.PersonalAssetOwnerIdentity{UserID: identity.UserID(userID), ProviderSubject: "zitadel_subject_1"}, nil
	}
	return s.resolved, nil
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

func redactedApplicationProxyResponse(body string) *app.ProxyResponse {
	return &app.ProxyResponse{StatusCode: http.StatusOK, Body: json.RawMessage(body), RequestID: "req_application_upstream", ETag: `"1"`}
}

func redactedApplicationPageProxyResponse(body string) *app.ProxyResponse {
	return &app.ProxyResponse{StatusCode: http.StatusOK, Body: json.RawMessage(body), RequestID: "req_application_page_upstream"}
}

func dreamUPBFFRouter(t *testing.T, service DreamUPAdminService) http.Handler {
	t.Helper()
	return dreamUPBFFRouterWithResolvers(t, service, &dreamUPPersonalAssetOwnerResolverStub{}, &dreamUPReviewIdentityResolverStub{})
}

func dreamUPBFFRouterWithOwnerResolver(t *testing.T, service DreamUPAdminService, resolver app.PersonalAssetOwnerResolver) http.Handler {
	t.Helper()
	return dreamUPBFFRouterWithResolvers(t, service, resolver, &dreamUPReviewIdentityResolverStub{})
}

func dreamUPBFFRouterWithResolvers(t *testing.T, service DreamUPAdminService, ownerResolver app.PersonalAssetOwnerResolver, reviewResolver app.ReviewIdentityResolver) http.Handler {
	t.Helper()
	handler, err := NewDreamUPAdminHandlers(service, "https://moonstone.org.cn", DreamUPAdminHandlerConfig{
		PersonalAssetOwnerResolver: ownerResolver,
		ReviewIdentityResolver:     reviewResolver,
	})
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

func TestDreamUPAdminHandlersReturnOnlyClosedRedactedBasicApplicationDetail(t *testing.T) {
	service := &dreamUPBFFServiceStub{response: redactedApplicationProxyResponse(`{"application":{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"submitted","version":1,"reviewAnswers":{"problemToSolve":"build"},"submittedAt":1787000000000,"updatedAt":1787000000000}}`)}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_1", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.Capability != permissions.ActionApplicationReadBasic {
		t.Fatalf("capability=%s", service.input.Capability)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 2 || payload["application"] == nil || string(payload["ownReview"]) != "null" {
		t.Fatalf("unexpected detail envelope: %s", recorder.Body.String())
	}
}

func TestDreamUPAdminHandlersRevealReviewIdentityThroughAuditedClosedContract(t *testing.T) {
	operationID := strings.Repeat("a", 32)
	receiptHash := strings.Repeat("b", 64)
	service := &dreamUPBFFServiceStub{response: &app.ProxyResponse{
		StatusCode: http.StatusOK,
		Body:       json.RawMessage(`{"identity":{"providerSubject":"zitadel_subject_42","legalName":"张三","email":"person@example.test","mobile":"+8613800000000"},"receipt":{"operationId":"` + operationID + `","receiptHash":"` + receiptHash + `","consumedAt":1787000000000}}`),
		RequestID:  "req_review_identity_upstream",
	}}
	resolver := &dreamUPReviewIdentityResolverStub{userID: "user_applicant_42"}
	router := dreamUPBFFRouterWithResolvers(t, service, &dreamUPPersonalAssetOwnerResolverStub{}, resolver)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_42/review-identity", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://moonstone.org.cn")
	req.Header.Set("Idempotency-Key", operationID)
	req.Header.Set("If-Match", `"3"`)
	req.Header.Set("X-Reauthentication-Token", strings.Repeat("R", 43))
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.EventID != "evt_shanghai" || service.input.ResourceKind != "application" || service.input.ResourceID != "app_42" ||
		service.input.Capability != permissions.ActionIdentityReadRestricted || service.input.Method != http.MethodPost ||
		service.input.Path != "/internal/v1/events/evt_shanghai/applications/app_42/review-identity" {
		t.Fatalf("input=%+v", service.input)
	}
	var upstreamBody map[string]json.RawMessage
	if err := json.Unmarshal(service.input.Body, &upstreamBody); err != nil {
		t.Fatal(err)
	}
	if len(upstreamBody) != 1 || upstreamBody["protectedReasonId"] == nil || upstreamBody["reason"] != nil ||
		upstreamBody["subject"] != nil || upstreamBody["fields"] != nil {
		t.Fatalf("rewritten body=%s", service.input.Body)
	}
	var protectedReasonID string
	if json.Unmarshal(upstreamBody["protectedReasonId"], &protectedReasonID) != nil || !strings.HasPrefix(protectedReasonID, "review_identity_") {
		t.Fatalf("protectedReasonId=%q", protectedReasonID)
	}
	if resolver.calls != 1 || resolver.subject != "zitadel_subject_42" {
		t.Fatalf("resolver=%+v", resolver)
	}
	var payload struct {
		Identity map[string]json.RawMessage `json:"identity"`
		Receipt  map[string]json.RawMessage `json:"receipt"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Identity) != 4 || string(payload.Identity["userId"]) != `"user_applicant_42"` ||
		payload.Identity["providerSubject"] != nil || len(payload.Receipt) != 3 {
		t.Fatalf("public body=%s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "zitadel_subject_42") || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("private subject leaked or cache policy missing: headers=%v body=%s", recorder.Header(), recorder.Body.String())
	}
}

func TestDreamUPAdminHandlersFailClosedForInvalidReviewIdentityRequestsAndResponses(t *testing.T) {
	operationID := strings.Repeat("a", 32)
	receiptHash := strings.Repeat("b", 64)
	validResponse := `{"identity":{"providerSubject":"zitadel_subject_42","legalName":null,"email":"person@example.test","mobile":null},"receipt":{"operationId":"` + operationID + `","receiptHash":"` + receiptHash + `","consumedAt":1787000000000}}`
	for name, body := range map[string]string{
		"open identity object":   strings.Replace(validResponse, `"mobile":null`, `"mobile":null,"role":"admin"`, 1),
		"open envelope":          strings.TrimSuffix(validResponse, "}") + `,"providerSubject":"zitadel_subject_42"}`,
		"invalid stable receipt": strings.Replace(validResponse, receiptHash, "not-a-hash", 1),
		"mismatched operation":   strings.Replace(validResponse, operationID, strings.Repeat("c", 32), 1),
		"zero consumption time":  strings.Replace(validResponse, "1787000000000", "0", 1),
	} {
		t.Run(name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{response: &app.ProxyResponse{StatusCode: http.StatusOK, Body: json.RawMessage(body)}}
			router := dreamUPBFFRouter(t, service)
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_42/review-identity", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://moonstone.org.cn")
			req.Header.Set("Idempotency-Key", operationID)
			req.Header.Set("If-Match", `"3"`)
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "person@example.test") || strings.Contains(recorder.Body.String(), "zitadel_subject_42") {
				t.Fatalf("restricted identity leaked: %s", recorder.Body.String())
			}
		})
	}

	for name, request := range map[string]struct{ target, body string }{
		"caller supplied fields":  {target: "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_42/review-identity", body: `{"fields":["email"]}`},
		"caller supplied subject": {target: "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_42/review-identity", body: `{"subject":"user_other"}`},
		"query string":            {target: "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_42/review-identity?fields=email", body: `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{}
			router := dreamUPBFFRouter(t, service)
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, request.target, strings.NewReader(request.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://moonstone.org.cn")
			req.Header.Set("Idempotency-Key", operationID)
			req.Header.Set("If-Match", `"3"`)
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusUnprocessableEntity || service.input.Path != "" {
				t.Fatalf("status=%d input=%+v body=%s", recorder.Code, service.input, recorder.Body.String())
			}
		})
	}
}

func TestDreamUPAdminHandlersFailClosedOnRestrictedIdentityFromBasicDetailUpstream(t *testing.T) {
	for name, responseBody := range map[string]string{
		"legacy restricted identity envelope":  `{"application":{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"submitted","version":1,"reviewAnswers":{},"submittedAt":1787000000000,"updatedAt":1787000000000},"restrictedIdentity":{"email":"person@example.test","mobile":"+8613800000000"},"ownReview":null}`,
		"identity field inside application":    `{"application":{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"submitted","version":1,"reviewAnswers":{},"submittedAt":1787000000000,"updatedAt":1787000000000,"legalName":"Example Person"},"ownReview":null}`,
		"identity field inside review answers": `{"application":{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"submitted","version":1,"reviewAnswers":{"contact_email":"person@example.test"},"submittedAt":1787000000000,"updatedAt":1787000000000},"ownReview":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{response: redactedApplicationProxyResponse(responseBody)}
			router := dreamUPBFFRouter(t, service)
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/applications/app_1", nil)
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "Example Person") || strings.Contains(recorder.Body.String(), "person@example.test") || strings.Contains(recorder.Body.String(), "13800000000") {
				t.Fatalf("restricted identity leaked in error response: %s", recorder.Body.String())
			}
		})
	}
}

func TestDreamUPAdminHandlersValidateClosedRedactedApplicationPage(t *testing.T) {
	service := &dreamUPBFFServiceStub{response: redactedApplicationPageProxyResponse(`{"applications":[{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"submitted","version":1,"reviewAnswers":{"problem_to_solve":"build","skill_tags":["typescript"]},"submittedAt":1787000000000,"updatedAt":1787000000000}],"nextCursor":null}`)}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/applications", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if service.input.Capability != permissions.ActionApplicationReadBasic || service.input.ResourceKind != "event" || service.input.ResourceID != "evt_shanghai" {
		t.Fatalf("input=%+v", service.input)
	}
}

func TestDreamUPAdminHandlersFailClosedOnPIIOrOpenApplicationPageUpstream(t *testing.T) {
	validItem := `{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"submitted","version":1,"reviewAnswers":{},"submittedAt":1787000000000,"updatedAt":1787000000000}`
	for name, responseBody := range map[string]string{
		"restricted envelope":                  `{"applications":[],"nextCursor":null,"restrictedIdentity":{"mobile":"+8613800000000"}}`,
		"identity field inside item":           `{"applications":[{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"submitted","version":1,"reviewAnswers":{},"submittedAt":1787000000000,"updatedAt":1787000000000,"legalName":"Example Person"}],"nextCursor":null}`,
		"identity field inside review answers": `{"applications":[{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"submitted","version":1,"reviewAnswers":{"contact_email":"person@example.test"},"submittedAt":1787000000000,"updatedAt":1787000000000}],"nextCursor":null}`,
		"nested object inside review answers":  `{"applications":[{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"submitted","version":1,"reviewAnswers":{"problem_to_solve":{"email":"person@example.test"}},"submittedAt":1787000000000,"updatedAt":1787000000000}],"nextCursor":null}`,
		"cross event item":                     `{"applications":[` + strings.Replace(validItem, `"evt_shanghai"`, `"evt_other"`, 1) + `],"nextCursor":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{response: redactedApplicationPageProxyResponse(responseBody)}
			router := dreamUPBFFRouter(t, service)
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/applications", nil)
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			for _, secret := range []string{"Example Person", "person@example.test", "13800000000"} {
				if strings.Contains(recorder.Body.String(), secret) {
					t.Fatalf("restricted value %q leaked in error response: %s", secret, recorder.Body.String())
				}
			}
		})
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
			if test.name == "applications" {
				service.response = redactedApplicationPageProxyResponse(`{"applications":[],"nextCursor":null}`)
			}
			handler, err := NewDreamUPAdminHandlers(service, "https://moonstone.org.cn", DreamUPAdminHandlerConfig{
				PersonalAssetOwnerResolver: &dreamUPPersonalAssetOwnerResolverStub{},
				ReviewIdentityResolver:     &dreamUPReviewIdentityResolverStub{},
				AllowMiniProgram:           true,
			})
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
	service := &dreamUPBFFServiceStub{response: redactedApplicationProxyResponse(`{"application":{"id":"app_1","eventId":"evt_shanghai","displayHandle":"MS-000000000001ABCD","status":"rejected","version":2,"reviewAnswers":{},"submittedAt":1787000000000,"updatedAt":1787000001000}}`)}
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

func TestDreamUPAdminHandlersForwardSignedPaginationForManagementLists(t *testing.T) {
	cursor := strings.Repeat("A", 64) + "." + strings.Repeat("B", 43)
	tests := []struct {
		name, path, upstreamPath string
	}{
		{name: "applications", path: "/api/v1/admin/dreamup/events/evt_shanghai/applications?limit=100&sort=updated_desc&cursor=" + cursor, upstreamPath: "/internal/v1/events/evt_shanghai/applications"},
		{name: "teams", path: "/api/v1/admin/dreamup/events/evt_shanghai/teams?limit=100&cursor=" + cursor, upstreamPath: "/internal/v1/events/evt_shanghai/teams"},
		{name: "content", path: "/api/v1/admin/dreamup/events/evt_shanghai/content?limit=100&cursor=" + cursor, upstreamPath: "/internal/v1/events/evt_shanghai/content"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{}
			if test.name == "applications" {
				service.response = redactedApplicationPageProxyResponse(`{"applications":[],"nextCursor":null}`)
			}
			router := dreamUPBFFRouter(t, service)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if service.input.Path != test.upstreamPath || service.input.Query.Get("limit") != "100" || service.input.Query.Get("cursor") != cursor {
				t.Fatalf("input=%+v", service.input)
			}
		})
	}

	service := &dreamUPBFFServiceStub{}
	router := dreamUPBFFRouter(t, service)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/teams?limit=101", nil))
	if recorder.Code != http.StatusUnprocessableEntity || service.input.EventID != "" {
		t.Fatalf("status=%d input=%+v", recorder.Code, service.input)
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
	handler, err := NewDreamUPAdminHandlers(service, "https://moonstone.org.cn", DreamUPAdminHandlerConfig{
		PersonalAssetOwnerResolver: &dreamUPPersonalAssetOwnerResolverStub{},
		ReviewIdentityResolver:     &dreamUPReviewIdentityResolverStub{},
	})
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
		{name: "create announcement background upload intent", method: http.MethodPost, path: "/api/v1/admin/dreamup/events/evt_shanghai/announcement-background-image-upload-intents", upstreamMethod: http.MethodPost, upstreamPath: "/internal/v1/events/evt_shanghai/announcement-background-image-upload-intents", resourceID: "evt_shanghai", mutation: true},
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

func TestDreamUPAdminHandlersMapSplashRoutesAndBindResources(t *testing.T) {
	body := `{"action":"publish","altText":"MoonStone poster"}`
	tests := []struct {
		name, method, path, upstreamMethod, upstreamPath string
		mutation                                         bool
	}{
		{name: "read splash", method: http.MethodGet, path: "/api/v1/admin/dreamup/events/evt_shanghai/splash-ad", upstreamMethod: http.MethodGet, upstreamPath: "/internal/v1/events/evt_shanghai/splash-ad"},
		{name: "create splash upload intent", method: http.MethodPost, path: "/api/v1/admin/dreamup/events/evt_shanghai/splash-poster-image-upload-intents", upstreamMethod: http.MethodPost, upstreamPath: "/internal/v1/events/evt_shanghai/splash-poster-image-upload-intents", mutation: true},
		{name: "publish splash", method: http.MethodPut, path: "/api/v1/admin/dreamup/events/evt_shanghai/splash-ad", upstreamMethod: http.MethodPut, upstreamPath: "/internal/v1/events/evt_shanghai/splash-ad", mutation: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{}
			router := dreamUPBFFRouter(t, service)
			recorder := httptest.NewRecorder()
			reader := strings.NewReader("")
			if test.mutation {
				reader = strings.NewReader(body)
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
			if service.input.Capability != permissions.ActionContentManage || service.input.ResourceKind != "splash_poster" || service.input.ResourceID != "evt_shanghai" || service.input.Method != test.upstreamMethod || service.input.Path != test.upstreamPath {
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
	handler, err := NewDreamUPAdminHandlers(&dreamUPBFFServiceStub{}, "https://moonstone.org.cn", DreamUPAdminHandlerConfig{
		PersonalAssetOwnerResolver: &dreamUPPersonalAssetOwnerResolverStub{},
		ReviewIdentityResolver:     &dreamUPReviewIdentityResolverStub{},
	})
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

func TestDreamUPAdminHandlersMapScanAndAssetRoutesExactly(t *testing.T) {
	tests := []struct {
		name, method, path, upstreamPath, kind, resourceID string
		capability                                         permissions.Action
		mutation                                           bool
	}{
		{"points list", http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points?status=active&limit=20", "/internal/v1/events/evt_shanghai/inspection-points", "event", "evt_shanghai", permissions.ActionInspectionPointRead, false},
		{"point create", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points", "/internal/v1/events/evt_shanghai/inspection-points", "event", "evt_shanghai", permissions.ActionInspectionPointManage, true},
		{"point image upload intent", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-point-image-upload-intents", "/internal/v1/events/evt_shanghai/inspection-point-image-upload-intents", "event", "evt_shanghai", permissions.ActionInspectionPointManage, true},
		{"point update", http.MethodPatch, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points/point_1", "/internal/v1/events/evt_shanghai/inspection-points/point_1", "inspection_point", "point_1", permissions.ActionInspectionPointManage, true},
		{"point code rotate", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points/point_1/code-rotations", "/internal/v1/events/evt_shanghai/inspection-points/point_1/code-rotations", "inspection_point", "point_1", permissions.ActionInspectionPointManage, true},
		{"inspection", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points/point_1/inspections", "/internal/v1/events/evt_shanghai/inspection-points/point_1/inspections", "inspection_point", "point_1", permissions.ActionInspectionPerform, true},
		{"inspection history", http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/inspections?pointId=point_1", "/internal/v1/events/evt_shanghai/inspections", "event", "evt_shanghai", permissions.ActionInspectionReview, false},
		{"inspection detail", http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/inspections/inspection_1", "/internal/v1/events/evt_shanghai/inspections/inspection_1", "inspection_record", "inspection_1", permissions.ActionInspectionReview, false},
		{"photo finalize", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-photo-uploads/upload_1/finalize", "/internal/v1/events/evt_shanghai/inspection-photo-uploads/upload_1/finalize", "inspection_photo_upload", "upload_1", permissions.ActionInspectionPerform, true},
		{"assets list", http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/assets?status=active", "/internal/v1/events/evt_shanghai/assets", "event", "evt_shanghai", permissions.ActionAssetRead, false},
		{"asset create", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/assets", "/internal/v1/events/evt_shanghai/assets", "event", "evt_shanghai", permissions.ActionAssetManage, true},
		{"asset image upload intent", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-image-upload-intents", "/internal/v1/events/evt_shanghai/asset-image-upload-intents", "event", "evt_shanghai", permissions.ActionAssetManage, true},
		{"asset update", http.MethodPatch, "/api/v1/admin/dreamup/events/evt_shanghai/assets/asset_1", "/internal/v1/events/evt_shanghai/assets/asset_1", "event_asset", "asset_1", permissions.ActionAssetManage, true},
		{"asset code rotate", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-units/unit_1/code-rotations", "/internal/v1/events/evt_shanghai/asset-units/unit_1/code-rotations", "asset_unit", "unit_1", permissions.ActionAssetCodeRotate, true},
		{"inventory", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-units/unit_1/inventory-adjustments", "/internal/v1/events/evt_shanghai/asset-units/unit_1/inventory-adjustments", "asset_unit", "unit_1", permissions.ActionAssetInventoryAdjust, true},
		{"reservations", http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/asset-reservations?status=pending", "/internal/v1/events/evt_shanghai/asset-reservations", "event", "evt_shanghai", permissions.ActionAssetReservationManage, false},
		{"reservation decision", http.MethodPatch, "/api/v1/admin/dreamup/events/evt_shanghai/asset-reservations/reservation_1", "/internal/v1/events/evt_shanghai/asset-reservations/reservation_1", "asset_reservation", "reservation_1", permissions.ActionAssetReservationManage, true},
		{"checkout", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-units/unit_1/checkout", "/internal/v1/events/evt_shanghai/asset-units/unit_1/checkout", "asset_unit", "unit_1", permissions.ActionAssetCustodyTransfer, true},
		{"checkin", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-units/unit_1/checkin", "/internal/v1/events/evt_shanghai/asset-units/unit_1/checkin", "asset_unit", "unit_1", permissions.ActionAssetCustodyTransfer, true},
		{"transfer", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/asset-units/unit_1/transfers", "/internal/v1/events/evt_shanghai/asset-units/unit_1/transfers", "asset_unit", "unit_1", permissions.ActionAssetCustodyTransfer, true},
		{"personal assets", http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-assignments", "/internal/v1/events/evt_shanghai/personal-asset-assignments", "event", "evt_shanghai", permissions.ActionPersonalAssetAssignment, false},
		{"personal create", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-assignments", "/internal/v1/events/evt_shanghai/personal-asset-assignments", "event", "evt_shanghai", permissions.ActionPersonalAssetAssignment, true},
		{"personal image upload intent", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-image-upload-intents", "/internal/v1/events/evt_shanghai/personal-asset-image-upload-intents", "event", "evt_shanghai", permissions.ActionPersonalAssetAssignment, true},
		{"personal update", http.MethodPatch, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-assignments/assignment_1", "/internal/v1/events/evt_shanghai/personal-asset-assignments/assignment_1", "personal_asset_assignment", "assignment_1", permissions.ActionPersonalAssetAssignment, true},
		{"single print", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/entity-codes/code_1/print-jobs", "/internal/v1/events/evt_shanghai/entity-codes/code_1/print-jobs", "entity_code", "code_1", permissions.ActionQRPrintSingle, true},
		{"bulk print", http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/qr-print-jobs/bulk", "/internal/v1/events/evt_shanghai/qr-print-jobs/bulk", "event", "evt_shanghai", permissions.ActionQRPrintBulk, true},
		{"print job", http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/qr-print-jobs/print_1", "/internal/v1/events/evt_shanghai/qr-print-jobs/print_1", "qr_print_job", "print_1", permissions.ActionQRPrintSingle, false},
		{"bulk print job", http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/qr-print-jobs/print_1/bulk", "/internal/v1/events/evt_shanghai/qr-print-jobs/print_1/bulk", "qr_print_job", "print_1", permissions.ActionQRPrintBulk, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{}
			router := dreamUPBFFRouter(t, service)
			body := strings.NewReader("")
			if test.mutation {
				body = strings.NewReader(`{"reason":"acceptance"}`)
			}
			if test.name == "personal create" {
				body = strings.NewReader(`{"equipmentLabel":"Radio A","assetIdentifier":"MS-A","ownerSubject":"user_owner","ownerDisplayName":"Owner","ownerContact":"owner@example.test","returnAddress":"Desk","assetId":"personal_catalog_1","image":{"objectKey":"events/evt_shanghai/asset-catalog/personal_catalog_1/images/image.png","contentType":"image/png","byteSize":1,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
			}
			request := httptest.NewRequest(test.method, test.path, body)
			if test.mutation {
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Origin", "https://moonstone.org.cn")
				request.Header.Set("Idempotency-Key", "0123456789abcdef0123456789abcdef")
				request.Header.Set("If-Match", `"1"`)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if service.input.Capability != test.capability || service.input.ResourceKind != test.kind || service.input.ResourceID != test.resourceID || service.input.Path != test.upstreamPath || service.input.Method != test.method {
				t.Fatalf("input=%+v", service.input)
			}
		})
	}
}

func TestDreamUPAdminOperationsCursorRoundTripsThroughBFF(t *testing.T) {
	nextCursor := strings.Repeat("A", 160) + "." + strings.Repeat("B", 43)
	service := &dreamUPBFFServiceStub{response: &app.ProxyResponse{
		StatusCode: http.StatusOK,
		Body:       json.RawMessage(`{"items":[{"pointId":"point_2"}],"nextCursor":"` + nextCursor + `"}`),
		RequestID:  "req_operations_page_1",
	}}
	router := dreamUPBFFRouter(t, service)

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points?limit=2", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first page status=%d body=%s", first.Code, first.Body.String())
	}
	var page struct {
		NextCursor string `json:"nextCursor"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode first page: %v", err)
	}
	if page.NextCursor != nextCursor {
		t.Fatalf("nextCursor=%q want=%q", page.NextCursor, nextCursor)
	}

	service.response = &app.ProxyResponse{
		StatusCode: http.StatusOK,
		Body:       json.RawMessage(`{"items":[{"pointId":"point_1"}],"nextCursor":null}`),
		RequestID:  "req_operations_page_2",
	}
	second := httptest.NewRecorder()
	router.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points?limit=2&cursor="+page.NextCursor, nil))
	if second.Code != http.StatusOK {
		t.Fatalf("second page status=%d body=%s", second.Code, second.Body.String())
	}
	if service.input.Query.Get("cursor") != nextCursor || service.input.Query.Get("limit") != "2" {
		t.Fatalf("second page query=%v", service.input.Query)
	}
	if service.input.Path != "/internal/v1/events/evt_shanghai/inspection-points" {
		t.Fatalf("second page input=%+v", service.input)
	}
}

func TestDreamUPAdminOperationsCursorRejectsMalformedOrShapeTamperedValues(t *testing.T) {
	payload := strings.Repeat("A", 160)
	signature := strings.Repeat("B", 43)
	for _, cursor := range []string{
		payload + signature,
		payload + "." + signature[:42],
		payload + "." + signature + "=",
		strings.Repeat("A", 1537) + "." + signature,
	} {
		service := &dreamUPBFFServiceStub{}
		recorder := httptest.NewRecorder()
		path := "/api/v1/admin/dreamup/events/evt_shanghai/inspection-points?cursor=" + cursor
		dreamUPBFFRouter(t, service).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusUnprocessableEntity || service.input.EventID != "" {
			t.Fatalf("cursor=%q status=%d input=%+v", cursor, recorder.Code, service.input)
		}
	}
}

func TestDreamUPAdminScanAndAssetListQueriesFailClosed(t *testing.T) {
	for _, path := range []string{
		"/api/v1/admin/dreamup/events/evt_shanghai/assets?expand=identity",
		"/api/v1/admin/dreamup/events/evt_shanghai/inspections?status=contains%20space",
		"/api/v1/admin/dreamup/events/evt_shanghai/asset-reservations?limit=101",
		"/api/v1/admin/dreamup/events/evt_shanghai/inspection-points?cursor=padding%3D",
	} {
		service := &dreamUPBFFServiceStub{}
		recorder := httptest.NewRecorder()
		dreamUPBFFRouter(t, service).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusUnprocessableEntity || service.input.EventID != "" {
			t.Fatalf("path=%s status=%d input=%+v", path, recorder.Code, service.input)
		}
	}
}

func TestDreamUPAdminPersonalAssetCreationBindsCanonicalProviderIdentityBeforeProxy(t *testing.T) {
	service := &dreamUPBFFServiceStub{}
	resolver := &dreamUPPersonalAssetOwnerResolverStub{resolved: app.PersonalAssetOwnerIdentity{
		UserID: "user_owner", ProviderSubject: "zitadel_subject_42",
	}}
	router := dreamUPBFFRouterWithOwnerResolver(t, service, resolver)
	body := `{"equipmentLabel":"Radio","assetIdentifier":"MS-1","ownerSubject":"user_owner","ownerDisplayName":"Owner","ownerContact":"owner@example.test","returnAddress":"Desk","assetId":"personal_catalog_1","image":{"objectKey":"key","contentType":"image/png","byteSize":1,"sha256":"aaa"}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-assignments", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://moonstone.org.cn")
	request.Header.Set("Idempotency-Key", "0123456789abcdef0123456789abcdef")
	request.Header.Set("If-Match", `"0"`)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if resolver.calls != 1 || resolver.userID != "user_owner" {
		t.Fatalf("resolver=%+v", resolver)
	}
	want := `{"assetId":"personal_catalog_1","assetIdentifier":"MS-1","equipmentLabel":"Radio","image":{"objectKey":"key","contentType":"image/png","byteSize":1,"sha256":"aaa"},"ownerContact":"owner@example.test","ownerDisplayName":"Owner","ownerSubject":"zitadel_subject_42","ownerUserId":"user_owner","returnAddress":"Desk"}`
	if string(service.input.Body) != want {
		t.Fatalf("body=%s\nwant=%s", service.input.Body, want)
	}
	if service.input.Capability != permissions.ActionPersonalAssetAssignment || service.input.Path != "/internal/v1/events/evt_shanghai/personal-asset-assignments" {
		t.Fatalf("input=%+v", service.input)
	}
}

func TestDreamUPAdminPersonalAssetCreationRejectsAmbiguousOrUnknownJSONBeforeProxy(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "caller supplied owner user id", body: `{"ownerSubject":"user_owner","ownerUserId":"user_other"}`},
		{name: "unknown field", body: `{"ownerSubject":"user_owner","providerSubject":"attacker"}`},
		{name: "duplicate owner", body: `{"ownerSubject":"user_owner","ownerSubject":"user_other"}`},
		{name: "nested duplicate", body: `{"ownerSubject":"user_owner","image":{"objectKey":"one","objectKey":"two"}}`},
		{name: "missing owner", body: `{"equipmentLabel":"Radio"}`},
		{name: "non string owner", body: `{"ownerSubject":42}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &dreamUPBFFServiceStub{}
			resolver := &dreamUPPersonalAssetOwnerResolverStub{}
			router := dreamUPBFFRouterWithOwnerResolver(t, service, resolver)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-assignments", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", "https://moonstone.org.cn")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnprocessableEntity || service.input.EventID != "" {
				t.Fatalf("status=%d body=%s input=%+v", recorder.Code, recorder.Body.String(), service.input)
			}
			if resolver.calls != 0 {
				t.Fatalf("ambiguous body reached resolver: %+v", resolver)
			}
		})
	}
}

func TestDreamUPAdminPersonalAssetCreationFailsClosedOnUnverifiedOwner(t *testing.T) {
	service := &dreamUPBFFServiceStub{}
	resolver := &dreamUPPersonalAssetOwnerResolverStub{err: app.ErrInvalidRequest}
	router := dreamUPBFFRouterWithOwnerResolver(t, service, resolver)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/dreamup/events/evt_shanghai/personal-asset-assignments", strings.NewReader(`{"ownerSubject":"user_disabled"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://moonstone.org.cn")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity || service.input.EventID != "" || resolver.calls != 1 {
		t.Fatalf("status=%d input=%+v resolver=%+v", recorder.Code, service.input, resolver)
	}
}

func TestNewDreamUPAdminHandlersRequiresIdentityResolvers(t *testing.T) {
	if _, err := NewDreamUPAdminHandlers(&dreamUPBFFServiceStub{}, "https://moonstone.org.cn", DreamUPAdminHandlerConfig{
		ReviewIdentityResolver: &dreamUPReviewIdentityResolverStub{},
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("missing personal asset owner resolver err=%v", err)
	}
	if _, err := NewDreamUPAdminHandlers(&dreamUPBFFServiceStub{}, "https://moonstone.org.cn", DreamUPAdminHandlerConfig{
		PersonalAssetOwnerResolver: &dreamUPPersonalAssetOwnerResolverStub{},
	}); !errors.Is(err, app.ErrInvalidRequest) {
		t.Fatalf("missing review identity resolver err=%v", err)
	}
}
