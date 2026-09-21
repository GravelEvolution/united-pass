package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/audit"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/mscaccess"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

const mscTestKeyID = "msc-work-console-2026-01"

type fakeMSCWorkforce struct {
	users       workforce.CursorPage[workforce.UserSummary]
	employees   workforce.CursorPage[workforce.EmployeeSummary]
	user        workforce.UserDetail
	departments []workforce.DepartmentSummary
	department  workforce.DepartmentDetail
	listErr     error
	detailErr   error
	lastQuery   workforce.UserListQuery
}

func (f *fakeMSCWorkforce) ListUsers(_ context.Context, query workforce.UserListQuery) (workforce.CursorPage[workforce.UserSummary], error) {
	f.lastQuery = query
	if f.listErr != nil {
		return workforce.CursorPage[workforce.UserSummary]{}, f.listErr
	}
	return f.users, nil
}

func (f *fakeMSCWorkforce) GetUserDetail(_ context.Context, _ identity.UserID) (workforce.UserDetail, error) {
	if f.detailErr != nil {
		return workforce.UserDetail{}, f.detailErr
	}
	return f.user, nil
}

func (f *fakeMSCWorkforce) ListEmployees(_ context.Context, _ workforce.EmployeeListQuery) (workforce.CursorPage[workforce.EmployeeSummary], error) {
	return f.employees, nil
}

func (f *fakeMSCWorkforce) ListDepartments(_ context.Context, _ string, _ int) ([]workforce.DepartmentSummary, error) {
	return f.departments, nil
}

func (f *fakeMSCWorkforce) GetDepartment(_ context.Context, _ workforce.DepartmentID) (workforce.DepartmentDetail, error) {
	return f.department, nil
}

type fakeMSCAudit struct {
	page audit.Page
}

func (f *fakeMSCAudit) List(_ context.Context, _ audit.Query) (audit.Page, error) {
	return f.page, nil
}

func mscTestVerifier(t *testing.T) (*mscaccess.Verifier, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verifier, err := mscaccess.NewVerifier(mscaccess.Config{
		Issuer:   "https://auth.moonstone.org.cn",
		Audience: "united-pass-msc-read",
		Subject:  "msc-work-console",
	}, map[string]ed25519.PublicKey{mscTestKeyID: publicKey})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return verifier, privateKey
}

func mscSignedRequest(t *testing.T, privateKey ed25519.PrivateKey, capability, target string) *http.Request {
	t.Helper()
	requestID := "req_" + strings.Repeat("ab", 16)
	now := time.Now().UTC().Unix()
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": mscTestKeyID}
	claims := map[string]any{
		"iss":         "https://auth.moonstone.org.cn",
		"aud":         "united-pass-msc-read",
		"sub":         "msc-work-console",
		"iat":         now,
		"nbf":         now,
		"exp":         now + 20,
		"jti":         requestID,
		"actor_kind":  "service",
		"capability":  capability,
		"htm":         "GET",
		"htu":         target,
		"body_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	headerRaw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsRaw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerRaw) + "." + base64.RawURLEncoding.EncodeToString(claimsRaw)
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(signingInput)))
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Request-ID", requestID)
	return request
}

func mscTestRouter(handlers *MSCReadonlyHandlers) http.Handler {
	router := chi.NewRouter()
	router.Get("/internal/v1/msc/users", handlers.ListUsers)
	router.Get("/internal/v1/msc/users/{userId}", handlers.GetUser)
	router.Get("/internal/v1/msc/employees", handlers.ListEmployees)
	router.Get("/internal/v1/msc/departments", handlers.ListDepartments)
	router.Get("/internal/v1/msc/departments/{departmentId}", handlers.GetDepartment)
	router.Get("/internal/v1/msc/audit-events", handlers.ListAuditEvents)
	return router
}

func mscRequestWithForeignTarget(t *testing.T, privateKey ed25519.PrivateKey, capability, requestTarget, signedTarget string) *http.Request {
	t.Helper()
	signed := mscSignedRequest(t, privateKey, capability, signedTarget)
	request := httptest.NewRequest(http.MethodGet, requestTarget, nil)
	request.Header.Set("Authorization", signed.Header.Get("Authorization"))
	request.Header.Set("X-Request-ID", signed.Header.Get("X-Request-ID"))
	return request
}

func mscTestHandlers(t *testing.T, source *fakeMSCWorkforce, auditSource *fakeMSCAudit) (http.Handler, ed25519.PrivateKey) {
	t.Helper()
	verifier, privateKey := mscTestVerifier(t)
	return mscTestRouter(NewMSCReadonlyHandlers(verifier, source, auditSource, nil)), privateKey
}

func decodeMSCBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return document
}

func TestMSCReadonlyHandlersRejectUnsignedRequests(t *testing.T) {
	source := &fakeMSCWorkforce{users: workforce.CursorPage[workforce.UserSummary]{}}
	router, _ := mscTestHandlers(t, source, &fakeMSCAudit{})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/internal/v1/msc/users", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestMSCReadonlyHandlersRejectForeignCapability(t *testing.T) {
	source := &fakeMSCWorkforce{users: workforce.CursorPage[workforce.UserSummary]{}}
	router, privateKey := mscTestHandlers(t, source, &fakeMSCAudit{})
	request := mscSignedRequest(t, privateKey, mscaccess.CapabilityAuditRead, "/internal/v1/msc/users")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestMSCReadonlyHandlersRejectUnboundTarget(t *testing.T) {
	source := &fakeMSCWorkforce{users: workforce.CursorPage[workforce.UserSummary]{}}
	router, privateKey := mscTestHandlers(t, source, &fakeMSCAudit{})
	request := mscRequestWithForeignTarget(t, privateKey, mscaccess.CapabilityUserRead,
		"/internal/v1/msc/users?limit=50", "/internal/v1/msc/users?limit=20")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestMSCReadonlyHandlersListUsers(t *testing.T) {
	active := time.Date(2026, time.September, 19, 10, 0, 0, 0, time.UTC)
	source := &fakeMSCWorkforce{users: workforce.CursorPage[workforce.UserSummary]{
		Items: []workforce.UserSummary{{
			UserID: identity.UserID("user_1"), DisplayName: "MSC", Email: "msc@moonstone.org.cn",
			PersonaLabel: "外部用户", Status: identity.UserStatusActive, LastActiveAt: active,
		}},
		NextCursor: "cursor_1", HasMore: true,
	}}
	router, privateKey := mscTestHandlers(t, source, &fakeMSCAudit{})
	request := mscSignedRequest(t, privateKey, mscaccess.CapabilityUserRead, "/internal/v1/msc/users?limit=20&status=active")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected no-store cache control, got %q", recorder.Header().Get("Cache-Control"))
	}
	document := decodeMSCBody(t, recorder)
	items, ok := document["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected one item, got %v", document["items"])
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected item shape: %v", items[0])
	}
	if item["userId"] != "user_1" || item["email"] != "msc@moonstone.org.cn" || item["status"] != "active" {
		t.Fatalf("unexpected item payload: %v", item)
	}
	page, ok := document["page"].(map[string]any)
	if !ok || page["nextCursor"] != "cursor_1" || page["hasMore"] != true {
		t.Fatalf("unexpected page payload: %v", document["page"])
	}
	if source.lastQuery.Limit != 20 || source.lastQuery.Status != "active" {
		t.Fatalf("query was not forwarded: %+v", source.lastQuery)
	}
}

func TestMSCReadonlyHandlersReportQueryFailures(t *testing.T) {
	source := &fakeMSCWorkforce{}
	router, privateKey := mscTestHandlers(t, source, &fakeMSCAudit{})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityUserRead, "/internal/v1/msc/users?limit=500"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for out-of-range limit, got %d", recorder.Code)
	}
	source.listErr = workforce.ErrInvalidCursor
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityUserRead, "/internal/v1/msc/users?cursor=stale"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for stale cursor, got %d", recorder.Code)
	}
	source.listErr = nil
	source.detailErr = workforce.ErrNotFound
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityUserRead, "/internal/v1/msc/users/user_1"))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown user, got %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityUserRead, "/internal/v1/msc/users/bad%20id"))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid user identifier, got %d", recorder.Code)
	}
}

func TestMSCReadonlyHandlersGetUserOmitsSensitiveCollections(t *testing.T) {
	active := time.Date(2026, time.September, 19, 10, 0, 0, 0, time.UTC)
	source := &fakeMSCWorkforce{user: workforce.UserDetail{
		User: identity.User{ID: identity.UserID("user_1"), DisplayName: "MSC", Email: "msc@moonstone.org.cn",
			Phone: "+8613800000000", Status: identity.UserStatusActive, Personas: []identity.Persona{identity.PersonaConsumer}},
		LastActiveAt: active,
		LinkedIdentities: []workforce.LinkedIdentity{{ProviderID: "feishu", ProviderName: "飞书",
			ExternalSubject: "ou_secret", LinkedAt: active}},
	}}
	router, privateKey := mscTestHandlers(t, source, &fakeMSCAudit{})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityUserRead, "/internal/v1/msc/users/user_1"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	document := decodeMSCBody(t, recorder)
	for _, forbidden := range []string{"phoneMasked", "linkedIdentities", "activeSessions", "recentAuditEvents", "personas"} {
		if _, exists := document[forbidden]; exists {
			t.Fatalf("sensitive field %q must not be exposed", forbidden)
		}
	}
	if document["userId"] != "user_1" || document["personaLabel"] != "外部用户" {
		t.Fatalf("unexpected payload: %v", document)
	}
}

func TestMSCReadonlyHandlersListDepartmentsAndDetail(t *testing.T) {
	source := &fakeMSCWorkforce{
		departments: []workforce.DepartmentSummary{{DepartmentID: "dep_1", Name: "研发", ParentName: "总部", MemberCount: 3, OwnerName: "MSC"}},
		department: workforce.DepartmentDetail{
			DepartmentID: "dep_1", Name: "研发", ParentDepartmentID: "dep_root", ParentName: "总部",
			OwnerUserID: "user_1", OwnerName: "MSC", MemberCount: 3,
			ChildDepartments: []workforce.DepartmentChild{},
			Members:          []workforce.DepartmentMember{{UserID: "user_1", DisplayName: "MSC", Title: "工程师", EmployeeNumber: "E001"}},
		},
	}
	router, privateKey := mscTestHandlers(t, source, &fakeMSCAudit{})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityDepartmentRead, "/internal/v1/msc/departments?limit=100"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	var list []map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 || list[0]["departmentId"] != "dep_1" || list[0]["memberCount"] != float64(3) {
		t.Fatalf("unexpected department list: %v", list)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityDepartmentRead, "/internal/v1/msc/departments/dep_1"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	detail := decodeMSCBody(t, recorder)
	if detail["departmentId"] != "dep_1" || detail["parentName"] != "总部" || detail["ownerUserId"] != "user_1" {
		t.Fatalf("unexpected department detail: %v", detail)
	}
	members, ok := detail["members"].([]any)
	if !ok || len(members) != 1 {
		t.Fatalf("unexpected department members: %v", detail["members"])
	}
}

func TestMSCReadonlyHandlersListEmployeesAndAudit(t *testing.T) {
	occurred := time.Date(2026, time.September, 19, 9, 30, 0, 0, time.UTC)
	source := &fakeMSCWorkforce{employees: workforce.CursorPage[workforce.EmployeeSummary]{
		Items: []workforce.EmployeeSummary{{UserID: "user_1", DisplayName: "MSC", EmployeeNumber: "E001",
			DepartmentName: "研发", Title: "工程师", Status: workforce.EmployeeStatusActive}},
	}}
	auditSource := &fakeMSCAudit{page: audit.Page{
		Items: []audit.Event{{EventID: "evt_1", EventType: "user.enabled", ActorName: "MSC", ActorID: "user_1",
			TargetLabel: "user", TargetID: "user_2", OccurredAt: occurred, Result: "success",
			RequestID: "req_1", Details: "sensitive operation payload"}},
		NextCursor: "audit_cursor", HasMore: false,
	}}
	router, privateKey := mscTestHandlers(t, source, auditSource)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityEmployeeRead, "/internal/v1/msc/employees?status=active"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	document := decodeMSCBody(t, recorder)
	items, ok := document["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("unexpected employee items: %v", document["items"])
	}
	employee, ok := items[0].(map[string]any)
	if !ok || employee["employeeId"] != "E001" || employee["departmentName"] != "研发" {
		t.Fatalf("unexpected employee payload: %v", employee)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityAuditRead, "/internal/v1/msc/audit-events?limit=20"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	document = decodeMSCBody(t, recorder)
	items, ok = document["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("unexpected audit items: %v", document["items"])
	}
	event, ok := items[0].(map[string]any)
	if !ok || event["eventId"] != "evt_1" || event["details"] != "" {
		t.Fatalf("unexpected audit payload: %v", event)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, mscSignedRequest(t, privateKey, mscaccess.CapabilityAuditRead, "/internal/v1/msc/audit-events?from=not-a-time"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed time filter, got %d", recorder.Code)
	}
}

func TestMSCReadonlyHandlersFailClosedWithoutVerifier(t *testing.T) {
	handlers := NewMSCReadonlyHandlers(nil, &fakeMSCWorkforce{}, &fakeMSCAudit{}, nil)
	recorder := httptest.NewRecorder()
	mscTestRouter(handlers).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/internal/v1/msc/users", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when the verifier is absent, got %d", recorder.Code)
	}
}
