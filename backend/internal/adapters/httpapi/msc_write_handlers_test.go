package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/mscaccess"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

const mscWriteActorUserID = identity.UserID("user_service_actor")

type fakeMSCStatusWriter struct {
	mutation workforce.UserStatusMutation
	calls    int
	pending  bool
	err      error

	sessionsRevoked []string
	employee        workforce.EmployeeProfileInput
	offboarded      []string
	departmentInput workforce.DepartmentInput
	departmentPatch workforce.DepartmentPatch
	departmentID    workforce.DepartmentID
	createdCalls    int
}

func (f *fakeMSCStatusWriter) ChangeUserStatus(_ context.Context, mutation workforce.UserStatusMutation) (bool, error) {
	f.calls++
	f.mutation = mutation
	return f.pending, f.err
}

func (f *fakeMSCStatusWriter) RevokeUserSessions(_ context.Context, _ identity.UserID, userID identity.UserID, _ string) error {
	if f.err != nil {
		return f.err
	}
	f.sessionsRevoked = append(f.sessionsRevoked, string(userID))
	return nil
}

func (f *fakeMSCStatusWriter) LinkEmployee(_ context.Context, _ identity.UserID, input workforce.EmployeeProfileInput, _ string) (workforce.EmployeeProfile, error) {
	if f.err != nil {
		return workforce.EmployeeProfile{}, f.err
	}
	f.employee = input
	return workforce.EmployeeProfile{UserID: input.UserID, EmployeeNumber: "E-1001", Title: input.Title, DepartmentID: input.DepartmentID}, nil
}

func (f *fakeMSCStatusWriter) UpdateEmployee(_ context.Context, _ identity.UserID, input workforce.EmployeeProfileInput, _ string) (workforce.EmployeeProfile, error) {
	if f.err != nil {
		return workforce.EmployeeProfile{}, f.err
	}
	f.employee = input
	return workforce.EmployeeProfile{UserID: input.UserID, EmployeeNumber: "E-1001", Title: input.Title, DepartmentID: input.DepartmentID}, nil
}

func (f *fakeMSCStatusWriter) OffboardEmployee(_ context.Context, _, userID identity.UserID, _ string) (workforce.OffboardingResult, error) {
	if f.err != nil {
		return workforce.OffboardingResult{}, f.err
	}
	f.offboarded = append(f.offboarded, string(userID))
	return workforce.OffboardingResult{Status: workforce.EmployeeStatusOffboarding, CleanupPending: f.pending}, nil
}

func (f *fakeMSCStatusWriter) CreateDepartment(_ context.Context, _ identity.UserID, input workforce.DepartmentInput, _ string) (workforce.DepartmentDetail, error) {
	if f.err != nil {
		return workforce.DepartmentDetail{}, f.err
	}
	f.createdCalls++
	f.departmentInput = input
	return workforce.DepartmentDetail{DepartmentID: workforce.DepartmentID("dep_created"), Name: input.Name}, nil
}

func (f *fakeMSCStatusWriter) UpdateDepartment(_ context.Context, _ identity.UserID, departmentID workforce.DepartmentID, patch workforce.DepartmentPatch, _ string) (workforce.DepartmentDetail, error) {
	if f.err != nil {
		return workforce.DepartmentDetail{}, f.err
	}
	f.departmentID = departmentID
	f.departmentPatch = patch
	return workforce.DepartmentDetail{DepartmentID: departmentID, Name: "updated"}, nil
}

func (f *fakeMSCStatusWriter) DeleteDepartment(_ context.Context, _ identity.UserID, departmentID workforce.DepartmentID, _ string) error {
	if f.err != nil {
		return f.err
	}
	f.departmentID = departmentID
	return nil
}

func mscSignedMutationRequest(t *testing.T, privateKey ed25519.PrivateKey, method, capability, target string, body []byte, actor string) *http.Request {
	t.Helper()
	requestID := "req_" + strings.Repeat("cd", 16)
	now := time.Now().UTC().Unix()
	digest := sha256.Sum256(body)
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
		"htm":         method,
		"htu":         target,
		"body_sha256": hex.EncodeToString(digest[:]),
		"actor":       actor,
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
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Request-ID", requestID)
	return request
}

func mscSignedWriteRequest(t *testing.T, privateKey ed25519.PrivateKey, capability, target string, body []byte, actor string) *http.Request {
	t.Helper()
	return mscSignedMutationRequest(t, privateKey, http.MethodPatch, capability, target, body, actor)
}

func mscWriteHandler(t *testing.T, writer *fakeMSCStatusWriter) (http.Handler, ed25519.PrivateKey) {
	t.Helper()
	verifier, privateKey := mscTestVerifier(t)
	handlers := NewMSCWriteHandlers(verifier, writer, mscWriteActorUserID, nil)
	router := chi.NewRouter()
	router.Use(RequestID)
	router.Patch("/internal/v1/msc/users/{userId}/status", handlers.UpdateUserStatus)
	router.Delete("/internal/v1/msc/users/{userId}/sessions", handlers.RevokeUserSessions)
	router.Post("/internal/v1/msc/employees/link", handlers.LinkEmployee)
	router.Put("/internal/v1/msc/users/{userId}/employee-profile", handlers.UpdateEmployee)
	router.Post("/internal/v1/msc/users/{userId}/offboarding", handlers.OffboardEmployee)
	router.Post("/internal/v1/msc/departments", handlers.CreateDepartment)
	router.Patch("/internal/v1/msc/departments/{departmentId}", handlers.UpdateDepartment)
	router.Delete("/internal/v1/msc/departments/{departmentId}", handlers.DeleteDepartment)
	return router, privateKey
}

func serveMSCWrite(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestUpdateUserStatusDisablesTarget(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"status":"disabled"}`)
	target := "/internal/v1/msc/users/user_target/status"
	request := mscSignedWriteRequest(t, privateKey, mscaccess.CapabilityUserWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if writer.calls != 1 {
		t.Fatalf("expected one mutation, got %d", writer.calls)
	}
	if writer.mutation.TargetUserID != identity.UserID("user_target") {
		t.Fatalf("target = %q", writer.mutation.TargetUserID)
	}
	if writer.mutation.Status != identity.UserStatusDisabled || !writer.mutation.RevokeSessions {
		t.Fatalf("unexpected mutation: %#v", writer.mutation)
	}
	if writer.mutation.ActorUserID != mscWriteActorUserID {
		t.Fatalf("actor = %q", writer.mutation.ActorUserID)
	}
	if writer.mutation.ActorLabel != "admin@moonstone.wtf" {
		t.Fatalf("actor label = %q", writer.mutation.ActorLabel)
	}
	if writer.mutation.RequestID == "" {
		t.Fatal("expected a request id on the mutation")
	}
	if !strings.Contains(recorder.Body.String(), `"status":"disabled"`) {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
}

func TestUpdateUserStatusEnablesTargetWithoutRevocation(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"status":"active"}`)
	target := "/internal/v1/msc/users/user_target/status"
	request := mscSignedWriteRequest(t, privateKey, mscaccess.CapabilityUserWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if writer.mutation.Status != identity.UserStatusActive || writer.mutation.RevokeSessions {
		t.Fatalf("unexpected mutation: %#v", writer.mutation)
	}
}

func TestUpdateUserStatusRejectsTamperedBody(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	target := "/internal/v1/msc/users/user_target/status"
	signed := mscSignedWriteRequest(t, privateKey, mscaccess.CapabilityUserWrite, target, []byte(`{"status":"disabled"}`), "admin@moonstone.wtf")
	request := httptest.NewRequest(http.MethodPatch, target, bytes.NewReader([]byte(`{"status":"active"}`)))
	request.Header.Set("Authorization", signed.Header.Get("Authorization"))
	request.Header.Set("X-Request-ID", signed.Header.Get("X-Request-ID"))
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if writer.calls != 0 {
		t.Fatal("expected no mutation for a tampered body")
	}
}

func TestUpdateUserStatusRejectsUnknownFields(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"status":"disabled","revokeSessions":false}`)
	target := "/internal/v1/msc/users/user_target/status"
	request := mscSignedWriteRequest(t, privateKey, mscaccess.CapabilityUserWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestUpdateUserStatusRejectsUnsupportedStatus(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"status":"pending"}`)
	target := "/internal/v1/msc/users/user_target/status"
	request := mscSignedWriteRequest(t, privateKey, mscaccess.CapabilityUserWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if writer.calls != 0 {
		t.Fatal("expected no mutation for an unsupported status")
	}
}

func TestUpdateUserStatusReportsSessionCleanupPending(t *testing.T) {
	writer := &fakeMSCStatusWriter{pending: true}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"status":"disabled"}`)
	target := "/internal/v1/msc/users/user_target/status"
	request := mscSignedWriteRequest(t, privateKey, mscaccess.CapabilityUserWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"sessionCleanupPending":true`) {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
}

func TestUpdateUserStatusMapsConflict(t *testing.T) {
	writer := &fakeMSCStatusWriter{err: workforce.ErrConflict}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"status":"active"}`)
	target := "/internal/v1/msc/users/user_target/status"
	request := mscSignedWriteRequest(t, privateKey, mscaccess.CapabilityUserWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", recorder.Code)
	}
}

func TestUpdateUserStatusFailsClosedWithoutWriter(t *testing.T) {
	verifier, _ := mscTestVerifier(t)
	router := chi.NewRouter()
	router.Use(RequestID)
	router.Patch("/internal/v1/msc/users/{userId}/status",
		NewMSCWriteHandlers(verifier, nil, mscWriteActorUserID, nil).UpdateUserStatus)
	request := httptest.NewRequest(http.MethodPatch, "/internal/v1/msc/users/user_target/status", bytes.NewReader([]byte(`{"status":"active"}`)))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestRevokeUserSessionsAcceptsEmptyBody(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	target := "/internal/v1/msc/users/user_target/sessions"
	request := mscSignedMutationRequest(t, privateKey, http.MethodDelete, mscaccess.CapabilityUserWrite, target, nil, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", recorder.Code, recorder.Body.String())
	}
	if len(writer.sessionsRevoked) != 1 || writer.sessionsRevoked[0] != "user_target" {
		t.Fatalf("unexpected revocations: %#v", writer.sessionsRevoked)
	}
}

func TestRevokeUserSessionsRejectsBody(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	target := "/internal/v1/msc/users/user_target/sessions"
	request := mscSignedMutationRequest(t, privateKey, http.MethodDelete, mscaccess.CapabilityUserWrite, target, nil, "admin@moonstone.wtf")
	replacement := httptest.NewRequest(http.MethodDelete, target, bytes.NewReader([]byte(`{"reason":"x"}`)))
	replacement.Header = request.Header
	recorder := serveMSCWrite(handler, replacement)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if len(writer.sessionsRevoked) != 0 {
		t.Fatal("expected no revocation for a mismatched request body")
	}
}

func TestUpdateEmployeeUsesPathUserAndEmployeeCapability(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"userId":"user_other","departmentId":"dep_engineering","title":"工程师"}`)
	target := "/internal/v1/msc/users/user_target/employee-profile"
	request := mscSignedMutationRequest(t, privateKey, http.MethodPut, mscaccess.CapabilityEmployeeWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if writer.employee.UserID != identity.UserID("user_target") {
		t.Fatalf("user = %q", writer.employee.UserID)
	}
	if writer.employee.DepartmentID != workforce.DepartmentID("dep_engineering") {
		t.Fatalf("department = %q", writer.employee.DepartmentID)
	}
}

func TestUpdateEmployeeRejectsWrongCapability(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"departmentId":"dep_engineering","title":"工程师"}`)
	target := "/internal/v1/msc/users/user_target/employee-profile"
	request := mscSignedMutationRequest(t, privateKey, http.MethodPut, mscaccess.CapabilityDepartmentWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if writer.employee.UserID != "" {
		t.Fatal("expected no employee mutation")
	}
}

func TestLinkEmployeeCreatesProfile(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"userId":"user_new","departmentId":"dep_engineering","title":"设计师"}`)
	target := "/internal/v1/msc/employees/link"
	request := mscSignedMutationRequest(t, privateKey, http.MethodPost, mscaccess.CapabilityEmployeeWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body.String())
	}
	if writer.employee.UserID != identity.UserID("user_new") {
		t.Fatalf("user = %q", writer.employee.UserID)
	}
}

func TestOffboardEmployeeReportsCleanupPending(t *testing.T) {
	writer := &fakeMSCStatusWriter{pending: true}
	handler, privateKey := mscWriteHandler(t, writer)
	target := "/internal/v1/msc/users/user_target/offboarding"
	request := mscSignedMutationRequest(t, privateKey, http.MethodPost, mscaccess.CapabilityEmployeeWrite, target, []byte(`{}`), "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if len(writer.offboarded) != 1 || writer.offboarded[0] != "user_target" {
		t.Fatalf("unexpected offboarding: %#v", writer.offboarded)
	}
	if !strings.Contains(recorder.Body.String(), `"sessionCleanupPending":true`) {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
}

func TestCreateDepartmentRequiresDepartmentCapability(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"name":"平台工程部"}`)
	target := "/internal/v1/msc/departments"
	request := mscSignedMutationRequest(t, privateKey, http.MethodPost, mscaccess.CapabilityDepartmentWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body.String())
	}
	if writer.departmentInput.Name != "平台工程部" {
		t.Fatalf("name = %q", writer.departmentInput.Name)
	}
}

func TestUpdateDepartmentAppliesOwnerPatch(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"name":"平台工程部","ownerUserId":"user_owner"}`)
	target := "/internal/v1/msc/departments/dep_engineering"
	request := mscSignedMutationRequest(t, privateKey, http.MethodPatch, mscaccess.CapabilityDepartmentWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if writer.departmentID != workforce.DepartmentID("dep_engineering") {
		t.Fatalf("department = %q", writer.departmentID)
	}
	if writer.departmentPatch.Name == nil || *writer.departmentPatch.Name != "平台工程部" {
		t.Fatalf("name patch = %#v", writer.departmentPatch.Name)
	}
	if writer.departmentPatch.OwnerUserID == nil || *writer.departmentPatch.OwnerUserID != identity.UserID("user_owner") {
		t.Fatalf("owner patch = %#v", writer.departmentPatch.OwnerUserID)
	}
	if writer.departmentPatch.ParentDepartmentID != nil {
		t.Fatalf("parent patch should be unset: %#v", writer.departmentPatch.ParentDepartmentID)
	}
}

func TestUpdateDepartmentRejectsInvalidIdentifier(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	body := []byte(`{"name":"平台工程部"}`)
	target := "/internal/v1/msc/departments/bad_id"
	request := mscSignedMutationRequest(t, privateKey, http.MethodPatch, mscaccess.CapabilityDepartmentWrite, target, body, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestDeleteDepartmentReturnsNoContent(t *testing.T) {
	writer := &fakeMSCStatusWriter{}
	handler, privateKey := mscWriteHandler(t, writer)
	target := "/internal/v1/msc/departments/dep_engineering"
	request := mscSignedMutationRequest(t, privateKey, http.MethodDelete, mscaccess.CapabilityDepartmentWrite, target, nil, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	if writer.departmentID != workforce.DepartmentID("dep_engineering") {
		t.Fatalf("department = %q", writer.departmentID)
	}
}

func TestDeleteDepartmentMapsNotEmptyConflict(t *testing.T) {
	writer := &fakeMSCStatusWriter{err: workforce.ErrDepartmentNotEmpty}
	handler, privateKey := mscWriteHandler(t, writer)
	target := "/internal/v1/msc/departments/dep_engineering"
	request := mscSignedMutationRequest(t, privateKey, http.MethodDelete, mscaccess.CapabilityDepartmentWrite, target, nil, "admin@moonstone.wtf")
	recorder := serveMSCWrite(handler, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", recorder.Code)
	}
}
