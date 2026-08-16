//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Administration dashboard authorization and response tests
//

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/audit"
	"github.com/GravelEvolution/united-pass/backend/internal/dashboard"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

type dashboardRepositoryStub struct {
	snapshot dashboard.Snapshot
	err      error
	access   dashboard.Access
	calls    int
}

func (s *dashboardRepositoryStub) Load(_ context.Context, access dashboard.Access) (dashboard.Snapshot, error) {
	s.calls++
	s.access = access
	return s.snapshot, s.err
}

func dashboardTestRequest(authenticated bool) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/dashboard", nil)
	if authenticated {
		req = req.WithContext(WithPrincipal(req.Context(), session.Principal{
			UserID: "user_admin", SessionID: "session_admin",
		}))
	}
	return req
}

func decodeDashboardResponse(t *testing.T, recorder *httptest.ResponseRecorder) dashboardResponse {
	t.Helper()
	var response dashboardResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode dashboard response: %v", err)
	}
	return response
}

func TestDashboardRequiresAuthenticationAndAdminCapability(t *testing.T) {
	repository := &dashboardRepositoryStub{}
	handler := NewDashboardHandlers(repository, &stubPermResolver{}, nil)

	unauthenticated := httptest.NewRecorder()
	handler.Get(unauthenticated, dashboardTestRequest(false))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", unauthenticated.Code)
	}

	forbidden := httptest.NewRecorder()
	handler.Get(forbidden, dashboardTestRequest(true))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("no-capability status = %d, want 403", forbidden.Code)
	}
	if repository.calls != 0 {
		t.Fatal("repository must not be queried before authorization")
	}
}

func TestDashboardScopesAggregatesToReadCapabilities(t *testing.T) {
	repository := &dashboardRepositoryStub{snapshot: dashboard.Snapshot{
		ActiveUsers: 2, PendingUsers: 1, ActiveEmployees: 1,
		DeniedEvents30Days: 3,
		RecentEvents: []audit.Event{{
			EventID: "evt_1", EventType: "authorization.denied", ActorName: "Admin",
			ActorID: "user_admin", TargetLabel: "action", TargetID: "user.read",
			OccurredAt: time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC),
			Result:     "denied", RequestID: "req_1", Details: "user.read",
		}},
	}}
	handler := NewDashboardHandlers(repository, &stubPermResolver{caps: permissions.Capabilities{
		UserRead: true, AuditRead: true,
	}}, nil)

	recorder := httptest.NewRecorder()
	handler.Get(recorder, dashboardTestRequest(true))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !repository.access.Users || !repository.access.Audit || repository.access.Applications {
		t.Fatalf("unexpected repository access: %+v", repository.access)
	}
	response := decodeDashboardResponse(t, recorder)
	if len(response.Metrics) != 3 || len(response.RecentEvents) != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
	for _, metric := range response.Metrics {
		if metric.Label == "OAuth 应用" {
			t.Fatal("application aggregate leaked without application.read")
		}
	}
}

func TestDashboardAllowsOtherAdminCapabilitiesWithoutLeakingAggregates(t *testing.T) {
	repository := &dashboardRepositoryStub{}
	handler := NewDashboardHandlers(repository, &stubPermResolver{caps: permissions.Capabilities{
		ProviderRead: true,
	}}, nil)
	recorder := httptest.NewRecorder()
	handler.Get(recorder, dashboardTestRequest(true))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	response := decodeDashboardResponse(t, recorder)
	if len(response.Metrics) != 0 || len(response.RecentEvents) != 0 {
		t.Fatalf("unauthorized aggregates returned: %+v", response)
	}
}

func TestDashboardRepositoryFailureIsInternalError(t *testing.T) {
	repository := &dashboardRepositoryStub{err: errors.New("storage unavailable")}
	handler := NewDashboardHandlers(repository, &stubPermResolver{caps: permissions.Capabilities{
		ApplicationRead: true,
	}}, nil)
	recorder := httptest.NewRecorder()
	handler.Get(recorder, dashboardTestRequest(true))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
}
