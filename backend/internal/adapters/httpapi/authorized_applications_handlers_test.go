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

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// stubGrantService satisfies AuthorizedApplicationService and records the
// calls it receives.
type stubGrantService struct {
	apps      []consent.AuthorizedApplication
	listErr   error
	revokeErr error

	listUser    identity.UserID
	revokeUser  identity.UserID
	revokeGrant consent.GrantID
	calls       int
	revokeCalls int
}

func (s *stubGrantService) ListAuthorizedApplications(_ context.Context, userID identity.UserID) ([]consent.AuthorizedApplication, error) {
	s.calls++
	s.listUser = userID
	return s.apps, s.listErr
}

func (s *stubGrantService) RevokeGrant(_ context.Context, userID identity.UserID, grantID consent.GrantID) error {
	s.revokeCalls++
	s.revokeUser = userID
	s.revokeGrant = grantID
	return s.revokeErr
}

const testGrantListUser = identity.UserID("user_actor")

// buildGrantRouter mounts the authorized-application routes and injects
// the authentication context RequireSession + RequireCSRF would have
// established in production.
func buildGrantRouter(svc *stubGrantService, injectPrincipal bool) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := request.WithID(req.Context(), "req-test-grant")
			if injectPrincipal {
				ctx = WithPrincipal(ctx, session.Principal{
					UserID:             testGrantListUser,
					SessionID:          session.SessionID("up-session-grant"),
					AuthenticationTime: time.Date(2026, 8, 6, 11, 55, 0, 0, time.UTC),
				})
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	handlers := NewAuthorizedApplicationHandlers(svc, discardLogger())
	r.Get("/me/authorized-applications", handlers.ListAuthorizedApplications)
	r.Delete("/me/authorized-applications/{grantId}", handlers.RevokeGrant)
	return r
}

func TestListAuthorizedApplicationsHappyPath(t *testing.T) {
	svc := &stubGrantService{apps: []consent.AuthorizedApplication{
		{
			GrantID:          consent.GrantID("grt_newer"),
			ApplicationID:    applications.ApplicationID("app_1"),
			ApplicationName:  "示例应用",
			ApplicationOwner: "砾石进化",
			ClientType:       applications.ClientType("confidential"),
			GrantedAt:        time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC),
			Scopes:           []string{"offline_access", "openid"},
			HasOfflineAccess: true,
		},
	}}
	router := buildGrantRouter(svc, true)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/me/authorized-applications", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control = %q", got)
	}
	if svc.listUser != testGrantListUser {
		t.Fatalf("listing ran for %q, want the authenticated principal", svc.listUser)
	}

	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("response is not a JSON array: %v (%s)", err, rec.Body.String())
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	row := rows[0]
	// Frozen contract shape: exactly these fields, nothing else.
	wantKeys := map[string]bool{
		"grantId": true, "applicationId": true, "applicationName": true,
		"applicationOwner": true, "clientType": true, "grantedAt": true,
		"lastUsedAt": true, "scopes": true, "hasOfflineAccess": true, "status": true,
	}
	if len(row) != len(wantKeys) {
		t.Fatalf("row keys = %v, want exactly the frozen contract shape", row)
	}
	for k := range wantKeys {
		if _, ok := row[k]; !ok {
			t.Fatalf("missing frozen field %q", k)
		}
	}
	if row["grantId"] != "grt_newer" || row["applicationId"] != "app_1" ||
		row["applicationName"] != "示例应用" || row["applicationOwner"] != "砾石进化" ||
		row["clientType"] != "confidential" || row["status"] != "active" {
		t.Fatalf("row = %v", row)
	}
	if row["grantedAt"] != "2026-08-05T10:00:00Z" {
		t.Fatalf("grantedAt = %v, want RFC3339 UTC", row["grantedAt"])
	}
	// lastUsedAt has no true signal on provider v2.71: always null.
	if row["lastUsedAt"] != nil {
		t.Fatalf("lastUsedAt = %v, want null (ADR-0005 §6)", row["lastUsedAt"])
	}
	if row["hasOfflineAccess"] != true {
		t.Fatalf("hasOfflineAccess = %v", row["hasOfflineAccess"])
	}
}

func TestListAuthorizedApplicationsEmptyStaysArray(t *testing.T) {
	router := buildGrantRouter(&stubGrantService{}, true)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/me/authorized-applications", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list must serialize as [], got %s", rec.Body.String())
	}
}

func TestListAuthorizedApplicationsRequiresSession(t *testing.T) {
	router := buildGrantRouter(&stubGrantService{}, false)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/me/authorized-applications", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestListAuthorizedApplicationsStoreFailureIs500(t *testing.T) {
	svc := &stubGrantService{listErr: errors.New("db exploded")}
	router := buildGrantRouter(svc, true)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/me/authorized-applications", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeGrantHappyPath(t *testing.T) {
	svc := &stubGrantService{}
	router := buildGrantRouter(svc, true)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/me/authorized-applications/grt_target", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("204 must carry no body, got %s", rec.Body.String())
	}
	if svc.revokeUser != testGrantListUser || svc.revokeGrant != consent.GrantID("grt_target") {
		t.Fatalf("revocation forwarded user=%q grant=%q", svc.revokeUser, svc.revokeGrant)
	}
}

func TestRevokeGrantRejectsMalformedID(t *testing.T) {
	svc := &stubGrantService{}
	router := buildGrantRouter(svc, true)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/me/authorized-applications/evil-injection", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if svc.revokeCalls != 0 {
		t.Fatal("malformed grant id must not reach the service")
	}
	body := decodeBody(t, rec)
	errBody := body["error"].(map[string]any)
	if errBody["code"] != CodeGrantNotFound {
		t.Fatalf("code = %v, want %s", errBody["code"], CodeGrantNotFound)
	}
}

func TestRevokeGrantNotFound(t *testing.T) {
	svc := &stubGrantService{revokeErr: consent.ErrGrantNotFound}
	router := buildGrantRouter(svc, true)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/me/authorized-applications/grt_foreign", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	errBody := body["error"].(map[string]any)
	// Foreign and unknown grants are indistinguishable: one stable class.
	if errBody["code"] != CodeGrantNotFound {
		t.Fatalf("code = %v, want %s", errBody["code"], CodeGrantNotFound)
	}
}

func TestRevokeGrantStoreFailureIs500(t *testing.T) {
	svc := &stubGrantService{revokeErr: errors.New("commit exploded")}
	router := buildGrantRouter(svc, true)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/me/authorized-applications/grt_target", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeGrantRequiresSession(t *testing.T) {
	router := buildGrantRouter(&stubGrantService{}, false)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/me/authorized-applications/grt_target", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
