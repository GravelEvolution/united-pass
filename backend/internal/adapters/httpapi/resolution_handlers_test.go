package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/httpapi/request"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// stubConsentResolver records the input it receives and returns canned
// outcomes.
type stubConsentResolver struct {
	resolution consent.Resolution
	err        error
	lastInput  consent.ResolutionInput
	calls      int
}

func (s *stubConsentResolver) Resolve(_ context.Context, input consent.ResolutionInput) (consent.Resolution, error) {
	s.lastInput = input
	s.calls++
	return s.resolution, s.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// buildResolutionRouter mounts the resolution route behind optional
// principal injection, mirroring the bootstrap OptionalSession wiring.
func buildResolutionRouter(resolver *stubConsentResolver, injectSession bool) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := request.WithID(req.Context(), "req-test-1")
			if injectSession {
				ctx = WithPrincipal(ctx, session.Principal{
					UserID:             identity.UserID("user_actor"),
					AuthenticationTime: time.Date(2026, 8, 6, 11, 55, 0, 0, time.UTC),
				})
			}
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	handlers := NewAuthorizationHandlers(resolver, discardLogger())
	r.Get("/authorization/requests/{requestId}", handlers.ResolveRequest)
	return r
}

func doGet(t *testing.T, router http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body
}

func TestResolveRequestValidShape(t *testing.T) {
	resolver := &stubConsentResolver{resolution: consent.Resolution{
		Status:                 consent.ResolutionValid,
		AuthRequestID:          "V2-request-1",
		ApplicationName:        "Example App",
		ApplicationDescription: "desc",
		ApplicationOwner:       "Owner",
		RedirectHost:           "rp.example",
		Scopes: []consent.ResolutionScope{
			{Scope: "openid", Label: "OpenID", Description: "获取基本身份标识"},
		},
	}}
	router := buildResolutionRouter(resolver, true)

	rec := doGet(t, router, "/authorization/requests/V2-request-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control = %q", got)
	}
	body := decodeBody(t, rec)
	if body["status"] != "valid" {
		t.Fatalf("body = %v", body)
	}
	req, ok := body["request"].(map[string]any)
	if !ok {
		t.Fatalf("request missing: %v", body)
	}
	if req["requestId"] != "V2-request-1" || req["applicationName"] != "Example App" ||
		req["applicationDescription"] != "desc" || req["applicationOwner"] != "Owner" ||
		req["redirectHost"] != "rp.example" {
		t.Fatalf("request fields: %v", req)
	}
	scopes, ok := req["scopes"].([]any)
	if !ok || len(scopes) != 1 {
		t.Fatalf("scopes: %v", req["scopes"])
	}
	scope := scopes[0].(map[string]any)
	if scope["scope"] != "openid" || scope["label"] != "OpenID" || scope["description"] != "获取基本身份标识" {
		t.Fatalf("scope entry: %v", scope)
	}
	// The frozen union has no user-identity field on the resolution body.
	if _, exists := body["user"]; exists {
		t.Fatal("unexpected user field in resolution response")
	}
	if resolver.lastInput.Session == nil || resolver.lastInput.Session.UserID != "user_actor" {
		t.Fatalf("session not forwarded: %+v", resolver.lastInput)
	}
	if !resolver.lastInput.Session.AuthenticationTime.Equal(time.Date(2026, 8, 6, 11, 55, 0, 0, time.UTC)) {
		t.Fatalf("authentication time not forwarded: %+v", resolver.lastInput.Session)
	}
}

func TestResolveRequestAnonymousHasNoSession(t *testing.T) {
	resolver := &stubConsentResolver{resolution: consent.Resolution{
		Status:        consent.ResolutionUnauthenticated,
		AuthRequestID: "V2-request-1",
	}}
	router := buildResolutionRouter(resolver, false)

	rec := doGet(t, router, "/authorization/requests/V2-request-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["status"] != "unauthenticated" || body["requestId"] != "V2-request-1" {
		t.Fatalf("body = %v", body)
	}
	if resolver.lastInput.Session != nil {
		t.Fatalf("unexpected session: %+v", resolver.lastInput.Session)
	}
}

func TestResolveRequestUnionShapes(t *testing.T) {
	expiredAt := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		resolution consent.Resolution
		want       map[string]any
	}{
		{
			name: "expired",
			resolution: consent.Resolution{
				Status: consent.ResolutionExpired, AuthRequestID: "req-1", ExpiredAt: expiredAt,
			},
			want: map[string]any{"status": "expired", "requestId": "req-1", "expiredAt": "2026-08-06T12:00:00Z"},
		},
		{
			name: "client_not_found",
			resolution: consent.Resolution{
				Status: consent.ResolutionClientNotFound, AuthRequestID: "req-1",
			},
			want: map[string]any{"status": "client_not_found", "requestId": "req-1"},
		},
		{
			name: "redirect_mismatch",
			resolution: consent.Resolution{
				Status: consent.ResolutionRedirectMismatch, AuthRequestID: "req-1",
				AttemptedRedirectHost: "evil.example",
			},
			want: map[string]any{
				"status": "redirect_mismatch", "requestId": "req-1", "attemptedRedirect": "evil.example",
			},
		},
		{
			name: "scope_not_allowed",
			resolution: consent.Resolution{
				Status: consent.ResolutionScopeNotAllowed, AuthRequestID: "req-1",
				DisallowedScopes: []string{"admin:read"},
			},
			want: map[string]any{
				"status": "scope_not_allowed", "requestId": "req-1",
				"disallowedScopes": []any{"admin:read"},
			},
		},
		{
			name: "already_authorized",
			resolution: consent.Resolution{
				Status: consent.ResolutionAlreadyAuthorized, AuthRequestID: "req-1",
				ApplicationName: "Example App", RedirectHost: "rp.example",
			},
			want: map[string]any{
				"status": "already_authorized", "requestId": "req-1",
				"applicationName": "Example App", "redirectHost": "rp.example",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &stubConsentResolver{resolution: tc.resolution}
			router := buildResolutionRouter(resolver, true)

			rec := doGet(t, router, "/authorization/requests/req-1")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			body := decodeBody(t, rec)
			if len(body) != len(tc.want) {
				t.Fatalf("body keys = %v, want %v", body, tc.want)
			}
			for key, want := range tc.want {
				if got, ok := body[key]; !ok || !jsonEqual(got, want) {
					t.Fatalf("body[%s] = %v, want %v", key, got, want)
				}
			}
		})
	}
}

func jsonEqual(a, b any) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

func TestResolveRequestRejectsMalformedID(t *testing.T) {
	resolver := &stubConsentResolver{}
	router := buildResolutionRouter(resolver, false)

	longID := make([]rune, consent.MaxAuthRequestIDLen+1)
	for i := range longID {
		longID[i] = 'a'
	}
	rec := doGet(t, router, "/authorization/requests/"+string(longID))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	errBody := body["error"].(map[string]any)
	if errBody["code"] != CodeBadRequest {
		t.Fatalf("code = %v", errBody["code"])
	}
	if resolver.calls != 0 {
		t.Fatal("resolver called for malformed id")
	}
}

func TestResolveRequestNotInteractive(t *testing.T) {
	resolver := &stubConsentResolver{err: consent.ErrResolutionNotInteractive}
	router := buildResolutionRouter(resolver, false)

	rec := doGet(t, router, "/authorization/requests/req-1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	errBody := body["error"].(map[string]any)
	if errBody["code"] != CodeInteractionNotSupported {
		t.Fatalf("code = %v", errBody["code"])
	}
}

func TestResolveRequestProviderUnavailable(t *testing.T) {
	for _, class := range []consent.ErrorClass{consent.ClassProviderUnavailable, consent.ClassRateLimited} {
		resolver := &stubConsentResolver{err: consent.NewProviderError(class, nil)}
		router := buildResolutionRouter(resolver, false)

		rec := doGet(t, router, "/authorization/requests/req-1")
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("%s: status = %d", class, rec.Code)
		}
		body := decodeBody(t, rec)
		errBody := body["error"].(map[string]any)
		if errBody["code"] != CodeProviderUnavailable {
			t.Fatalf("%s: code = %v", class, errBody["code"])
		}
	}
}

func TestResolveRequestUnexpectedProviderClassIsInternal(t *testing.T) {
	resolver := &stubConsentResolver{err: consent.NewProviderError(consent.ClassInternal, nil)}
	router := buildResolutionRouter(resolver, false)

	rec := doGet(t, router, "/authorization/requests/req-1")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	errBody := body["error"].(map[string]any)
	if errBody["code"] != CodeInternal {
		t.Fatalf("code = %v", errBody["code"])
	}
}

func TestResolveRequestStoreFailureIsInternal(t *testing.T) {
	resolver := &stubConsentResolver{err: context.DeadlineExceeded}
	router := buildResolutionRouter(resolver, false)

	rec := doGet(t, router, "/authorization/requests/req-1")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestResolveRequestVanishedUserStaysInUnion(t *testing.T) {
	// identity.ErrUserNotFound must degrade into the frozen union, never
	// into a 401 error body that escapes the ConsentResolution contract.
	resolver := &stubConsentResolver{err: identity.ErrUserNotFound}
	router := buildResolutionRouter(resolver, true)

	rec := doGet(t, router, "/authorization/requests/req-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["status"] != "unauthenticated" || body["requestId"] != "req-1" || len(body) != 2 {
		t.Fatalf("body = %v, want the frozen unauthenticated shape", body)
	}
}
