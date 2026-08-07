//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the client management handlers
//

package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

const validClientBody = `{
  "name": "新增客户端", "profile": "web_server",
  "redirectUris": ["https://app.example.com/callback"],
  "allowedScopes": ["openid", "profile"], "consentMode": "always"
}`

const validPublicClientBody = `{
  "name": "SPA 新增客户端", "profile": "spa_mobile",
  "redirectUris": ["https://spa.example.com/callback"],
  "allowedScopes": ["openid"], "consentMode": "first_authorization"
}`

// doClientRequestWithReauth issues a request with an optional reauthentication
// token header, mirroring doAppRequest otherwise.
func doClientRequestWithReauth(handler http.Handler, method, path, body, reauthToken string, withCSRF bool) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if withCSRF {
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-token"})
		req.Header.Set(CSRFHeaderName, "csrf-token")
	}
	if reauthToken != "" {
		req.Header.Set("X-Reauthentication-Token", reauthToken)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// --- Create client ---

func TestCreateClient_ConfidentialSuccess(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients", validClientBody, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp clientCreationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(resp.ClientID, "clt_") {
		t.Errorf("clientId = %q, want clt_ prefix", resp.ClientID)
	}
	if resp.ClientSecret == "" {
		t.Fatal("confidential client must include the one-time secret")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Request-ID"); got != "req-test-1" {
		t.Errorf("X-Request-ID = %q, want req-test-1", got)
	}

	// The detail view never returns the secret value, only metadata.
	rec = doAppRequest(router, http.MethodGet, "/admin/applications/"+appID+"/clients/"+resp.ClientID, "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), resp.ClientSecret) {
		t.Error("detail must never contain the raw secret")
	}
}

func TestCreateClient_PublicNoSecret(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients", validPublicClientBody, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp clientCreationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ClientSecret != "" {
		t.Fatal("public client must never receive a secret")
	}
}

func TestCreateClient_UnknownOrMalformedApp404(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/app_missing/clients", validClientBody, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	rec = doAppRequest(router, http.MethodPost, "/admin/applications/bogus/clients", validClientBody, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestCreateClient_ProfileValidation422(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)

	cases := []struct {
		name  string
		body  string
		field string
	}{
		{
			name:  "server_to_server rejected as unsupported provider capability",
			body:  `{"name": "S2S 客户端", "profile": "server_to_server", "redirectUris": [], "allowedScopes": ["profile"], "consentMode": "always"}`,
			field: "profile",
		},
		{
			name:  "invalid redirect uri reports the index",
			body:  `{"name": "新增客户端", "profile": "web_server", "redirectUris": ["http://insecure.example.com/cb"], "allowedScopes": ["openid"], "consentMode": "always"}`,
			field: "redirectUris[0]",
		},
		{
			name:  "unknown profile",
			body:  `{"name": "新增客户端", "profile": "bogus", "redirectUris": ["https://x.example.com/cb"], "allowedScopes": ["openid"], "consentMode": "always"}`,
			field: "profile",
		},
		{
			name:  "unknown consent mode rejected",
			body:  `{"name": "新增客户端", "profile": "web_server", "redirectUris": ["https://x.example.com/cb"], "allowedScopes": ["openid"], "consentMode": "trusted_first_party"}`,
			field: "consentMode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients", tc.body, true)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
			}
			body := decodeErrorBody(t, rec)
			if body.Code != CodeValidation {
				t.Errorf("code = %q, want %q", body.Code, CodeValidation)
			}
			found := false
			for _, fe := range body.FieldErrors {
				if fe.Field == tc.field {
					found = true
				}
			}
			if !found {
				t.Errorf("field errors = %+v, want field %q", body.FieldErrors, tc.field)
			}
		})
	}
}

func TestCreateClient_RejectsUnknownField(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)

	body := `{"name": "新增客户端", "profile": "web_server", "redirectUris": ["https://x.example.com/cb"], "allowedScopes": ["openid"], "consentMode": "always", "profileExtra": true}`
	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients", body, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateClient_ForbiddenRecordsDenied(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)

	env.resolver.caps = permissions.Capabilities{}
	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients", validClientBody, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !env.events.denied(applications.EventOAuthClientCreated) {
		t.Error("expected denied audit event for client create")
	}
}

func TestCreateClient_ProviderUnavailable502(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)
	env.prov.ProvisionErr = applications.ErrProviderUnavailable

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients", validClientBody, true)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeProviderUnavailable {
		t.Errorf("code = %q, want %q", body.Code, CodeProviderUnavailable)
	}
}

func TestCreateClient_ProviderConflict409(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)
	env.prov.ProvisionErr = applications.ErrProviderConflict

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients", validClientBody, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

// --- Client detail ---

func TestGetClient_DetailShape(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodGet, "/admin/applications/"+appID+"/clients/"+clientID, "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp clientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ClientID != clientID || resp.ApplicationID != appID {
		t.Errorf("ids = %s/%s, want %s/%s", resp.ClientID, resp.ApplicationID, clientID, appID)
	}
	// grantTypes are derived from the stored profile, never client-submitted.
	wantGrants := []string{"authorization_code", "refresh_token"}
	if len(resp.GrantTypes) != len(wantGrants) {
		t.Fatalf("grantTypes = %v, want %v", resp.GrantTypes, wantGrants)
	}
	for i, gt := range wantGrants {
		if resp.GrantTypes[i] != gt {
			t.Errorf("grantTypes[%d] = %q, want %q", i, resp.GrantTypes[i], gt)
		}
	}
	if resp.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("tokenEndpointAuthMethod = %q", resp.TokenEndpointAuthMethod)
	}
	if len(resp.ClientSecrets) != 1 {
		t.Errorf("clientSecrets = %d entries, want 1 metadata record", len(resp.ClientSecrets))
	}
	if resp.LogoutURI != nil {
		t.Errorf("logoutUri = %v, want null", *resp.LogoutURI)
	}
}

func TestGetClient_AntiEnumeration404(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	otherAppID := createAppViaAPI(t, env, router, validPublicCreateBody)

	cases := []string{
		"/admin/applications/" + appID + "/clients/clt_missing",      // unknown client
		"/admin/applications/" + appID + "/clients/bogus",            // malformed shape
		"/admin/applications/" + otherAppID + "/clients/" + clientID, // bound to another app
		"/admin/applications/app_missing/clients/" + clientID,
	}
	for _, path := range cases {
		rec := doAppRequest(router, http.MethodGet, path, "", false)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want 404", path, rec.Code)
		}
	}
}

func TestGetClient_RequiresReadCapability(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	env.resolver.caps = permissions.Capabilities{}

	rec := doAppRequest(router, http.MethodGet, "/admin/applications/"+appID+"/clients/"+clientID, "", false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// --- Update client ---

func TestUpdateClient_EmptyBody400(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/"+appID+"/clients/"+clientID, `{}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateClient_ProfileImmutable(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)

	// Submitting profile is an unknown field: it can never be mutated.
	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/"+appID+"/clients/"+clientID, `{"profile": "spa_mobile"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateClient_Success(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)

	body := `{
	  "name": "重命名客户端",
	  "redirectUris": ["https://new.example.com/callback", "http://127.0.0.1:8080/cb"],
	  "logoutUri": "https://new.example.com/logout",
	  "allowedScopes": ["openid", "email"]
	}`
	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/"+appID+"/clients/"+clientID, body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp clientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "重命名客户端" {
		t.Errorf("name = %q", resp.Name)
	}
	if len(resp.RedirectURIs) != 2 {
		t.Fatalf("redirectUris = %d entries, want 2 (full replacement)", len(resp.RedirectURIs))
	}
	// Stored exactly as submitted: no normalization ever applied.
	if resp.RedirectURIs[1].URI != "http://127.0.0.1:8080/cb" || !resp.RedirectURIs[1].IsLoopback {
		t.Errorf("loopback uri = %+v", resp.RedirectURIs[1])
	}
	if resp.LogoutURI == nil || *resp.LogoutURI != "https://new.example.com/logout" {
		t.Errorf("logoutUri = %v", resp.LogoutURI)
	}
	if len(resp.AllowedScopes) != 2 {
		t.Errorf("allowedScopes = %d entries, want 2", len(resp.AllowedScopes))
	}

	// The provider received the synchronized settings.
	stored := env.store.clients[applications.OAuthClientID(clientID)]
	fake := env.prov.Client(stored.ProviderApplicationID)
	if fake == nil || fake.DisplayName != applications.ProviderDisplayName("测试应用", "重命名客户端", applications.OAuthClientID(clientID)) {
		t.Errorf("provider client not synchronized: %+v", fake)
	}
}

func TestUpdateClient_InvalidRedirectURI422(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/"+appID+"/clients/"+clientID,
		`{"redirectUris": ["https://ok.example.com/cb", "http://wild*.example.com/cb"]}`, true)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeErrorBody(t, rec)
	found := false
	for _, fe := range body.FieldErrors {
		if fe.Field == "redirectUris[1]" {
			found = true
		}
	}
	if !found {
		t.Errorf("field errors = %+v, want redirectUris[1]", body.FieldErrors)
	}
}

func TestUpdateClient_InvalidConsentMode422(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/"+appID+"/clients/"+clientID,
		`{"consentMode": "trusted_first_party"}`, true)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateClient_ProviderFailureLeavesLocalUnchanged(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	before := env.store.clients[applications.OAuthClientID(clientID)]
	env.prov.UpdateErr = applications.ErrProviderUnavailable

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/"+appID+"/clients/"+clientID,
		`{"name": "新名字"}`, true)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
	after := env.store.clients[applications.OAuthClientID(clientID)]
	if after.Name != before.Name || after.Version != before.Version {
		t.Error("local state must stay unchanged on provider failure")
	}
}

func TestUpdateClient_VersionConflict409(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	env.store.updateClientErr = applications.ErrConflict

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/"+appID+"/clients/"+clientID,
		`{"name": "新名字"}`, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateClient_NotFound404(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, _ := createAppAndClientViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPatch, "/admin/applications/"+appID+"/clients/clt_missing",
		`{"name": "新名字"}`, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// --- Enable / Disable client ---

func TestSetClientStatus_DisableThenEnable(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients/"+clientID+"/disable", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp clientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "disabled" {
		t.Errorf("status = %q, want disabled", resp.Status)
	}
	stored := env.store.clients[applications.OAuthClientID(clientID)]
	fake := env.prov.Client(stored.ProviderApplicationID)
	if fake == nil || !fake.Disabled {
		t.Error("provider client must be disabled")
	}

	rec = doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients/"+clientID+"/enable", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "active" {
		t.Errorf("status = %q, want active", resp.Status)
	}
}

func TestEnableClient_AlreadyActive409(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients/"+clientID+"/enable", "", true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSetClientStatus_ProviderFailureFailsClosed(t *testing.T) {
	env := newAppEnv(nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	env.prov.DisableErr = applications.ErrProviderUnavailable

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients/"+clientID+"/disable", "", true)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
	if got := env.store.clients[applications.OAuthClientID(clientID)].Status; got != applications.StatusActive {
		t.Errorf("local status = %s, want active (fail closed)", got)
	}
}

// --- Delete client ---

func TestDeleteClient_ReauthFailClosed(t *testing.T) {
	env := newAppEnv(nil) // nil reauth verifier: fail closed
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)

	rec := doClientRequestWithReauth(router, http.MethodDelete,
		"/admin/applications/"+appID+"/clients/"+clientID, "", "reauth-token", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeReauthenticationReq {
		t.Errorf("code = %q, want %q", body.Code, CodeReauthenticationReq)
	}
	if !env.events.denied(applications.EventOAuthClientDeleted) {
		t.Error("expected denied audit event for client delete")
	}
}

func TestDeleteClient_TokenRequired(t *testing.T) {
	verifier := &fakeReauthVerifier{validToken: "reauth-good"}
	env := newAppEnv(verifier)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	path := "/admin/applications/" + appID + "/clients/" + clientID

	// Missing token.
	rec := doClientRequestWithReauth(router, http.MethodDelete, path, "", "", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing token: status = %d, want 403", rec.Code)
	}
	// Wrong token.
	rec = doClientRequestWithReauth(router, http.MethodDelete, path, "", "reauth-bad", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad token: status = %d, want 403", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeReauthenticationReq {
		t.Errorf("code = %q, want %q", body.Code, CodeReauthenticationReq)
	}
	if !env.events.denied(applications.EventOAuthClientDeleted) {
		t.Error("expected denied audit event")
	}
}

func TestDeleteClient_SuccessConsumesToken(t *testing.T) {
	verifier := &fakeReauthVerifier{validToken: "reauth-good"}
	env := newAppEnv(verifier)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	path := "/admin/applications/" + appID + "/clients/" + clientID

	rec := doClientRequestWithReauth(router, http.MethodDelete, path, "", "reauth-good", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if !verifier.consumed {
		t.Error("reauthentication token must be consumed")
	}

	// The token cannot be reused.
	rec = doClientRequestWithReauth(router, http.MethodDelete, path, "", "reauth-good", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reuse status = %d, want 403", rec.Code)
	}

	// The client is gone; detail yields the same 404 as never-existing.
	rec = doAppRequest(router, http.MethodGet, path, "", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("detail status = %d, want 404", rec.Code)
	}
	// The provider resource was removed.
	if env.prov.ClientCount() != 0 {
		t.Errorf("provider clients = %d, want 0", env.prov.ClientCount())
	}
}

// --- Secret rotation ---

type fakeRotationChecker struct {
	allow bool
	err   error
	calls int
}

func (f *fakeRotationChecker) CheckRotation(_ context.Context, _, _ string, _ int, _ time.Duration) (bool, time.Duration, error) {
	f.calls++
	return f.allow, 30 * time.Second, f.err
}

// newRotationAppEnv mirrors newAppEnv but wires a rotation rate checker.
func newRotationAppEnv(reauth ReauthVerifier, rates RotationRateChecker) *appEnv {
	store := newFakeAppStore()
	prov := applications.NewFakeProvisioner()
	events := &captureEvents{}
	svc := applications.NewService(store, prov, events, stubAuditReader{},
		&stubUserLookup{exists: map[string]bool{"user_owner_1": true}}, "fake", "proj_test", 0)
	resolver := &stubPermResolver{caps: permissions.AllCapabilities()}
	return &appEnv{
		store:    store,
		prov:     prov,
		events:   events,
		resolver: resolver,
		reauth:   reauth,
		handlers: NewApplicationHandlers(svc, resolver, reauth, rates, 3, 15*time.Minute, slog.Default()),
	}
}

func TestRotateClientSecret_SuccessOneTimeSecret(t *testing.T) {
	verifier := &fakeReauthVerifier{validToken: "reauth-good"}
	rates := &fakeRotationChecker{allow: true}
	env := newRotationAppEnv(verifier, rates)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	path := "/admin/applications/" + appID + "/clients/" + clientID + "/secret-rotations"

	rec := doClientRequestWithReauth(router, http.MethodPost, path, "", "reauth-good", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
	var body struct {
		SecretID                string `json:"secretId"`
		ClientSecret            string `json:"clientSecret"`
		PreviousSecretExpiresAt string `json:"previousSecretExpiresAt"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.SecretID == "" || body.ClientSecret == "" || body.PreviousSecretExpiresAt == "" {
		t.Errorf("body = %+v, want secretId + one-time clientSecret + expiry", body)
	}
	if rates.calls != 1 {
		t.Errorf("rate limiter calls = %d, want 1", rates.calls)
	}
	if fc := env.prov.Client("fake-app-1"); fc == nil || fc.SecretVersion != 2 {
		t.Error("provider secret must have been rotated exactly once")
	}

	// The consumed reauth token cannot authorize a second rotation.
	rec = doClientRequestWithReauth(router, http.MethodPost, path, "", "reauth-good", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reuse status = %d, want 403", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeReauthenticationReq {
		t.Errorf("code = %q, want %q", body.Code, CodeReauthenticationReq)
	}
}

func TestRotateClientSecret_RequiresToken(t *testing.T) {
	env := newRotationAppEnv(&fakeReauthVerifier{validToken: "reauth-good"}, &fakeRotationChecker{allow: true})
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	path := "/admin/applications/" + appID + "/clients/" + clientID + "/secret-rotations"

	rec := doClientRequestWithReauth(router, http.MethodPost, path, "", "", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if body := decodeErrorBody(t, rec); body.Code != CodeReauthenticationReq {
		t.Errorf("code = %q, want %q", body.Code, CodeReauthenticationReq)
	}
}

func TestRotateClientSecret_RequiresCapability(t *testing.T) {
	env := newRotationAppEnv(&fakeReauthVerifier{validToken: "reauth-good"}, &fakeRotationChecker{allow: true})
	env.resolver.caps = permissions.Capabilities{ApplicationRead: true, ApplicationManage: true}
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	path := "/admin/applications/" + appID + "/clients/" + clientID + "/secret-rotations"

	rec := doClientRequestWithReauth(router, http.MethodPost, path, "", "reauth-good", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !env.events.denied(applications.EventSecretRotationFailed) {
		t.Error("expected denied rotation audit event")
	}
}

func TestRotateClientSecret_RateLimited(t *testing.T) {
	rates := &fakeRotationChecker{allow: false}
	env := newRotationAppEnv(&fakeReauthVerifier{validToken: "reauth-good"}, rates)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	path := "/admin/applications/" + appID + "/clients/" + clientID + "/secret-rotations"

	rec := doClientRequestWithReauth(router, http.MethodPost, path, "", "reauth-good", true)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	for _, call := range env.prov.Calls {
		if call == "rotate" {
			t.Fatal("rate-limited rotation must never reach the provider")
		}
	}
}

func TestRotateClientSecret_PublicClient422(t *testing.T) {
	env := newRotationAppEnv(&fakeReauthVerifier{validToken: "reauth-good"}, &fakeRotationChecker{allow: true})
	router := buildAppRouter(env, true)
	appID := createAppViaAPI(t, env, router, validCreateBody)

	rec := doAppRequest(router, http.MethodPost, "/admin/applications/"+appID+"/clients", validPublicClientBody, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup create: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ClientID string `json:"clientId"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	path := "/admin/applications/" + appID + "/clients/" + created.ClientID + "/secret-rotations"
	rec = doClientRequestWithReauth(router, http.MethodPost, path, "", "reauth-good", true)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRotateClientSecret_MalformedIDs404(t *testing.T) {
	env := newRotationAppEnv(&fakeReauthVerifier{validToken: "reauth-good"}, &fakeRotationChecker{allow: true})
	router := buildAppRouter(env, true)

	rec := doClientRequestWithReauth(router, http.MethodPost,
		"/admin/applications/bogus/clients/clt_x/secret-rotations", "", "reauth-good", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRotateClientSecret_NilRateCheckerFailsClosed(t *testing.T) {
	env := newRotationAppEnv(&fakeReauthVerifier{validToken: "reauth-good"}, nil)
	router := buildAppRouter(env, true)
	appID, clientID := createAppAndClientViaAPI(t, env, router, validCreateBody)
	path := "/admin/applications/" + appID + "/clients/" + clientID + "/secret-rotations"

	rec := doClientRequestWithReauth(router, http.MethodPost, path, "", "reauth-good", true)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (fail closed)", rec.Code)
	}
}
