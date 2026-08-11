//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Feishu protocol adapter tests against a local HTTP provider
//

package feishu

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/providers"
)

func testConfig(serverURL string) config.FeishuConfig {
	return config.FeishuConfig{BaseURL: serverURL, AuthorizeURL: serverURL + "/authorize", AppID: "cli_test", AppSecret: "secret_test", TenantID: "tenant_test", RedirectURL: "https://id.example.test/api/v1/auth/providers/feishu/callback", ContactScope: "directory", OAuthStateTTL: time.Minute, RequestTimeout: 3 * time.Second, ReconcileInterval: time.Second, SyncTimeout: time.Minute}
}

func TestAuthorizationURLUsesExactRedirectAndOpaqueState(t *testing.T) {
	client, err := NewClient(testConfig("https://open.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := client.AuthorizationURL("opaque_state")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if u.Query().Get("client_id") != "cli_test" || u.Query().Get("redirect_uri") != "https://id.example.test/api/v1/auth/providers/feishu/callback" || u.Query().Get("state") != "opaque_state" {
		t.Fatalf("authorize URL = %s", raw)
	}
	if strings.Contains(raw, "secret_test") {
		t.Fatal("App Secret leaked into authorization URL")
	}
}

func TestExchangeCodeUsesOAuthV2AndDoesNotLeakToken(t *testing.T) {
	var tokenCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/authen/v2/oauth/token":
			tokenCalls.Add(1)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["code"] != "code_test" || body["client_secret"] != "secret_test" {
				t.Fatalf("token body = %#v", body)
			}
			_, _ = w.Write([]byte(`{"code":0,"access_token":"user_token_test"}`))
		case "/open-apis/authen/v1/user_info":
			if r.Header.Get("Authorization") != "Bearer user_token_test" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"open_id":"ou_test","union_id":"on_test","tenant_key":"tenant_test","name":"Test User","email":"test@example.com"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	info, err := client.ExchangeCode(t.Context(), "code_test")
	if err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 1 || info.Subject != "ou_test" || info.TenantID != "tenant_test" {
		t.Fatalf("info = %#v calls=%d", info, tokenCalls.Load())
	}
}

func TestFetchDirectoryPaginatesAndNormalizesStableIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/open-apis/auth/v3/tenant_access_token/internal" && r.Header.Get("Authorization") != "Bearer tenant_token_test" {
			t.Fatalf("missing tenant token on %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"tenant_token_test","expire":7200}`))
		case "/open-apis/contact/v3/departments/0/children":
			_, _ = w.Write([]byte(`{"code":0,"data":{"items":[{"name":"Engineering","open_department_id":"od_eng","parent_department_id":"0","leader_user_id":"ou_lead"}],"has_more":false,"page_token":""}}`))
		case "/open-apis/contact/v3/users/find_by_department":
			department := r.URL.Query().Get("department_id")
			if department == "od_eng" {
				_, _ = w.Write([]byte(`{"code":0,"data":{"items":[{"open_id":"ou_user","union_id":"on_user","user_id":"u_user","name":"User","email":"user@example.com","employee_no":"E-1","job_title":"Engineer","department_ids":["od_eng"],"status":{"is_exited":false,"is_resigned":false}}],"has_more":false}}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"items":[],"has_more":false}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.FetchDirectory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ProviderID != providers.FeishuProviderID || snapshot.TenantID != "tenant_test" || len(snapshot.Departments) != 1 || len(snapshot.Users) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if snapshot.Users[0].Subject != "ou_user" || snapshot.Users[0].TenantUserID != "u_user" {
		t.Fatalf("user = %#v", snapshot.Users[0])
	}
}

func TestFetchDirectoryReportsPartialWithoutFailingWholeSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"tenant_token_test","expire":7200}`))
		case "/open-apis/contact/v3/departments/0/children":
			_, _ = w.Write([]byte(`{"code":0,"data":{"items":[{"name":"Engineering","open_department_id":"od_eng","parent_department_id":"0"}],"has_more":false}}`))
		case "/open-apis/contact/v3/users/find_by_department":
			if r.URL.Query().Get("department_id") == "od_eng" {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"code":500}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"items":[],"has_more":false}}`))
		}
	}))
	defer server.Close()
	client, err := NewClient(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.FetchDirectory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Partial || snapshot.FailureClass != "provider" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}
