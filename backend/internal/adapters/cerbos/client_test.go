package cerbos

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

func TestClientPublishUsesAdminAuthAndCompilesDenyFallback(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/policy" || r.Method != http.MethodPut {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "private" {
			t.Fatal("missing or incorrect Admin API basic authentication")
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":{}}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.URL, "admin", "private", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	policy := policies.PublishedPolicy{
		PolicyID: "pol_0123456789abcdef", Version: 3, Effect: policies.EffectDeny,
		Principals: []policies.Clause{{Attribute: "department", Operator: policies.OperatorEqual, Value: `ops"team`}},
	}
	if err := client.Publish(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(body)
	var envelope struct {
		Policies []resourcePolicyDocument `json:"policies"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Policies) != 1 || len(envelope.Policies[0].ResourcePolicy.Rules) != 2 {
		t.Fatalf("compiled policy did not contain match + deny fallback: %#v", envelope)
	}
	if got := envelope.Policies[0].ResourcePolicy.Rules[0].Condition.Match.Expr; got != `request.principal.attr.department == "ops\"team"` {
		t.Fatalf("condition expression = %q", got)
	}
}

func TestClientCheckCorrelatesDecisions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request checkRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Principal.ID != "user_1" || len(request.Resources) != 2 {
			t.Fatalf("unexpected request: %#v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"resource":{"id":"pol_allow","kind":"united_pass_pol_allow","policyVersion":"1","attr":{}},"actions":{"evaluate":"EFFECT_ALLOW"}},{"resource":{"id":"pol_deny","kind":"united_pass_pol_deny","policyVersion":"2","attr":{}},"actions":{"evaluate":"EFFECT_DENY"}}]}`))
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, server.URL, "admin", "private", server.Client())
	decisions, err := client.Check(context.Background(), "req", Principal{ID: "user_1", Roles: []string{"authenticated"}}, []ResourceCheck{{PolicyID: "pol_allow", Version: 1}, {PolicyID: "pol_deny", Version: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if !decisions[0].Allowed || decisions[1].Allowed {
		t.Fatalf("decisions = %#v", decisions)
	}
}

func TestClientFailsClosedOnIncompleteResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, server.URL, "admin", "private", server.Client())
	if _, err := client.Check(context.Background(), "", Principal{ID: "user"}, []ResourceCheck{{PolicyID: "pol_allow", Version: 1}}); err == nil {
		t.Fatal("incomplete response must fail closed")
	}
}

func TestClientReadyChecksPDPAndAuthenticatedAdminAPI(t *testing.T) {
	var healthChecked, adminChecked bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_cerbos/health":
			healthChecked = true
		case "/admin/policies":
			username, password, ok := r.BasicAuth()
			if !ok || username != "admin" || password != "private" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			adminChecked = true
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, server.URL, "admin", "private", server.Client())
	if err := client.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !healthChecked || !adminChecked {
		t.Fatalf("healthChecked=%v adminChecked=%v", healthChecked, adminChecked)
	}
}
