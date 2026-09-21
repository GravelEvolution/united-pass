package wechat

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wechatdomain "github.com/GravelEvolution/united-pass/backend/internal/wechat"
)

func TestVerifyRegistrationUsesServerSideExchangesAndReturnsOnlyProof(t *testing.T) {
	t.Helper()
	requests := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/sns/jscode2session":
			if r.URL.Query().Get("js_code") != "login-code" || r.URL.Query().Get("appid") != "test-app" {
				t.Fatalf("unexpected login query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"openid":"open-id","unionid":"union-id","session_key":"secret-session-key"}`))
		case "/cgi-bin/token":
			if r.URL.Query().Get("grant_type") != "client_credential" {
				t.Fatalf("unexpected token query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"access_token":"provider-access-token"}`))
		case "/wxa/business/getuserphonenumber":
			if r.URL.Query().Get("access_token") != "provider-access-token" {
				t.Fatalf("missing provider access token")
			}
			_, _ = w.Write([]byte(`{"phone_info":{"phoneNumber":"+8613800138000"}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{AppID: "test-app", AppSecret: "test-secret", APIBaseURL: server.URL, RequestTimeout: time.Second}, server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	proof, err := client.VerifyRegistration(context.Background(), "login-code", "phone-code")
	if err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}
	if proof != (wechatdomain.IdentityProof{TenantID: "test-app", Subject: "open-id", Phone: "+8613800138000"}) {
		t.Fatalf("proof = %#v", proof)
	}
	if strings.Join(requests, ",") != "/sns/jscode2session,/cgi-bin/token,/wxa/business/getuserphonenumber" {
		t.Fatalf("calls = %#v", requests)
	}
}

func TestVerifyOnboardingRequiresVerifiedPhoneAndFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name        string
		phoneCode   string
		tokenBody   string
		phoneBody   string
		phoneStatus int
		wantPhone   string
		wantCalls   int32
		wantErr     error
	}{
		{name: "absent", wantCalls: 0, wantErr: wechatdomain.ErrPhoneRequired},
		{name: "malformed", phoneCode: " bad", wantCalls: 0, wantErr: wechatdomain.ErrPhoneRequired},
		{name: "access token rejected", phoneCode: "phone-code", tokenBody: `{"errcode":40013}`, wantCalls: 0, wantErr: wechatdomain.ErrUnavailable},
		{name: "phone rejected", phoneCode: "phone-code", phoneBody: `{"errcode":40029}`, wantCalls: 1, wantErr: wechatdomain.ErrPhoneRequired},
		{name: "phone unavailable", phoneCode: "phone-code", phoneStatus: http.StatusBadGateway, wantCalls: 1, wantErr: wechatdomain.ErrUnavailable},
		{name: "verified", phoneCode: "phone-code", phoneBody: `{"phone_info":{"phoneNumber":"+8613800138000"}}`, wantPhone: "+8613800138000", wantCalls: 1},
		{name: "mainland local normalized", phoneCode: "phone-code", phoneBody: `{"phone_info":{"phoneNumber":"13800138000"}}`, wantPhone: "+8613800138000", wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var phoneCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/sns/jscode2session":
					_, _ = w.Write([]byte(`{"openid":"open-id","session_key":"secret-session-key"}`))
				case "/cgi-bin/token":
					body := test.tokenBody
					if body == "" {
						body = `{"access_token":"provider-access-token"}`
					}
					_, _ = w.Write([]byte(body))
				case "/wxa/business/getuserphonenumber":
					phoneCalls.Add(1)
					if test.phoneStatus != 0 {
						w.WriteHeader(test.phoneStatus)
					}
					_, _ = w.Write([]byte(test.phoneBody))
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
			}))
			defer server.Close()
			client, err := NewClient(Config{AppID: "test-app", AppSecret: "test-secret", APIBaseURL: server.URL, RequestTimeout: time.Second}, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			proof, err := client.VerifyOnboarding(context.Background(), "login-code", test.phoneCode)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("VerifyOnboarding error = %v, want %v", err, test.wantErr)
			}
			if errors.Is(test.wantErr, wechatdomain.ErrUnavailable) && errors.Is(err, wechatdomain.ErrPhoneRequired) {
				t.Fatalf("provider outage was misclassified as phone denial: %v", err)
			}
			if test.wantErr == nil && (proof.TenantID != "test-app" || proof.Subject != "open-id" || proof.Phone != test.wantPhone) {
				t.Fatalf("proof = %#v", proof)
			}
			if test.wantErr != nil && proof != (wechatdomain.IdentityProof{}) {
				t.Fatalf("failed onboarding returned partial proof = %#v", proof)
			}
			if phoneCalls.Load() != test.wantCalls {
				t.Fatalf("phone calls = %d, want %d", phoneCalls.Load(), test.wantCalls)
			}
		})
	}
}

func TestVerifyOnboardingNeverDowngradesLoginFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":40029}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{AppID: "test-app", AppSecret: "test-secret", APIBaseURL: server.URL, RequestTimeout: time.Second}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyOnboarding(context.Background(), "login-code", "phone-code"); !errors.Is(err, wechatdomain.ErrRejected) {
		t.Fatalf("error = %v, want ErrRejected", err)
	}
}

func TestVerifyLoginFailsClosedForProviderRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":40029,"errmsg":"invalid code"}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{AppID: "test-app", AppSecret: "test-secret", APIBaseURL: server.URL, RequestTimeout: time.Second}, server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.VerifyLogin(context.Background(), "login-code"); err != wechatdomain.ErrRejected {
		t.Fatalf("VerifyLogin error = %v, want ErrRejected", err)
	}
}

func TestNewClientRejectsNonLoopbackHTTP(t *testing.T) {
	if _, err := NewClient(Config{AppID: "a", AppSecret: "b", APIBaseURL: "http://wechat.example", RequestTimeout: time.Second}, nil); err == nil {
		t.Fatal("NewClient accepted cleartext non-loopback URL")
	}
}

func TestNewClientPinsProductionEndpointAndKeepsLoopbackTestOnly(t *testing.T) {
	for _, endpoint := range []string{
		"https://api.weixin.qq.com",
		"https://api.weixin.qq.com:443/",
		"https://API.WEIXIN.QQ.COM",
	} {
		t.Run("accept_"+strings.NewReplacer(":", "_", "/", "_").Replace(endpoint), func(t *testing.T) {
			if _, err := NewClient(Config{AppID: "a", AppSecret: "b", APIBaseURL: endpoint, RequestTimeout: time.Second}, nil); err != nil {
				t.Fatalf("NewClient(%q): %v", endpoint, err)
			}
		})
	}

	for _, endpoint := range []string{
		"http://api.weixin.qq.com",
		"https://wechat.example",
		"https://api.weixin.qq.com.attacker.example",
		"https://api.weixin.qq.com:444",
		"https://api.weixin.qq.com/provider-prefix",
		"http://127.0.0.1:18080",
	} {
		t.Run("reject_"+strings.NewReplacer(":", "_", "/", "_").Replace(endpoint), func(t *testing.T) {
			if _, err := NewClient(Config{AppID: "a", AppSecret: "b", APIBaseURL: endpoint, RequestTimeout: time.Second}, nil); err == nil {
				t.Fatalf("NewClient accepted non-production endpoint %q", endpoint)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	if _, err := NewClient(Config{AppID: "a", AppSecret: "b", APIBaseURL: server.URL, RequestTimeout: time.Second}, server.Client()); err != nil {
		t.Fatalf("NewClient rejected injected loopback test endpoint: %v", err)
	}
	if _, err := NewClient(Config{AppID: "a", AppSecret: "b", APIBaseURL: "https://wechat.example", RequestTimeout: time.Second}, server.Client()); err == nil {
		t.Fatal("NewClient accepted arbitrary HTTPS endpoint through the test seam")
	}
}

func TestNewClientCopiesCustomHTTPClientAndCapsTimeout(t *testing.T) {
	originalRedirect := errors.New("original redirect policy")
	original := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return originalRedirect
		},
	}
	client, err := NewClient(Config{
		AppID:          "a",
		AppSecret:      "b",
		APIBaseURL:     "https://api.weixin.qq.com",
		RequestTimeout: 2 * time.Second,
	}, original)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.http == original {
		t.Fatal("NewClient mutated/reused the caller-owned HTTP client")
	}
	if client.http.Timeout != 2*time.Second {
		t.Fatalf("copied client timeout = %s, want 2s", client.http.Timeout)
	}
	if original.Timeout != 10*time.Second {
		t.Fatalf("caller-owned timeout changed to %s", original.Timeout)
	}
	if err := client.http.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v, want ErrUseLastResponse", err)
	}
	if err := original.CheckRedirect(&http.Request{}, nil); !errors.Is(err, originalRedirect) {
		t.Fatalf("caller-owned redirect policy changed: %v", err)
	}

	shorter := &http.Client{Timeout: 500 * time.Millisecond}
	shortClient, err := NewClient(Config{
		AppID:          "a",
		AppSecret:      "b",
		APIBaseURL:     "https://api.weixin.qq.com",
		RequestTimeout: 2 * time.Second,
	}, shorter)
	if err != nil {
		t.Fatalf("NewClient with shorter timeout: %v", err)
	}
	if shortClient.http.Timeout != shorter.Timeout {
		t.Fatalf("shorter caller timeout = %s, want %s", shortClient.http.Timeout, shorter.Timeout)
	}
}

func TestVerifyLoginRejectsRedirectWithoutForwardingCredentials(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"openid":"redirected-open","session_key":"redirected-session"}`))
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("secret") != "test-secret" || r.URL.Query().Get("js_code") != "login-code" {
			t.Errorf("source request did not contain the expected provider credentials")
		}
		http.Redirect(w, r, target.URL+"/capture", http.StatusFound)
	}))
	defer source.Close()

	client, err := NewClient(Config{AppID: "test-app", AppSecret: "test-secret", APIBaseURL: source.URL, RequestTimeout: time.Second}, source.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.VerifyLogin(context.Background(), "login-code"); !errors.Is(err, wechatdomain.ErrUnavailable) {
		t.Fatalf("VerifyLogin error = %v, want ErrUnavailable", err)
	}
	if calls := targetCalls.Load(); calls != 0 {
		t.Fatalf("redirect target received %d requests, want 0", calls)
	}
}

func TestVerifyLoginRejectsOversizedOrTrailingProviderJSON(t *testing.T) {
	valid := `{"openid":"open-id","unionid":"union-id","session_key":"secret-session-key"}`
	tests := []struct {
		name          string
		body          string
		chunkedStream bool
	}{
		{name: "second JSON value", body: valid + ` {"errcode":0}`},
		{name: "trailing non-JSON data", body: valid + ` provider-debug-output`},
		{name: "oversized response", body: valid + strings.Repeat(" ", maxProviderResponseBytes-len(valid)+1), chunkedStream: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if test.chunkedStream {
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := NewClient(Config{AppID: "test-app", AppSecret: "test-secret", APIBaseURL: server.URL, RequestTimeout: time.Second}, server.Client())
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if _, err := client.VerifyLogin(context.Background(), "login-code"); !errors.Is(err, wechatdomain.ErrUnavailable) {
				t.Fatalf("VerifyLogin error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestVerifyLoginAcceptsProviderJSONAtSizeLimit(t *testing.T) {
	valid := `{"openid":"open-id","unionid":"union-id","session_key":"secret-session-key"}`
	body := valid + strings.Repeat(" ", maxProviderResponseBytes-len(valid))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	client, err := NewClient(Config{AppID: "test-app", AppSecret: "test-secret", APIBaseURL: server.URL, RequestTimeout: time.Second}, server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	proof, err := client.VerifyLogin(context.Background(), "login-code")
	if err != nil {
		t.Fatalf("VerifyLogin: %v", err)
	}
	if proof.Subject != "open-id" {
		t.Fatalf("proof subject = %q, want open-id", proof.Subject)
	}
}
