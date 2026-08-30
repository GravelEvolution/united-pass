package aliyunsms

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validTestConfig(endpoint string) Config {
	return Config{
		AccessKeyID:     "test-access-key-id",
		AccessKeySecret: "test-access-key-secret",
		SignName:        "test-sign",
		TemplateCode:    "SMS_123456789",
		Endpoint:        endpoint,
	}
}

func TestNewClientRequiresCompleteTrimmedCredentials(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "access key id", mutate: func(cfg *Config) { cfg.AccessKeyID = "" }},
		{name: "access key secret", mutate: func(cfg *Config) { cfg.AccessKeySecret = "" }},
		{name: "sign name", mutate: func(cfg *Config) { cfg.SignName = "" }},
		{name: "template code", mutate: func(cfg *Config) { cfg.TemplateCode = "" }},
		{name: "surrounding whitespace", mutate: func(cfg *Config) { cfg.AccessKeyID = " test-access-key-id" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validTestConfig(officialEndpoint)
			test.mutate(&cfg)
			if _, err := NewClient(cfg, nil); err == nil {
				t.Fatal("NewClient accepted incomplete or untrimmed credentials")
			}
		})
	}
}

func TestNewClientPinsRuntimeEndpointAndKeepsLoopbackTestOnly(t *testing.T) {
	for _, endpoint := range []string{
		"https://dysmsapi.aliyuncs.com",
		"https://dysmsapi.aliyuncs.com/",
		"https://DYSMSAPI.ALIYUNCS.COM:443/",
	} {
		t.Run("accept_"+strings.NewReplacer(":", "_", "/", "_").Replace(endpoint), func(t *testing.T) {
			if _, err := NewClient(validTestConfig(endpoint), nil); err != nil {
				t.Fatalf("NewClient(%q): %v", endpoint, err)
			}
		})
	}

	for _, endpoint := range []string{
		"http://dysmsapi.aliyuncs.com/",
		"https://dysmsapi.aliyuncs.com:80/",
		"https://dysmsapi.aliyuncs.com:444/",
		"https://dysmsapi.aliyuncs.com:/",
		"https://dysmsapi.aliyuncs.com:0443/",
		"https://dysmsapi.aliyuncs.com.attacker.example/",
		"https://sms.example/",
		"https://user:pass@dysmsapi.aliyuncs.com/",
		"https://dysmsapi.aliyuncs.com/provider-prefix",
		"https://dysmsapi.aliyuncs.com/%2e",
		"https://dysmsapi.aliyuncs.com/?target=other",
		"https://dysmsapi.aliyuncs.com/?",
		"https://dysmsapi.aliyuncs.com/#",
		"https://dysmsapi.aliyuncs.com/#fragment",
		"https://dysmsapi.aliyuncs.com:bad/",
		"http://127.0.0.1:18080/",
	} {
		t.Run("reject_"+strings.NewReplacer(":", "_", "/", "_").Replace(endpoint), func(t *testing.T) {
			if _, err := NewClient(validTestConfig(endpoint), nil); err == nil {
				t.Fatalf("NewClient accepted non-production endpoint %q", endpoint)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	if _, err := NewClient(validTestConfig(server.URL), server.Client()); err != nil {
		t.Fatalf("NewClient rejected injected loopback test endpoint: %v", err)
	}
	if _, err := NewClient(validTestConfig("https://sms.example/"), server.Client()); err == nil {
		t.Fatal("NewClient accepted an arbitrary HTTPS endpoint through the test seam")
	}
}

func TestSendCodeUsesSignedFormPost(t *testing.T) {
	requestValues := make(chan map[string]string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := make(map[string]string)
		if r.Method == http.MethodPost && r.ParseForm() == nil {
			for _, name := range []string{"AccessKeyId", "Action", "PhoneNumbers", "SignName", "TemplateCode", "TemplateParam", "Signature"} {
				values[name] = r.PostForm.Get(name)
			}
		}
		requestValues <- values
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Code":"OK","Message":"OK","RequestId":"request-id"}`))
	}))
	defer server.Close()

	client, err := NewClient(validTestConfig(server.URL), server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.SendCode(context.Background(), "+8613800138000", "123456"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	values := <-requestValues
	if values["AccessKeyId"] != "test-access-key-id" || values["Action"] != "SendSms" || values["PhoneNumbers"] != "+8613800138000" || values["SignName"] != "test-sign" || values["TemplateCode"] != "SMS_123456789" || values["TemplateParam"] != `{"code":"123456"}` || values["Signature"] == "" {
		t.Fatalf("unexpected SendSms form: %#v", values)
	}
}

func TestSendCodeRejectsRedirectWithoutForwardingSensitiveForm(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	originalRedirect := errors.New("original redirect policy")
	original := source.Client()
	original.Timeout = 30 * time.Second
	original.CheckRedirect = func(*http.Request, []*http.Request) error { return originalRedirect }
	client, err := NewClient(validTestConfig(source.URL), original)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.httpClient == original {
		t.Fatal("NewClient reused the caller-owned HTTP client")
	}
	if client.httpClient.Timeout != requestTimeout {
		t.Fatalf("hardened timeout = %s, want %s", client.httpClient.Timeout, requestTimeout)
	}
	if err := client.httpClient.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("hardened redirect policy = %v, want ErrUseLastResponse", err)
	}
	if err := original.CheckRedirect(&http.Request{}, nil); !errors.Is(err, originalRedirect) {
		t.Fatalf("caller-owned redirect policy changed: %v", err)
	}

	if err := client.SendCode(context.Background(), "+8613800138000", "123456"); err == nil {
		t.Fatal("SendCode accepted a redirect response")
	}
	if calls := targetCalls.Load(); calls != 0 {
		t.Fatalf("redirect target received %d requests, want 0", calls)
	}
}
