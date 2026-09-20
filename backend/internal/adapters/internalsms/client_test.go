package internalsms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendCodePostsInternationalChannelWithStrippedPrefix(t *testing.T) {
	var received sendRequest
	var apiKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey = r.Header.Get("X-API-Key")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"code":"OK","message":"OK","bizId":"1"}}`))
	}))
	defer server.Close()

	client := NewClient(Config{Endpoint: server.URL, APIKey: "key", From: "MoonStone"}, server.Client())
	if err := client.SendCode(context.Background(), "+37257013843", "135790"); err != nil {
		t.Fatal(err)
	}
	if apiKey != "key" {
		t.Fatalf("api key=%q", apiKey)
	}
	if received.Channel != "international" || received.MessageType != "NOTIFY" || received.From != "MoonStone" {
		t.Fatalf("request=%#v", received)
	}
	if len(received.PhoneNumbers) != 1 || received.PhoneNumbers[0] != "37257013843" {
		t.Fatalf("numbers=%v", received.PhoneNumbers)
	}
	if !strings.Contains(received.Message, "135790") {
		t.Fatalf("message=%q", received.Message)
	}
}

func TestSendCodeSurfacesGatewayErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"API_KEY_REQUIRED","message":"missing"}}`))
	}))
	defer server.Close()

	client := NewClient(Config{Endpoint: server.URL, APIKey: "key"}, server.Client())
	err := client.SendCode(context.Background(), "+37257013843", "135790")
	if err == nil || !strings.Contains(err.Error(), "API_KEY_REQUIRED") {
		t.Fatalf("error=%v", err)
	}

	rejected := NewClient(Config{Endpoint: server.URL}, server.Client())
	if err := rejected.SendCode(context.Background(), "+37257013843", "135790"); err == nil {
		t.Fatal("expected an error when no API key is configured")
	}
}

func TestSendCodeRejectsNonOKGatewayEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"code":"SPAM_LIMIT","message":"limited"}}`))
	}))
	defer server.Close()

	client := NewClient(Config{Endpoint: server.URL, APIKey: "key"}, server.Client())
	err := client.SendCode(context.Background(), "+37257013843", "135790")
	if err == nil || !strings.Contains(err.Error(), "SPAM_LIMIT") {
		t.Fatalf("error=%v", err)
	}
}
