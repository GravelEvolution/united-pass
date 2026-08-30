package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
)

func TestDreamUPJWKSHandlerPublishesOnlyPublicEd25519Material(t *testing.T) {
	keyring := loadHTTPDelegationKeyring(t)
	handler, err := NewDreamUPJWKSHandler(keyring)
	if err != nil {
		t.Fatalf("NewDreamUPJWKSHandler: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/dreamup-jwks.json", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := recorder.Header().Get("ETag"); got == "" || !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Fatalf("ETag = %q", got)
	}
	if got := recorder.Header().Get("Content-Length"); got != strconv.Itoa(recorder.Body.Len()) {
		t.Fatalf("GET Content-Length = %q, body bytes = %d", got, recorder.Body.Len())
	}
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	keys, ok := document["keys"].([]any)
	if !ok || len(keys) != 2 {
		t.Fatalf("keys = %#v", document["keys"])
	}
	for _, raw := range keys {
		key := raw.(map[string]any)
		if len(key) != 6 || key["kty"] != "OKP" || key["crv"] != "Ed25519" || key["use"] != "sig" || key["alg"] != "EdDSA" || key["kid"] == "" || key["x"] == "" {
			t.Fatalf("unexpected public JWK = %#v", key)
		}
		if _, exists := key["d"]; exists {
			t.Fatal("JWKS contains private d")
		}
	}
}

func TestDreamUPJWKSHandlerUsesStableETagAndHonorsIfNoneMatch(t *testing.T) {
	handler, err := NewDreamUPJWKSHandler(loadHTTPDelegationKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/.well-known/dreamup-jwks.json", nil))
	etag := first.Header().Get("ETag")

	secondRequest := httptest.NewRequest(http.MethodGet, "/.well-known/dreamup-jwks.json", nil)
	secondRequest.Header.Set("If-None-Match", `"different", W/`+etag)
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, secondRequest)
	if second.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Fatalf("304 body = %q", second.Body.String())
	}
	if second.Header().Get("ETag") != etag || second.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("304 headers = %#v", second.Header())
	}

	third := httptest.NewRecorder()
	handler.ServeHTTP(third, httptest.NewRequest(http.MethodGet, "/.well-known/dreamup-jwks.json", nil))
	if third.Header().Get("ETag") != etag || third.Body.String() != first.Body.String() {
		t.Fatal("JWKS representation is not stable")
	}
}

func TestDreamUPJWKSHandlerSupportsHEADWithoutAResponseBody(t *testing.T) {
	handler, _ := NewDreamUPJWKSHandler(loadHTTPDelegationKeyring(t))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodHead, "/.well-known/dreamup-jwks.json", nil))
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Fatalf("HEAD status/body = %d/%q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("ETag") == "" || recorder.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("HEAD headers = %#v", recorder.Header())
	}
	if got := recorder.Header().Get("Content-Length"); got == "" || got != strconv.Itoa(len(handler.representation)) {
		t.Fatalf("HEAD Content-Length = %q, want %d", got, len(handler.representation))
	}
}

func TestDreamUPJWKSHandlerRejectsMissingKeyringAndUnsafeMethods(t *testing.T) {
	if _, err := NewDreamUPJWKSHandler(nil); err == nil {
		t.Fatal("nil keyring accepted")
	}
	handler, _ := NewDreamUPJWKSHandler(loadHTTPDelegationKeyring(t))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/.well-known/dreamup-jwks.json", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST status/Allow = %d/%q", recorder.Code, recorder.Header().Get("Allow"))
	}
}

func loadHTTPDelegationKeyring(t *testing.T) *dreamupdelegation.Keyring {
	t.Helper()
	currentPublic, currentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	retainedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	document := map[string]any{
		"current": map[string]any{
			"kty": "OKP", "crv": "Ed25519", "kid": "kid-current", "x": encode(currentPublic),
			"d": encode(currentPrivate.Seed()), "use": "sig", "alg": "EdDSA",
		},
		"retained": []any{map[string]any{
			"kty": "OKP", "crv": "Ed25519", "kid": "kid-retained", "x": encode(retainedPublic),
			"use": "sig", "alg": "EdDSA",
		}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := dreamupdelegation.LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}
