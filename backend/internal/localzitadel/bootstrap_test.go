package localzitadel

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestValidateLoopbackBaseURL(t *testing.T) {
	t.Parallel()

	for _, accepted := range []string{
		"http://localhost:18185",
		"http://LOCALHOST.:18185/",
		"http://127.0.0.1:18185",
		"https://[::1]:18185",
	} {
		if _, err := validateLoopbackBaseURL(accepted); err != nil {
			t.Errorf("validateLoopbackBaseURL(%q) returned %v", accepted, err)
		}
	}

	for _, rejected := range []string{
		"https://auth.example.com",
		"http://localhost.example.com:18185",
		"http://0.0.0.0:18185",
		"http://localhost:18185/admin",
		"http://localhost:18185?target=production",
		"http://user:password@localhost:18185",
		"file:///tmp/zitadel",
	} {
		if _, err := validateLoopbackBaseURL(rejected); err == nil {
			t.Errorf("validateLoopbackBaseURL(%q) unexpectedly succeeded", rejected)
		}
	}
}

func TestSignJWTAssertionUsesRS256AndBoundedClaims(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key := serviceAccountKey{KeyID: "key-1", UserID: "service-user-1"}
	now := time.Unix(1_800_000_000, 0)
	assertion, err := signJWTAssertion(key, privateKey, "http://127.0.0.1:18185/", now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d, want 3", len(parts))
	}
	var header map[string]any
	decodeJWTPart(t, parts[0], &header)
	if header["alg"] != "RS256" || header["kid"] != "key-1" {
		t.Fatalf("unexpected JWT header: %#v", header)
	}
	var claims map[string]any
	decodeJWTPart(t, parts[1], &claims)
	if claims["iss"] != "service-user-1" || claims["sub"] != "service-user-1" || claims["aud"] != "http://127.0.0.1:18185" {
		t.Fatalf("unexpected JWT claims: %#v", claims)
	}
	if claims["exp"].(float64)-claims["iat"].(float64) != 610 {
		t.Fatalf("unexpected JWT lifetime: %#v", claims)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, 0, digest[:], signature); err == nil {
		t.Fatal("signature verification unexpectedly accepted a missing hash identifier")
	}
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("verify assertion signature: %v", err)
	}
}

func TestTOTPCodeRFC6238Vector(t *testing.T) {
	t.Parallel()

	// RFC 6238 SHA-1 test secret "12345678901234567890" at Unix time 59.
	code, err := totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatalf("TOTP code = %s, want 287082", code)
	}
}

func TestRunBootstrapsAndRepeatsWithoutLeakingSecrets(t *testing.T) {
	initPrivateKey := mustRSAKey(t)
	servicePrivateKey := mustRSAKey(t)
	testPassword := "Aa1!local-bootstrap-test-password"
	totpSecret := "JBSWY3DPEHPK3PXP"
	providerToken := "provider-access-token-must-not-leak"
	initPEM := encodePrivateKey(t, initPrivateKey)
	servicePEM := encodePrivateKey(t, servicePrivateKey)

	fake := &fakeZITADEL{
		t:                 t,
		initPublicKey:     &initPrivateKey.PublicKey,
		providerToken:     providerToken,
		expectedPassword:  testPassword,
		totpSecret:        totpSecret,
		servicePrivatePEM: servicePEM,
	}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()

	outDir := t.TempDir()
	initKeyPath := filepath.Join(outDir, "init-sa.json")
	writeTestKeyFile(t, initKeyPath, serviceAccountKey{
		Type:          json.RawMessage(`"serviceaccount"`),
		KeyID:         "init-key-1",
		PrivateKeyPEM: initPEM,
		UserID:        "init-user-1",
	})
	var output bytes.Buffer
	fixedNow := time.Unix(1_800_000_000, 0)
	config := Config{
		BaseURL:       server.URL,
		OutDir:        outDir,
		InitKeyFile:   initKeyPath,
		TestPassword:  testPassword,
		ReadyTimeout:  2 * time.Second,
		RetryInterval: time.Millisecond,
		Output:        &output,
		Now:           func() time.Time { return fixedNow },
	}

	first, err := Run(context.Background(), config)
	if err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	config.TestPassword = ""
	second, err := Run(context.Background(), config)
	if err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
	if first != second {
		t.Fatalf("idempotent result changed:\nfirst:  %#v\nsecond: %#v", first, second)
	}
	if first.UserLogin != "zhixing.lin@example.com" || first.ProjectID != "project-1" || first.Organization != "org-1" {
		t.Fatalf("unexpected bootstrap result: %#v", first)
	}

	persisted, ok, err := readState(filepath.Join(outDir, "init-state.json"))
	if err != nil || !ok {
		t.Fatalf("read bootstrap state: ok=%v err=%v", ok, err)
	}
	if persisted.Password != testPassword || persisted.TOTPSecret != totpSecret {
		t.Fatal("bootstrap state did not preserve integration-test credentials")
	}
	for _, path := range []string{first.StateFile, first.ServiceKey} {
		assertSecretFileRestricted(t, path)
	}

	logs := output.String()
	for _, secret := range []string{testPassword, totpSecret, providerToken, initPEM, servicePEM} {
		if strings.Contains(logs, secret) {
			t.Fatal("bootstrap output leaked secret material")
		}
	}
	fake.assertIdempotentCounts(t)
}

func assertSecretFileRestricted(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("secret file %s mode = %o, want no group/other access", path, info.Mode().Perm())
		}
		return
	}
	output, err := exec.Command("icacls.exe", path).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect secret ACL: %v", err)
	}
	if bytes.Contains(output, []byte("(I)")) {
		t.Fatalf("secret file still has inherited ACL entries: %s", output)
	}
}

func TestRoleReconciliationFailsClosedWithoutRewritingUnexpectedMemberships(t *testing.T) {
	tests := []struct {
		name       string
		searchPath string
		roles      []string
		invoke     func(context.Context, *client) error
	}{
		{
			name:       "instance role has an extra owner grant",
			searchPath: "/admin/v1/members/_search",
			roles:      []string{"IAM_LOGIN_CLIENT", "IAM_OWNER"},
			invoke: func(ctx context.Context, c *client) error {
				return c.ensureIAMLoginClient(ctx, "machine-1")
			},
		},
		{
			name:       "organization role is unexpected",
			searchPath: "/management/v1/orgs/me/members/_search",
			roles:      []string{"ORG_OWNER"},
			invoke: func(ctx context.Context, c *client) error {
				return c.assertNoOrganizationMembership(ctx, "org-1", "machine-1")
			},
		},
		{
			name:       "project role has an extra editor grant",
			searchPath: "/management/v1/projects/project-1/members/_search",
			roles:      []string{"PROJECT_OWNER", "PROJECT_EDITOR"},
			invoke: func(ctx context.Context, c *client) error {
				return c.ensureProjectOwner(ctx, "org-1", "project-1", "machine-1")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.searchPath || r.Method != http.MethodPost {
					writes++
					http.Error(w, "unexpected mutation", http.StatusConflict)
					return
				}
				writeJSON(w, map[string]any{"result": []map[string]any{{"userId": "machine-1", "roles": test.roles}}})
			}))
			defer server.Close()

			base, err := validateLoopbackBaseURL(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			c := &client{base: base, http: server.Client(), token: "local-test-token"}
			if err := test.invoke(context.Background(), c); err == nil {
				t.Fatal("unexpected membership was accepted")
			}
			if writes != 0 {
				t.Fatalf("unexpected membership triggered %d provider mutations", writes)
			}
		})
	}
}

func TestRunRejectsRemoteBaseURLBeforeReadingSecretFiles(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), Config{
		BaseURL:     "https://auth.example.com",
		OutDir:      t.TempDir(),
		InitKeyFile: filepath.Join(t.TempDir(), "missing-secret.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("Run remote URL error = %v", err)
	}
}

func TestHTTPStatusErrorDoesNotExposeResponseBody(t *testing.T) {
	t.Parallel()

	const responseSecret = "response-body-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, responseSecret, http.StatusBadGateway)
	}))
	defer server.Close()
	base, err := validateLoopbackBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{base: base, http: newLoopbackHTTPClient(time.Second)}
	err = c.json(context.Background(), http.MethodPost, "/v2/users", "", map[string]any{}, nil)
	if err == nil {
		t.Fatal("request unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), responseSecret) {
		t.Fatal("HTTP error exposed provider response body")
	}
}

func decodeJWTPart(t *testing.T, encoded string, output any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, output); err != nil {
		t.Fatal(err)
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func encodePrivateKey(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
}

func writeTestKeyFile(t *testing.T, path string, key serviceAccountKey) {
	t.Helper()
	raw, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

type fakeZITADEL struct {
	t                 *testing.T
	mu                sync.Mutex
	initPublicKey     *rsa.PublicKey
	providerToken     string
	expectedPassword  string
	totpSecret        string
	servicePrivatePEM string
	humanCreated      bool
	machineCreated    bool
	totpRegistered    bool
	instanceMember    bool
	projectCreated    bool
	projectMember     bool
	passwordSet       bool
	humanCreates      int
	machineCreates    int
	totpVerifies      int
	totpDeletes       int
	keyCreates        int
	projectCreates    int
	passwordSets      int
}

func (f *fakeZITADEL) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.URL.Path == "/debug/ready" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path == "/oauth/v2/token" {
		f.handleToken(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.providerToken {
		f.t.Errorf("%s %s missing bootstrap bearer", r.Method, r.URL.Path)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/management/v1/orgs/") || strings.HasPrefix(r.URL.Path, "/management/v1/projects") {
		if r.Header.Get("X-Zitadel-Orgid") != "org-1" {
			f.t.Errorf("%s %s missing organization scope", r.Method, r.URL.Path)
		}
	}

	switch r.URL.Path {
	case "/v2/users":
		f.requireMethod(r, http.MethodPost)
		users := make([]map[string]any, 0, 2)
		if f.humanCreated {
			users = append(users, map[string]any{
				"userId":             "human-1",
				"preferredLoginName": "zhixing.lin@example.com",
				"details":            map[string]string{"resourceOwner": "org-1"},
			})
		}
		if f.machineCreated {
			users = append(users, map[string]any{
				"userId":             "machine-1",
				"preferredLoginName": "up-backend-sa@zitadel.localhost",
				"details":            map[string]string{"resourceOwner": "org-1"},
			})
		}
		writeJSON(w, map[string]any{"result": users})
	case "/v2/users/human":
		f.requireMethod(r, http.MethodPost)
		var body struct {
			Username string          `json:"username"`
			UserName json.RawMessage `json:"userName"`
			Password struct {
				Password string `json:"password"`
			} `json:"password"`
		}
		decodeBody(f.t, r.Body, &body)
		if body.Username != "zhixing.lin@zitadel.localhost" || len(body.UserName) != 0 {
			f.t.Errorf("create-human username fields are invalid: username=%q legacy=%s", body.Username, body.UserName)
		}
		if body.Password.Password != f.expectedPassword {
			f.t.Error("create-human request did not use the configured password")
		}
		f.humanCreated = true
		f.humanCreates++
		writeJSON(w, map[string]string{"userId": "human-1"})
	case "/v2/users/human-1/password":
		f.requireMethod(r, http.MethodPost)
		var body struct {
			NewPassword struct {
				Password       string `json:"password"`
				ChangeRequired bool   `json:"changeRequired"`
			} `json:"newPassword"`
		}
		decodeBody(f.t, r.Body, &body)
		if body.NewPassword.Password != f.expectedPassword || body.NewPassword.ChangeRequired {
			f.t.Error("set-password request did not bind the expected stable local credential")
		}
		f.passwordSet = true
		f.passwordSets++
		writeJSON(w, map[string]any{})
	case "/v2/users/human-1/totp":
		switch r.Method {
		case http.MethodPost:
			if f.totpRegistered {
				http.Error(w, "already exists", http.StatusConflict)
				return
			}
			f.totpRegistered = true
			writeJSON(w, map[string]string{"secret": f.totpSecret})
		case http.MethodDelete:
			f.totpRegistered = false
			f.totpDeletes++
			writeJSON(w, map[string]any{})
		default:
			f.t.Errorf("unexpected TOTP method %s", r.Method)
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	case "/v2/users/human-1/totp/verify":
		f.requireMethod(r, http.MethodPost)
		var body map[string]string
		decodeBody(f.t, r.Body, &body)
		if len(body["code"]) != 6 {
			f.t.Error("TOTP verify request is missing a six-digit code")
		}
		f.totpVerifies++
		writeJSON(w, map[string]any{})
	case "/management/v1/users/machine":
		f.requireMethod(r, http.MethodPost)
		f.machineCreated = true
		f.machineCreates++
		writeJSON(w, map[string]string{"userId": "machine-1"})
	case "/management/v1/orgs/me/members/_search":
		f.requireMethod(r, http.MethodPost)
		writeJSON(w, map[string]any{"result": []map[string]any{}})
	case "/admin/v1/members/_search":
		f.requireMethod(r, http.MethodPost)
		if f.instanceMember {
			writeJSON(w, map[string]any{"result": []map[string]any{{"userId": "machine-1", "roles": []string{"IAM_LOGIN_CLIENT"}}}})
			break
		}
		writeJSON(w, map[string]any{"result": []map[string]any{}})
	case "/admin/v1/members":
		f.requireMethod(r, http.MethodPost)
		var body struct {
			UserID string   `json:"userId"`
			Roles  []string `json:"roles"`
		}
		decodeBody(f.t, r.Body, &body)
		if body.UserID != "machine-1" || len(body.Roles) != 1 || body.Roles[0] != "IAM_LOGIN_CLIENT" {
			f.t.Errorf("unexpected login-client membership: user=%q roles=%v", body.UserID, body.Roles)
		}
		f.instanceMember = true
		writeJSON(w, map[string]any{})
	case "/management/v1/users/machine-1/keys":
		f.requireMethod(r, http.MethodPost)
		keyJSON, err := json.Marshal(serviceAccountKey{
			Type:          json.RawMessage(`"serviceaccount"`),
			KeyID:         "service-key-1",
			PrivateKeyPEM: f.servicePrivatePEM,
			UserID:        "machine-1",
		})
		if err != nil {
			f.t.Fatal(err)
		}
		f.keyCreates++
		writeJSON(w, map[string]string{"keyDetails": base64.StdEncoding.EncodeToString(keyJSON)})
	case "/management/v1/projects/_search":
		f.requireMethod(r, http.MethodPost)
		result := []map[string]string{}
		if f.projectCreated {
			result = append(result, map[string]string{"id": "project-1", "name": defaultProjectName})
		}
		writeJSON(w, map[string]any{"result": result})
	case "/management/v1/projects":
		f.requireMethod(r, http.MethodPost)
		f.projectCreated = true
		f.projectCreates++
		writeJSON(w, map[string]string{"id": "project-1"})
	case "/management/v1/projects/project-1/members/_search":
		f.requireMethod(r, http.MethodPost)
		result := []map[string]string{}
		if f.projectMember {
			writeJSON(w, map[string]any{"result": []map[string]any{{"userId": "machine-1", "roles": []string{"PROJECT_OWNER"}}}})
			break
		}
		writeJSON(w, map[string]any{"result": result})
	case "/management/v1/projects/project-1/members":
		f.requireMethod(r, http.MethodPost)
		f.projectMember = true
		writeJSON(w, map[string]any{})
	case "/management/v1/projects/project-1/members/machine-1":
		f.requireMethod(r, http.MethodPut)
		writeJSON(w, map[string]any{})
	default:
		f.t.Errorf("unexpected fake ZITADEL request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *fakeZITADEL) handleToken(w http.ResponseWriter, r *http.Request) {
	f.requireMethod(r, http.MethodPost)
	if err := r.ParseForm(); err != nil {
		f.t.Error(err)
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		f.t.Error("unexpected token grant type")
	}
	assertion := r.Form.Get("assertion")
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		f.t.Error("malformed JWT assertion")
		http.Error(w, "assertion", http.StatusBadRequest)
		return
	}
	var claims map[string]any
	decodeJWTPart(f.t, parts[1], &claims)
	requestURL, _ := url.Parse("http://" + r.Host)
	if claims["aud"] != requestURL.String() {
		f.t.Errorf("JWT audience = %v, want %s", claims["aud"], requestURL)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		f.t.Error(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(f.initPublicKey, crypto.SHA256, digest[:], signature); err != nil {
		f.t.Errorf("verify JWT assertion: %v", err)
	}
	writeJSON(w, map[string]string{"access_token": f.providerToken})
}

func (f *fakeZITADEL) requireMethod(r *http.Request, want string) {
	if r.Method != want {
		f.t.Errorf("%s method = %s, want %s", r.URL.Path, r.Method, want)
	}
}

func (f *fakeZITADEL) assertIdempotentCounts(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.humanCreates != 1 || f.machineCreates != 1 || f.keyCreates != 1 || f.projectCreates != 1 {
		t.Fatalf("non-idempotent create counts: human=%d machine=%d key=%d project=%d", f.humanCreates, f.machineCreates, f.keyCreates, f.projectCreates)
	}
	if !f.passwordSet || f.passwordSets != 2 {
		t.Fatalf("local credential was not authoritatively set on both bootstrap passes: set=%v count=%d", f.passwordSet, f.passwordSets)
	}
	if f.totpVerifies != 1 || f.totpDeletes != 0 {
		t.Fatalf("unexpected TOTP counts: verify=%d delete=%d", f.totpVerifies, f.totpDeletes)
	}
}

func decodeBody(t *testing.T, body io.Reader, output any) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(output); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(fmt.Sprintf("encode fake ZITADEL response: %v", err))
	}
}
