package mscaccess

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testKeyID = "msc-work-console-2026-01"

func testConfig() Config {
	return Config{
		Issuer:   "https://auth.moonstone.org.cn",
		Audience: "united-pass-msc-read",
		Subject:  "msc-work-console",
	}
}

func testVerifier(t *testing.T) (*Verifier, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verifier, err := NewVerifier(testConfig(), map[string]ed25519.PublicKey{testKeyID: publicKey})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return verifier, privateKey
}

func baseClaims() map[string]any {
	now := time.Now().UTC().Unix()
	return map[string]any{
		"iss":         "https://auth.moonstone.org.cn",
		"aud":         "united-pass-msc-read",
		"sub":         "msc-work-console",
		"iat":         now,
		"nbf":         now,
		"exp":         now + 20,
		"jti":         "req_" + strings.Repeat("ab", 16),
		"actor_kind":  "service",
		"capability":  CapabilityUserRead,
		"htm":         "GET",
		"htu":         "/internal/v1/msc/users",
		"body_sha256": emptyBodySHA256,
	}
}

func sign(t *testing.T, privateKey ed25519.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": keyID}
	if override, ok := claims["kid"].(string); ok {
		header["kid"] = override
		delete(claims, "kid")
	}
	if override, ok := claims["alg"].(string); ok {
		header["alg"] = override
		delete(claims, "alg")
	}
	headerRaw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsRaw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerRaw) + "." + base64.RawURLEncoding.EncodeToString(claimsRaw)
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func assertionRequest(token, requestID, target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if requestID != "" {
		request.Header.Set(requestIDHeader, requestID)
	}
	return request
}

func TestVerifyAcceptsRequestBoundServiceAssertion(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	target := "/internal/v1/msc/users?limit=20&query=abc"
	claims := baseClaims()
	claims["htu"] = target
	token := sign(t, privateKey, testKeyID, claims)
	request := assertionRequest(token, claims["jti"].(string), target)
	if _, err := verifier.Verify(request, CapabilityUserRead, nil); err != nil {
		t.Fatalf("expected acceptance, got %v", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	claims := baseClaims()
	token := sign(t, privateKey, testKeyID, claims)
	parts := strings.Split(token, ".")
	replacement, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	tampered := strings.Replace(string(replacement), CapabilityUserRead, CapabilityAuditRead, 1)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(tampered))
	request := assertionRequest(strings.Join(parts, "."), claims["jti"].(string), "/internal/v1/msc/users")
	if _, err := verifier.Verify(request, CapabilityUserRead, nil); err == nil {
		t.Fatal("expected tampered assertion to be rejected")
	}
}

func TestVerifyRejectsCapabilityMismatch(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	claims := baseClaims()
	claims["capability"] = CapabilityDepartmentRead
	token := sign(t, privateKey, testKeyID, claims)
	request := assertionRequest(token, claims["jti"].(string), "/internal/v1/msc/users")
	if _, err := verifier.Verify(request, CapabilityUserRead, nil); err == nil {
		t.Fatal("expected capability mismatch to be rejected")
	}
}

func TestVerifyRejectsTargetMismatch(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	claims := baseClaims()
	token := sign(t, privateKey, testKeyID, claims)
	request := assertionRequest(token, claims["jti"].(string), "/internal/v1/msc/users?limit=50")
	if _, err := verifier.Verify(request, CapabilityUserRead, nil); err == nil {
		t.Fatal("expected target mismatch to be rejected")
	}
}

func TestVerifyRejectsExpiredAndFutureAssertions(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	cases := map[string]func(claims map[string]any){
		"expired": func(claims map[string]any) {
			claims["iat"] = time.Now().UTC().Unix() - 600
			claims["nbf"] = claims["iat"]
			claims["exp"] = claims["iat"].(int64) + 20
		},
		"future": func(claims map[string]any) {
			claims["iat"] = time.Now().UTC().Unix() + 600
			claims["nbf"] = claims["iat"]
			claims["exp"] = claims["iat"].(int64) + 20
		},
		"longLived": func(claims map[string]any) {
			claims["exp"] = claims["iat"].(int64) + 600
		},
		"notBeforeAfterIssuedAt": func(claims map[string]any) {
			claims["nbf"] = claims["iat"].(int64) + 30
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claims := baseClaims()
			mutate(claims)
			token := sign(t, privateKey, testKeyID, claims)
			request := assertionRequest(token, claims["jti"].(string), "/internal/v1/msc/users")
			if _, err := verifier.Verify(request, CapabilityUserRead, nil); err == nil {
				t.Fatal("expected assertion to be rejected")
			}
		})
	}
}

func TestVerifyRejectsRequestIdentifierMismatch(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	claims := baseClaims()
	token := sign(t, privateKey, testKeyID, claims)
	if _, err := verifier.Verify(assertionRequest(token, "req_"+strings.Repeat("cd", 16), "/internal/v1/msc/users"), CapabilityUserRead, nil); err == nil {
		t.Fatal("expected request identifier mismatch to be rejected")
	}
	if _, err := verifier.Verify(assertionRequest(token, "", "/internal/v1/msc/users"), CapabilityUserRead, nil); err == nil {
		t.Fatal("expected missing request identifier to be rejected")
	}
}

func TestVerifyRejectsUnknownKeyIdentifier(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	claims := baseClaims()
	token := sign(t, privateKey, "another-key", claims)
	request := assertionRequest(token, claims["jti"].(string), "/internal/v1/msc/users")
	if _, err := verifier.Verify(request, CapabilityUserRead, nil); err == nil {
		t.Fatal("expected unknown key identifier to be rejected")
	}
}

func TestVerifyRejectsUnsupportedAlgorithmAndUnknownClaims(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	claims := baseClaims()
	claims["alg"] = "HS256"
	token := sign(t, privateKey, testKeyID, claims)
	request := assertionRequest(token, claims["jti"].(string), "/internal/v1/msc/users")
	if _, err := verifier.Verify(request, CapabilityUserRead, nil); err == nil {
		t.Fatal("expected unsupported algorithm to be rejected")
	}
	claims = baseClaims()
	claims["role"] = "admin"
	token = sign(t, privateKey, testKeyID, claims)
	request = assertionRequest(token, claims["jti"].(string), "/internal/v1/msc/users")
	if _, err := verifier.Verify(request, CapabilityUserRead, nil); err == nil {
		t.Fatal("expected unknown claim to be rejected")
	}
}

func TestVerifyRejectsNonGETAndBodyBearingRequests(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	claims := baseClaims()
	token := sign(t, privateKey, testKeyID, claims)
	post := httptest.NewRequest(http.MethodPost, "/internal/v1/msc/users", nil)
	post.Header.Set("Authorization", "Bearer "+token)
	post.Header.Set(requestIDHeader, claims["jti"].(string))
	if _, err := verifier.Verify(post, CapabilityUserRead, nil); err == nil {
		t.Fatal("expected non-GET method to be rejected")
	}
	body := httptest.NewRequest(http.MethodGet, "/internal/v1/msc/users", strings.NewReader("payload"))
	body.Header.Set("Authorization", "Bearer "+token)
	body.Header.Set(requestIDHeader, claims["jti"].(string))
	if _, err := verifier.Verify(body, CapabilityUserRead, nil); err == nil {
		t.Fatal("expected request body to be rejected")
	}
}

func TestVerifyRejectsMissingAndMalformedAuthorization(t *testing.T) {
	verifier, _ := testVerifier(t)
	if _, err := verifier.Verify(assertionRequest("", "req_"+strings.Repeat("ab", 16), "/internal/v1/msc/users"), CapabilityUserRead, nil); err == nil {
		t.Fatal("expected missing authorization to be rejected")
	}
	if _, err := verifier.Verify(assertionRequest("not-a-jwt", "req_"+strings.Repeat("ab", 16), "/internal/v1/msc/users"), CapabilityUserRead, nil); err == nil {
		t.Fatal("expected malformed token to be rejected")
	}
}

func TestNewVerifierRejectsInvalidConfiguration(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys := map[string]ed25519.PublicKey{testKeyID: publicKey}
	for name, config := range map[string]Config{
		"insecureIssuer": {Issuer: "http://auth.moonstone.org.cn", Audience: "aud", Subject: "sub"},
		"issuerWithPath": {Issuer: "https://auth.moonstone.org.cn/issuer", Audience: "aud", Subject: "sub"},
		"emptyAudience":  {Issuer: "https://auth.moonstone.org.cn", Audience: "", Subject: "sub"},
		"paddedSubject":  {Issuer: "https://auth.moonstone.org.cn", Audience: "aud", Subject: " sub "},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewVerifier(config, keys); err == nil {
				t.Fatal("expected configuration to be rejected")
			}
		})
	}
	if _, err := NewVerifier(testConfig(), map[string]ed25519.PublicKey{"bad kid": publicKey}); err == nil {
		t.Fatal("expected invalid key identifier to be rejected")
	}
	if _, err := NewVerifier(testConfig(), map[string]ed25519.PublicKey{}); err == nil {
		t.Fatal("expected empty key set to be rejected")
	}
}

func TestParseJWKSRejectsNonStrictDocuments(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	material := base64.RawURLEncoding.EncodeToString(publicKey)
	entry := "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"" + testKeyID + "\",\"x\":\"" + material + "\"}"
	valid := "{\"keys\":[" + entry + "]}"
	keys, err := ParseJWKS([]byte(valid))
	if err != nil || len(keys) != 1 {
		t.Fatalf("expected valid JWKS to parse, keys=%d err=%v", len(keys), err)
	}
	rejected := map[string]string{
		"duplicateKeyIdentifier": "{\"keys\":[" + entry + "," + entry + "]}",
		"duplicateMember":        "{\"keys\":[" + entry + "],\"keys\":[]}",
		"unknownMember":          "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"" + testKeyID + "\",\"x\":\"" + material + "\",\"d\":\"secret\"}]}",
		"unsupportedKeyType":     "{\"keys\":[{\"kty\":\"RSA\",\"crv\":\"Ed25519\",\"kid\":\"" + testKeyID + "\",\"x\":\"" + material + "\"}]}",
		"invalidMaterial":        "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"" + testKeyID + "\",\"x\":\"AAAA\"}]}",
		"invalidKeyIdentifier":   "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"bad kid\",\"x\":\"" + material + "\"}]}",
		"trailingContent":        valid + valid,
	}
	for name, document := range rejected {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJWKS([]byte(document)); err == nil {
				t.Fatal("expected JWKS to be rejected")
			}
		})
	}
}

func TestLoadVerifierEnforcesFileBoundaries(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	document, err := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "OKP", "crv": "Ed25519", "kid": testKeyID,
		"x": base64.RawURLEncoding.EncodeToString(publicKey), "use": "sig", "alg": "EdDSA",
	}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	directory := t.TempDir()
	secure := filepath.Join(directory, "msc-public-jwks.json")
	if err := os.WriteFile(secure, document, 0o600); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	if _, err := LoadVerifier(secure, testConfig()); err != nil {
		t.Fatalf("expected owner-only JWKS to load: %v", err)
	}
	loose := filepath.Join(directory, "loose.json")
	if err := os.WriteFile(loose, document, 0o644); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	if _, err := LoadVerifier(loose, testConfig()); err == nil {
		t.Fatal("expected group-readable JWKS to be rejected")
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(secure, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := LoadVerifier(link, testConfig()); err == nil {
		t.Fatal("expected symlinked JWKS to be rejected")
	}
}

const testWriteTarget = "/internal/v1/msc/users/user_abc/status"

func testWriteBody() []byte {
	return []byte(`{"status":"disabled"}`)
}

func writeClaims(body []byte) map[string]any {
	digest := sha256.Sum256(body)
	claims := baseClaims()
	claims["capability"] = CapabilityUserWrite
	claims["htm"] = http.MethodPatch
	claims["htu"] = testWriteTarget
	claims["body_sha256"] = hex.EncodeToString(digest[:])
	claims["actor"] = "admin@moonstone.wtf"
	return claims
}

func writeRequest(token, requestID string, body []byte) *http.Request {
	request := httptest.NewRequest(http.MethodPatch, testWriteTarget, bytes.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if requestID != "" {
		request.Header.Set(requestIDHeader, requestID)
	}
	return request
}

func TestVerifyAcceptsBodyBoundWriteAssertion(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	body := testWriteBody()
	claims := writeClaims(body)
	token := sign(t, privateKey, testKeyID, claims)
	request := writeRequest(token, claims["jti"].(string), body)
	actor, err := verifier.Verify(request, CapabilityUserWrite, body)
	if err != nil {
		t.Fatalf("expected write assertion to verify: %v", err)
	}
	if actor != "admin@moonstone.wtf" {
		t.Fatalf("actor = %q, want the signed actor label", actor)
	}
}

func TestVerifyRejectsWriteAssertionBoundToAnotherBody(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	body := testWriteBody()
	claims := writeClaims(body)
	token := sign(t, privateKey, testKeyID, claims)
	tampered := []byte(`{"status":"active"}`)
	request := writeRequest(token, claims["jti"].(string), tampered)
	if _, err := verifier.Verify(request, CapabilityUserWrite, tampered); err == nil {
		t.Fatal("expected a body swap to be rejected")
	}
}

func TestVerifyRejectsReadCapabilityOnWriteRequest(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	body := testWriteBody()
	claims := writeClaims(body)
	claims["capability"] = CapabilityUserRead
	token := sign(t, privateKey, testKeyID, claims)
	request := writeRequest(token, claims["jti"].(string), body)
	if _, err := verifier.Verify(request, CapabilityUserWrite, body); err == nil {
		t.Fatal("expected capability mismatch to be rejected")
	}
}

func TestVerifyRejectsWriteAssertionWithoutActor(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	body := testWriteBody()
	claims := writeClaims(body)
	delete(claims, "actor")
	token := sign(t, privateKey, testKeyID, claims)
	request := writeRequest(token, claims["jti"].(string), body)
	if _, err := verifier.Verify(request, CapabilityUserWrite, body); err == nil {
		t.Fatal("expected a write assertion without actor to be rejected")
	}
}

func TestVerifyRejectsMalformedActorLabel(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	body := testWriteBody()
	claims := writeClaims(body)
	claims["actor"] = "admin moonstone"
	token := sign(t, privateKey, testKeyID, claims)
	request := writeRequest(token, claims["jti"].(string), body)
	if _, err := verifier.Verify(request, CapabilityUserWrite, body); err == nil {
		t.Fatal("expected a malformed actor label to be rejected")
	}
}

func TestVerifyRejectsEmptyWriteBody(t *testing.T) {
	verifier, privateKey := testVerifier(t)
	claims := baseClaims()
	claims["capability"] = CapabilityUserWrite
	claims["htm"] = http.MethodPatch
	claims["htu"] = testWriteTarget
	claims["actor"] = "admin@moonstone.wtf"
	token := sign(t, privateKey, testKeyID, claims)
	request := writeRequest(token, claims["jti"].(string), nil)
	if _, err := verifier.Verify(request, CapabilityUserWrite, nil); err == nil {
		t.Fatal("expected an empty write body to be rejected")
	}
}
