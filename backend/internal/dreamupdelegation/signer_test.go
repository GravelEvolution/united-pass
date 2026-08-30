package dreamupdelegation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/identityaccess"
)

var delegationTestNow = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func TestOwnerOnlyPermissionsRejectGroupOrWorldAccess(t *testing.T) {
	if ownerOnlyPermissions(0o644) || ownerOnlyPermissions(0o640) || ownerOnlyPermissions(0o604) {
		t.Fatal("group/world access classified as owner-only")
	}
	if !ownerOnlyPermissions(0o600) || !ownerOnlyPermissions(0o400) {
		t.Fatal("owner-only permissions rejected")
	}
}

func TestLoadKeyringRequiresOwnerOnlyFileAndPublishesPublicKeys(t *testing.T) {
	path, currentPublic, retainedPublic := writeDelegationTestKeyring(t, 0o644)
	if runtime.GOOS != "windows" {
		if _, err := LoadKeyring(path); err == nil {
			t.Fatal("group/world-readable keyring accepted")
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod keyring: %v", err)
	}

	keyring, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if got := keyring.CurrentKeyID(); got != "kid-current" {
		t.Fatalf("CurrentKeyID = %q", got)
	}

	var set JSONWebKeySet
	if err := json.Unmarshal(keyring.PublicJWKS(), &set); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(set.Keys))
	}
	wantX := map[string]string{
		"kid-current":  base64.RawURLEncoding.EncodeToString(currentPublic),
		"kid-retained": base64.RawURLEncoding.EncodeToString(retainedPublic),
	}
	for _, key := range set.Keys {
		if key.Kty != "OKP" || key.Crv != "Ed25519" || key.Use != "sig" || key.Alg != "EdDSA" {
			t.Fatalf("unsafe JWKS metadata: %+v", key)
		}
		if key.X != wantX[key.Kid] {
			t.Fatalf("x for %q = %q", key.Kid, key.X)
		}
	}
	if strings.Contains(string(keyring.PublicJWKS()), `"d"`) {
		t.Fatal("private key material leaked through JWKS")
	}
	if keyring.ETag() == "" || keyring.ETag() != keyring.ETag() {
		t.Fatal("JWKS ETag is not stable")
	}
}

func TestLoadKeyringRejectsMalformedOrAmbiguousMaterial(t *testing.T) {
	_, currentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	currentPublic := currentPrivate.Public().(ed25519.PublicKey)
	seed := currentPrivate.Seed()
	valid := map[string]any{
		"current": map[string]any{
			"kty": "OKP", "crv": "Ed25519", "kid": "kid-current", "x": b64(currentPublic),
			"d": b64(seed), "use": "sig", "alg": "EdDSA",
		},
		"retained": []any{},
	}
	cases := map[string]func(map[string]any){
		"unknown top-level field": func(document map[string]any) { document["unexpected"] = true },
		"missing retained set":    func(document map[string]any) { delete(document, "retained") },
		"null retained set":       func(document map[string]any) { document["retained"] = nil },
		"mismatched public key": func(document map[string]any) {
			document["current"].(map[string]any)["x"] = b64(make([]byte, ed25519.PublicKeySize))
		},
		"private retained key": func(document map[string]any) {
			document["retained"] = []any{map[string]any{
				"kty": "OKP", "crv": "Ed25519", "kid": "kid-old", "x": b64(currentPublic),
				"d": b64(seed), "use": "sig", "alg": "EdDSA",
			}}
		},
		"duplicate key id": func(document map[string]any) {
			document["retained"] = []any{map[string]any{
				"kty": "OKP", "crv": "Ed25519", "kid": "kid-current", "x": b64(currentPublic),
				"use": "sig", "alg": "EdDSA",
			}}
		},
		"more keys than the verifier accepts": func(document map[string]any) {
			retained := make([]any, 32)
			for index := range retained {
				retained[index] = map[string]any{
					"kty": "OKP", "crv": "Ed25519", "kid": fmt.Sprintf("kid-retained-%02d", index), "x": b64(currentPublic),
					"use": "sig", "alg": "EdDSA",
				}
			}
			document["retained"] = retained
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(valid)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			mutate(document)
			path := filepath.Join(t.TempDir(), "keyring.json")
			raw, _ = json.Marshal(document)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadKeyring(path); err == nil {
				t.Fatal("invalid keyring accepted")
			}
		})
	}
}

func TestLoadKeyringRejectsDuplicateJSONMembers(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"current":{"kty":"OKP","crv":"Ed25519","kid":"kid-current","kid":"kid-shadow","x":"%s","d":"%s","use":"sig","alg":"EdDSA"},"retained":[]}`,
		b64(public), b64(private.Seed()))
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err == nil {
		t.Fatal("duplicate JSON member accepted")
	}
}

func TestAdministratorSignerBindsRequestAndAuthorizationState(t *testing.T) {
	keyring, currentPublic := loadDelegationTestKeyring(t)
	signer, err := NewAdministratorSigner(keyring, SignerConfig{
		Issuer:    Issuer,
		Audience:  "https://dreamup.moonstone.org.cn",
		TTL:       25 * time.Second,
		ClockSkew: 3 * time.Second,
		Now:       func() time.Time { return delegationTestNow },
	})
	if err != nil {
		t.Fatalf("NewAdministratorSigner: %v", err)
	}
	input := validAdministratorAssertion()
	signed, err := signer.SignAdministrator(input)
	if err != nil {
		t.Fatalf("SignAdministrator: %v", err)
	}
	if !signed.NotBefore.Equal(delegationTestNow.Add(-3*time.Second)) || !signed.ExpiresAt.Equal(delegationTestNow.Add(25*time.Second)) {
		t.Fatalf("signed envelope = %+v", signed)
	}
	header, claims := verifyDelegationToken(t, signed.Token, currentPublic)
	if header["alg"] != "EdDSA" || header["kid"] != "kid-current" || header["typ"] != "JWT" {
		t.Fatalf("header = %#v", header)
	}
	assertStringClaim(t, claims, "iss", Issuer)
	assertStringClaim(t, claims, "aud", "https://dreamup.moonstone.org.cn")
	assertStringClaim(t, claims, "sub", string(input.Subject))
	assertStringClaim(t, claims, "actor_kind", "administrator")
	assertStringClaim(t, claims, "capability", string(input.Capability))
	assertStringClaim(t, claims, "request_id", input.JWTID)
	assertStringClaim(t, claims, "htm", input.Method)
	assertStringClaim(t, claims, "htu", input.PathAndQuery)
	assertStringClaim(t, claims, "body_sha256", input.BodySHA256)
	assertStringClaim(t, claims, "headers_sha256", AdministratorHeadersSHA256(input.IfMatch, input.IdempotencyKey))
	assertStringClaim(t, claims, "event_id", input.EventID)
	assertStringClaim(t, claims, "role_binding_id", input.RoleBindingID)
	assertStringClaim(t, claims, "idempotency_key", input.IdempotencyKey)
	assertStringClaim(t, claims, "reauth_grant_id", input.ReauthGrantID)
	if int64(claims["role_version"].(float64)) != input.RoleVersion || int64(claims["challenge_version"].(float64)) != input.ChallengeVersion {
		t.Fatalf("authorization versions not bound: %#v", claims)
	}
	if got := int64(claims["iat"].(float64)); got != delegationTestNow.Unix() {
		t.Fatalf("iat = %d", got)
	}
	if got := int64(claims["nbf"].(float64)); got != delegationTestNow.Add(-3*time.Second).Unix() {
		t.Fatalf("nbf = %d", got)
	}
	if got := int64(claims["exp"].(float64)) - int64(claims["iat"].(float64)); got != 25 {
		t.Fatalf("TTL = %d seconds", got)
	}
	for _, forbidden := range []string{"cap", "http_method", "http_path", "query_sha256", "role", "role_binding_version", "step_up_time", "oa", "grant_id"} {
		if _, exists := claims[forbidden]; exists {
			t.Fatalf("verifier-incompatible claim %q present", forbidden)
		}
	}
	assertExactClaimNames(t, claims, []string{
		"iss", "aud", "sub", "iat", "nbf", "exp", "jti",
		"actor_kind", "event_id", "capability", "request_id", "htm", "htu", "body_sha256", "headers_sha256", "idempotency_key",
		"role_binding_id", "role_version", "challenge_version", "auth_time", "step_up_at", "reauth_grant_id",
	})
}

func TestAdministratorSignerAcceptsAndBindsAValidEscapedPath(t *testing.T) {
	keyring, currentPublic := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, Now: func() time.Time { return delegationTestNow }})
	input := validAdministratorAssertion()
	input.PathAndQuery = "/api/v1/admin/events/event%2Fa/applications/app%2Fb/review?mode=final&tag=a&tag=b"
	signed, err := signer.SignAdministrator(input)
	if err != nil {
		t.Fatalf("SignAdministrator escaped path: %v", err)
	}
	_, claims := verifyDelegationToken(t, signed.Token, currentPublic)
	assertStringClaim(t, claims, "htu", input.PathAndQuery)
}

func TestSignerConstructorsEnforceTTLAndClockSkewContract(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	cases := []struct {
		name   string
		config SignerConfig
	}{
		{"empty issuer", SignerConfig{Audience: "dreamup", TTL: time.Second, Now: time.Now}},
		{"non https issuer", SignerConfig{Issuer: "http://auth.moonstone.org.cn", Audience: "dreamup", TTL: time.Second, Now: time.Now}},
		{"issuer with path", SignerConfig{Issuer: Issuer + "/issuer", Audience: "dreamup", TTL: time.Second, Now: time.Now}},
		{"empty audience", SignerConfig{Issuer: Issuer, TTL: time.Second, Now: time.Now}},
		{"zero ttl", SignerConfig{Issuer: Issuer, Audience: "dreamup", Now: time.Now}},
		{"sub-second ttl", SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: 500 * time.Millisecond, Now: time.Now}},
		{"fractional ttl", SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: 1500 * time.Millisecond, Now: time.Now}},
		{"ttl above ceiling", SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: MaxOrdinaryTTL + time.Nanosecond, Now: time.Now}},
		{"negative skew", SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, ClockSkew: -time.Second, Now: time.Now}},
		{"fractional skew", SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, ClockSkew: 500 * time.Millisecond, Now: time.Now}},
		{"skew above ceiling", SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, ClockSkew: MaxClockSkew + time.Nanosecond, Now: time.Now}},
		{"missing clock", SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAdministratorSigner(keyring, tc.config); err == nil {
				t.Fatal("administrator signer accepted unsafe config")
			}
			if _, err := NewServiceSigner(keyring, tc.config); err == nil {
				t.Fatal("service signer accepted unsafe config")
			}
		})
	}
}

func TestAdministratorAndServiceCapabilitiesCannotCrossKinds(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	config := SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, Now: func() time.Time { return delegationTestNow }}
	administrator, _ := NewAdministratorSigner(keyring, config)
	service, _ := NewServiceSigner(keyring, config)

	adminInput := validAdministratorAssertion()
	adminInput.Capability = AdministratorCapability(ServiceCapabilityOperationReceiptRead)
	if _, err := administrator.SignAdministrator(adminInput); err == nil {
		t.Fatal("administrator signer accepted service capability")
	}
	serviceInput := validServiceAssertion()
	serviceInput.Capability = ServiceCapability(AdministratorCapabilityApplicationReview)
	if _, err := service.SignService(serviceInput); err == nil {
		t.Fatal("service signer accepted administrator capability")
	}
}

func TestAdministratorSignerFailsClosedWhenBindingsAreIncomplete(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, Now: func() time.Time { return delegationTestNow }})
	cases := map[string]func(*AdministratorAssertion){
		"subject":              func(value *AdministratorAssertion) { value.Subject = "" },
		"whitespace subject":   func(value *AdministratorAssertion) { value.Subject = " " },
		"jwt id":               func(value *AdministratorAssertion) { value.JWTID = "" },
		"capability":           func(value *AdministratorAssertion) { value.Capability = "" },
		"method":               func(value *AdministratorAssertion) { value.Method = "" },
		"htu":                  func(value *AdministratorAssertion) { value.PathAndQuery = "" },
		"body hash":            func(value *AdministratorAssertion) { value.BodySHA256 = "" },
		"event":                func(value *AdministratorAssertion) { value.EventID = "" },
		"role binding":         func(value *AdministratorAssertion) { value.RoleBindingID = "" },
		"role binding version": func(value *AdministratorAssertion) { value.RoleVersion = 0 },
		"unsafe role version":  func(value *AdministratorAssertion) { value.RoleVersion = 1 << 53 },
		"challenge version":    func(value *AdministratorAssertion) { value.ChallengeVersion = 0 },
		"unsafe challenge":     func(value *AdministratorAssertion) { value.ChallengeVersion = 1 << 53 },
		"authentication":       func(value *AdministratorAssertion) { value.AuthTime = time.Time{} },
		"step-up":              func(value *AdministratorAssertion) { value.StepUpAt = time.Time{} },
		"idempotency":          func(value *AdministratorAssertion) { value.IdempotencyKey = "" },
		"if-match":             func(value *AdministratorAssertion) { value.IfMatch = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := validAdministratorAssertion()
			mutate(&input)
			if _, err := signer.SignAdministrator(input); err == nil {
				t.Fatal("incomplete assertion accepted")
			}
		})
	}
}

func TestAdministratorSignerMatchesTheGlobalRequestIDContract(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, Now: func() time.Time { return delegationTestNow }})
	input := validAdministratorAssertion()
	input.JWTID = strings.Repeat("a", 128)
	if _, err := signer.SignAdministrator(input); err != nil {
		t.Fatalf("128-character request ID rejected: %v", err)
	}
	input.JWTID += "a"
	if _, err := signer.SignAdministrator(input); err == nil {
		t.Fatal("129-character request ID accepted")
	}
}

func TestAdministratorSignerEnforcesVerifierReauthenticationRules(t *testing.T) {
	keyring, currentPublic := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: 25 * time.Second, Now: func() time.Time { return delegationTestNow }})

	highRisk := validAdministratorAssertion()
	highRisk.Capability = AdministratorCapabilityContactSubmissionManage
	highRisk.ReauthGrantID = ""
	if _, err := signer.SignAdministrator(highRisk); err == nil {
		t.Fatal("high-risk capability accepted without reauthentication grant")
	}
	highRisk.ReauthGrantID = "reauth_audit_001"
	highRisk.StepUpAt = delegationTestNow.Add(-5*time.Minute - time.Second)
	if _, err := signer.SignAdministrator(highRisk); err == nil {
		t.Fatal("stale high-risk step-up accepted")
	}

	ordinary := validAdministratorAssertion()
	ordinary.Capability = AdministratorCapabilityDashboardRead
	ordinary.Method = "GET"
	ordinary.PathAndQuery = "/internal/v1/events/evt_shanghai/dashboard"
	ordinary.BodySHA256 = SHA256Digest(nil)
	ordinary.IdempotencyKey = ""
	ordinary.IfMatch = ""
	ordinary.ReauthGrantID = "reauth_not_allowed"
	if _, err := signer.SignAdministrator(ordinary); err == nil {
		t.Fatal("ordinary assertion accepted a reauthentication grant")
	}
	ordinary = validAdministratorAssertion()
	ordinary.AuthTime = delegationTestNow.Add(-30 * time.Minute)
	if _, err := signer.SignAdministrator(ordinary); err != nil {
		t.Fatalf("login exactly thirty minutes old rejected: %v", err)
	}
	ordinary.AuthTime = delegationTestNow.Add(-30*time.Minute - time.Second)
	if _, err := signer.SignAdministrator(ordinary); err == nil {
		t.Fatal("stale login accepted")
	}

	read := validAdministratorAssertion()
	read.Capability = AdministratorCapabilityDashboardRead
	read.Method = "GET"
	read.PathAndQuery = "/internal/v1/events/evt_shanghai/dashboard"
	read.BodySHA256 = SHA256Digest(nil)
	read.IdempotencyKey = ""
	read.IfMatch = ""
	read.ReauthGrantID = ""
	signed, err := signer.SignAdministrator(read)
	if err != nil {
		t.Fatalf("read-only assertion: %v", err)
	}
	_, claims := verifyDelegationToken(t, signed.Token, currentPublic)
	if _, exists := claims["idempotency_key"]; exists {
		t.Fatal("read-only assertion emitted an idempotency claim without a matching header")
	}
	assertStringClaim(t, claims, "headers_sha256", AdministratorHeadersSHA256("", ""))
}

func TestAdministratorSignerKeepsLegacyCookieStepUpIDInExistingWorkerClaim(t *testing.T) {
	keyring, currentPublic := loadDelegationTestKeyring(t)
	signer, err := NewAdministratorSigner(keyring, SignerConfig{
		Issuer: Issuer, Audience: "https://dreamup.moonstone.org.cn", TTL: 25 * time.Second,
		ClockSkew: MaxClockSkew, Now: func() time.Time { return delegationTestNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	input := validAdministratorAssertion()
	input.StepUpAt = delegationTestNow.Add(-MaxHighRiskStepUpAge)
	input.ReauthGrantID = "asu_cookie_session_001"
	signed, err := signer.SignAdministrator(input)
	if err != nil {
		t.Fatalf("fresh legacy cookie proof rejected: %v", err)
	}
	_, claims := verifyDelegationToken(t, signed.Token, currentPublic)
	assertStringClaim(t, claims, "reauth_grant_id", "asu_cookie_session_001")
	if _, exists := claims["proof_kind"]; exists {
		t.Fatalf("worker-incompatible compatibility claim added: %#v", claims)
	}
	assertExactClaimNames(t, claims, []string{
		"iss", "aud", "sub", "iat", "nbf", "exp", "jti",
		"actor_kind", "event_id", "capability", "request_id", "htm", "htu", "body_sha256", "headers_sha256", "idempotency_key",
		"role_binding_id", "role_version", "challenge_version", "auth_time", "step_up_at", "reauth_grant_id",
	})
}

func TestAdministratorSignerUsesTheWorkerCapabilityAllowlist(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, Now: func() time.Time { return delegationTestNow }})
	for _, capability := range []AdministratorCapability{
		AdministratorCapabilityDashboardRead,
		AdministratorCapabilityApplicationRead,
		AdministratorCapabilityApplicationReview,
		AdministratorCapabilityApproveAdmission,
		AdministratorCapabilityApplicationDecide,
		AdministratorCapabilityRegistrationManage,
		AdministratorCapabilityCheckinScan,
		AdministratorCapabilityCheckinWindowManage,
		AdministratorCapabilityIdentityTargetValidate,
		AdministratorCapabilityIdentityAccessConsume,
		AdministratorCapabilityRestrictedIdentityRead,
		AdministratorCapabilityLegalRead,
		AdministratorCapabilityApplicationExport,
		AdministratorCapabilityAuditRead,
		AdministratorCapabilityContactSubmissionManage,
		AdministratorCapabilityContentManage,
		AdministratorCapabilityRoleMigrationRead,
	} {
		input := validAdministratorAssertion()
		input.Role = adminroles.RoleSuperAdmin
		input.Capability = capability
		if IsHighRiskAdministratorCapability(capability) {
			input.ReauthGrantID = "reauth_exact_allowlist"
		}
		if capability == AdministratorCapabilityIdentityAccessConsume {
			input.OA = validOAClaim()
		}
		if _, err := signer.SignAdministrator(input); err != nil {
			t.Fatalf("allowlisted capability %q rejected: %v", capability, err)
		}
	}
	for _, capability := range []AdministratorCapability{
		"event.identity_access.request",
		"event.identity_access.approve",
		"system.event_registry.manage",
	} {
		input := validAdministratorAssertion()
		input.Capability = capability
		if _, err := signer.SignAdministrator(input); err == nil {
			t.Fatalf("unsupported capability %q accepted", capability)
		}
	}
}

func TestAdministratorSignerRequiresFreshDurableProofForEveryMutationCapability(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, Now: func() time.Time { return delegationTestNow }})
	for _, capability := range []AdministratorCapability{
		AdministratorCapabilityApplicationReview,
		AdministratorCapabilityApproveAdmission,
		AdministratorCapabilityApplicationDecide,
		AdministratorCapabilityRegistrationManage,
		AdministratorCapabilityCheckinScan,
		AdministratorCapabilityContactSubmissionManage,
		AdministratorCapabilityContentManage,
	} {
		input := validAdministratorAssertion()
		input.Role = adminroles.RoleSuperAdmin
		input.Capability = capability
		input.ReauthGrantID = ""
		if _, err := signer.SignAdministrator(input); err == nil {
			t.Errorf("mutation capability %q accepted without durable proof", capability)
		}
		input.ReauthGrantID = "reauth_fresh_001"
		input.StepUpAt = delegationTestNow.Add(-MaxHighRiskStepUpAge - time.Second)
		if _, err := signer.SignAdministrator(input); err == nil {
			t.Errorf("mutation capability %q accepted stale proof", capability)
		}
	}
}

func TestAdministratorSignerTreatsContentReadsAsHighRisk(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, Now: func() time.Time { return delegationTestNow }})
	input := validAdministratorAssertion()
	input.Role = adminroles.RoleAdmin
	input.Capability = AdministratorCapabilityContentManage
	input.Method = "GET"
	input.PathAndQuery = "/internal/v1/events/evt_shanghai/content"
	input.BodySHA256 = SHA256Digest(nil)
	input.IdempotencyKey = ""
	input.IfMatch = ""
	input.ReauthGrantID = ""
	if _, err := signer.SignAdministrator(input); err == nil {
		t.Fatal("content draft read accepted without a fresh durable proof")
	}
	input.ReauthGrantID = "reauth_content_001"
	if _, err := signer.SignAdministrator(input); err != nil {
		t.Fatalf("fresh content draft read rejected: %v", err)
	}
}

func TestRequiresFreshAdministratorProofDefaultsFutureMutationsToOneShot(t *testing.T) {
	if !RequiresFreshAdministratorProof(AdministratorCapabilityDashboardRead, "POST") {
		t.Fatal("non-allowlisted mutation did not default to one-shot proof")
	}
	if RequiresFreshAdministratorProof(AdministratorCapabilityDashboardRead, "GET") {
		t.Fatal("ordinary read unexpectedly required a one-shot proof")
	}
}

func TestAdministratorSignerAllowsEveryAdministratorTierToApproveAdmission(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, Now: func() time.Time { return delegationTestNow }})
	for _, role := range []adminroles.Role{adminroles.RoleAdmin, adminroles.RoleSeniorAdmin, adminroles.RoleSuperAdmin} {
		t.Run(string(role), func(t *testing.T) {
			input := validAdministratorAssertion()
			input.Role = role
			input.Capability = AdministratorCapabilityApproveAdmission
			if _, err := signer.SignAdministrator(input); err != nil {
				t.Fatalf("%s admission approval assertion: %v", role, err)
			}
		})
	}
}

func TestAdministratorSignerBindsExactOAClaimAndUsesShorterTTL(t *testing.T) {
	keyring, currentPublic := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: 25 * time.Second, ClockSkew: time.Second, Now: func() time.Time { return delegationTestNow }})
	input := validAdministratorAssertion()
	input.Capability = AdministratorCapabilityIdentityAccessConsume
	input.ReauthGrantID = "reauth_oa_001"
	input.OA = validOAClaim()

	signed, err := signer.SignAdministrator(input)
	if err != nil {
		t.Fatalf("SignAdministrator(OA): %v", err)
	}
	if !signed.ExpiresAt.Equal(delegationTestNow.Add(MaxOATTL)) {
		t.Fatalf("OA envelope expiry = %s", signed.ExpiresAt)
	}
	_, claims := verifyDelegationToken(t, signed.Token, currentPublic)
	if got := int64(claims["exp"].(float64)) - int64(claims["iat"].(float64)); got != 10 {
		t.Fatalf("OA TTL = %d seconds, want 10", got)
	}
	want := input.OA
	assertStringClaim(t, claims, "grant_id", want.GrantID)
	assertStringClaim(t, claims, "requester_user_id", string(want.RequesterID))
	assertStringClaim(t, claims, "target_subject_user_id", string(want.TargetSubject))
	assertStringClaim(t, claims, "target_type", "application")
	assertStringClaim(t, claims, "target_id", want.TargetID)
	assertStringClaim(t, claims, "field_set_hash", ApprovedIdentityFieldSetHash(want.Fields))
	assertStringClaim(t, claims, "claim_nonce", want.ClaimNonce)
	assertStringClaim(t, claims, "reauth_grant_id", input.ReauthGrantID)
	approved := claims["approved_fields"].([]any)
	if len(approved) != len(want.Fields) || approved[0] != "identity_document_number" || approved[1] != "portrait" || int64(claims["grant_version"].(float64)) != want.Version {
		t.Fatalf("OA exact fields not bound: %#v", claims)
	}
	if _, exists := claims["oa"]; exists {
		t.Fatal("nested OA claim is not accepted by the verifier")
	}
	assertExactClaimNames(t, claims, []string{
		"iss", "aud", "sub", "iat", "nbf", "exp", "jti",
		"actor_kind", "event_id", "capability", "request_id", "htm", "htu", "body_sha256", "headers_sha256", "idempotency_key",
		"role_binding_id", "role_version", "challenge_version", "auth_time", "step_up_at", "reauth_grant_id",
		"grant_id", "grant_version", "requester_user_id", "target_type", "target_id", "target_subject_user_id",
		"approved_fields", "field_set_hash", "claim_nonce",
	})
}

func TestAdministratorSignerRejectsOAClaimDriftAndUngrantedIdentityRead(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, _ := NewAdministratorSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: 25 * time.Second, Now: func() time.Time { return delegationTestNow }})
	cases := map[string]func(*AdministratorAssertion){
		"missing grant": func(value *AdministratorAssertion) {
			value.Capability = AdministratorCapabilityIdentityAccessConsume
			value.ReauthGrantID = "reauth_oa_001"
		},
		"wrong capability": func(value *AdministratorAssertion) {
			value.OA = validOAClaim()
		},
		"event drift": func(value *AdministratorAssertion) {
			value.Capability, value.OA, value.ReauthGrantID = AdministratorCapabilityIdentityAccessConsume, validOAClaim(), "reauth_oa_001"
			value.OA.EventID = "evt_other"
		},
		"requester drift": func(value *AdministratorAssertion) {
			value.Capability, value.OA, value.ReauthGrantID = AdministratorCapabilityIdentityAccessConsume, validOAClaim(), "reauth_oa_001"
			value.OA.RequesterID = "usr_other"
		},
		"role binding drift": func(value *AdministratorAssertion) {
			value.Capability, value.OA, value.ReauthGrantID = AdministratorCapabilityIdentityAccessConsume, validOAClaim(), "reauth_oa_001"
			value.OA.RoleBindingVersion++
		},
		"field set drift": func(value *AdministratorAssertion) {
			value.Capability, value.OA, value.ReauthGrantID = AdministratorCapabilityIdentityAccessConsume, validOAClaim(), "reauth_oa_001"
			value.OA.FieldSetHash = SHA256Digest([]byte("wrong"))
		},
		"expired lease": func(value *AdministratorAssertion) {
			value.Capability, value.OA, value.ReauthGrantID = AdministratorCapabilityIdentityAccessConsume, validOAClaim(), "reauth_oa_001"
			value.OA.LeaseExpiresAt = delegationTestNow
		},
		"unsafe grant version": func(value *AdministratorAssertion) {
			value.Capability, value.OA, value.ReauthGrantID = AdministratorCapabilityIdentityAccessConsume, validOAClaim(), "reauth_oa_001"
			value.OA.Version = 1 << 53
		},
		"sub-second lease": func(value *AdministratorAssertion) {
			value.Capability, value.OA, value.ReauthGrantID = AdministratorCapabilityIdentityAccessConsume, validOAClaim(), "reauth_oa_001"
			value.OA.LeaseExpiresAt = delegationTestNow.Add(500 * time.Millisecond)
		},
		"whitespace target": func(value *AdministratorAssertion) {
			value.Capability, value.OA, value.ReauthGrantID = AdministratorCapabilityIdentityAccessConsume, validOAClaim(), "reauth_oa_001"
			value.OA.TargetSubject = " "
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := validAdministratorAssertion()
			mutate(&input)
			if _, err := signer.SignAdministrator(input); err == nil {
				t.Fatal("unsafe OA assertion accepted")
			}
		})
	}
}

func TestServiceSignerBindsDeliveryStateAndOmitsAdministratorClaims(t *testing.T) {
	keyring, currentPublic := loadDelegationTestKeyring(t)
	signer, _ := NewServiceSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup-worker", TTL: 20 * time.Second, Now: func() time.Time { return delegationTestNow }})
	input := validServiceAssertion()
	signed, err := signer.SignService(input)
	if err != nil {
		t.Fatalf("SignService: %v", err)
	}
	if !signed.ExpiresAt.Equal(delegationTestNow.Add(20*time.Second)) || !signed.NotBefore.Equal(delegationTestNow) {
		t.Fatalf("service envelope = %+v", signed)
	}
	_, claims := verifyDelegationToken(t, signed.Token, currentPublic)
	assertStringClaim(t, claims, "actor_kind", "service")
	assertStringClaim(t, claims, "sub", input.Subject)
	assertStringClaim(t, claims, "capability", string(input.Capability))
	assertStringClaim(t, claims, "event_id", input.EventID)
	assertStringClaim(t, claims, "request_id", input.JWTID)
	assertStringClaim(t, claims, "htm", input.Method)
	assertStringClaim(t, claims, "htu", input.PathAndQuery)
	assertStringClaim(t, claims, "headers_sha256", AdministratorHeadersSHA256("", input.IdempotencyKey))
	assertStringClaim(t, claims, "outbox_id", input.OutboxID)
	assertStringClaim(t, claims, "operation_request_id", input.OperationRequestID)
	assertStringClaim(t, claims, "idempotency_key", input.IdempotencyKey)
	if int64(claims["service_version"].(float64)) != input.ServiceVersion {
		t.Fatalf("subject version not bound: %#v", claims)
	}
	for _, forbidden := range []string{"cap", "http_method", "http_path", "query_sha256", "subject_version", "operation_request", "role_binding_id", "challenge_version", "auth_time", "step_up_at", "grant_id"} {
		if _, exists := claims[forbidden]; exists {
			t.Fatalf("service assertion contains administrator claim %q", forbidden)
		}
	}
	assertExactClaimNames(t, claims, []string{
		"iss", "aud", "sub", "iat", "nbf", "exp", "jti",
		"actor_kind", "event_id", "capability", "request_id", "htm", "htu", "body_sha256", "headers_sha256", "idempotency_key",
		"service_version", "outbox_id", "operation_request_id",
	})
}

func TestServiceSignerFailsClosedWhenBindingsAreIncomplete(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, _ := NewServiceSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: time.Second, Now: func() time.Time { return delegationTestNow }})
	cases := map[string]func(*ServiceAssertion){
		"subject":           func(value *ServiceAssertion) { value.Subject = "" },
		"service version":   func(value *ServiceAssertion) { value.ServiceVersion = 0 },
		"unsafe version":    func(value *ServiceAssertion) { value.ServiceVersion = 1 << 53 },
		"jwt id":            func(value *ServiceAssertion) { value.JWTID = "" },
		"capability":        func(value *ServiceAssertion) { value.Capability = "" },
		"event":             func(value *ServiceAssertion) { value.EventID = "" },
		"method":            func(value *ServiceAssertion) { value.Method = "" },
		"htu":               func(value *ServiceAssertion) { value.PathAndQuery = "" },
		"body hash":         func(value *ServiceAssertion) { value.BodySHA256 = "" },
		"outbox":            func(value *ServiceAssertion) { value.OutboxID = "" },
		"operation request": func(value *ServiceAssertion) { value.OperationRequestID = "" },
		"idempotency":       func(value *ServiceAssertion) { value.IdempotencyKey = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := validServiceAssertion()
			mutate(&input)
			if _, err := signer.SignService(input); err == nil {
				t.Fatal("incomplete service assertion accepted")
			}
		})
	}
}

func TestServiceSignerAllowsOnlyExactSubjectCapabilityAndRoute(t *testing.T) {
	keyring, _ := loadDelegationTestKeyring(t)
	signer, _ := NewServiceSigner(keyring, SignerConfig{Issuer: Issuer, Audience: "dreamup", TTL: 20 * time.Second, Now: func() time.Time { return delegationTestNow }})

	for name, mutate := range map[string]func(*ServiceAssertion){
		"wrong subject":          func(value *ServiceAssertion) { value.Subject = "united-pass:other" },
		"unsupported capability": func(value *ServiceAssertion) { value.Capability = "system.operation_receipt.write" },
		"receipt route drift":    func(value *ServiceAssertion) { value.PathAndQuery += "?leak=1" },
		"receipt method drift":   func(value *ServiceAssertion) { value.Method = "POST" },
	} {
		t.Run(name, func(t *testing.T) {
			input := validServiceAssertion()
			mutate(&input)
			if _, err := signer.SignService(input); err == nil {
				t.Fatal("unsafe service assertion accepted")
			}
		})
	}
}

func validAdministratorAssertion() AdministratorAssertion {
	return AdministratorAssertion{
		Subject:          identity.UserID("usr_admin"),
		JWTID:            "assertion_admin_001",
		Capability:       AdministratorCapabilityApplicationReview,
		Method:           "POST",
		PathAndQuery:     "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me",
		BodySHA256:       SHA256Digest([]byte(`{"decision":"accept"}`)),
		EventID:          "evt_shanghai",
		Role:             adminroles.RoleSeniorAdmin,
		RoleBindingID:    "arb_001",
		RoleVersion:      4,
		ChallengeVersion: 3,
		AuthTime:         delegationTestNow.Add(-10 * time.Minute),
		StepUpAt:         delegationTestNow.Add(-30 * time.Second),
		ReauthGrantID:    "reauth_admin_001",
		IdempotencyKey:   "idem_0123456789abcdefghijklmnopqrstuv",
		IfMatch:          `"7"`,
	}
}

func TestAdministratorHeadersSHA256UsesTheCrossServiceCanonicalForm(t *testing.T) {
	if got := AdministratorHeadersSHA256(`"7"`, "idem_0123456789abcdefghijklmnopqrstuv"); got != "c970b5885bcf0f8d1b3620e3e2581fe30ca067858b03c3f9d90ef3cb8d197487" {
		t.Fatalf("headers digest = %q", got)
	}
	if got := AdministratorHeadersSHA256("", ""); got != "f5bd13ced6ee5ee0df7a6fb7851e8354c8f12e03d26892622891b2f3e4cca69a" {
		t.Fatalf("empty headers digest = %q", got)
	}
	if got := AdministratorHeadersSHA256("", "idem_0123456789abcdefghijklmnopqrstuv"); got != "5d12e60ab694cd3d1bcfb323be6b6c3d68c52e392ae5a7a5698e2db212eea734" {
		t.Fatalf("service headers digest = %q", got)
	}
}

func validOAClaim() *OAClaim {
	fields := []identityaccess.Field{identityaccess.FieldIdentityNumber, identityaccess.FieldIdentityPhoto}
	return &OAClaim{
		GrantID:            "iag_001",
		EventID:            "evt_shanghai",
		RequesterID:        identity.UserID("usr_admin"),
		TargetSubject:      identity.UserID("usr_participant"),
		TargetType:         identityaccess.TargetApplication,
		TargetID:           "app_1",
		Fields:             fields,
		FieldSetHash:       IdentityFieldSetHash(fields),
		RoleBindingID:      "arb_001",
		RoleBindingVersion: 4,
		ChallengeVersion:   3,
		ClaimNonce:         "claim_nonce_0123456789abcdef",
		LeaseExpiresAt:     delegationTestNow.Add(time.Minute),
		Version:            2,
	}
}

func validServiceAssertion() ServiceAssertion {
	return ServiceAssertion{
		Subject:            ReconcilerServiceSubject,
		ServiceVersion:     7,
		JWTID:              "assertion_service_001",
		Capability:         ServiceCapabilityOperationReceiptRead,
		EventID:            "evt_shanghai",
		Method:             "GET",
		PathAndQuery:       "/internal/v1/events/evt_shanghai/operation-receipts/opreq_001",
		BodySHA256:         SHA256Digest(nil),
		OutboxID:           "aop_001",
		OperationRequestID: "opreq_001",
		IdempotencyKey:     "idem_0123456789abcdefghijklmnopqrstuv",
	}
}

func writeDelegationTestKeyring(t *testing.T, mode os.FileMode) (string, ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	currentPublic, currentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	retainedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"current": map[string]any{
			"kty": "OKP", "crv": "Ed25519", "kid": "kid-current",
			"x": b64(currentPublic), "d": b64(currentPrivate.Seed()), "use": "sig", "alg": "EdDSA",
		},
		"retained": []any{map[string]any{
			"kty": "OKP", "crv": "Ed25519", "kid": "kid-retained",
			"x": b64(retainedPublic), "use": "sig", "alg": "EdDSA",
		}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "delegation-keyring.json")
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path, currentPublic, retainedPublic
}

func loadDelegationTestKeyring(t *testing.T) (*Keyring, ed25519.PublicKey) {
	t.Helper()
	path, currentPublic, _ := writeDelegationTestKeyring(t, 0o600)
	keyring, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	return keyring, currentPublic
}

func verifyDelegationToken(t *testing.T, token string, public ed25519.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS parts = %d", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("invalid Ed25519 signature")
	}
	decode := func(part string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	return decode(parts[0]), decode(parts[1])
}

func assertStringClaim(t *testing.T, claims map[string]any, name, want string) {
	t.Helper()
	if got, _ := claims[name].(string); got != want {
		t.Fatalf("claim %s = %q, want %q", name, got, want)
	}
}

func assertExactClaimNames(t *testing.T, claims map[string]any, expected []string) {
	t.Helper()
	if len(claims) != len(expected) {
		t.Fatalf("claim count = %d, want %d: %#v", len(claims), len(expected), claims)
	}
	for _, name := range expected {
		if _, exists := claims[name]; !exists {
			t.Fatalf("required claim %q missing: %#v", name, claims)
		}
	}
}

func b64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func TestSHA256DigestUsesLowercaseHex(t *testing.T) {
	digest := sha256.Sum256([]byte("moonstone"))
	if got, want := SHA256Digest([]byte("moonstone")), fmt.Sprintf("%x", digest); got != want {
		t.Fatalf("SHA256Digest = %q, want %q", got, want)
	}
}

func TestCanonicalPathAndQueryMatchesWHATWGFormEncoding(t *testing.T) {
	query := url.Values{
		"tilde": {"~"},
		"star":  {"*"},
		"word":  {"Moon Stone"},
		"emoji": {"🌕"},
	}
	got, err := CanonicalPathAndQuery("/internal/v1/events/evt_shanghai/dashboard", query)
	if err != nil {
		t.Fatalf("CanonicalPathAndQuery: %v", err)
	}
	want := "/internal/v1/events/evt_shanghai/dashboard?emoji=%F0%9F%8C%95&star=*&tilde=%7E&word=Moon+Stone"
	if got != want {
		t.Fatalf("canonical htu = %q, want %q", got, want)
	}
}
