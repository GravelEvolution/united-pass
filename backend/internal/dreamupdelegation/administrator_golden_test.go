package dreamupdelegation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
)

type administratorGoldenFixture struct {
	Version                   int                       `json:"version"`
	Description               string                    `json:"description"`
	CanonicalHeadersAlgorithm string                    `json:"canonicalHeadersAlgorithm"`
	Verification              administratorVerification `json:"verification"`
	Cases                     []administratorGoldenCase `json:"cases"`
}

type administratorVerification struct {
	Issuer                   string        `json:"issuer"`
	Audience                 string        `json:"audience"`
	Algorithm                string        `json:"algorithm"`
	KeyID                    string        `json:"keyId"`
	TTLSeconds               int           `json:"ttlSeconds"`
	ClockSkewSeconds         int           `json:"clockSkewSeconds"`
	Now                      string        `json:"now"`
	MaxLoginAgeSeconds       int           `json:"maxLoginAgeSeconds"`
	MaxFreshStepUpAgeSeconds int           `json:"maxFreshStepUpAgeSeconds"`
	JWKS                     JSONWebKeySet `json:"jwks"`
}

type administratorGoldenCase struct {
	Name             string `json:"name"`
	ExpectedVerifier string `json:"expectedVerifier"`
	ProductionSigner string `json:"productionSigner"`
	Capability       string `json:"capability"`
	Method           string `json:"method"`
	PathAndQuery     string `json:"pathAndQuery"`
	BodyUTF8         string `json:"bodyUtf8"`
	BodySHA256       string `json:"bodySha256"`
	IfMatch          string `json:"ifMatch"`
	IdempotencyKey   string `json:"idempotencyKey"`
	HeadersSHA256    string `json:"headersSha256"`
	Role             string `json:"role"`
	RoleBindingID    string `json:"roleBindingId"`
	RoleVersion      int64  `json:"roleVersion"`
	ChallengeVersion int64  `json:"challengeVersion"`
	AuthTime         string `json:"authTime"`
	StepUpAt         string `json:"stepUpAt"`
	ReauthGrantID    string `json:"reauthGrantId"`
	CompactJWS       string `json:"compactJws"`
}

func TestAdministratorAssertionCrossLanguageGoldenFixture(t *testing.T) {
	fixture := buildAdministratorGoldenFixture(t)
	generated, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	generated = append(generated, '\n')
	path := filepath.Join("testdata", "administrator_assertions_v1.json")
	committed, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(committed, generated) {
		t.Fatalf("administrator cross-language fixture drift; replace %s with:\n%s", path, generated)
	}
}

func buildAdministratorGoldenFixture(t *testing.T) administratorGoldenFixture {
	t.Helper()
	const keyID = "administrator-golden-v1"
	seed := sha256.Sum256([]byte("United Pass administrator assertion cross-language fixture v1; TEST KEY ONLY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyring, err := buildKeyring(keyringDocument{
		Current: privateJSONWebKey{
			Kty: "OKP", Crv: "Ed25519", Kid: keyID,
			X: base64.RawURLEncoding.EncodeToString(publicKey), D: base64.RawURLEncoding.EncodeToString(seed[:]),
			Use: "sig", Alg: "EdDSA",
		},
		Retained: []JSONWebKey{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var jwks JSONWebKeySet
	if err := json.Unmarshal(keyring.PublicJWKS(), &jwks); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 13, 0, 0, 0, time.UTC)
	config := SignerConfig{Issuer: Issuer, Audience: "dreamup-admin-api", TTL: 25 * time.Second, ClockSkew: 2 * time.Second, Now: func() time.Time { return now }}
	signer, err := NewAdministratorSigner(keyring, config)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"recommendation":"accept","note":"fixture"}`
	inputs := []struct {
		name, expected string
		input          AdministratorAssertion
	}{
		{
			name: "read-basic-without-durable-grant", expected: "accept",
			input: AdministratorAssertion{
				Subject: "user_admin_golden", JWTID: "req_admin_golden_read", Capability: AdministratorCapabilityApplicationRead,
				Method: "GET", PathAndQuery: "/internal/v1/events/evt_shanghai/applications/app_1", BodySHA256: SHA256Digest(nil),
				EventID: "evt_shanghai", Role: adminroles.RoleAdmin, RoleBindingID: "binding_golden_1", RoleVersion: 7, ChallengeVersion: 4,
				AuthTime: now.Add(-20 * time.Minute), StepUpAt: now.Add(-10 * time.Minute),
			},
		},
		{
			name: "application-review-with-fresh-durable-grant", expected: "accept",
			input: AdministratorAssertion{
				Subject: "user_admin_golden", JWTID: "req_admin_golden_review", Capability: AdministratorCapabilityApplicationReview,
				Method: "PUT", PathAndQuery: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", BodySHA256: SHA256Digest([]byte(body)), IfMatch: `"7"`, IdempotencyKey: "idem_admin_golden_0123456789abcdef",
				EventID: "evt_shanghai", Role: adminroles.RoleAdmin, RoleBindingID: "binding_golden_1", RoleVersion: 7, ChallengeVersion: 4,
				AuthTime: now.Add(-20 * time.Minute), StepUpAt: now.Add(-2 * time.Minute), ReauthGrantID: "asu_golden_fresh_1",
			},
		},
		{
			name: "application-review-missing-durable-grant", expected: "reject",
			input: AdministratorAssertion{
				Subject: "user_admin_golden", JWTID: "req_admin_golden_missing", Capability: AdministratorCapabilityApplicationReview,
				Method: "PUT", PathAndQuery: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", BodySHA256: SHA256Digest([]byte(body)), IfMatch: `"7"`, IdempotencyKey: "idem_admin_missing_0123456789abcdef",
				EventID: "evt_shanghai", Role: adminroles.RoleAdmin, RoleBindingID: "binding_golden_1", RoleVersion: 7, ChallengeVersion: 4,
				AuthTime: now.Add(-20 * time.Minute), StepUpAt: now.Add(-2 * time.Minute),
			},
		},
		{
			name: "application-review-expired-durable-grant", expected: "reject",
			input: AdministratorAssertion{
				Subject: "user_admin_golden", JWTID: "req_admin_golden_expired", Capability: AdministratorCapabilityApplicationReview,
				Method: "PUT", PathAndQuery: "/internal/v1/events/evt_shanghai/applications/app_1/reviews/me", BodySHA256: SHA256Digest([]byte(body)), IfMatch: `"7"`, IdempotencyKey: "idem_admin_expired_0123456789abcdef",
				EventID: "evt_shanghai", Role: adminroles.RoleAdmin, RoleBindingID: "binding_golden_1", RoleVersion: 7, ChallengeVersion: 4,
				AuthTime: now.Add(-20 * time.Minute), StepUpAt: now.Add(-MaxHighRiskStepUpAge - time.Second), ReauthGrantID: "asu_golden_expired_1",
			},
		},
	}
	cases := make([]administratorGoldenCase, 0, len(inputs))
	for _, item := range inputs {
		signed, signErr := signer.SignAdministrator(item.input)
		productionResult := "signed"
		if item.expected == "reject" {
			if !errors.Is(signErr, ErrInvalidAssertion) {
				t.Fatalf("%s production signer error=%v", item.name, signErr)
			}
			productionResult = "rejected"
			signed = signUncheckedAdministratorGolden(t, keyring, config, item.input, now)
		} else if signErr != nil {
			t.Fatalf("%s production signer error=%v", item.name, signErr)
		}
		assertAdministratorGoldenSignature(t, signed.Token, keyID, publicKey)
		caseBody := ""
		if item.input.Method != "GET" {
			caseBody = body
		}
		cases = append(cases, administratorGoldenCase{
			Name: item.name, ExpectedVerifier: item.expected, ProductionSigner: productionResult,
			Capability: string(item.input.Capability), Method: item.input.Method, PathAndQuery: item.input.PathAndQuery,
			BodyUTF8: caseBody, BodySHA256: item.input.BodySHA256, IfMatch: item.input.IfMatch, IdempotencyKey: item.input.IdempotencyKey,
			HeadersSHA256: AdministratorHeadersSHA256(item.input.IfMatch, item.input.IdempotencyKey), Role: string(item.input.Role),
			RoleBindingID: item.input.RoleBindingID, RoleVersion: item.input.RoleVersion, ChallengeVersion: item.input.ChallengeVersion,
			AuthTime: item.input.AuthTime.UTC().Format(time.RFC3339), StepUpAt: item.input.StepUpAt.UTC().Format(time.RFC3339),
			ReauthGrantID: item.input.ReauthGrantID, CompactJWS: signed.Token,
		})
	}
	return administratorGoldenFixture{
		Version:                   1,
		Description:               "Deterministic TEST-ONLY Go AdministratorSigner/verifier vectors. Reject cases are signed only by the test helper after the production signer rejects them.",
		CanonicalHeadersAlgorithm: "sha256(utf8('if-match\\0' + ifMatch + '\\0idempotency-key\\0' + idempotencyKey)) as lowercase hex",
		Verification: administratorVerification{
			Issuer: Issuer, Audience: config.Audience, Algorithm: "EdDSA", KeyID: keyID, TTLSeconds: 25, ClockSkewSeconds: 2,
			Now: now.Format(time.RFC3339), MaxLoginAgeSeconds: int(MaxAdministratorLoginAge / time.Second), MaxFreshStepUpAgeSeconds: int(MaxHighRiskStepUpAge / time.Second), JWKS: jwks,
		},
		Cases: cases,
	}
}

func signUncheckedAdministratorGolden(t *testing.T, keyring *Keyring, config SignerConfig, input AdministratorAssertion, now time.Time) SignedAssertion {
	t.Helper()
	claims := administratorClaims{
		registeredClaims: newRegisteredClaims(config, string(input.Subject), input.JWTID, now, config.TTL),
		commonClaims: commonClaims{
			ActorKind: "administrator", EventID: input.EventID, Capability: string(input.Capability), RequestID: input.JWTID,
			Method: input.Method, PathAndQuery: input.PathAndQuery, BodySHA256: input.BodySHA256,
			HeadersSHA256: AdministratorHeadersSHA256(input.IfMatch, input.IdempotencyKey), IdempotencyKey: input.IdempotencyKey,
		},
		RoleBindingID: input.RoleBindingID, RoleVersion: input.RoleVersion, ChallengeVersion: input.ChallengeVersion,
		AuthTime: input.AuthTime.UTC().Unix(), StepUpAt: input.StepUpAt.UTC().Unix(), ReauthGrantID: input.ReauthGrantID,
	}
	signed, err := keyring.signedAssertion(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func assertAdministratorGoldenSignature(t *testing.T, token, keyID string, publicKey ed25519.PublicKey) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWS parts=%d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(header) != `{"alg":"EdDSA","kid":"`+keyID+`","typ":"JWT"}` {
		t.Fatalf("protected header=%s err=%v", header, err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("fixture token has invalid Ed25519 signature")
	}
}
