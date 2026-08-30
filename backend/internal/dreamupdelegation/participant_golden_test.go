package dreamupdelegation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type participantGoldenFixture struct {
	Version                   int                     `json:"version"`
	Description               string                  `json:"description"`
	CanonicalHeadersAlgorithm string                  `json:"canonicalHeadersAlgorithm"`
	Subject                   string                  `json:"subject"`
	Verification              participantVerification `json:"verification"`
	Cases                     []participantGoldenCase `json:"cases"`
}

type participantVerification struct {
	Issuer           string        `json:"issuer"`
	Audience         string        `json:"audience"`
	Algorithm        string        `json:"algorithm"`
	KeyID            string        `json:"keyId"`
	TTLSeconds       int           `json:"ttlSeconds"`
	ClockSkewSeconds int           `json:"clockSkewSeconds"`
	Now              string        `json:"now"`
	JWKS             JSONWebKeySet `json:"jwks"`
}

type participantGoldenCase struct {
	Name             string                   `json:"name"`
	JWTID            string                   `json:"jti"`
	Method           string                   `json:"method"`
	PathAndQuery     string                   `json:"pathAndQuery"`
	BodyUTF8         string                   `json:"bodyUtf8"`
	BodySHA256       string                   `json:"bodySha256"`
	IfMatch          string                   `json:"ifMatch"`
	IdempotencyKey   string                   `json:"idempotencyKey"`
	CanonicalHeaders string                   `json:"canonicalHeaders"`
	HeadersSHA256    string                   `json:"headersSha256"`
	ResumeUpload     *participantGoldenResume `json:"resumeUpload,omitempty"`
	CompactJWS       string                   `json:"compactJws"`
}

type participantGoldenResume struct {
	FileName    string `json:"fileName"`
	ContentType string `json:"contentType"`
	ByteSize    int64  `json:"byteSize"`
}

type participantGoldenClaims struct {
	Issuer            string `json:"iss"`
	Audience          string `json:"aud"`
	Subject           string `json:"sub"`
	IssuedAt          int64  `json:"iat"`
	NotBefore         int64  `json:"nbf"`
	ExpiresAt         int64  `json:"exp"`
	JWTID             string `json:"jti"`
	ActorKind         string `json:"actor_kind"`
	Method            string `json:"htm"`
	PathAndQuery      string `json:"htu"`
	BodySHA256        string `json:"body_sha256"`
	HeadersSHA256     string `json:"headers_sha256"`
	ResumeFileName    string `json:"resume_file_name,omitempty"`
	ResumeContentType string `json:"resume_content_type,omitempty"`
	ResumeByteSize    int64  `json:"resume_byte_size,omitempty"`
}

func TestParticipantAssertionCrossLanguageGoldenFixture(t *testing.T) {
	fixture := buildParticipantGoldenFixture(t)
	generated, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	generated = append(generated, '\n')
	path := filepath.Join("testdata", "participant_assertions_v1.json")
	committed, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(committed, generated) {
		t.Fatalf("participant cross-language fixture drift; replace %s with:\n%s", path, generated)
	}
}

func buildParticipantGoldenFixture(t *testing.T) participantGoldenFixture {
	t.Helper()
	const keyID = "participant-golden-v1"
	seed := sha256.Sum256([]byte("United Pass participant assertion cross-language fixture v1; TEST KEY ONLY"))
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
	now := time.Date(2026, 8, 27, 12, 34, 56, 0, time.UTC)
	signer, err := NewParticipantSigner(keyring, SignerConfig{
		Issuer: Issuer, Audience: "dreamup-mobile-api", TTL: 15 * time.Second,
		ClockSkew: 2 * time.Second, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	type inputCase struct {
		name, jti, method, path, body, ifMatch, idempotencyKey string
		resume                                                 *ResumeUploadMetadata
	}
	inputs := []inputCase{
		{name: "get-application-empty-body", jti: "req_golden_get_application", method: "GET", path: "/api/v1/events/dreamup-shanghai/me/application"},
		{name: "contact-feedback", jti: "req_golden_contact_feedback", method: "POST", path: "/api/v1/events/dreamup-shanghai/me/feedback", body: `{"content":"The application form cannot be submitted."}`, idempotencyKey: "idem_contact_0123456789abcdefghijkl"},
		{name: "team-patch", jti: "req_golden_team_patch", method: "PATCH", path: "/api/v1/events/dreamup-shanghai/me/team", body: `{"name":"Moonstone Builders","description":"Cross-language fixture"}`, ifMatch: `"7"`, idempotencyKey: "idem_team_0123456789abcdefghijklmno"},
		{name: "resume-upload-metadata", jti: "req_golden_resume_upload", method: "PUT", path: "/api/v1/events/dreamup-shanghai/me/application/resume", body: "fixture resume bytes\n", resume: &ResumeUploadMetadata{FileName: "简历-fixture.pdf", ContentType: "application/pdf", ByteSize: 21}},
		{name: "admission-entry-code", jti: "req_golden_entry_code", method: "POST", path: "/api/v1/events/dreamup-shanghai/me/admission/entry-code", body: `{"code":"ENTRY-2026"}`, idempotencyKey: "idem_entry_0123456789abcdefghijklmn"},
		{name: "admission-group-qr", jti: "req_golden_group_qr", method: "GET", path: "/api/v1/events/dreamup-shanghai/me/admission/group-qr"},
	}
	cases := make([]participantGoldenCase, 0, len(inputs))
	for _, input := range inputs {
		bodyHash := SHA256Digest([]byte(input.body))
		canonicalHeaders := "if-match\x00" + input.ifMatch + "\x00idempotency-key\x00" + input.idempotencyKey
		headersHash := ParticipantHeadersSHA256(input.ifMatch, input.idempotencyKey)
		signed, err := signer.SignParticipant(ParticipantAssertion{
			Subject: "zitadel-subject-golden-01", JWTID: input.jti, Method: input.method,
			PathAndQuery: input.path, BodySHA256: bodyHash, HeaderSHA256: headersHash, ResumeUpload: input.resume,
		})
		if err != nil {
			t.Fatalf("sign %s: %v", input.name, err)
		}
		expected := participantGoldenClaims{
			Issuer: Issuer, Audience: "dreamup-mobile-api", Subject: "zitadel-subject-golden-01",
			IssuedAt: now.Unix(), NotBefore: now.Add(-2 * time.Second).Unix(), ExpiresAt: now.Add(15 * time.Second).Unix(), JWTID: input.jti,
			ActorKind: "participant", Method: input.method, PathAndQuery: input.path, BodySHA256: bodyHash, HeadersSHA256: headersHash,
		}
		if input.resume != nil {
			expected.ResumeFileName = input.resume.FileName
			expected.ResumeContentType = input.resume.ContentType
			expected.ResumeByteSize = input.resume.ByteSize
		}
		assertParticipantGoldenToken(t, signed.Token, keyID, publicKey, expected)
		var resume *participantGoldenResume
		if input.resume != nil {
			resume = &participantGoldenResume{FileName: input.resume.FileName, ContentType: input.resume.ContentType, ByteSize: input.resume.ByteSize}
		}
		cases = append(cases, participantGoldenCase{
			Name: input.name, JWTID: input.jti, Method: input.method, PathAndQuery: input.path, BodyUTF8: input.body,
			BodySHA256: bodyHash, IfMatch: input.ifMatch, IdempotencyKey: input.idempotencyKey,
			CanonicalHeaders: canonicalHeaders, HeadersSHA256: headersHash, ResumeUpload: resume, CompactJWS: signed.Token,
		})
	}
	return participantGoldenFixture{
		Version:                   1,
		Description:               "Deterministic TEST-ONLY Go ParticipantSigner outputs consumed by the DreamUP TypeScript verifier.",
		CanonicalHeadersAlgorithm: "sha256(utf8('if-match\\0' + ifMatch + '\\0idempotency-key\\0' + idempotencyKey)) as lowercase hex",
		Subject:                   "zitadel-subject-golden-01",
		Verification: participantVerification{
			Issuer: Issuer, Audience: "dreamup-mobile-api", Algorithm: "EdDSA", KeyID: keyID,
			TTLSeconds: 15, ClockSkewSeconds: 2, Now: now.Format(time.RFC3339), JWKS: jwks,
		},
		Cases: cases,
	}
}

func assertParticipantGoldenToken(t *testing.T, token, keyID string, publicKey ed25519.PublicKey, expected participantGoldenClaims) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWS parts=%d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(header) != `{"alg":"EdDSA","kid":"`+keyID+`","typ":"JWT"}` {
		t.Fatalf("protected header=%s err=%v", header, err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	expectedPayload, err := json.Marshal(expected)
	if err != nil || !bytes.Equal(payload, expectedPayload) {
		t.Fatalf("payload=%s expected=%s err=%v", payload, expectedPayload, err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("fixture token has invalid Ed25519 signature")
	}
}
