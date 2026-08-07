//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the session store
//

package redis

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// TestSessionRecordJSONRoundTrip verifies that a SessionRecord survives JSON
// encoding and decoding with all fields intact, especially time.Time fields
// (which must use RFC3339) and slice fields. This is critical because the
// session store persists records as JSON in Redis.
func TestSessionRecordJSONRoundTrip(t *testing.T) {
	t.Parallel()

	reauthUntil := time.Date(2026, 8, 5, 14, 30, 0, 0, time.UTC)
	original := session.SessionRecord{
		Version:                  1,
		SessionID:                session.SessionID("sess_abc123"),
		UserID:                   identity.UserID("user_01HZX9"),
		Provider:                 "zitadel",
		ProviderSessionReference: "provider-session-ref-xyz",
		CreatedAt:                time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		LastSeenAt:               time.Date(2026, 8, 5, 12, 5, 0, 0, time.UTC),
		ExpiresAt:                time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC),
		AuthenticationTime:       time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		AuthenticationMethods: []auth.AuthenticationMethod{
			auth.MethodPassword,
			auth.MethodTOTP,
		},
		ReauthenticatedUntil: &reauthUntil,
		CSRFTokenHash:        "csrf_hash_aabbccdd",
		UserAgentHash:        "ua_hash_eeff0011",
		Remember:             true,
	}

	payload, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal SessionRecord: %v", err)
	}

	// Verify time fields are encoded as RFC3339 strings, not Unix timestamps
	// or epoch numbers. This ensures interoperability and human readability.
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("unmarshal to raw map: %v", err)
	}

	createdAtRaw, ok := raw["createdAt"]
	if !ok {
		t.Fatal("createdAt field missing from JSON")
	}
	createdAtStr, ok := createdAtRaw.(string)
	if !ok {
		t.Fatalf("createdAt is %T, want string (RFC3339)", createdAtRaw)
	}
	if _, err := time.Parse(time.RFC3339Nano, createdAtStr); err != nil {
		t.Fatalf("createdAt %q is not valid RFC3339: %v", createdAtStr, err)
	}

	var decoded session.SessionRecord
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal SessionRecord: %v", err)
	}

	// Compare each field explicitly rather than using reflect.DeepEqual on
	// the whole struct, because time.Time equality can be tricky with
	// monotonic clocks. We compare UTC representations.
	if decoded.Version != original.Version {
		t.Errorf("Version: got %d, want %d", decoded.Version, original.Version)
	}
	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID: got %q, want %q", decoded.SessionID, original.SessionID)
	}
	if decoded.UserID != original.UserID {
		t.Errorf("UserID: got %q, want %q", decoded.UserID, original.UserID)
	}
	if decoded.Provider != original.Provider {
		t.Errorf("Provider: got %q, want %q", decoded.Provider, original.Provider)
	}
	if decoded.ProviderSessionReference != original.ProviderSessionReference {
		t.Errorf("ProviderSessionReference: got %q, want %q",
			decoded.ProviderSessionReference, original.ProviderSessionReference)
	}
	if !decoded.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt: got %v, want %v", decoded.CreatedAt, original.CreatedAt)
	}
	if !decoded.LastSeenAt.Equal(original.LastSeenAt) {
		t.Errorf("LastSeenAt: got %v, want %v", decoded.LastSeenAt, original.LastSeenAt)
	}
	if !decoded.ExpiresAt.Equal(original.ExpiresAt) {
		t.Errorf("ExpiresAt: got %v, want %v", decoded.ExpiresAt, original.ExpiresAt)
	}
	if !decoded.AuthenticationTime.Equal(original.AuthenticationTime) {
		t.Errorf("AuthenticationTime: got %v, want %v",
			decoded.AuthenticationTime, original.AuthenticationTime)
	}
	if len(decoded.AuthenticationMethods) != len(original.AuthenticationMethods) {
		t.Errorf("AuthenticationMethods length: got %d, want %d",
			len(decoded.AuthenticationMethods), len(original.AuthenticationMethods))
	} else {
		for i, m := range original.AuthenticationMethods {
			if decoded.AuthenticationMethods[i] != m {
				t.Errorf("AuthenticationMethods[%d]: got %q, want %q",
					i, decoded.AuthenticationMethods[i], m)
			}
		}
	}
	if decoded.ReauthenticatedUntil == nil {
		t.Fatal("ReauthenticatedUntil: got nil, want non-nil")
	}
	if !decoded.ReauthenticatedUntil.Equal(*original.ReauthenticatedUntil) {
		t.Errorf("ReauthenticatedUntil: got %v, want %v",
			*decoded.ReauthenticatedUntil, *original.ReauthenticatedUntil)
	}
	if decoded.CSRFTokenHash != original.CSRFTokenHash {
		t.Errorf("CSRFTokenHash: got %q, want %q",
			decoded.CSRFTokenHash, original.CSRFTokenHash)
	}
	if decoded.UserAgentHash != original.UserAgentHash {
		t.Errorf("UserAgentHash: got %q, want %q",
			decoded.UserAgentHash, original.UserAgentHash)
	}
	if decoded.Remember != original.Remember {
		t.Errorf("Remember: got %v, want %v", decoded.Remember, original.Remember)
	}
}

// TestSessionRecordJSONNilReauthenticatedUntil verifies that a nil
// ReauthenticatedUntil pointer is omitted from JSON and decodes back to nil.
func TestSessionRecordJSONNilReauthenticatedUntil(t *testing.T) {
	t.Parallel()

	original := session.SessionRecord{
		Version:              1,
		SessionID:            session.SessionID("sess_no_reauth"),
		UserID:               identity.UserID("user_01"),
		Provider:             "zitadel",
		CreatedAt:            time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		LastSeenAt:           time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		ExpiresAt:            time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC),
		AuthenticationTime:   time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		CSRFTokenHash:        "csrf_hash",
		ReauthenticatedUntil: nil,
	}

	payload, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The omitempty tag should omit the field entirely.
	if strings.Contains(string(payload), "reauthenticatedUntil") {
		t.Errorf("JSON should omit reauthenticatedUntil when nil, got: %s", payload)
	}

	var decoded session.SessionRecord
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ReauthenticatedUntil != nil {
		t.Errorf("ReauthenticatedUntil: got %v, want nil", *decoded.ReauthenticatedUntil)
	}
}

// TestSessionKeyConstruction verifies that the session store constructs Redis
// keys as {prefix}session:{tokenHash} and that the key prefix is applied
// correctly.
func TestSessionKeyConstruction(t *testing.T) {
	t.Parallel()

	const prefix = "up:test:"
	client := &Client{keyPrefix: prefix}

	tokenHash := "aabbccdd11223344"
	key := client.buildKey(sessionKeySegment, tokenHash)

	expected := "up:test:session:aabbccdd11223344"
	if key != expected {
		t.Errorf("session key: got %q, want %q", key, expected)
	}
}

// TestMFAKeyConstruction verifies that the MFA store constructs keys for both
// challenge data and the attempt counter.
func TestMFAKeyConstruction(t *testing.T) {
	t.Parallel()

	const prefix = "up:test:"
	client := &Client{keyPrefix: prefix}

	mfaTokenHash := "eeff00112233"
	challengeKey := client.buildKey(mfaKeySegment, mfaTokenHash)
	attemptsKey := client.buildKey(mfaAttemptsKeySegment, mfaTokenHash)

	expectedChallenge := "up:test:mfa:eeff00112233"
	if challengeKey != expectedChallenge {
		t.Errorf("mfa challenge key: got %q, want %q", challengeKey, expectedChallenge)
	}

	expectedAttempts := "up:test:mfa:attempts:eeff00112233"
	if attemptsKey != expectedAttempts {
		t.Errorf("mfa attempts key: got %q, want %q", attemptsKey, expectedAttempts)
	}
}

// TestRateLimitKeyConstruction verifies that rate limiter keys include the IP
// and the identifier hash, never the raw identifier.
func TestRateLimitKeyConstruction(t *testing.T) {
	t.Parallel()

	const prefix = "up:test:"
	client := &Client{keyPrefix: prefix}

	ip := "192.168.1.100"
	identifierHash := "deadbeefcafebabe"
	mfaTokenHash := "aabbccddeeff0011"

	loginKey := client.buildKey(rateLimitLoginSegment, ip, ":", identifierHash)
	expectedLogin := "up:test:rl:login:192.168.1.100:deadbeefcafebabe"
	if loginKey != expectedLogin {
		t.Errorf("login rate limit key: got %q, want %q", loginKey, expectedLogin)
	}

	mfaKey := client.buildKey(rateLimitMFASegment, ip, ":", mfaTokenHash)
	expectedMFA := "up:test:rl:mfa:192.168.1.100:aabbccddeeff0011"
	if mfaKey != expectedMFA {
		t.Errorf("mfa rate limit key: got %q, want %q", mfaKey, expectedMFA)
	}
}

// TestKeysUseHashesNotRawTokens verifies that session.HashToken produces a
// hex-encoded SHA-256 hash that differs from the raw token. This is the
// security invariant that prevents raw tokens from appearing in Redis keys.
func TestKeysUseHashesNotRawTokens(t *testing.T) {
	t.Parallel()

	rawToken := "super-secret-session-token-value"
	tokenHash := session.HashToken(rawToken)

	// The hash must not equal the raw token.
	if tokenHash == rawToken {
		t.Fatal("token hash equals raw token — this is a security violation")
	}

	// The hash must be 64 hex characters (SHA-256 = 32 bytes = 64 hex chars).
	if len(tokenHash) != 64 {
		t.Errorf("token hash length: got %d, want 64 (SHA-256 hex)", len(tokenHash))
	}

	// The hash must only contain hex characters.
	for _, c := range tokenHash {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Errorf("token hash contains non-hex character %q in %q", c, tokenHash)
			break
		}
	}

	// Construct the full key and verify the raw token does not appear in it.
	const prefix = "up:test:"
	client := &Client{keyPrefix: prefix}
	key := client.buildKey(sessionKeySegment, tokenHash)

	if strings.Contains(key, rawToken) {
		t.Fatal("Redis key contains the raw session token — security violation")
	}

	// The key must contain the hash.
	if !strings.Contains(key, tokenHash) {
		t.Errorf("Redis key %q does not contain the token hash %q", key, tokenHash)
	}
}

// TestHashTokenDeterministic verifies that the same input always produces the
// same hash, which is essential for session lookups.
func TestHashTokenDeterministic(t *testing.T) {
	t.Parallel()

	token := "some-token-value"
	hash1 := session.HashToken(token)
	hash2 := session.HashToken(token)

	if hash1 != hash2 {
		t.Fatalf("HashToken is not deterministic: %q vs %q", hash1, hash2)
	}

	// Different tokens must produce different hashes.
	otherToken := "different-token"
	otherHash := session.HashToken(otherToken)
	if hash1 == otherHash {
		t.Fatal("different tokens produced the same hash")
	}
}

// TestMFAChallengeDataJSONRoundTrip verifies that MFAChallengeData survives JSON
// encoding and decoding with all fields intact.
func TestMFAChallengeDataJSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := auth.MFAChallengeData{
		UserID:                   identity.UserID("user_01HZX9"),
		Provider:                 "zitadel",
		ProviderSessionReference: "provider-ref-abc",
		AuthenticationMethods: []auth.AuthenticationMethod{
			auth.MethodPassword,
		},
		AvailableMethods: []auth.MFAMethod{
			auth.MFAMethodTOTP,
			auth.MFAMethodPasskey,
		},
		Attempts:  0,
		CreatedAt: time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
	}

	payload, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal MFAChallengeData: %v", err)
	}

	var decoded auth.MFAChallengeData
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal MFAChallengeData: %v", err)
	}

	if decoded.UserID != original.UserID {
		t.Errorf("UserID: got %q, want %q", decoded.UserID, original.UserID)
	}
	if decoded.Provider != original.Provider {
		t.Errorf("Provider: got %q, want %q", decoded.Provider, original.Provider)
	}
	if decoded.ProviderSessionReference != original.ProviderSessionReference {
		t.Errorf("ProviderSessionReference: got %q, want %q",
			decoded.ProviderSessionReference, original.ProviderSessionReference)
	}
	if len(decoded.AuthenticationMethods) != len(original.AuthenticationMethods) {
		t.Errorf("AuthenticationMethods length: got %d, want %d",
			len(decoded.AuthenticationMethods), len(original.AuthenticationMethods))
	}
	if len(decoded.AvailableMethods) != len(original.AvailableMethods) {
		t.Errorf("AvailableMethods length: got %d, want %d",
			len(decoded.AvailableMethods), len(original.AvailableMethods))
	}
	if decoded.Attempts != original.Attempts {
		t.Errorf("Attempts: got %d, want %d", decoded.Attempts, original.Attempts)
	}
	if !decoded.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt: got %v, want %v", decoded.CreatedAt, original.CreatedAt)
	}
}

// TestKeyPrefixIsolation verifies that different key prefixes produce
// non-overlapping keys. This prevents development, test, and production
// environments from colliding in a shared Redis instance.
func TestKeyPrefixIsolation(t *testing.T) {
	t.Parallel()

	devClient := &Client{keyPrefix: "up:development:"}
	prodClient := &Client{keyPrefix: "up:production:"}
	testClient := &Client{keyPrefix: "up:test:"}

	tokenHash := "sharedhash123"

	devKey := devClient.buildKey(sessionKeySegment, tokenHash)
	prodKey := prodClient.buildKey(sessionKeySegment, tokenHash)
	testKey := testClient.buildKey(sessionKeySegment, tokenHash)

	if devKey == prodKey {
		t.Errorf("development and production keys collide: %q", devKey)
	}
	if devKey == testKey {
		t.Errorf("development and test keys collide: %q", devKey)
	}
	if prodKey == testKey {
		t.Errorf("production and test keys collide: %q", prodKey)
	}

	// All keys must contain the same hash.
	for _, key := range []string{devKey, prodKey, testKey} {
		if !strings.Contains(key, tokenHash) {
			t.Errorf("key %q does not contain token hash %q", key, tokenHash)
		}
	}
}
