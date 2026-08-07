//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the session crypto helpers
//

package session

import (
	"strings"
	"testing"
)

const testKeyB64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes

func mustEncryptor(t *testing.T) *AESGCMEncryptor {
	t.Helper()
	enc, err := NewAESGCMEncryptor(testKeyB64, "test-v1")
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	return enc
}

func TestAESGCMEncryptorRoundTrip(t *testing.T) {
	enc := mustEncryptor(t)

	plaintext := "provider-session-ref-abc123"
	encoded, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The ciphertext must not contain the plaintext.
	if strings.Contains(encoded, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	decrypted, err := enc.Decrypt(encoded)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAESGCMEncryptorRandomizedCiphertext(t *testing.T) {
	enc := mustEncryptor(t)

	// Encrypting the same plaintext twice must yield different ciphertexts
	// because each encryption uses a fresh random nonce.
	a, err := enc.Encrypt("same-value")
	if err != nil {
		t.Fatalf("Encrypt a: %v", err)
	}
	b, err := enc.Encrypt("same-value")
	if err != nil {
		t.Fatalf("Encrypt b: %v", err)
	}
	if a == b {
		t.Fatal("encrypting the same value twice produced identical ciphertext")
	}
}

func TestAESGCMEncryptorRejectsTamperedCiphertext(t *testing.T) {
	enc := mustEncryptor(t)

	encoded, err := enc.Encrypt("sensitive-reference")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip one character in the payload section (after the keyID prefix).
	idx := strings.IndexByte(encoded, ':') + 1
	tampered := encoded[:idx] + "A" + encoded[idx+1:]
	if tampered == encoded {
		// The first payload char was already 'A'; flip it to 'B'.
		tampered = encoded[:idx] + "B" + encoded[idx+1:]
	}

	if _, err := enc.Decrypt(tampered); err == nil {
		t.Fatal("Decrypt accepted tampered ciphertext")
	}
	if _, err := enc.Decrypt(tampered); err != ErrInvalidCiphertext {
		t.Errorf("Decrypt tampered error = %v, want ErrInvalidCiphertext", err)
	}
}

func TestAESGCMEncryptorRejectsWrongKeyID(t *testing.T) {
	enc := mustEncryptor(t)

	encoded, err := enc.Encrypt("ref")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	other, err := NewAESGCMEncryptor(testKeyB64, "other-key")
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor other: %v", err)
	}
	if _, err := other.Decrypt(encoded); err != ErrInvalidCiphertext {
		t.Errorf("Decrypt with wrong key ID error = %v, want ErrInvalidCiphertext", err)
	}
}

func TestAESGCMEncryptorRejectsWrongKey(t *testing.T) {
	enc := mustEncryptor(t)

	encoded, err := enc.Encrypt("ref")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// A different 32-byte key must not decrypt the value.
	other, err := NewAESGCMEncryptor("ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=", "test-v1")
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor other: %v", err)
	}
	if _, err := other.Decrypt(encoded); err != ErrInvalidCiphertext {
		t.Errorf("Decrypt with wrong key error = %v, want ErrInvalidCiphertext", err)
	}
}

func TestAESGCMEncryptorEmptyValues(t *testing.T) {
	enc := mustEncryptor(t)

	encoded, err := enc.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	if encoded != "" {
		t.Errorf("Encrypt empty = %q, want empty string", encoded)
	}

	decrypted, err := enc.Decrypt("")
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if decrypted != "" {
		t.Errorf("Decrypt empty = %q, want empty string", decrypted)
	}
}

func TestNewAESGCMEncryptorRejectsBadKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{name: "empty", key: ""},
		{name: "not base64", key: "!!!not-base64!!!"},
		{name: "wrong length", key: "c2hvcnQ="}, // 4 bytes
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAESGCMEncryptor(tc.key, "v1"); err == nil {
				t.Fatal("expected error for invalid key")
			}
		})
	}
}
