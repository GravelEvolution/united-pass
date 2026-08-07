//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Session encryption helpers (key derivation and AEAD sealing)
//

// Package session also provides at-rest encryption for provider session
// references. Per ADR-0002 section 13, if the provider session reference
// contains sensitive data (e.g. a refresh token), it is encrypted with
// AES-256-GCM before being stored in Redis. The plaintext reference never
// touches Redis.
package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ErrMissingEncryptionKey is returned when a provider session reference must
// be encrypted but no encryption key is configured. Refusing to store the
// reference in plaintext is intentional: ADR-0002 requires encryption at rest.
var ErrMissingEncryptionKey = errors.New("session encryption key not configured")

// ErrInvalidCiphertext is returned when encrypted data cannot be decrypted:
// wrong key ID, malformed encoding, or tampered ciphertext.
var ErrInvalidCiphertext = errors.New("session encrypted value is invalid")

// Encryptor encrypts and decrypts provider session references at rest.
// Implementations must never return the plaintext through logs.
type Encryptor interface {
	// Encrypt returns the ciphertext encoded as "{keyID}:{base64(nonce||ct)}".
	Encrypt(plaintext string) (string, error)
	// Decrypt reverses Encrypt.
	Decrypt(encoded string) (string, error)
}

// AESGCMEncryptor implements Encryptor with AES-256-GCM. Each encryption uses
// a fresh random 12-byte nonce, so identical plaintexts produce different
// ciphertexts. The key ID is stored alongside the ciphertext for future key
// rotation.
type AESGCMEncryptor struct {
	keyID string
	aead  cipher.AEAD
}

// NewAESGCMEncryptor builds an AESGCMEncryptor from a base64-encoded 32-byte
// key and a key identifier. keyID defaults to "v1" when empty.
func NewAESGCMEncryptor(keyB64, keyID string) (*AESGCMEncryptor, error) {
	if keyB64 == "" {
		return nil, ErrMissingEncryptionKey
	}
	if keyID == "" {
		keyID = "v1"
	}

	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("session: decode encryption key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("session: encryption key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("session: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("session: create GCM: %w", err)
	}

	return &AESGCMEncryptor{keyID: keyID, aead: aead}, nil
}

// Encrypt seals the plaintext with a fresh random nonce and returns
// "{keyID}:{base64(nonce || ciphertext)}".
func (e *AESGCMEncryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("session: generate nonce: %w", err)
	}

	sealed := e.aead.Seal(nil, nonce, []byte(plaintext), nil)
	payload := make([]byte, 0, len(nonce)+len(sealed))
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)

	return e.keyID + ":" + base64.RawStdEncoding.EncodeToString(payload), nil
}

// Decrypt reverses Encrypt. It rejects unknown key IDs and any payload that
// fails GCM authentication (tampering or corruption).
func (e *AESGCMEncryptor) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}

	keyID, payloadB64, ok := strings.Cut(encoded, ":")
	if !ok || keyID != e.keyID {
		return "", ErrInvalidCiphertext
	}

	payload, err := base64.RawStdEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", ErrInvalidCiphertext
	}

	nonceSize := e.aead.NonceSize()
	if len(payload) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]
	plain, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrInvalidCiphertext
	}

	return string(plain), nil
}
