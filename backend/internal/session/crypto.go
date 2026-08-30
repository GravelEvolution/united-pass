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

// AESGCMKeyring encrypts with one current key while retaining explicitly
// configured historical keys for decryption. This is required for durable
// cleanup obligations: rotating the write key must not make an older provider
// session reference impossible to revoke.
type AESGCMKeyring struct {
	current    *AESGCMEncryptor
	decryptors map[string]cipher.AEAD
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
	if !validEncryptionKeyID(keyID) {
		return nil, errors.New("session: encryption key ID must be non-empty, trimmed and must not contain ':'")
	}

	aead, _, err := newAESGCMAEAD(keyB64)
	if err != nil {
		return nil, err
	}

	return &AESGCMEncryptor{keyID: keyID, aead: aead}, nil
}

// NewAESGCMKeyring constructs a rotating Encryptor. Encrypt always uses the
// current key; Decrypt selects the current or one retained key by the encoded
// key ID. Retained keys are read-only and duplicate key IDs or key material are
// rejected to keep rotation configuration unambiguous.
func NewAESGCMKeyring(currentKeyB64, currentKeyID string, retained map[string]string) (*AESGCMKeyring, error) {
	current, err := NewAESGCMEncryptor(currentKeyB64, currentKeyID)
	if err != nil {
		return nil, err
	}
	_, currentKey, err := newAESGCMAEAD(currentKeyB64)
	if err != nil {
		return nil, err
	}
	decryptors := map[string]cipher.AEAD{current.keyID: current.aead}
	keyMaterials := [][]byte{currentKey}
	for keyID, keyB64 := range retained {
		if !validEncryptionKeyID(keyID) {
			return nil, errors.New("session: retained encryption key ID must be non-empty, trimmed and must not contain ':'")
		}
		if _, exists := decryptors[keyID]; exists {
			return nil, errors.New("session: retained encryption key ID duplicates the current key ID")
		}
		aead, key, keyErr := newAESGCMAEAD(keyB64)
		if keyErr != nil {
			return nil, fmt.Errorf("session: invalid retained encryption key: %w", keyErr)
		}
		for _, existing := range keyMaterials {
			if string(existing) == string(key) {
				return nil, errors.New("session: retained encryption key material must be unique")
			}
		}
		decryptors[keyID] = aead
		keyMaterials = append(keyMaterials, key)
	}
	return &AESGCMKeyring{current: current, decryptors: decryptors}, nil
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

	return decryptAESGCMPayload(e.aead, payloadB64)
}

// Encrypt delegates to the current write key.
func (k *AESGCMKeyring) Encrypt(plaintext string) (string, error) {
	if k == nil || k.current == nil {
		return "", ErrMissingEncryptionKey
	}
	return k.current.Encrypt(plaintext)
}

// Decrypt selects the matching current or retained read key. Unknown key IDs
// and authentication failures deliberately collapse to ErrInvalidCiphertext.
func (k *AESGCMKeyring) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if k == nil {
		return "", ErrInvalidCiphertext
	}
	keyID, payloadB64, ok := strings.Cut(encoded, ":")
	if !ok {
		return "", ErrInvalidCiphertext
	}
	aead, ok := k.decryptors[keyID]
	if !ok {
		return "", ErrInvalidCiphertext
	}
	return decryptAESGCMPayload(aead, payloadB64)
}

func validEncryptionKeyID(keyID string) bool {
	return keyID != "" && strings.TrimSpace(keyID) == keyID && !strings.Contains(keyID, ":")
}

func newAESGCMAEAD(keyB64 string) (cipher.AEAD, []byte, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("session: decode encryption key: %w", err)
	}
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("session: encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("session: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("session: create GCM: %w", err)
	}
	return aead, key, nil
}

func decryptAESGCMPayload(aead cipher.AEAD, payloadB64 string) (string, error) {
	payload, err := base64.RawStdEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", ErrInvalidCiphertext
	}

	nonceSize := aead.NonceSize()
	if len(payload) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrInvalidCiphertext
	}

	return string(plain), nil
}
