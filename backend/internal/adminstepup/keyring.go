package adminstepup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
)

var (
	ErrInvalidKeyring = errors.New("adminstepup: invalid keyring")
	ErrKeyUnavailable = errors.New("adminstepup: key unavailable")
)

// Keyring is an immutable, purpose-specific collection of 256-bit or longer
// symmetric keys. CurrentID is used for writes; retained keys remain read-only.
type Keyring struct {
	currentID string
	keys      map[string][]byte
}

type keyringDocument struct {
	Keys     map[string]string `json:"keys"`
	Disabled []string          `json:"disabledKeyIds,omitempty"`
}

func NewKeyring(currentID string, keys map[string][]byte) (*Keyring, error) {
	if currentID == "" || len(keys) == 0 {
		return nil, ErrInvalidKeyring
	}
	owned := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if id == "" || len(key) < 32 {
			return nil, ErrInvalidKeyring
		}
		owned[id] = append([]byte(nil), key...)
	}
	if _, ok := owned[currentID]; !ok {
		return nil, ErrInvalidKeyring
	}
	return &Keyring{currentID: currentID, keys: owned}, nil
}

// LoadKeyring reads an owner-only JSON keyring. Key values are unpadded or
// padded base64. Disabled keys are removed before validating the current key.
func LoadKeyring(path, currentID string) (*Keyring, error) {
	if path == "" || currentID == "" {
		return nil, ErrInvalidKeyring
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("adminstepup: stat keyring: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrInvalidKeyring
	}
	// Windows ACLs are not represented faithfully by os.FileMode. On Unix,
	// reject every group/other permission so secret files are owner-only.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("adminstepup: keyring must be owner-only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("adminstepup: read keyring: %w", err)
	}
	var document keyringDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("adminstepup: decode keyring: %w", err)
	}
	disabled := make(map[string]bool, len(document.Disabled))
	for _, id := range document.Disabled {
		disabled[id] = true
	}
	keys := make(map[string][]byte, len(document.Keys))
	for id, encoded := range document.Keys {
		if disabled[id] {
			continue
		}
		decoded, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(encoded)
		}
		if err != nil {
			return nil, ErrInvalidKeyring
		}
		keys[id] = decoded
	}
	return NewKeyring(currentID, keys)
}

func (k *Keyring) Current() (string, []byte, error) {
	if k == nil {
		return "", nil, ErrKeyUnavailable
	}
	key, ok := k.keys[k.currentID]
	if !ok {
		return "", nil, ErrKeyUnavailable
	}
	return k.currentID, append([]byte(nil), key...), nil
}

func (k *Keyring) Key(id string) ([]byte, error) {
	if k == nil || id == "" {
		return nil, ErrKeyUnavailable
	}
	key, ok := k.keys[id]
	if !ok {
		return nil, ErrKeyUnavailable
	}
	return append([]byte(nil), key...), nil
}

// Snapshot returns a defensive copy for adapters that must translate the
// purpose-specific keyring into an existing cryptographic port.
func (k *Keyring) Snapshot() (string, map[string][]byte, error) {
	if k == nil {
		return "", nil, ErrKeyUnavailable
	}
	keys := make(map[string][]byte, len(k.keys))
	for id, key := range k.keys {
		keys[id] = append([]byte(nil), key...)
	}
	if _, ok := keys[k.currentID]; !ok {
		return "", nil, ErrKeyUnavailable
	}
	return k.currentID, keys, nil
}

type EncryptionPurpose string

const (
	PurposeChallengeQuestion EncryptionPurpose = "admin-challenge-question"
	PurposeProtectedReason   EncryptionPurpose = "protected-operation-reason"
)

type EncryptedValue struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

// AESGCMCipher encrypts a single purpose with immutable owner, record and
// credential-version AAD. A ciphertext cannot be moved across any boundary.
type AESGCMCipher struct {
	keyring *Keyring
	random  io.Reader
}

func NewAESGCMCipher(keyring *Keyring) (*AESGCMCipher, error) {
	if _, key, err := keyring.Current(); err != nil || len(key) != 32 {
		return nil, ErrInvalidKeyring
	}
	return &AESGCMCipher{keyring: keyring, random: rand.Reader}, nil
}

func (c *AESGCMCipher) Encrypt(purpose EncryptionPurpose, owner, record string, credentialVersion int64, plaintext string) (EncryptedValue, error) {
	if !validEncryptionBinding(purpose, owner, record, credentialVersion) {
		return EncryptedValue{}, errors.New("adminstepup: invalid encryption binding")
	}
	keyID, key, err := c.keyring.Current()
	if err != nil {
		return EncryptedValue{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedValue{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedValue{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return EncryptedValue{}, fmt.Errorf("adminstepup: generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), encryptionAAD(purpose, owner, record, credentialVersion))
	return EncryptedValue{KeyID: keyID, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (c *AESGCMCipher) Decrypt(purpose EncryptionPurpose, owner, record string, credentialVersion int64, value EncryptedValue) (string, error) {
	if !validEncryptionBinding(purpose, owner, record, credentialVersion) || value.KeyID == "" {
		return "", errors.New("adminstepup: invalid encryption binding")
	}
	key, err := c.keyring.Key(value.KeyID)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(value.Nonce) != aead.NonceSize() {
		return "", errors.New("adminstepup: invalid nonce")
	}
	plaintext, err := aead.Open(nil, value.Nonce, value.Ciphertext, encryptionAAD(purpose, owner, record, credentialVersion))
	if err != nil {
		return "", errors.New("adminstepup: ciphertext authentication failed")
	}
	return string(plaintext), nil
}

func validEncryptionBinding(purpose EncryptionPurpose, owner, record string, version int64) bool {
	return (purpose == PurposeChallengeQuestion || purpose == PurposeProtectedReason) && owner != "" && record != "" && version > 0
}

func encryptionAAD(purpose EncryptionPurpose, owner, record string, version int64) []byte {
	return []byte("united-pass/adminstepup/aes-gcm/v1\x00" + string(purpose) + "\x00" + owner + "\x00" + record + "\x00" + strconv.FormatInt(version, 10))
}
