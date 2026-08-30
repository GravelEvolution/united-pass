package adminstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const FingerprintVersion = "hmac-sha256-v1"

type Keyring struct {
	ActiveKeyID string
	Keys        map[string][]byte
}

type Fingerprint struct {
	Version string
	KeyID   string
	Digest  string
}

type OperationFingerprinter struct{ keyring Keyring }

func NewOperationFingerprinter(keyring Keyring) (*OperationFingerprinter, error) {
	active, ok := keyring.Keys[keyring.ActiveKeyID]
	if keyring.ActiveKeyID == "" || !ok || len(active) < 32 {
		return nil, errors.New("adminstore: invalid fingerprint keyring")
	}
	owned := Keyring{ActiveKeyID: keyring.ActiveKeyID, Keys: make(map[string][]byte, len(keyring.Keys))}
	for id, key := range keyring.Keys {
		if len(key) < 32 {
			return nil, errors.New("adminstore: fingerprint key too short")
		}
		owned.Keys[id] = append([]byte(nil), key...)
	}
	return &OperationFingerprinter{keyring: owned}, nil
}

func (f *OperationFingerprinter) Fingerprint(purpose string, canonicalInput []byte) (Fingerprint, error) {
	if purpose == "" || len(canonicalInput) == 0 {
		return Fingerprint{}, errors.New("adminstore: fingerprint requires purpose and canonical input")
	}
	key := f.keyring.Keys[f.keyring.ActiveKeyID]
	digest := fingerprintDigest(key, purpose, canonicalInput)
	return Fingerprint{Version: FingerprintVersion, KeyID: f.keyring.ActiveKeyID, Digest: encodeDigest(digest)}, nil
}

func (f *OperationFingerprinter) Verify(purpose string, canonicalInput []byte, fingerprint Fingerprint) bool {
	if fingerprint.Version != FingerprintVersion || purpose == "" || len(canonicalInput) == 0 {
		return false
	}
	key, ok := f.keyring.Keys[fingerprint.KeyID]
	if !ok {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(fingerprint.Digest)
	if err != nil {
		return false
	}
	return hmac.Equal(want, fingerprintDigest(key, purpose, canonicalInput))
}

func fingerprintDigest(key []byte, purpose string, canonical []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("united-pass/admin-operation-fingerprint/v1\x00"))
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(canonical)
	return mac.Sum(nil)
}

func encodeDigest(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
