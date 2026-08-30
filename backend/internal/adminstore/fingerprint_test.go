package adminstore

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestOperationFingerprinterUsesPurposeSeparatedKeyedDigest(t *testing.T) {
	keys := Keyring{ActiveKeyID: "k2", Keys: map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32), "k2": bytes.Repeat([]byte{2}, 32)}}
	f, err := NewOperationFingerprinter(keys)
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"answer":"low entropy","reason":"specific"}`)
	got, err := f.Fingerprint("admin-challenge.verify", canonical)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != FingerprintVersion || got.KeyID != "k2" || got.Digest == "" {
		t.Fatalf("fingerprint=%+v", got)
	}
	if got.Digest == string(canonical) {
		t.Fatal("raw canonical input was persisted")
	}
	unkeyed := sha256.Sum256(canonical)
	if got.Digest == encodeDigest(unkeyed[:]) {
		t.Fatal("fingerprint is an unkeyed body sha256")
	}
	if !f.Verify("admin-challenge.verify", canonical, got) {
		t.Fatal("active fingerprint did not verify")
	}
	if f.Verify("identity-access.reason", canonical, got) {
		t.Fatal("fingerprint replayed across purposes")
	}
}

func TestOperationFingerprinterRetainsOldVerificationKeysAcrossRotation(t *testing.T) {
	old, err := NewOperationFingerprinter(Keyring{ActiveKeyID: "k1", Keys: map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := old.Fingerprint("operation", []byte("complete canonical input"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewOperationFingerprinter(Keyring{ActiveKeyID: "k2", Keys: map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32), "k2": bytes.Repeat([]byte{2}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if !rotated.Verify("operation", []byte("complete canonical input"), fp) {
		t.Fatal("old fingerprint stopped verifying after rotation")
	}
	if rotated.Verify("operation", []byte("different"), fp) {
		t.Fatal("different canonical input verified")
	}
}

func TestOperationFingerprinterOwnsAnImmutableKeyringSnapshot(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	keys := map[string][]byte{"k1": key}
	f, err := NewOperationFingerprinter(Keyring{ActiveKeyID: "k1", Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := f.Fingerprint("operation", []byte("canonical input"))
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 9
	keys["k1"] = bytes.Repeat([]byte{8}, 32)
	if !f.Verify("operation", []byte("canonical input"), fingerprint) {
		t.Fatal("external keyring mutation changed the fingerprinter")
	}
}
