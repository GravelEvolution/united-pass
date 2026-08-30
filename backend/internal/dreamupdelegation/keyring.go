// Package dreamupdelegation signs short-lived, request-bound assertions for
// the DreamUP service boundary. Private signing material never leaves this
// package; consumers receive only a deterministic public JWKS representation.
package dreamupdelegation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"sort"
)

const (
	maxKeyringBytes = 64 << 10
	maxPublicKeys   = 32
	maxKeyringDepth = 16
)

var (
	ErrInvalidKeyring      = errors.New("dreamup delegation: invalid keyring")
	ErrInsecureKeyring     = errors.New("dreamup delegation: keyring must be an owner-only regular file")
	delegationKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// JSONWebKey is the only JWK shape exposed to a caller. It deliberately has
// no private-key field, making accidental serialization of d impossible.
type JSONWebKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

type privateJSONWebKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	D   string `json:"d"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type keyringDocument struct {
	Current  privateJSONWebKey `json:"current"`
	Retained []JSONWebKey      `json:"retained"`
}

// Keyring contains the current signing key and a deterministic public view of
// the current and retained verification keys. Its fields are private so no
// generic JSON encoder can expose the Ed25519 seed.
type Keyring struct {
	currentKeyID string
	current      ed25519.PrivateKey
	publicJWKS   []byte
	etag         string
}

// LoadKeyring reads an owner-only JSON keyring. The current key is an Ed25519
// private JWK whose d member is the 32-byte seed. Retained keys are public
// JWKs; a retained d member is rejected by the strict decoder.
func LoadKeyring(path string) (*Keyring, error) {
	if path == "" {
		return nil, ErrInvalidKeyring
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("dreamup delegation: inspect keyring: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() || !keyringPermissionsSecure(linkInfo.Mode().Perm()) {
		return nil, ErrInsecureKeyring
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dreamup delegation: open keyring: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("dreamup delegation: stat keyring: %w", err)
	}
	if !os.SameFile(linkInfo, openedInfo) || !openedInfo.Mode().IsRegular() || !keyringPermissionsSecure(openedInfo.Mode().Perm()) {
		return nil, ErrInsecureKeyring
	}

	limited := io.LimitReader(file, maxKeyringBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("dreamup delegation: read keyring: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxKeyringBytes {
		return nil, ErrInvalidKeyring
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document keyringDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: decode JSON", ErrInvalidKeyring)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return buildKeyring(document)
}

func rejectDuplicateJSONMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder, 0); err != nil {
		return ErrInvalidKeyring
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidKeyring
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxKeyringDepth {
		return ErrInvalidKeyring
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			member, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := member.(string)
			if !ok {
				return ErrInvalidKeyring
			}
			if _, duplicate := seen[name]; duplicate {
				return ErrInvalidKeyring
			}
			seen[name] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidKeyring
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidKeyring
		}
	default:
		return ErrInvalidKeyring
	}
	return nil
}

func keyringPermissionsSecure(mode os.FileMode) bool {
	// Windows reports 0666 for ordinary NTFS files even after Chmod(0600);
	// FileMode therefore cannot represent the ACL. Production keyrings are
	// Linux credentials, where the owner-only check below is authoritative.
	if runtime.GOOS == "windows" {
		return true
	}
	return ownerOnlyPermissions(mode)
}

func ownerOnlyPermissions(mode os.FileMode) bool {
	return mode.Perm()&0o077 == 0 && mode.Perm()&0o400 != 0
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidKeyring
	}
	return nil
}

func buildKeyring(document keyringDocument) (*Keyring, error) {
	if document.Retained == nil || len(document.Retained) > maxPublicKeys-1 {
		return nil, ErrInvalidKeyring
	}
	if err := validateJWKMetadata(document.Current.Kty, document.Current.Crv, document.Current.Kid, document.Current.Use, document.Current.Alg); err != nil {
		return nil, err
	}
	seed, err := decodeExactBase64URL(document.Current.D, ed25519.SeedSize)
	if err != nil {
		return nil, ErrInvalidKeyring
	}
	currentPublic, err := decodeExactBase64URL(document.Current.X, ed25519.PublicKeySize)
	if err != nil {
		return nil, ErrInvalidKeyring
	}
	private := ed25519.NewKeyFromSeed(seed)
	derivedPublic := private.Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(currentPublic, derivedPublic) != 1 {
		return nil, ErrInvalidKeyring
	}

	publicKeys := make([]JSONWebKey, 0, len(document.Retained)+1)
	publicKeys = append(publicKeys, JSONWebKey{
		Kty: document.Current.Kty, Crv: document.Current.Crv, Kid: document.Current.Kid,
		X: document.Current.X, Use: document.Current.Use, Alg: document.Current.Alg,
	})
	seen := map[string]struct{}{document.Current.Kid: {}}
	for _, retained := range document.Retained {
		if err := validateJWKMetadata(retained.Kty, retained.Crv, retained.Kid, retained.Use, retained.Alg); err != nil {
			return nil, err
		}
		if _, exists := seen[retained.Kid]; exists {
			return nil, ErrInvalidKeyring
		}
		if _, err := decodeExactBase64URL(retained.X, ed25519.PublicKeySize); err != nil {
			return nil, ErrInvalidKeyring
		}
		seen[retained.Kid] = struct{}{}
		publicKeys = append(publicKeys, retained)
	}
	sort.Slice(publicKeys, func(i, j int) bool { return publicKeys[i].Kid < publicKeys[j].Kid })
	jwks, err := json.Marshal(JSONWebKeySet{Keys: publicKeys})
	if err != nil {
		return nil, fmt.Errorf("dreamup delegation: encode JWKS: %w", err)
	}
	digest := sha256.Sum256(jwks)
	return &Keyring{
		currentKeyID: document.Current.Kid,
		current:      append(ed25519.PrivateKey(nil), private...),
		publicJWKS:   jwks,
		etag:         `"` + hex.EncodeToString(digest[:]) + `"`,
	}, nil
}

func validateJWKMetadata(kty, crv, kid, use, alg string) error {
	if kty != "OKP" || crv != "Ed25519" || use != "sig" || alg != "EdDSA" || !delegationKeyIDPattern.MatchString(kid) {
		return ErrInvalidKeyring
	}
	return nil
}

func decodeExactBase64URL(value string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidKeyring
	}
	return decoded, nil
}

func (k *Keyring) CurrentKeyID() string {
	if k == nil {
		return ""
	}
	return k.currentKeyID
}

// PublicJWKS returns a defensive copy of the stable public representation.
func (k *Keyring) PublicJWKS() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.publicJWKS...)
}

func (k *Keyring) ETag() string {
	if k == nil {
		return ""
	}
	return k.etag
}

func (k *Keyring) sign(message []byte) ([]byte, error) {
	if k == nil || len(k.current) != ed25519.PrivateKeySize || k.currentKeyID == "" {
		return nil, ErrInvalidKeyring
	}
	return ed25519.Sign(k.current, message), nil
}
