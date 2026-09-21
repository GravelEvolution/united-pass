package mscaccess

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	CapabilityUserRead        = "msc.admin.user.read"
	CapabilityUserWrite       = "msc.admin.user.write"
	CapabilityEmployeeRead    = "msc.admin.employee.read"
	CapabilityEmployeeWrite   = "msc.admin.employee.write"
	CapabilityDepartmentRead  = "msc.admin.department.read"
	CapabilityDepartmentWrite = "msc.admin.department.write"
	CapabilityAuditRead       = "msc.admin.audit.read"

	emptyBodySHA256    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	actorKindService   = "service"
	maxJWKSBytes       = 16 * 1024
	maxJWKSKeys        = 8
	maxWriteBodyBytes  = 4 * 1024
	maxAssertionTTL    = 25 * time.Second
	allowedClockSkew   = 5 * time.Second
	assertionPartCount = 3
	requestIDHeader    = "X-Request-ID"
)

var (
	ErrUnauthorized  = errors.New("mscaccess: request assertion rejected")
	ErrInvalidConfig = errors.New("mscaccess: verifier configuration is invalid")
	ErrInvalidJWKS   = errors.New("mscaccess: JWKS is invalid")

	requestIDPattern = regexp.MustCompile("^req_[a-f0-9]{32}$")
	keyIDPattern     = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
	actorPattern     = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._@+:-]{2,199}$")
)

type Config struct {
	Issuer   string
	Audience string
	Subject  string
}

type Verifier struct {
	config Config
	keys   map[string]ed25519.PublicKey
	clock  func() time.Time
}

type assertionHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type assertionClaims struct {
	Issuer     string `json:"iss"`
	Audience   string `json:"aud"`
	Subject    string `json:"sub"`
	IssuedAt   int64  `json:"iat"`
	NotBefore  int64  `json:"nbf"`
	ExpiresAt  int64  `json:"exp"`
	RequestID  string `json:"jti"`
	ActorKind  string `json:"actor_kind"`
	Capability string `json:"capability"`
	Method     string `json:"htm"`
	Target     string `json:"htu"`
	BodySHA256 string `json:"body_sha256"`
	Actor      string `json:"actor"`
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	KeyID     string `json:"kid"`
	Material  string `json:"x"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
}

func NewVerifier(config Config, keys map[string]ed25519.PublicKey) (*Verifier, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if len(keys) == 0 || len(keys) > maxJWKSKeys {
		return nil, fmt.Errorf("%w: key set size is out of range", ErrInvalidJWKS)
	}
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, key := range keys {
		if !keyIDPattern.MatchString(keyID) || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: key entry is not a usable Ed25519 key", ErrInvalidJWKS)
		}
		copied[keyID] = key
	}
	return &Verifier{config: config, keys: copied, clock: func() time.Time { return time.Now().UTC() }}, nil
}

func LoadVerifier(path string, config Config) (*Verifier, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJWKS, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxJWKSBytes {
		return nil, fmt.Errorf("%w: JWKS must be a regular non-symlink file of at most 16 KiB", ErrInvalidJWKS)
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o400 == 0 {
		return nil, fmt.Errorf("%w: JWKS must be readable only by its owner", ErrInvalidJWKS)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJWKS, err)
	}
	keys, err := ParseJWKS(raw)
	if err != nil {
		return nil, err
	}
	return NewVerifier(config, keys)
}

func ParseJWKS(raw []byte) (map[string]ed25519.PublicKey, error) {
	if hasDuplicateMembers(raw) {
		return nil, fmt.Errorf("%w: duplicate JSON members", ErrInvalidJWKS)
	}
	var document jwksDocument
	if err := decodeStrict(raw, &document); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJWKS, err)
	}
	if len(document.Keys) == 0 || len(document.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("%w: key set size is out of range", ErrInvalidJWKS)
	}
	keys := make(map[string]ed25519.PublicKey, len(document.Keys))
	for _, key := range document.Keys {
		if key.KeyType != "OKP" || key.Curve != "Ed25519" {
			return nil, fmt.Errorf("%w: only Ed25519 JWK entries are accepted", ErrInvalidJWKS)
		}
		if key.Use != "" && key.Use != "sig" {
			return nil, fmt.Errorf("%w: key use must be sig", ErrInvalidJWKS)
		}
		if key.Algorithm != "" && key.Algorithm != "EdDSA" {
			return nil, fmt.Errorf("%w: key algorithm must be EdDSA", ErrInvalidJWKS)
		}
		if !keyIDPattern.MatchString(key.KeyID) {
			return nil, fmt.Errorf("%w: key id is invalid", ErrInvalidJWKS)
		}
		if _, exists := keys[key.KeyID]; exists {
			return nil, fmt.Errorf("%w: key id is duplicated", ErrInvalidJWKS)
		}
		material, err := base64.RawURLEncoding.DecodeString(key.Material)
		if err != nil || len(material) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: key material is invalid", ErrInvalidJWKS)
		}
		keys[key.KeyID] = ed25519.PublicKey(material)
	}
	return keys, nil
}

func (v *Verifier) Verify(request *http.Request, capability string, body []byte) (string, error) {
	if v == nil || request == nil {
		return "", ErrUnauthorized
	}
	token, err := bearerToken(request.Header.Get("Authorization"))
	if err != nil {
		return "", err
	}
	parts := strings.Split(token, ".")
	if len(parts) != assertionPartCount {
		return "", ErrUnauthorized
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrUnauthorized
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrUnauthorized
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return "", ErrUnauthorized
	}
	var header assertionHeader
	if err := decodeStrict(headerRaw, &header); err != nil {
		return "", ErrUnauthorized
	}
	if header.Algorithm != "EdDSA" || !strings.EqualFold(header.Type, "JWT") || !keyIDPattern.MatchString(header.KeyID) {
		return "", ErrUnauthorized
	}
	key, ok := v.keys[header.KeyID]
	if !ok {
		return "", ErrUnauthorized
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return "", ErrUnauthorized
	}
	var claims assertionClaims
	if err := decodeStrict(payloadRaw, &claims); err != nil {
		return "", ErrUnauthorized
	}
	return v.validateClaims(request, claims, capability, body)
}

func (v *Verifier) validateClaims(request *http.Request, claims assertionClaims, capability string, body []byte) (string, error) {
	if claims.Issuer != v.config.Issuer || claims.Audience != v.config.Audience || claims.Subject != v.config.Subject {
		return "", ErrUnauthorized
	}
	if claims.ActorKind != actorKindService || claims.Capability != capability {
		return "", ErrUnauthorized
	}
	if !requestIDPattern.MatchString(claims.RequestID) || request.Header.Get(requestIDHeader) != claims.RequestID {
		return "", ErrUnauthorized
	}
	if claims.Method != request.Method || claims.Target != requestTarget(request) {
		return "", ErrUnauthorized
	}
	expectedBodySHA256 := ""
	switch request.Method {
	case http.MethodGet, http.MethodDelete:
		if request.ContentLength > 0 || len(body) != 0 {
			return "", ErrUnauthorized
		}
		expectedBodySHA256 = emptyBodySHA256
	case http.MethodPatch, http.MethodPost, http.MethodPut:
		if len(body) == 0 || len(body) > maxWriteBodyBytes {
			return "", ErrUnauthorized
		}
		digest := sha256.Sum256(body)
		expectedBodySHA256 = hex.EncodeToString(digest[:])
	default:
		return "", ErrUnauthorized
	}
	if claims.BodySHA256 != expectedBodySHA256 {
		return "", ErrUnauthorized
	}
	if claims.Actor != "" {
		if !actorPattern.MatchString(claims.Actor) {
			return "", ErrUnauthorized
		}
	} else if request.Method != http.MethodGet {
		return "", ErrUnauthorized
	}
	if claims.ExpiresAt <= claims.IssuedAt || claims.NotBefore > claims.IssuedAt {
		return "", ErrUnauthorized
	}
	if time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second > maxAssertionTTL {
		return "", ErrUnauthorized
	}
	now := v.clock()
	if now.After(time.Unix(claims.ExpiresAt, 0).Add(allowedClockSkew)) {
		return "", ErrUnauthorized
	}
	if now.Before(time.Unix(claims.NotBefore, 0).Add(-allowedClockSkew)) {
		return "", ErrUnauthorized
	}
	return claims.Actor, nil
}

func (c Config) validate() error {
	if err := validateOrigin(c.Issuer); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	for name, value := range map[string]string{"audience": c.Audience, "subject": c.Subject} {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 256 {
			return fmt.Errorf("%w: %s must be a trimmed value of at most 256 bytes", ErrInvalidConfig, name)
		}
	}
	return nil
}

func validateOrigin(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return errors.New("issuer must be a canonical HTTPS origin")
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || value != parsed.Scheme+"://"+parsed.Host {
		return errors.New("issuer must be a canonical HTTPS origin without path, query, credentials or fragment")
	}
	return nil
}

func bearerToken(header string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", ErrUnauthorized
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, " 	") {
		return "", ErrUnauthorized
	}
	return token, nil
}

func requestTarget(request *http.Request) string {
	target := request.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if request.URL.RawQuery != "" {
		target += "?" + request.URL.RawQuery
	}
	return target
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("mscaccess: trailing JSON content")
	}
	return nil
}

func hasDuplicateMembers(raw []byte) bool {
	type scope struct {
		object    bool
		expectKey bool
		keys      map[string]struct{}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	stack := make([]scope, 0, 8)
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, scope{object: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				stack = append(stack, scope{})
			default:
				if len(stack) == 0 {
					return false
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expectKey = true
				}
			}
		case string:
			if len(stack) == 0 || !stack[len(stack)-1].object {
				continue
			}
			top := &stack[len(stack)-1]
			if top.expectKey {
				if _, exists := top.keys[value]; exists {
					return true
				}
				top.keys[value] = struct{}{}
				top.expectKey = false
				continue
			}
			top.expectKey = true
		default:
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
		}
	}
}
