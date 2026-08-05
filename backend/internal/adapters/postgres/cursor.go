package postgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
)

// ErrInvalidCursor is the domain sentinel for tampered, malformed or
// state-mismatched cursors. Callers must map it to a 400 response; raw
// offsets are never exposed (ADR-0004 §9).
var ErrInvalidCursor = applications.ErrInvalidCursor

// cursorSigningContext separates cursor HMAC keys from any other HMAC use of
// the same base key material.
const cursorSigningContext = "united-pass/cursor-signing/v1"

// applicationCursor is the opaque pagination state for the application list.
// It binds the sort and filter state so a cursor issued for one query is
// rejected when replayed against another.
type applicationCursor struct {
	Sort     string `json:"s"`
	Query    string `json:"q"`
	Status   string `json:"st"`
	Audience string `json:"au"`
	OwnerID  string `json:"ow"`
	// Boundary of the last returned row. Value is the primary sort column
	// value (RFC3339Nano for time columns); Name is set for name sorts.
	Value string `json:"v"`
	Name  string `json:"n"`
	ID    string `json:"id"`
}

// cursorSigner signs and verifies opaque cursors with HMAC-SHA256 using a
// key derived from the session encryption key.
type cursorSigner struct {
	key []byte
}

// newCursorSigner derives a cursor signing key from the base64-encoded
// 32-byte session encryption key. An empty key fails closed.
func newCursorSigner(sessionKeyB64 string) (*cursorSigner, error) {
	if sessionKeyB64 == "" {
		return nil, errors.New("postgres: cursor signing requires UP_SESSION_ENCRYPTION_KEY")
	}
	raw, err := base64.StdEncoding.DecodeString(sessionKeyB64)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("postgres: cursor signing key derivation failed")
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte(cursorSigningContext))
	return &cursorSigner{key: mac.Sum(nil)}, nil
}

// encode serializes and signs a cursor state into an opaque string.
func (s *cursorSigner) encode(state applicationCursor) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", ErrInvalidCursor
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	sig := mac.Sum(nil)

	buf := make([]byte, 0, len(payload)+len(sig))
	buf = append(buf, sig...)
	buf = append(buf, payload...)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// decode verifies and deserializes an opaque cursor. Any tampering,
// malformed encoding or signature mismatch yields ErrInvalidCursor.
func (s *cursorSigner) decode(cursor string) (applicationCursor, error) {
	var empty applicationCursor
	buf, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(buf) <= sha256.Size {
		return empty, ErrInvalidCursor
	}
	sig, payload := buf[:sha256.Size], buf[sha256.Size:]
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return empty, ErrInvalidCursor
	}
	var state applicationCursor
	if err := json.Unmarshal(payload, &state); err != nil {
		return empty, ErrInvalidCursor
	}
	return state, nil
}

// parseCursorTime parses the boundary value of a time-sorted cursor.
func parseCursorTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, ErrInvalidCursor
	}
	return t, nil
}
