// Package adminpagination defines signed, actor-bound cursors for United Pass
// administration lists. Downstream cursors are treated as opaque data and are
// never exposed unsigned.
package adminpagination

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

const (
	MaxPageSize           = 100
	MaxEncodedCursorBytes = 4096
	maxCursorLifetime     = 15 * time.Minute
	cursorClockSkew       = 5 * time.Second
	cursorPurpose         = "united-pass/admin-pagination/cursor/v1"
)

var ErrInvalidCursor = errors.New("adminpagination: invalid cursor")

type Query struct {
	ActorID          string
	ScopeKind        string
	EventID          string
	ListKind         string
	Filters          map[string]string
	Sort             string
	Cursor           string
	Limit            int
	DownstreamCursor string
}

type Page[T any] struct {
	Items      []T
	NextCursor string
	HasMore    bool
}

type State struct {
	Version          int               `json:"v"`
	ActorID          string            `json:"actor"`
	ScopeKind        string            `json:"scope"`
	EventID          string            `json:"event,omitempty"`
	ListKind         string            `json:"list"`
	Filters          map[string]string `json:"filters,omitempty"`
	Sort             string            `json:"sort"`
	LastPosition     map[string]string `json:"last,omitempty"`
	IssuedAt         time.Time         `json:"iat"`
	ExpiresAt        time.Time         `json:"exp"`
	Limit            int               `json:"limit"`
	DownstreamCursor string            `json:"downstream,omitempty"`
}

type Expectation struct {
	ActorID   string
	ScopeKind string
	EventID   string
	ListKind  string
	Filters   map[string]string
	Sort      string
	Limit     int
}

type CursorCodec struct {
	key []byte
	now func() time.Time
}

func NewCursorCodec(sessionEncryptionKeyB64 string, now func() time.Time) (*CursorCodec, error) {
	raw, err := base64.StdEncoding.DecodeString(sessionEncryptionKeyB64)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("adminpagination: invalid cursor key custody")
	}
	key, err := hkdf.Key(sha256.New, raw, nil, cursorPurpose, sha256.Size)
	if err != nil {
		return nil, errors.New("adminpagination: cursor key derivation failed")
	}
	if now == nil {
		now = time.Now
	}
	return &CursorCodec{key: key, now: now}, nil
}

func (c *CursorCodec) Encode(state State) (string, error) {
	state.Version = 1
	state.Filters = normalizeFilters(state.Filters)
	state.Sort = normalizeSpace(state.Sort)
	if !validState(state, c.now().UTC()) {
		return "", ErrInvalidCursor
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", ErrInvalidCursor
	}
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(payload)
	buffer := append(mac.Sum(nil), payload...)
	raw := base64.RawURLEncoding.EncodeToString(buffer)
	if len(raw) > MaxEncodedCursorBytes {
		return "", ErrInvalidCursor
	}
	return raw, nil
}

func (c *CursorCodec) Decode(raw string, expected Expectation) (State, error) {
	var state State
	if raw == "" || len(raw) > MaxEncodedCursorBytes {
		return state, ErrInvalidCursor
	}
	buffer, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(buffer) <= sha256.Size {
		return state, ErrInvalidCursor
	}
	signature, payload := buffer[:sha256.Size], buffer[sha256.Size:]
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return state, ErrInvalidCursor
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || decoder.More() {
		return State{}, ErrInvalidCursor
	}
	now := c.now().UTC()
	if !validState(state, now) ||
		state.ActorID != expected.ActorID ||
		state.ScopeKind != expected.ScopeKind ||
		state.EventID != expected.EventID ||
		state.ListKind != expected.ListKind ||
		state.Sort != normalizeSpace(expected.Sort) ||
		state.Limit != expected.Limit ||
		!equalFilters(state.Filters, normalizeFilters(expected.Filters)) {
		return State{}, ErrInvalidCursor
	}
	return state, nil
}

func validState(state State, now time.Time) bool {
	if state.Version != 1 || state.ActorID == "" || state.ListKind == "" || state.Sort == "" || state.Limit < 1 || state.Limit > MaxPageSize {
		return false
	}
	if state.ScopeKind == "system" {
		if state.EventID != "" {
			return false
		}
	} else if state.ScopeKind == "event" {
		if state.EventID == "" {
			return false
		}
	} else {
		return false
	}
	if state.IssuedAt.IsZero() || state.ExpiresAt.IsZero() || !state.ExpiresAt.After(state.IssuedAt) || state.ExpiresAt.Sub(state.IssuedAt) > maxCursorLifetime {
		return false
	}
	if state.IssuedAt.After(now.Add(cursorClockSkew)) || !now.Before(state.ExpiresAt) {
		return false
	}
	return true
}

func normalizeFilters(filters map[string]string) map[string]string {
	if len(filters) == 0 {
		return nil
	}
	keys := make([]string, 0, len(filters))
	for key := range filters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	normalized := make(map[string]string, len(filters))
	for _, key := range keys {
		key = normalizeSpace(key)
		if key != "" {
			normalized[key] = normalizeSpace(filters[key])
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeSpace(value string) string { return strings.Join(strings.Fields(value), " ") }

func equalFilters(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
