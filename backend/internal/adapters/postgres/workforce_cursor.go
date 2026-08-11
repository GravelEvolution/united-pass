//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Signed opaque cursors for Phase 5 directory listings
//

package postgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

const workforceCursorSigningContext = "united-pass/workforce-cursor-signing/v1"
const workforceCursorMaxEncodedBytes = 4096

type workforceCursor struct {
	Kind   string `json:"k"`
	Sort   string `json:"s"`
	Query  string `json:"q"`
	Status string `json:"st"`
	Value  string `json:"v"`
	ID     string `json:"id"`
}

type workforceCursorSigner struct {
	key []byte
}

func newWorkforceCursorSigner(sessionKeyB64 string) (*workforceCursorSigner, error) {
	if sessionKeyB64 == "" {
		return nil, errors.New("postgres: workforce cursor signing requires UP_SESSION_ENCRYPTION_KEY")
	}
	raw, err := base64.StdEncoding.DecodeString(sessionKeyB64)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("postgres: workforce cursor signing key derivation failed")
	}
	mac := hmac.New(sha256.New, raw)
	_, _ = mac.Write([]byte(workforceCursorSigningContext))
	return &workforceCursorSigner{key: mac.Sum(nil)}, nil
}

func (s *workforceCursorSigner) encode(state workforceCursor) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", workforce.ErrInvalidCursor
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	buf := append(mac.Sum(nil), payload...)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *workforceCursorSigner) decode(raw string) (workforceCursor, error) {
	var state workforceCursor
	if len(raw) > workforceCursorMaxEncodedBytes {
		return state, workforce.ErrInvalidCursor
	}
	buf, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(buf) <= sha256.Size {
		return state, workforce.ErrInvalidCursor
	}
	signature, payload := buf[:sha256.Size], buf[sha256.Size:]
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return state, workforce.ErrInvalidCursor
	}
	if err := json.Unmarshal(payload, &state); err != nil {
		return workforceCursor{}, workforce.ErrInvalidCursor
	}
	return state, nil
}
