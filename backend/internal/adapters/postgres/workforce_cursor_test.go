//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 5 signed workforce cursor boundary tests
//

package postgres

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

func TestWorkforceCursorRejectsOversizedInputBeforeDecode(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	signer, err := newWorkforceCursorSigner(key)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	_, err = signer.decode(strings.Repeat("A", workforceCursorMaxEncodedBytes+1))
	if !errors.Is(err, workforce.ErrInvalidCursor) {
		t.Fatalf("decode oversized cursor = %v, want ErrInvalidCursor", err)
	}
}

func TestWorkforceCursorBindsSignedPayload(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	signer, err := newWorkforceCursorSigner(key)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	raw, err := signer.encode(workforceCursor{
		Kind: "users", Sort: "displayName", Query: "alice", Value: "Alice", ID: "user_alice",
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := signer.decode(raw)
	if err != nil || decoded.Query != "alice" || decoded.ID != "user_alice" {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	index := len(raw) / 2
	tamperedByte := byte('A')
	if raw[index] == tamperedByte {
		tamperedByte = 'B'
	}
	_, err = signer.decode(raw[:index] + string(tamperedByte) + raw[index+1:])
	if !errors.Is(err, workforce.ErrInvalidCursor) {
		t.Fatalf("decode tampered cursor = %v, want ErrInvalidCursor", err)
	}
}
