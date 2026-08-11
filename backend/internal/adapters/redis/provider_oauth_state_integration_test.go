//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 6 Feishu OAuth state integration tests
//

//go:build integration

package redis

import (
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/providers"
)

func TestIntegration_ProviderOAuthStateIsSingleUse(t *testing.T) {
	client := setupTestRedis(t)
	store := NewProviderOAuthStateStore(client)
	state := providers.OAuthState{
		ResumeRequestID: "resume_test",
		Remember:        true,
		CreatedAt:       time.Now().UTC(),
	}
	if err := store.Create(t.Context(), "state_hash_test", state, time.Minute); err != nil {
		t.Fatalf("create OAuth state: %v", err)
	}
	if err := store.Create(t.Context(), "state_hash_test", state, time.Minute); !errors.Is(err, providers.ErrConflict) {
		t.Fatalf("duplicate OAuth state: %v", err)
	}
	loaded, err := store.Consume(t.Context(), "state_hash_test")
	if err != nil {
		t.Fatalf("consume OAuth state: %v", err)
	}
	if loaded.ResumeRequestID != state.ResumeRequestID || !loaded.Remember {
		t.Fatalf("loaded OAuth state = %#v", loaded)
	}
	if _, err := store.Consume(t.Context(), "state_hash_test"); !errors.Is(err, providers.ErrOAuthStateNotFound) {
		t.Fatalf("replayed OAuth state: %v", err)
	}
}
