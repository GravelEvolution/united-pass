//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for security-epoch stamping and generation-scoped cleanup (ADR-0007 B2, F4)
//

package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

// fakeEpochStamper is a configurable EpochStamper mirroring the durable
// store's CurrentEpoch port.
type fakeEpochStamper struct {
	epoch securitystate.Epoch
	err   error
}

func (f *fakeEpochStamper) CurrentEpoch(context.Context, identity.UserID) (securitystate.Epoch, error) {
	return f.epoch, f.err
}

func epochTestService(store Store, stamper EpochStamper) *Service {
	return NewService(store, SystemClock{}, time.Hour, 30*time.Hour, 15*time.Minute, 5*time.Minute, nil, WithEpochStamper(stamper))
}

func epochTestInput(userID identity.UserID) CreateSessionInput {
	return CreateSessionInput{
		UserID:                userID,
		Provider:              "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		UserAgent:             "epoch-test-agent",
		ClientIP:              "203.0.113.55",
	}
}

// TestCreateSessionStampsAuthoritativeEpoch covers B2: the stamped epoch
// always comes from the durable authority (never Redis), and a lookup
// failure fails closed so no session is ever minted unstamped.
func TestCreateSessionStampsAuthoritativeEpoch(t *testing.T) {
	stamper := &fakeEpochStamper{epoch: 4}
	store := newFakeStore()
	svc := epochTestService(store, stamper)

	result, err := svc.CreateSession(t.Context(), epochTestInput("user_epoch"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, record, err := svc.ValidateSession(t.Context(), result.SessionToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if record.SecurityEpoch != 4 {
		t.Fatalf("stamped epoch = %d, want authoritative 4", record.SecurityEpoch)
	}

	// Lookup failure fails closed: no session minted.
	stamper.err = errors.New("pg down")
	if _, err := svc.CreateSession(t.Context(), epochTestInput("user_epoch")); err == nil {
		t.Fatal("a stamper failure must fail closed")
	}

	// No stamper (fake dev mode) defaults to generation 1.
	bare := NewService(newFakeStore(), SystemClock{}, time.Hour, 30*time.Hour, 15*time.Minute, 5*time.Minute, nil)
	bareResult, err := bare.CreateSession(t.Context(), epochTestInput("user_epoch"))
	if err != nil {
		t.Fatalf("create without stamper: %v", err)
	}
	_, bareRecord, _ := bare.ValidateSession(t.Context(), bareResult.SessionToken)
	if bareRecord.SecurityEpoch != 1 {
		t.Fatalf("unstamped-mode epoch = %d, want default 1", bareRecord.SecurityEpoch)
	}
}

// TestRotateSessionRestampsNewEpoch verifies settlement rotation moves the
// current session into the new generation.
func TestRotateSessionRestampsNewEpoch(t *testing.T) {
	stamper := &fakeEpochStamper{epoch: 1}
	svc := epochTestService(newFakeStore(), stamper)
	created, err := svc.CreateSession(t.Context(), epochTestInput("user_rotate"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	rotated, err := svc.RotateSession(t.Context(), created.SessionToken, 2)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.Record.SecurityEpoch != 2 {
		t.Fatalf("rotated epoch = %d, want new generation 2", rotated.Record.SecurityEpoch)
	}
	_, record, err := svc.ValidateSession(t.Context(), rotated.SessionToken)
	if err != nil {
		t.Fatalf("validate rotated: %v", err)
	}
	if record.SecurityEpoch != 2 {
		t.Fatalf("validated rotated epoch = %d, want 2", record.SecurityEpoch)
	}
}

// TestRevokeSessionsBeforeEpoch covers F4 at the service boundary: only
// sessions stamped before the new epoch are revoked; the new generation and
// foreign users are never touched.
func TestRevokeSessionsBeforeEpoch(t *testing.T) {
	stamper := &fakeEpochStamper{epoch: 1}
	svc := epochTestService(newFakeStore(), stamper)

	old1, err := svc.CreateSession(t.Context(), epochTestInput("user_gen"))
	if err != nil {
		t.Fatalf("create old1: %v", err)
	}
	old2, err := svc.CreateSession(t.Context(), epochTestInput("user_gen"))
	if err != nil {
		t.Fatalf("create old2: %v", err)
	}
	foreign, err := svc.CreateSession(t.Context(), epochTestInput("user_other"))
	if err != nil {
		t.Fatalf("create foreign: %v", err)
	}

	// A new-generation login happens before settlement cleanup runs.
	stamper.epoch = 2
	fresh, err := svc.CreateSession(t.Context(), epochTestInput("user_gen"))
	if err != nil {
		t.Fatalf("create fresh: %v", err)
	}

	revoked, err := svc.RevokeSessionsBeforeEpoch(t.Context(), "user_gen", 2)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("revoked = %d, want the two pre-epoch sessions", revoked)
	}

	// Old generation is dead.
	for _, res := range []CreateSessionResult{old1, old2} {
		if _, _, err := svc.ValidateSession(t.Context(), res.SessionToken); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("pre-epoch session err = %v, want ErrSessionNotFound", err)
		}
	}
	// The new generation survives (generation-scoped, F4).
	if _, record, err := svc.ValidateSession(t.Context(), fresh.SessionToken); err != nil || record.SecurityEpoch != 2 {
		t.Fatalf("new-generation session err = %v epoch = %v, want alive at epoch 2", err, record.SecurityEpoch)
	}
	// Foreign users are never touched.
	if _, _, err := svc.ValidateSession(t.Context(), foreign.SessionToken); err != nil {
		t.Fatalf("foreign session err = %v, want alive", err)
	}
}
