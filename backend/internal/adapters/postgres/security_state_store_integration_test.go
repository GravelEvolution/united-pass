//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: PostgreSQL integration tests for the authoritative security-state ledger (ADR-0007)
//

//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

// securityUser seeds a fresh user row for security-state tests and returns
// its ID.
func securityUser(t *testing.T, repo *UserRepository, id string) identity.UserID {
	t.Helper()
	user := identity.User{
		ID:        identity.UserID(id),
		Status:    identity.UserStatusActive,
		Email:     id + "@example.com",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user.ID
}

func TestIntegration_SecurityStateDefaultsAndMissingUser(t *testing.T) {
	pool := setupTestPool(t, 5)
	repo := NewUserRepository(pool.PgxPool())
	store := NewSecurityStateStore(pool.PgxPool())
	ctx := context.Background()
	userID := securityUser(t, repo, "user_sec_defaults")

	// A fresh user carries epoch 1 and no intent.
	state, err := store.GetSecurityState(ctx, userID)
	if err != nil {
		t.Fatalf("get state: %v", err)
	}
	if state.Epoch != 1 || state.Intent != nil {
		t.Fatalf("state = %+v, want epoch 1 without intent", state)
	}
	if epoch, err := store.CurrentEpoch(ctx, userID); err != nil || epoch != 1 {
		t.Fatalf("CurrentEpoch = %v, %v; want 1, nil", epoch, err)
	}

	// A missing user fails closed on both reads.
	if _, err := store.GetSecurityState(ctx, "user_missing"); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("missing-user state err = %v, want ErrUserNotFound", err)
	}
	if _, err := store.CurrentEpoch(ctx, "user_missing"); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("missing-user epoch err = %v, want ErrUserNotFound", err)
	}
	if _, err := store.AcquireIntent(ctx, "user_missing", time.Minute); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("missing-user acquire err = %v, want ErrUserNotFound", err)
	}
}

// TestIntegration_AcquireIntentConcurrentSingleWinner proves B4 at the SQL
// fence: the per-user primary key serializes concurrent acquirers and
// exactly one wins; every loser fails closed before any provider call.
func TestIntegration_AcquireIntentConcurrentSingleWinner(t *testing.T) {
	pool := setupTestPool(t, 10)
	repo := NewUserRepository(pool.PgxPool())
	store := NewSecurityStateStore(pool.PgxPool())
	ctx := context.Background()
	userID := securityUser(t, repo, "user_sec_winner")

	const contenders = 8
	var winners atomic.Int64
	var held atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			intent, err := store.AcquireIntent(ctx, userID, time.Minute)
			switch {
			case err == nil:
				winners.Add(1)
				if intent.Status != securitystate.IntentActive || intent.EpochAtAcquire != 1 {
					t.Errorf("winning intent = %+v, want active at epoch 1", intent)
				}
			case errors.Is(err, securitystate.ErrIntentHeld):
				held.Add(1)
			default:
				t.Errorf("unexpected acquire error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners.Load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners.Load())
	}
	if held.Load() != contenders-1 {
		t.Fatalf("ErrIntentHeld losers = %d, want %d", held.Load(), contenders-1)
	}
}

// TestIntegration_IntentLifecycleFences walks the full four-state lifecycle
// and verifies every CAS fence: a stale transition never advances the epoch,
// overwrites a recorded outcome or settles a foreign intent.
func TestIntegration_IntentLifecycleFences(t *testing.T) {
	pool := setupTestPool(t, 5)
	repo := NewUserRepository(pool.PgxPool())
	store := NewSecurityStateStore(pool.PgxPool())
	ctx := context.Background()
	userID := securityUser(t, repo, "user_sec_lifecycle")

	intent, err := store.AcquireIntent(ctx, userID, time.Minute)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Settlement transitions are fenced from the wrong phase.
	if err := store.BeginSettlement(ctx, userID, intent.IntentID); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("BeginSettlement from active err = %v, want ErrFenceLost", err)
	}
	if err := store.Settle(ctx, userID, intent.IntentID, securitystate.SettlementOutcomeSettled); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("Settle from active err = %v, want ErrFenceLost", err)
	}
	// A foreign intent id never matches the fence.
	if _, err := store.RecordOutcomeAdvanceEpoch(ctx, userID, intent.IntentID+999, securitystate.ProviderOutcomeSuccess); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("foreign intent record err = %v, want ErrFenceLost", err)
	}

	// Ordering invariant: outcome record + epoch advancement in one fenced
	// transaction, exactly once.
	newEpoch, err := store.RecordOutcomeAdvanceEpoch(ctx, userID, intent.IntentID, securitystate.ProviderOutcomeSuccess)
	if err != nil {
		t.Fatalf("record outcome: %v", err)
	}
	if newEpoch != 2 {
		t.Fatalf("new epoch = %d, want 2", newEpoch)
	}
	if _, err := store.RecordOutcomeAdvanceEpoch(ctx, userID, intent.IntentID, securitystate.ProviderOutcomeSuccess); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("second record err = %v, want ErrFenceLost", err)
	}
	if epoch, _ := store.CurrentEpoch(ctx, userID); epoch != 2 {
		t.Fatalf("epoch = %d after fence loss, want 2 (no double bump)", epoch)
	}
	state, _ := store.GetSecurityState(ctx, userID)
	if state.Intent == nil || state.Intent.Status != securitystate.IntentOutcomeRecorded ||
		state.Intent.ProviderOutcome != securitystate.ProviderOutcomeSuccess {
		t.Fatalf("state = %+v, want outcome_recorded/success", state)
	}

	// local_settlement -> settled, terminal and immutable.
	if err := store.BeginSettlement(ctx, userID, intent.IntentID); err != nil {
		t.Fatalf("begin settlement: %v", err)
	}
	if err := store.BeginSettlement(ctx, userID, intent.IntentID); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("second BeginSettlement err = %v, want ErrFenceLost", err)
	}
	if err := store.Settle(ctx, userID, intent.IntentID, securitystate.SettlementOutcomeSettled); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if err := store.Settle(ctx, userID, intent.IntentID, securitystate.SettlementOutcomeDegraded); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("settled intent rewrite err = %v, want ErrFenceLost", err)
	}

	// Settled: no barrier, acquisition reusable, settlement counter reset.
	state, _ = store.GetSecurityState(ctx, userID)
	if state.Intent != nil || state.Epoch != 2 {
		t.Fatalf("post-settle state = %+v, want epoch 2 without intent", state)
	}
	if _, err := store.BumpSettlementAttempts(ctx, userID, intent.IntentID); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("bump on settled err = %v, want ErrFenceLost", err)
	}
	if _, err := store.AcquireIntent(ctx, userID, time.Minute); err != nil {
		t.Fatalf("re-acquire after settlement: %v", err)
	}
}

// TestIntegration_SettleConfirmedFailureZeroSideEffects covers the frozen §6
// semantics at the SQL layer: the epoch is never touched and the row goes
// straight to settled/confirmed_failure.
func TestIntegration_SettleConfirmedFailureZeroSideEffects(t *testing.T) {
	pool := setupTestPool(t, 5)
	repo := NewUserRepository(pool.PgxPool())
	store := NewSecurityStateStore(pool.PgxPool())
	ctx := context.Background()
	userID := securityUser(t, repo, "user_sec_confirmed")

	intent, err := store.AcquireIntent(ctx, userID, time.Minute)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := store.SettleConfirmedFailure(ctx, userID, intent.IntentID); err != nil {
		t.Fatalf("settle confirmed failure: %v", err)
	}
	if err := store.SettleConfirmedFailure(ctx, userID, intent.IntentID); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("second settle err = %v, want ErrFenceLost", err)
	}
	if epoch, _ := store.CurrentEpoch(ctx, userID); epoch != 1 {
		t.Fatalf("epoch = %d, want 1 (zero side effects)", epoch)
	}
	state, _ := store.GetSecurityState(ctx, userID)
	if state.Intent != nil {
		t.Fatalf("state = %+v, want no non-terminal intent", state)
	}
}

// TestIntegration_TakeoverExpiredAdvanceEpoch covers the F6 takeover fence:
// a live lease cannot be taken over; an expired one records unknown and
// advances the epoch exactly once in one transaction.
func TestIntegration_TakeoverExpiredAdvanceEpoch(t *testing.T) {
	pool := setupTestPool(t, 5)
	repo := NewUserRepository(pool.PgxPool())
	store := NewSecurityStateStore(pool.PgxPool())
	ctx := context.Background()
	userID := securityUser(t, repo, "user_sec_takeover")

	intent, err := store.AcquireIntent(ctx, userID, time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// A live provider call's lease cannot be taken over.
	if _, err := store.TakeoverExpiredAdvanceEpoch(ctx, userID, intent.IntentID, time.Now()); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("live-lease takeover err = %v, want ErrFenceLost", err)
	}
	if epoch, _ := store.CurrentEpoch(ctx, userID); epoch != 1 {
		t.Fatalf("epoch = %d, want 1 (live fence untouched)", epoch)
	}

	// Backdate the lease to simulate a crashed predecessor.
	if _, err := pool.PgxPool().Exec(ctx,
		`UPDATE password_mutation_intents SET lease_expires_at = NOW() - interval '1 minute' WHERE user_id = $1`,
		string(userID)); err != nil {
		t.Fatalf("backdate lease: %v", err)
	}

	newEpoch, err := store.TakeoverExpiredAdvanceEpoch(ctx, userID, intent.IntentID, time.Now())
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if newEpoch != 2 {
		t.Fatalf("takeover epoch = %d, want exactly one advancement to 2", newEpoch)
	}
	// Exactly-once: the fence now sees outcome_recorded, never active again.
	if _, err := store.TakeoverExpiredAdvanceEpoch(ctx, userID, intent.IntentID, time.Now()); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("second takeover err = %v, want ErrFenceLost", err)
	}
	state, _ := store.GetSecurityState(ctx, userID)
	if state.Intent == nil || state.Intent.ProviderOutcome != securitystate.ProviderOutcomeUnknown {
		t.Fatalf("state = %+v, want recorded unknown outcome", state)
	}
	if epoch, _ := store.CurrentEpoch(ctx, userID); epoch != 2 {
		t.Fatalf("epoch = %d, want 2 (no double bump)", epoch)
	}
}

// TestIntegration_BumpSettlementAttempts covers the bounded-terminalization
// counter: it increments on every non-terminal intent and loses the fence on
// settled or missing rows.
func TestIntegration_BumpSettlementAttempts(t *testing.T) {
	pool := setupTestPool(t, 5)
	repo := NewUserRepository(pool.PgxPool())
	store := NewSecurityStateStore(pool.PgxPool())
	ctx := context.Background()
	userID := securityUser(t, repo, "user_sec_attempts")

	intent, err := store.AcquireIntent(ctx, userID, time.Minute)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	for i := 1; i <= 3; i++ {
		attempts, err := store.BumpSettlementAttempts(ctx, userID, intent.IntentID)
		if err != nil {
			t.Fatalf("bump %d: %v", i, err)
		}
		if attempts != i {
			t.Fatalf("attempts = %d, want %d", attempts, i)
		}
	}
	if _, err := store.BumpSettlementAttempts(ctx, userID, intent.IntentID+42); !errors.Is(err, securitystate.ErrFenceLost) {
		t.Fatalf("foreign intent bump err = %v, want ErrFenceLost", err)
	}
}
