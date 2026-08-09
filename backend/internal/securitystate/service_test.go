//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the security-state service (ADR-0007 B4, F1, F3, F4, F6)
//

package securitystate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// --- Test fakes ---

// fakeLedger is an in-memory Ledger mirroring the PostgreSQL adapter's
// CAS-fenced semantics: every transition checks (intentID, expected status)
// before mutating, a lost fence returns ErrFenceLost, and epoch
// advancement happens atomically with the outcome record.
type fakeLedger struct {
	mu     sync.Mutex
	epoch  Epoch
	intent *Intent
	nextID int64

	stateErr    error
	acquireErr  error
	takeoverErr error
	recordErr   error
	beginErr    error
	settleErr   error
	bumpErr     error

	beginCalls int
	settles    []SettlementOutcome
}

func (f *fakeLedger) GetSecurityState(_ context.Context, _ identity.UserID) (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stateErr != nil {
		return State{}, f.stateErr
	}
	st := State{Epoch: f.epoch}
	if f.intent != nil {
		cp := *f.intent
		st.Intent = &cp
	}
	return st, nil
}

func (f *fakeLedger) CurrentEpoch(_ context.Context, _ identity.UserID) (Epoch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.epoch, nil
}

func (f *fakeLedger) AcquireIntent(_ context.Context, userID identity.UserID, leaseTTL time.Duration) (Intent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acquireErr != nil {
		return Intent{}, f.acquireErr
	}
	if f.intent != nil {
		return Intent{}, ErrIntentHeld
	}
	f.nextID++
	intent := Intent{
		UserID:         userID,
		IntentID:       f.nextID,
		Status:         IntentActive,
		EpochAtAcquire: f.epoch,
		LeaseExpiresAt: time.Now().Add(leaseTTL),
	}
	f.intent = &intent
	return intent, nil
}

func (f *fakeLedger) SettleConfirmedFailure(_ context.Context, _ identity.UserID, intentID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.intent == nil || f.intent.IntentID != intentID || f.intent.Status != IntentActive {
		return ErrFenceLost
	}
	f.intent.Status = IntentSettled
	f.intent.ProviderOutcome = ProviderOutcomeConfirmedFailure
	f.intent = nil
	return nil
}

func (f *fakeLedger) RecordOutcomeAdvanceEpoch(_ context.Context, _ identity.UserID, intentID int64, outcome ProviderOutcome) (Epoch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordErr != nil {
		return 0, f.recordErr
	}
	if f.intent == nil || f.intent.IntentID != intentID || f.intent.Status != IntentActive {
		return 0, ErrFenceLost
	}
	f.epoch++
	f.intent.Status = IntentOutcomeRecorded
	f.intent.ProviderOutcome = outcome
	return f.epoch, nil
}

func (f *fakeLedger) TakeoverExpiredAdvanceEpoch(_ context.Context, _ identity.UserID, intentID int64, now time.Time) (Epoch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.takeoverErr != nil {
		return 0, f.takeoverErr
	}
	if f.intent == nil || f.intent.IntentID != intentID || f.intent.Status != IntentActive || now.Before(f.intent.LeaseExpiresAt) {
		return 0, ErrFenceLost
	}
	f.epoch++
	f.intent.Status = IntentOutcomeRecorded
	f.intent.ProviderOutcome = ProviderOutcomeUnknown
	return f.epoch, nil
}

func (f *fakeLedger) BeginSettlement(_ context.Context, _ identity.UserID, intentID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beginCalls++
	if f.beginErr != nil {
		return f.beginErr
	}
	if f.intent == nil || f.intent.IntentID != intentID || f.intent.Status != IntentOutcomeRecorded {
		return ErrFenceLost
	}
	f.intent.Status = IntentLocalSettlement
	return nil
}

func (f *fakeLedger) Settle(_ context.Context, _ identity.UserID, intentID int64, outcome SettlementOutcome) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.settleErr != nil {
		return f.settleErr
	}
	if f.intent == nil || f.intent.IntentID != intentID || f.intent.Status != IntentLocalSettlement {
		return ErrFenceLost
	}
	f.intent.Status = IntentSettled
	f.intent.SettlementOutcome = outcome
	f.settles = append(f.settles, outcome)
	f.intent = nil
	return nil
}

func (f *fakeLedger) BumpSettlementAttempts(_ context.Context, _ identity.UserID, intentID int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bumpErr != nil {
		return 0, f.bumpErr
	}
	if f.intent == nil || f.intent.IntentID != intentID || f.intent.Status.Terminal() {
		return 0, ErrFenceLost
	}
	f.intent.SettlementAttempts++
	return f.intent.SettlementAttempts, nil
}

func (f *fakeLedger) currentEpoch() Epoch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.epoch
}

func (f *fakeLedger) terminalSettles() []SettlementOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SettlementOutcome(nil), f.settles...)
}

func (f *fakeLedger) liveIntent() (*Intent, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.intent == nil {
		return nil, false
	}
	cp := *f.intent
	return &cp, true
}

// fakeCleaner records generation-scoped cleanup calls (F4) and can inject
// an infrastructure failure.
type fakeCleaner struct {
	mu       sync.Mutex
	err      error
	calls    []Epoch
	revokedN int
}

func (c *fakeCleaner) RevokeSessionsBeforeEpoch(_ context.Context, _ identity.UserID, newEpoch Epoch) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	c.calls = append(c.calls, newEpoch)
	return c.revokedN, nil
}

func (c *fakeCleaner) epochCalls() []Epoch {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Epoch(nil), c.calls...)
}

const testUser = identity.UserID("user_security")

func testClock() (*time.Time, Option) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	return &now, WithClock(func() time.Time { return now })
}

func newTestService(ledger *fakeLedger, cleaner SettlementCleaner, clock Option) *Service {
	return NewService(ledger, cleaner, time.Minute, clock)
}

// --- F1: shared promotion validator ---

func TestEvaluatePromotion_SharedValidatorMatrix(t *testing.T) {
	cases := []struct {
		name        string
		intent      *Intent
		epoch       Epoch
		stateErr    error
		recordEpoch Epoch
		want        PromotionVerdict
		wantTrigger bool
	}{
		{name: "no intent current epoch allows", epoch: 3, recordEpoch: 3, want: PromotionAllowed},
		{name: "no intent stale epoch dies permanently", epoch: 3, recordEpoch: 2, want: PromotionEpochStale},
		{
			name:   "active intent denies everything transiently",
			epoch:  1,
			intent: &Intent{IntentID: 1, Status: IntentActive, LeaseExpiresAt: time.Now().Add(time.Hour)},
			want:   PromotionDeniedTransient, wantTrigger: true,
		},
		{
			name:   "expired active intent still denies until takeover completes",
			epoch:  1,
			intent: &Intent{IntentID: 1, Status: IntentActive, LeaseExpiresAt: time.Now().Add(-time.Hour)},
			want:   PromotionDeniedTransient, wantTrigger: true,
		},
		{
			name:        "outcome_recorded current epoch ordinarily promotes",
			epoch:       2,
			intent:      &Intent{IntentID: 1, Status: IntentOutcomeRecorded, ProviderOutcome: ProviderOutcomeSuccess},
			recordEpoch: 2, want: PromotionAllowed, wantTrigger: true,
		},
		{
			name:        "local_settlement current epoch ordinarily promotes",
			epoch:       2,
			intent:      &Intent{IntentID: 1, Status: IntentLocalSettlement, ProviderOutcome: ProviderOutcomeSuccess},
			recordEpoch: 2, want: PromotionAllowed, wantTrigger: true,
		},
		{
			name:        "post-epoch old-generation session stays stale",
			epoch:       2,
			intent:      &Intent{IntentID: 1, Status: IntentOutcomeRecorded, ProviderOutcome: ProviderOutcomeUnknown},
			recordEpoch: 1, want: PromotionEpochStale, wantTrigger: true,
		},
		{name: "lookup failure fails closed without cookie clearing", stateErr: errors.New("pg down"), want: PromotionDeniedTransient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ledger := &fakeLedger{epoch: tc.epoch, intent: tc.intent, stateErr: tc.stateErr}
			svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
			got, trigger := svc.EvaluatePromotion(t.Context(), testUser, tc.recordEpoch)
			if got != tc.want {
				t.Fatalf("verdict = %v, want %v", got, tc.want)
			}
			if trigger != tc.wantTrigger {
				t.Fatalf("trigger = %v, want %v", trigger, tc.wantTrigger)
			}
		})
	}
}

// TestBarrierPhases covers the two-phase barrier: active denies everything,
// post-epoch phases deny only sensitive consumption, settled denies nothing.
func TestBarrierPhases(t *testing.T) {
	cases := []struct {
		status              IntentStatus
		wantActive, wantSen bool
	}{
		{IntentActive, true, true},
		{IntentOutcomeRecorded, false, true},
		{IntentLocalSettlement, false, true},
		{IntentSettled, false, false},
	}
	for _, tc := range cases {
		state := State{Epoch: 2, Intent: &Intent{IntentID: 1, Status: tc.status}}
		if got := BarrierActive(state); got != tc.wantActive {
			t.Errorf("BarrierActive(%s) = %v, want %v", tc.status, got, tc.wantActive)
		}
		if got := BarrierSensitive(state); got != tc.wantSen {
			t.Errorf("BarrierSensitive(%s) = %v, want %v", tc.status, got, tc.wantSen)
		}
	}
	if got := BarrierSensitive(State{Epoch: 2}); got {
		t.Error("BarrierSensitive without intent must be false")
	}
}

// TestAllowSensitiveConsumption verifies the consumption gate: a stale stamp
// is a permanent death, any non-terminal intent denies, settled/current
// allows, lookup failures fail closed.
func TestAllowSensitiveConsumption(t *testing.T) {
	t.Run("current epoch no intent allows", func(t *testing.T) {
		svc := newTestService(&fakeLedger{epoch: 2}, &fakeCleaner{}, WithClock(time.Now))
		if err := svc.AllowSensitiveConsumption(t.Context(), testUser, 2); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
	})
	t.Run("stale stamp dies permanently", func(t *testing.T) {
		svc := newTestService(&fakeLedger{epoch: 2}, &fakeCleaner{}, WithClock(time.Now))
		if err := svc.AllowSensitiveConsumption(t.Context(), testUser, 1); !errors.Is(err, ErrEpochStale) {
			t.Fatalf("err = %v, want ErrEpochStale", err)
		}
	})
	for _, status := range []IntentStatus{IntentActive, IntentOutcomeRecorded, IntentLocalSettlement} {
		t.Run("barrier phase "+string(status)+" denies", func(t *testing.T) {
			ledger := &fakeLedger{epoch: 2, intent: &Intent{IntentID: 1, Status: status}}
			svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
			if err := svc.AllowSensitiveConsumption(t.Context(), testUser, 2); !errors.Is(err, ErrBarrierHeld) {
				t.Fatalf("err = %v, want ErrBarrierHeld", err)
			}
		})
	}
	t.Run("lookup failure fails closed", func(t *testing.T) {
		svc := newTestService(&fakeLedger{stateErr: errors.New("pg down")}, &fakeCleaner{}, WithClock(time.Now))
		if err := svc.AllowSensitiveConsumption(t.Context(), testUser, 1); err == nil {
			t.Fatal("lookup failure must fail closed")
		}
	})
}

// --- B4 + lifecycle: single-winner acquisition and CAS fencing ---

func TestAcquire_SingleWinnerBeforeProvider(t *testing.T) {
	ledger := &fakeLedger{epoch: 1}
	svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))

	first, err := svc.Acquire(t.Context(), testUser)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if first.Status != IntentActive || first.EpochAtAcquire != 1 {
		t.Fatalf("first intent = %+v, want active at epoch 1", first)
	}
	// The concurrent requester fails closed before any provider call.
	if _, err := svc.Acquire(t.Context(), testUser); !errors.Is(err, ErrIntentHeld) {
		t.Fatalf("second acquire err = %v, want ErrIntentHeld", err)
	}
}

func TestSettleConfirmedFailure_LeavesEpochUntouched(t *testing.T) {
	ledger := &fakeLedger{epoch: 4}
	svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
	intent, err := svc.Acquire(t.Context(), testUser)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := svc.SettleConfirmedFailure(t.Context(), testUser, intent.IntentID); err != nil {
		t.Fatalf("settle confirmed failure: %v", err)
	}
	if got := ledger.currentEpoch(); got != 4 {
		t.Fatalf("epoch = %d after confirmed failure, want 4 (zero side effects)", got)
	}
	if _, live := ledger.liveIntent(); live {
		t.Fatal("intent must be terminal after confirmed-failure settlement")
	}
}

func TestRecordOutcome_AdvancesEpochExactlyOnce(t *testing.T) {
	for _, outcome := range []ProviderOutcome{ProviderOutcomeSuccess, ProviderOutcomeUnknown} {
		t.Run(string(outcome), func(t *testing.T) {
			ledger := &fakeLedger{epoch: 1}
			svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
			intent, err := svc.Acquire(t.Context(), testUser)
			if err != nil {
				t.Fatalf("acquire: %v", err)
			}
			newEpoch, err := svc.RecordOutcome(t.Context(), testUser, intent.IntentID, outcome)
			if err != nil {
				t.Fatalf("record outcome: %v", err)
			}
			if newEpoch != 2 || ledger.currentEpoch() != 2 {
				t.Fatalf("epoch = %d/%d, want exactly one advancement to 2", newEpoch, ledger.currentEpoch())
			}
			// A second record against the same intent loses the fence and
			// never advances the epoch again.
			if _, err := svc.RecordOutcome(t.Context(), testUser, intent.IntentID, outcome); !errors.Is(err, ErrFenceLost) {
				t.Fatalf("second record err = %v, want ErrFenceLost", err)
			}
			if ledger.currentEpoch() != 2 {
				t.Fatalf("epoch = %d after fence loss, want 2 (no double bump)", ledger.currentEpoch())
			}
		})
	}
}

func TestRecordOutcome_RejectsConfirmedFailure(t *testing.T) {
	ledger := &fakeLedger{epoch: 1}
	svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
	intent, _ := svc.Acquire(t.Context(), testUser)
	if _, err := svc.RecordOutcome(t.Context(), testUser, intent.IntentID, ProviderOutcomeConfirmedFailure); err == nil {
		t.Fatal("confirmed failure must never pass through RecordOutcome")
	}
	if ledger.currentEpoch() != 1 {
		t.Fatal("epoch must stay untouched")
	}
}

// --- F4: settlement matrix (generation-scoped cleanup) ---

func advanceToOutcomeRecorded(t *testing.T, svc *Service, ledger *fakeLedger, outcome ProviderOutcome) Intent {
	t.Helper()
	intent, err := svc.Acquire(t.Context(), testUser)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	intent.Status = IntentOutcomeRecorded
	intent.ProviderOutcome = outcome
	if _, err := svc.RecordOutcome(t.Context(), testUser, intent.IntentID, outcome); err != nil {
		t.Fatalf("record outcome: %v", err)
	}
	return intent
}

func TestSettleIntent_Matrix(t *testing.T) {
	t.Run("success with rotation settles and cleans the old generation only", func(t *testing.T) {
		ledger := &fakeLedger{epoch: 1}
		cleaner := &fakeCleaner{revokedN: 3}
		svc := newTestService(ledger, cleaner, WithClock(time.Now))
		intent := advanceToOutcomeRecorded(t, svc, ledger, ProviderOutcomeSuccess)

		result, err := svc.SettleIntent(t.Context(), intent, 2, func(context.Context) (bool, error) { return false, nil })
		if err != nil {
			t.Fatalf("settle: %v", err)
		}
		if result.Outcome != SettlementOutcomeSettled || !result.Rotated {
			t.Fatalf("result = %+v, want settled+rotated", result)
		}
		if calls := cleaner.epochCalls(); len(calls) != 1 || calls[0] != 2 {
			t.Fatalf("cleanup calls = %v, want exactly [2] (generation-scoped)", calls)
		}
		if _, live := ledger.liveIntent(); live {
			t.Fatal("intent must be terminal")
		}
	})

	t.Run("unknown outcome settles degraded", func(t *testing.T) {
		ledger := &fakeLedger{epoch: 1}
		svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
		intent := advanceToOutcomeRecorded(t, svc, ledger, ProviderOutcomeUnknown)

		result, err := svc.SettleIntent(t.Context(), intent, 2, nil)
		if err != nil {
			t.Fatalf("settle: %v", err)
		}
		if result.Outcome != SettlementOutcomeDegraded {
			t.Fatalf("outcome = %v, want degraded", result.Outcome)
		}
	})

	t.Run("vanished current session settles relogin", func(t *testing.T) {
		ledger := &fakeLedger{epoch: 1}
		svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
		intent := advanceToOutcomeRecorded(t, svc, ledger, ProviderOutcomeSuccess)

		result, err := svc.SettleIntent(t.Context(), intent, 2, func(context.Context) (bool, error) { return true, nil })
		if err != nil {
			t.Fatalf("settle: %v", err)
		}
		if result.Outcome != SettlementOutcomeSettledRelogin {
			t.Fatalf("outcome = %v, want settled_relogin", result.Outcome)
		}
	})

	t.Run("rotation infrastructure failure degrades", func(t *testing.T) {
		ledger := &fakeLedger{epoch: 1}
		svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
		intent := advanceToOutcomeRecorded(t, svc, ledger, ProviderOutcomeSuccess)

		result, err := svc.SettleIntent(t.Context(), intent, 2, func(context.Context) (bool, error) {
			return false, errors.New("redis down")
		})
		if err != nil {
			t.Fatalf("settle: %v", err)
		}
		if result.Outcome != SettlementOutcomeDegraded {
			t.Fatalf("outcome = %v, want degraded", result.Outcome)
		}
	})

	t.Run("cleanup failure degrades but never undoes the epoch boundary", func(t *testing.T) {
		ledger := &fakeLedger{epoch: 1}
		cleaner := &fakeCleaner{err: errors.New("redis walk failed")}
		svc := newTestService(ledger, cleaner, WithClock(time.Now))
		intent := advanceToOutcomeRecorded(t, svc, ledger, ProviderOutcomeSuccess)

		result, err := svc.SettleIntent(t.Context(), intent, 2, func(context.Context) (bool, error) { return false, nil })
		if err == nil {
			t.Fatal("cleanup failure must surface an error")
		}
		if result.Outcome != SettlementOutcomeDegraded || !result.Rotated {
			t.Fatalf("result = %+v, want degraded+rotated", result)
		}
		if ledger.currentEpoch() != 2 {
			t.Fatalf("epoch = %d, want 2 (boundary survives cleanup failure)", ledger.currentEpoch())
		}
		if settles := ledger.terminalSettles(); len(settles) != 1 || settles[0] != SettlementOutcomeDegraded {
			t.Fatalf("settles = %v, want exactly one degraded terminalization", settles)
		}
	})

	t.Run("unsettled phases fail closed", func(t *testing.T) {
		svc := newTestService(&fakeLedger{}, &fakeCleaner{}, WithClock(time.Now))
		for _, status := range []IntentStatus{IntentActive, IntentSettled} {
			if _, err := svc.SettleIntent(t.Context(), Intent{UserID: testUser, IntentID: 1, Status: status}, 2, nil); err == nil {
				t.Fatalf("status %s must refuse settlement", status)
			}
		}
	})

	t.Run("unset cleaner fails closed", func(t *testing.T) {
		ledger := &fakeLedger{epoch: 1}
		svc := NewService(ledger, nil, time.Minute)
		intent := advanceToOutcomeRecorded(t, svc, ledger, ProviderOutcomeSuccess)
		if _, err := svc.SettleIntent(t.Context(), intent, 2, nil); err == nil {
			t.Fatal("settlement without a cleaner must fail closed")
		}
	})
}

// --- F6: takeover/recovery, four-state matrix ---

func TestRecover_NoIntentOrSettledIsNoop(t *testing.T) {
	svc := newTestService(&fakeLedger{epoch: 2}, &fakeCleaner{}, WithClock(time.Now))
	if err := svc.Recover(t.Context(), testUser); err != nil {
		t.Fatalf("recover without intent: %v", err)
	}
}

func TestRecover_LiveActiveIntentUntouchable(t *testing.T) {
	now, clock := testClock()
	ledger := &fakeLedger{epoch: 1, intent: &Intent{
		IntentID: 7, Status: IntentActive, LeaseExpiresAt: now.Add(time.Minute),
	}}
	svc := newTestService(ledger, &fakeCleaner{}, clock)
	if err := svc.Recover(t.Context(), testUser); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if ledger.currentEpoch() != 1 {
		t.Fatal("a live provider call's fence must never be taken over")
	}
}

// TestRecover_ExpiredActiveTakeover covers F6 row 1: crash after acquire,
// before any recorded outcome. Takeover records unknown, advances the epoch
// exactly once and settles degraded — never re-invoking the provider.
func TestRecover_ExpiredActiveTakeover(t *testing.T) {
	now, clock := testClock()
	ledger := &fakeLedger{epoch: 3, intent: &Intent{
		UserID: testUser, IntentID: 7, Status: IntentActive,
		EpochAtAcquire: 3, LeaseExpiresAt: now.Add(-time.Second),
	}}
	cleaner := &fakeCleaner{}
	svc := newTestService(ledger, cleaner, clock)

	if err := svc.Recover(t.Context(), testUser); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := ledger.currentEpoch(); got != 4 {
		t.Fatalf("epoch = %d, want exactly one advancement to 4", got)
	}
	if settles := ledger.terminalSettles(); len(settles) != 1 || settles[0] != SettlementOutcomeDegraded {
		t.Fatalf("settles = %v, want one degraded terminalization", settles)
	}
	if calls := cleaner.epochCalls(); len(calls) != 1 || calls[0] != 4 {
		t.Fatalf("cleanup calls = %v, want [4]", calls)
	}
	// Idempotence: a second takeover against the settled ledger is a no-op.
	if err := svc.Recover(t.Context(), testUser); err != nil {
		t.Fatalf("second recover: %v", err)
	}
	if ledger.currentEpoch() != 4 {
		t.Fatal("epoch must never advance twice for one intent")
	}
}

// TestRecover_StaleTakeoverLosesFence covers F6 row 3: a stale worker that
// lost the CAS fence must never bump the epoch or settle someone else's
// intent.
func TestRecover_StaleTakeoverLosesFence(t *testing.T) {
	now, clock := testClock()
	ledger := &fakeLedger{
		epoch: 3,
		intent: &Intent{
			UserID: testUser, IntentID: 7, Status: IntentActive,
			LeaseExpiresAt: now.Add(-time.Second),
		},
		takeoverErr: ErrFenceLost,
	}
	svc := newTestService(ledger, &fakeCleaner{}, clock)
	if err := svc.Recover(t.Context(), testUser); err != nil {
		t.Fatalf("fence loser must exit silently, got %v", err)
	}
	if ledger.currentEpoch() != 3 {
		t.Fatal("a fence loser must never advance the epoch")
	}
	if settles := ledger.terminalSettles(); len(settles) != 0 {
		t.Fatalf("fence loser settled %v, want nothing", settles)
	}
}

// TestRecover_OutcomeRecordedResume covers F6 row 2: crash after the
// outcome record. The recorded providerOutcome is immutable, the epoch never
// advances again, and settlement simply resumes.
func TestRecover_OutcomeRecordedResume(t *testing.T) {
	ledger := &fakeLedger{epoch: 4, intent: &Intent{
		UserID: testUser, IntentID: 9, Status: IntentOutcomeRecorded,
		ProviderOutcome: ProviderOutcomeSuccess,
	}}
	svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
	if err := svc.Recover(t.Context(), testUser); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if ledger.currentEpoch() != 4 {
		t.Fatal("epoch must never advance again after outcome_recorded")
	}
	if settles := ledger.terminalSettles(); len(settles) != 1 || settles[0] != SettlementOutcomeSettled {
		t.Fatalf("settles = %v, want one settled terminalization (recovery holds no token to rotate)", settles)
	}
	if live, ok := ledger.liveIntent(); ok {
		t.Fatalf("intent still live: %+v", live)
	}
}

// TestRecover_LocalSettlementResume covers F6 row 2b: resuming an intent
// already in local_settlement skips BeginSettlement and finishes idempotently.
func TestRecover_LocalSettlementResume(t *testing.T) {
	ledger := &fakeLedger{epoch: 4, intent: &Intent{
		UserID: testUser, IntentID: 9, Status: IntentLocalSettlement,
		ProviderOutcome: ProviderOutcomeUnknown,
	}}
	svc := newTestService(ledger, &fakeCleaner{}, WithClock(time.Now))
	if err := svc.Recover(t.Context(), testUser); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if ledger.beginCalls != 0 {
		t.Fatalf("BeginSettlement called %d times, want 0 on a local_settlement resume", ledger.beginCalls)
	}
	if settles := ledger.terminalSettles(); len(settles) != 1 || settles[0] != SettlementOutcomeDegraded {
		t.Fatalf("settles = %v, want one degraded (unknown outcome) terminalization", settles)
	}
	if ledger.currentEpoch() != 4 {
		t.Fatal("epoch must never advance on resume")
	}
}

// TestRecover_CleanupFailureSurfacesForNextAttempt covers F6 row 2c: a
// cleanup failure degrades the settlement (terminalized in the ledger) and
// surfaces the error for the next bounded attempt.
func TestRecover_CleanupFailureSurfacesForNextAttempt(t *testing.T) {
	ledger := &fakeLedger{epoch: 4, intent: &Intent{
		UserID: testUser, IntentID: 9, Status: IntentOutcomeRecorded,
		ProviderOutcome: ProviderOutcomeSuccess,
	}}
	svc := newTestService(ledger, &fakeCleaner{err: errors.New("redis down")}, WithClock(time.Now))
	if err := svc.Recover(t.Context(), testUser); err == nil {
		t.Fatal("cleanup failure must surface for the next bounded attempt")
	}
	if settles := ledger.terminalSettles(); len(settles) != 1 || settles[0] != SettlementOutcomeDegraded {
		t.Fatalf("settles = %v, want the intent already terminalized degraded", settles)
	}
}

// TestRecover_BoundedAttemptsForceDegrade covers the bounded terminalization
// guarantee: after the attempt budget is exhausted the intent force-settles
// degraded — terminalization can never stall.
func TestRecover_BoundedAttemptsForceDegrade(t *testing.T) {
	ledger := &fakeLedger{epoch: 4, intent: &Intent{
		UserID: testUser, IntentID: 9, Status: IntentOutcomeRecorded,
		ProviderOutcome:    ProviderOutcomeSuccess,
		SettlementAttempts: 3, // one bump away from the budget (default 3)
	}}
	svc := newTestService(ledger, &fakeCleaner{err: errors.New("redis down")}, WithClock(time.Now))
	if err := svc.Recover(t.Context(), testUser); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if settles := ledger.terminalSettles(); len(settles) != 1 || settles[0] != SettlementOutcomeDegraded {
		t.Fatalf("settles = %v, want force-degraded terminalization", settles)
	}
	if _, live := ledger.liveIntent(); live {
		t.Fatal("intent must be terminal after bounded attempts")
	}
}

// TestRecover_LedgerLookupFailureFailsClosed ensures recovery never mutates
// anything when it cannot read the authoritative state.
func TestRecover_LedgerLookupFailureFailsClosed(t *testing.T) {
	svc := newTestService(&fakeLedger{stateErr: errors.New("pg down")}, &fakeCleaner{}, WithClock(time.Now))
	if err := svc.Recover(t.Context(), testUser); err == nil {
		t.Fatal("recovery must fail closed on a state-read failure")
	}
}

// TestTriggerRecovery_SettlesDetached verifies the opportunistic trigger runs
// a detached recovery that terminalizes an expired intent.
func TestTriggerRecovery_SettlesDetached(t *testing.T) {
	now, clock := testClock()
	ledger := &fakeLedger{epoch: 1, intent: &Intent{
		UserID: testUser, IntentID: 5, Status: IntentActive,
		LeaseExpiresAt: now.Add(-time.Second),
	}}
	svc := newTestService(ledger, &fakeCleaner{}, clock)
	svc.TriggerRecovery(testUser)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, live := ledger.liveIntent(); !live {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("triggered recovery did not terminalize the expired intent")
}
