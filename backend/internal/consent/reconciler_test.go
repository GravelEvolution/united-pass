//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the decision operation reconciler
//

package consent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// stubInFlight returns a fixed operation list (or error), decoupled from
// the store state — used to exercise reconciler reactions that the real
// listing predicate would otherwise filter out (e.g. already-terminal
// rows racing a pass).
type stubInFlight struct {
	ops []DecisionOperation
	err error
}

func (s stubInFlight) ListInFlightDecisionOperations(context.Context, time.Time, int) ([]DecisionOperation, error) {
	return s.ops, s.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestReconciler(t *testing.T, store GrantStore, inFlight InFlightDecisionOperations) *Reconciler {
	t.Helper()
	r, err := NewReconciler(store, inFlight, time.Second, 5*time.Minute, 10, discardLogger())
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	r.now = testClock()
	return r
}

// seedProvenOperation claims an operation and records the provider
// success proof, leaving the local commit outstanding (the 4→5 crash
// window the reconciler must repair).
func seedProvenOperation(t *testing.T, store *fakeGrantStore, authRequestID string, kind CompletionKind) DecisionOperation {
	t.Helper()
	op := DecisionOperation{
		ID: NewDecisionOperationID(), Provider: "zitadel", ProviderTenantID: "tenant-test",
		AuthRequestID: authRequestID, CompletionKind: kind,
		LocalUserID: "user_01TEST", ClientID: "cli_test",
	}
	if kind == CompletionAllow {
		op.Scopes = []string{"openid"}
	}
	claimed, won, err := store.ClaimDecisionOperation(context.Background(), op)
	if err != nil || !won {
		t.Fatalf("seed claim: won=%v err=%v", won, err)
	}
	if err := store.RecordProviderSucceeded(context.Background(), claimed.ID, testNow); err != nil {
		t.Fatalf("seed proof: %v", err)
	}
	return claimed
}

func TestReconcilerRepairsProvenOperationsForward(t *testing.T) {
	store := newFakeGrantStore()
	allow := seedProvenOperation(t, store, "V2-r-allow", CompletionAllow)
	deny := seedProvenOperation(t, store, "V2-r-deny", CompletionAccessDenied)
	// An error completion (gateway-side fail-closed kind) also repairs
	// through its canonical commit.
	serverErr := seedProvenOperation(t, store, "V2-r-server-error", CompletionServerError)

	r := newTestReconciler(t, store, store)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	for id, want := range map[DecisionOperationID]DecisionOperationStatus{
		allow.ID:     DecisionOperationSucceeded,
		deny.ID:      DecisionOperationSucceeded,
		serverErr.ID: DecisionOperationSucceeded,
	} {
		if got := store.ops[id].Status; got != want {
			t.Fatalf("operation %s status = %s, want %s", id, got, want)
		}
	}
	if store.allowCommits != 1 || store.denyCommits != 1 || store.errorCommits != 1 {
		t.Fatalf("commits: allow=%d deny=%d error=%d", store.allowCommits, store.denyCommits, store.errorCommits)
	}
}

func TestReconcilerIsIdempotentOnTerminalRows(t *testing.T) {
	// A row that raced a pass: the listing still reports it as
	// proof-bearing, but the store has already committed it. The commit
	// CAS returns ErrDecisionStateConflict and the pass must swallow it
	// silently.
	store := newFakeGrantStore()
	op := seedProvenOperation(t, store, "V2-r-done", CompletionAllow)
	if err := store.CommitAllowDecision(context.Background(), AllowCommit{OperationID: op.ID}); err != nil {
		t.Fatalf("pre-commit: %v", err)
	}

	r := newTestReconciler(t, store, stubInFlight{ops: []DecisionOperation{{
		ID: op.ID, Status: DecisionOperationProviderSucceeded, CompletionKind: CompletionAllow, CreatedAt: testNow,
	}}})
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if store.allowCommits != 1 {
		t.Fatalf("allow commits = %d, want exactly the pre-commit", store.allowCommits)
	}
}

func TestReconcilerFailsStalePendingOperations(t *testing.T) {
	store := newFakeGrantStore()
	op, won, err := store.ClaimDecisionOperation(context.Background(), DecisionOperation{
		ID: NewDecisionOperationID(), Provider: "zitadel", ProviderTenantID: "tenant-test",
		AuthRequestID: "V2-r-stale", CompletionKind: CompletionAllow,
		LocalUserID: "user_01TEST", ClientID: "cli_test", Scopes: []string{"openid"},
	})
	if err != nil || !won {
		t.Fatalf("seed claim: won=%v err=%v", won, err)
	}
	// Age the row past the staleness horizon (claim stamps testNow).
	stale := store.ops[op.ID]
	stale.CreatedAt = testNow.Add(-10 * time.Minute)
	store.ops[op.ID] = stale

	r := newTestReconciler(t, store, store)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if store.ops[op.ID].Status != DecisionOperationFailed || store.failed[op.ID] != ClassProviderUnavailable {
		t.Fatalf("stale pending not failed closed: %+v", store.ops[op.ID])
	}
	if store.allowCommits != 0 {
		t.Fatal("an unproven pending row must never become a grant")
	}
}

func TestReconcilerSkipsFreshPendingOperations(t *testing.T) {
	store := newFakeGrantStore()
	op, won, err := store.ClaimDecisionOperation(context.Background(), DecisionOperation{
		ID: NewDecisionOperationID(), Provider: "zitadel", ProviderTenantID: "tenant-test",
		AuthRequestID: "V2-r-fresh", CompletionKind: CompletionAllow,
		LocalUserID: "user_01TEST", ClientID: "cli_test", Scopes: []string{"openid"},
	})
	if err != nil || !won {
		t.Fatalf("seed claim: won=%v err=%v", won, err)
	}

	r := newTestReconciler(t, store, store)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if store.ops[op.ID].Status != DecisionOperationPending {
		t.Fatalf("fresh pending row must stay pending: %+v", store.ops[op.ID])
	}
	if len(store.failed) != 0 {
		t.Fatal("fresh pending row must not be failed")
	}
}

func TestReconcilerPoisonedRowDoesNotStallThePass(t *testing.T) {
	store := newFakeGrantStore()
	poisoned := seedProvenOperation(t, store, "V2-r-poison", CompletionAllow)
	healthy := seedProvenOperation(t, store, "V2-r-healthy", CompletionAllow)
	// Corrupt the plan: an unknown completion kind can never be repaired,
	// but the pass must log-and-skip instead of stalling.
	bad := store.ops[poisoned.ID]
	bad.CompletionKind = CompletionKind("bogus")
	store.ops[poisoned.ID] = bad

	r := newTestReconciler(t, store, stubInFlight{ops: []DecisionOperation{store.ops[poisoned.ID], store.ops[healthy.ID]}})
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if store.ops[poisoned.ID].Status != DecisionOperationProviderSucceeded {
		t.Fatal("poisoned row must stay untouched for the next pass")
	}
	if store.ops[healthy.ID].Status != DecisionOperationSucceeded || store.allowCommits != 1 {
		t.Fatalf("healthy row not repaired: %+v commits=%d", store.ops[healthy.ID], store.allowCommits)
	}
}

func TestReconcilerPropagatesListingFailure(t *testing.T) {
	r := newTestReconciler(t, newFakeGrantStore(), stubInFlight{err: errors.New("db exploded")})
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("listing failure must surface")
	}
}

func TestReconcilerStartStop(t *testing.T) {
	r := newTestReconciler(t, newFakeGrantStore(), stubInFlight{})
	r.interval = 5 * time.Millisecond
	r.Start()
	time.Sleep(20 * time.Millisecond)
	r.Stop()
}

// Lifecycle idempotency is part of the public contract: server
// shutdown/recovery paths may call Start/Stop more than once and from
// multiple goroutines, and none of these sequences may panic or leak a
// second worker.
func TestReconcilerStartTwice(t *testing.T) {
	r := newTestReconciler(t, newFakeGrantStore(), stubInFlight{})
	r.interval = 5 * time.Millisecond
	r.Start()
	r.Start() // documented no-op: exactly one loop must exist
	time.Sleep(20 * time.Millisecond)
	r.Stop()
}

func TestReconcilerStopTwice(t *testing.T) {
	r := newTestReconciler(t, newFakeGrantStore(), stubInFlight{})
	r.interval = 5 * time.Millisecond
	r.Start()
	r.Stop()
	r.Stop() // repeated Stop must not panic on a closed channel
}

func TestReconcilerStopBeforeStart(t *testing.T) {
	r := newTestReconciler(t, newFakeGrantStore(), stubInFlight{})
	r.Stop() // no worker yet: must be a no-op, not a deadlock
}

func TestReconcilerConcurrentStop(t *testing.T) {
	r := newTestReconciler(t, newFakeGrantStore(), stubInFlight{})
	r.interval = 5 * time.Millisecond
	r.Start()
	time.Sleep(20 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Stop()
		}()
	}
	wg.Wait()
}

func TestNewReconcilerValidationAndDefaults(t *testing.T) {
	store := newFakeGrantStore()
	inFlight := stubInFlight{}
	logger := discardLogger()

	if _, err := NewReconciler(nil, inFlight, 0, 0, 0, logger); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewReconciler(store, nil, 0, 0, 0, logger); err == nil {
		t.Fatal("nil in-flight source accepted")
	}
	if _, err := NewReconciler(store, inFlight, 0, 0, 0, nil); err == nil {
		t.Fatal("nil logger accepted")
	}

	r, err := NewReconciler(store, inFlight, 0, 0, 0, logger)
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	if r.interval != DefaultReconciliationInterval || r.pendingStaleFor != DefaultPendingStaleAfter || r.batch != DefaultReconciliationBatch {
		t.Fatalf("defaults not applied: %+v", r)
	}
}
