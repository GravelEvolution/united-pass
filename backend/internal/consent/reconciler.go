//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Background reconciler that repairs stranded decision operations
//

package consent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DefaultReconciliationInterval is the background reconciler tick used by
// the standard wiring.
const DefaultReconciliationInterval = 30 * time.Second

// DefaultPendingStaleAfter is how long a pending decision operation may
// stay unconfirmed before the reconciler terminates it fail-closed.
// Pending rows without the provider success proof can never be repaired
// into a grant (ADR-0005 §4).
const DefaultPendingStaleAfter = 5 * time.Minute

// DefaultReconciliationBatch bounds one reconciler pass.
const DefaultReconciliationBatch = 100

// InFlightDecisionOperations enumerates the decision operations that need
// reconciliation attention (ADR-0005 §4): rows carrying the provider
// success proof (forward repair candidates) plus pending rows claimed
// before the staleness horizon (fail-closed candidates). The PostgreSQL
// repository implements it.
type InFlightDecisionOperations interface {
	// ListInFlightDecisionOperations returns at most limit operations
	// whose status is provider_succeeded, or pending with a creation time
	// strictly before staleBefore, oldest first.
	ListInFlightDecisionOperations(ctx context.Context, staleBefore time.Time, limit int) ([]DecisionOperation, error)
}

// Reconciler repairs in-flight decision operations in the background
// (ADR-0005 §4, §5). It is strictly fail-closed: only rows carrying the
// explicit provider_succeeded proof are ever repaired forward (grant +
// audit completed exactly once from the immutable plan); stale pending
// rows are terminated without a grant, and the reconciler never attempts
// to re-complete an auth request whose provider call is unconfirmed —
// there is no waiting browser to deliver a callback URL to.
type Reconciler struct {
	store           GrantStore
	inFlight        InFlightDecisionOperations
	interval        time.Duration
	pendingStaleFor time.Duration
	batch           int
	logger          *slog.Logger
	now             func() time.Time

	mu       sync.Mutex
	started  bool
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

// NewReconciler builds the consent decision reconciler. All dependencies
// are required; non-positive tuning values fall back to the defaults.
func NewReconciler(
	store GrantStore,
	inFlight InFlightDecisionOperations,
	interval, pendingStaleAfter time.Duration,
	batch int,
	logger *slog.Logger,
) (*Reconciler, error) {
	if store == nil {
		return nil, errors.New("consent: reconciler requires a grant store")
	}
	if inFlight == nil {
		return nil, errors.New("consent: reconciler requires an in-flight operation source")
	}
	if logger == nil {
		return nil, errors.New("consent: reconciler requires a logger")
	}
	if interval <= 0 {
		interval = DefaultReconciliationInterval
	}
	if pendingStaleAfter <= 0 {
		pendingStaleAfter = DefaultPendingStaleAfter
	}
	if batch <= 0 {
		batch = DefaultReconciliationBatch
	}
	return &Reconciler{
		store:           store,
		inFlight:        inFlight,
		interval:        interval,
		pendingStaleFor: pendingStaleAfter,
		batch:           batch,
		logger:          logger,
		now:             func() time.Time { return time.Now().UTC() },
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}, nil
}

// Start launches the background loop. It is idempotent: only the first
// call starts the loop, later calls are no-ops.
func (r *Reconciler) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return
	}
	r.started = true
	go r.loop()
}

// Stop signals the loop to exit and waits for it. It is idempotent and
// safe to call concurrently: repeated calls return after the single loop
// has terminated, and Stop before Start is a no-op.
func (r *Reconciler) Stop() {
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	r.stopOnce.Do(func() { close(r.stop) })
	<-r.done
}

func (r *Reconciler) loop() {
	defer close(r.done)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), r.interval)
			if err := r.RunOnce(ctx); err != nil {
				r.logger.Error("consent reconciliation pass failed", "error", err)
			}
			cancel()
		}
	}
}

// RunOnce performs a single reconciliation pass: forward-repair every
// proof-bearing row and fail every stale pending row. Individual row
// failures are logged and skipped — one poisoned row must never stall the
// pass, and every transition is an idempotent compare-and-set, so the
// next pass retries safely.
func (r *Reconciler) RunOnce(ctx context.Context) error {
	ops, err := r.inFlight.ListInFlightDecisionOperations(ctx, r.now().Add(-r.pendingStaleFor), r.batch)
	if err != nil {
		return fmt.Errorf("consent: list in-flight decision operations: %w", err)
	}
	staleHorizon := r.now().Add(-r.pendingStaleFor)
	for _, op := range ops {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch op.Status {
		case DecisionOperationProviderSucceeded:
			// Forward repair: the row alone carries the immutable
			// completion plan; the commit is constructed from the locked
			// row exactly like the interactive path (ADR-0005 §4).
			if err := repairCompletionForward(ctx, r.store, op); err != nil && !errors.Is(err, ErrDecisionStateConflict) {
				r.logger.Error("consent reconciliation: forward repair failed",
					"operationId", string(op.ID),
					"completionKind", string(op.CompletionKind),
					"error", err,
				)
			}
		case DecisionOperationPending:
			if !op.CreatedAt.Before(staleHorizon) {
				// Not stale yet — the provider call may still be in
				// flight on a live request.
				continue
			}
			// Fail closed: no provider success proof exists, so the
			// outcome is unknown and must never become a grant. The
			// provider_unavailable class records the unconfirmed call.
			if err := r.store.FailDecisionOperation(ctx, op.ID, ClassProviderUnavailable); err != nil && !errors.Is(err, ErrDecisionStateConflict) {
				r.logger.Error("consent reconciliation: fail stale pending operation",
					"operationId", string(op.ID),
					"error", err,
				)
			}
		default:
			// Terminal rows need no attention; defensive skip.
		}
	}
	return nil
}
