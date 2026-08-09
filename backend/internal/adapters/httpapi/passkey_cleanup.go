//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-09
// Description: Abandoned passkey enrollment cleanup worker
//

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

// PasskeyEnrollmentCleanupStore is the durable transient-work seam used by
// the abandoned passkey enrollment worker. Implementations lease due items so
// a worker crash cannot permanently lose provider cleanup work (ADR-0008 §7).
type PasskeyEnrollmentCleanupStore interface {
	ClaimExpiredPasskeyEnrollments(ctx context.Context, limit int) ([]auth.ExpiredPasskeyEnrollment, error)
	CompletePasskeyEnrollmentCleanup(ctx context.Context, tokenHash string) error
	RequeuePasskeyEnrollmentCleanup(ctx context.Context, entry auth.ExpiredPasskeyEnrollment, delay time.Duration) error
}

// PasskeyEnrollmentCleanupWorker settles provider-side pending registrations
// whose browser ceremony disappeared. Provider readback is authoritative: an
// active target is always preserved, including the provider-success / Redis-
// finalization ambiguity after confirmation.
type PasskeyEnrollmentCleanupWorker struct {
	factors    auth.FactorManager
	store      PasskeyEnrollmentCleanupStore
	interval   time.Duration
	batchLimit int
	logger     *slog.Logger

	cancel context.CancelFunc
	done   chan struct{}
}

func NewPasskeyEnrollmentCleanupWorker(
	factors auth.FactorManager,
	store PasskeyEnrollmentCleanupStore,
	interval time.Duration,
	logger *slog.Logger,
) *PasskeyEnrollmentCleanupWorker {
	if interval <= 0 {
		interval = time.Minute
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PasskeyEnrollmentCleanupWorker{
		factors: factors, store: store, interval: interval, batchLimit: 100, logger: logger,
	}
}

func (w *PasskeyEnrollmentCleanupWorker) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.run(ctx)
}

func (w *PasskeyEnrollmentCleanupWorker) Stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
}

func (w *PasskeyEnrollmentCleanupWorker) run(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	w.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

const passkeyCleanupProviderTimeout = 10 * time.Second

func (w *PasskeyEnrollmentCleanupWorker) sweep(ctx context.Context) int {
	entries, err := w.store.ClaimExpiredPasskeyEnrollments(ctx, w.batchLimit)
	if err != nil {
		w.logger.Warn("passkey enrollment cleanup claim failed",
			"errorClass", observability.ClassifyError(err))
		return 0
	}

	settled := 0
	for _, entry := range entries {
		if w.settle(ctx, entry) {
			settled++
		}
	}
	if settled > 0 {
		w.logger.Info("passkey enrollment cleanup settled", "count", settled)
	}
	return settled
}

func (w *PasskeyEnrollmentCleanupWorker) settle(parent context.Context, entry auth.ExpiredPasskeyEnrollment) bool {
	ctx, cancel := context.WithTimeout(parent, passkeyCleanupProviderTimeout)
	passkeys, err := w.factors.ListPasskeys(ctx, entry.UserID)
	cancel()
	if err != nil {
		w.requeue(parent, entry, err)
		return false
	}
	for _, passkey := range passkeys {
		if passkey.ID == entry.Target && passkey.State == auth.PasskeyStateActive {
			// Mandatory active-preservation guard: confirmation may have
			// succeeded even when local finalization did not.
			return w.complete(parent, entry)
		}
	}

	ctx, cancel = context.WithTimeout(parent, passkeyCleanupProviderTimeout)
	err = w.factors.RemovePasskey(ctx, entry.UserID, entry.Target)
	cancel()
	if err != nil && !errors.Is(err, auth.ErrFactorNotSet) {
		w.requeue(parent, entry, err)
		return false
	}
	return w.complete(parent, entry)
}

func (w *PasskeyEnrollmentCleanupWorker) complete(ctx context.Context, entry auth.ExpiredPasskeyEnrollment) bool {
	if err := w.store.CompletePasskeyEnrollmentCleanup(ctx, entry.TokenHash); err != nil {
		w.requeue(ctx, entry, err)
		return false
	}
	return true
}

func (w *PasskeyEnrollmentCleanupWorker) requeue(ctx context.Context, entry auth.ExpiredPasskeyEnrollment, cause error) {
	delay := passkeyCleanupBackoff(entry.Attempts)
	if err := w.store.RequeuePasskeyEnrollmentCleanup(ctx, entry, delay); err != nil {
		w.logger.Warn("passkey enrollment cleanup requeue failed",
			"errorClass", observability.ClassifyError(err))
		return
	}
	w.logger.Warn("passkey enrollment cleanup deferred",
		"attempt", entry.Attempts+1,
		"errorClass", observability.ClassifyError(cause))
}

func passkeyCleanupBackoff(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	if attempts > 5 {
		attempts = 5
	}
	return time.Minute * time.Duration(1<<attempts)
}
