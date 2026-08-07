//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Background cleaner for expired re-authentication challenges and grants
//

package httpapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/platform/observability"
)

// ReauthCleanupWorker revokes temporary provider sessions left behind by
// reauthentication challenges that expired in Redis or were abandoned by the
// user (ADR-0004 §7). Challenges index their expiry in Redis at creation; the
// worker periodically pops index entries past their expiry whose challenge
// record is gone and revokes each recorded provider session best-effort.
// Revocation is idempotent: a session already terminated at an explicit
// terminal state is simply terminated again, and a failed revocation records
// a security event and falls back to provider-side expiry.
type ReauthCleanupWorker struct {
	authenticator ReauthAuthenticator
	challenges    ReauthChallengeStore
	auditor       ReauthEventRecorder
	interval      time.Duration
	batchLimit    int
	logger        *slog.Logger

	cancel context.CancelFunc
	done   chan struct{}
}

// NewReauthCleanupWorker builds the abandoned-challenge cleanup worker. A
// non-positive interval falls back to one minute.
func NewReauthCleanupWorker(
	authenticator ReauthAuthenticator,
	challenges ReauthChallengeStore,
	auditor ReauthEventRecorder,
	interval time.Duration,
	logger *slog.Logger,
) *ReauthCleanupWorker {
	if interval <= 0 {
		interval = time.Minute
	}
	return &ReauthCleanupWorker{
		authenticator: authenticator,
		challenges:    challenges,
		auditor:       auditor,
		interval:      interval,
		batchLimit:    100,
		logger:        logger,
	}
}

// Start launches the background sweep loop. It sweeps once immediately, then
// on every interval tick, until Stop is called.
func (w *ReauthCleanupWorker) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.run(ctx)
}

// Stop terminates the sweep loop and waits for any in-flight sweep to finish.
// It is a no-op when the worker was never started.
func (w *ReauthCleanupWorker) Stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
}

func (w *ReauthCleanupWorker) run(ctx context.Context) {
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

// sweep pops expired/abandoned challenge cleanup entries and revokes their
// temporary provider sessions. It returns the number of sessions revoked.
// Every failure is logged and never blocks the loop: cleanup is best-effort
// and provider-side expiry remains the safety net.
func (w *ReauthCleanupWorker) sweep(ctx context.Context) int {
	entries, err := w.challenges.PopExpiredChallenges(ctx, w.batchLimit)
	if err != nil {
		w.logger.Warn("reauth cleanup pop failed",
			"errorClass", observability.ClassifyError(err),
			"errorDetail", observability.RedactedError(err, 256),
		)
		return 0
	}

	revoked := 0
	for _, entry := range entries {
		if entry.ProviderSessionID == "" {
			continue
		}
		if err := w.authenticator.RevokeProviderSession(ctx, entry.ProviderSessionID); err != nil {
			w.logger.Warn("reauth cleanup revocation failed",
				"errorClass", observability.ClassifyError(err),
				"errorDetail", observability.RedactedError(err, 256),
			)
			w.auditor.RecordEvent(ctx, applications.EventProviderSessionRevokeFailed, entry.UserID,
				applications.ApplicationID(entry.ApplicationID), applications.OAuthClientID(entry.ClientID),
				"", entry.Action, applications.SecurityEventDenied,
				string(observability.ClassifyError(err)))
			continue
		}
		revoked++
	}
	if revoked > 0 {
		w.logger.Info("reauth cleanup revoked abandoned provider sessions", "count", revoked)
	}
	return revoked
}
