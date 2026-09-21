package dreamupadmin

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
)

const (
	defaultProtectedReasonCleanupInterval = 15 * time.Minute
	defaultProtectedReasonCleanupBatch    = 100
	defaultProtectedReasonCleanupTimeout  = 30 * time.Second

	maxProtectedReasonCleanupBatch    = 100
	maxProtectedReasonCleanupInterval = 24 * time.Hour
	maxProtectedReasonCleanupTimeout  = 5 * time.Minute
)

var errProtectedReasonCleanupInvalidState = errors.New("dreamupadmin: protected reason cleanup is unavailable")

type ProtectedReasonCleanupDependencies struct {
	UnitOfWork adminstore.UnitOfWork
	Logger     *slog.Logger
}

type ProtectedReasonCleanupConfig struct {
	Interval  time.Duration
	BatchSize int
	Timeout   time.Duration
	Now       func() time.Time
}

// ProtectedReasonCleanupWorker cryptographically erases expired privileged
// operation reasons in bounded authority-database transactions. It logs only
// an allowlisted error class and aggregate counts; reason IDs, owners,
// ciphertext and repository errors never enter logs.
type ProtectedReasonCleanupWorker struct {
	uow      adminstore.UnitOfWork
	logger   *slog.Logger
	now      func() time.Time
	interval time.Duration
	batch    int
	timeout  time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewProtectedReasonCleanupWorker(dependencies ProtectedReasonCleanupDependencies, config ProtectedReasonCleanupConfig) (*ProtectedReasonCleanupWorker, error) {
	if config.Interval == 0 {
		config.Interval = defaultProtectedReasonCleanupInterval
	}
	if config.BatchSize == 0 {
		config.BatchSize = defaultProtectedReasonCleanupBatch
	}
	if config.Timeout == 0 {
		config.Timeout = defaultProtectedReasonCleanupTimeout
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if dependencies.UnitOfWork == nil || config.Interval < time.Second || config.Interval > maxProtectedReasonCleanupInterval || config.BatchSize < 1 || config.BatchSize > maxProtectedReasonCleanupBatch || config.Timeout < time.Second || config.Timeout > maxProtectedReasonCleanupTimeout {
		return nil, ErrInvalidRequest
	}
	return &ProtectedReasonCleanupWorker{
		uow: dependencies.UnitOfWork, logger: dependencies.Logger, now: config.Now,
		interval: config.Interval, batch: config.BatchSize, timeout: config.Timeout,
	}, nil
}

// RunOnce purges at most the configured batch. Its timeout covers both the
// authority transaction and row updates, so a stalled database cannot pin the
// worker indefinitely.
func (w *ProtectedReasonCleanupWorker) RunOnce(parent context.Context) (int, error) {
	if w == nil || parent == nil || w.uow == nil || w.now == nil || w.batch < 1 || w.batch > maxProtectedReasonCleanupBatch || w.timeout <= 0 || w.timeout > maxProtectedReasonCleanupTimeout {
		return 0, errProtectedReasonCleanupInvalidState
	}
	if err := parent.Err(); err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(parent, w.timeout)
	defer cancel()
	now := w.now().UTC()
	purged := 0
	err := w.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		if repositories.Reasons == nil {
			return errProtectedReasonCleanupInvalidState
		}
		count, err := repositories.Reasons.PurgeExpired(ctx, now, w.batch)
		if err != nil {
			return err
		}
		if count < 0 || count > w.batch {
			return errProtectedReasonCleanupInvalidState
		}
		purged = count
		return nil
	})
	if err != nil {
		return 0, err
	}
	return purged, nil
}

// Start launches a single cleanup loop and performs the first sweep
// immediately. Repeated calls are idempotent. A stopped worker may be started
// again with a new parent context.
func (w *ProtectedReasonCleanupWorker) Start(parent context.Context) {
	if w == nil || parent == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil || w.uow == nil || w.interval <= 0 || w.timeout <= 0 || w.batch < 1 || w.batch > maxProtectedReasonCleanupBatch {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	w.cancel, w.done = cancel, done
	go w.run(ctx, done)
}

// Stop cancels an in-flight sweep and waits for it before authority database
// resources may be closed. Repeated and concurrent calls are safe.
func (w *ProtectedReasonCleanupWorker) Stop() {
	if w == nil {
		return
	}
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
	w.mu.Lock()
	if w.done == done {
		w.cancel, w.done = nil, nil
	}
	w.mu.Unlock()
}

func (w *ProtectedReasonCleanupWorker) run(ctx context.Context, done chan struct{}) {
	defer func() {
		// Close first so every Stop waiter can make progress, then clear only
		// this generation. This also makes a naturally cancelled parent
		// context restartable without requiring an extra Stop call.
		w.mu.Lock()
		close(done)
		if w.done == done {
			w.cancel, w.done = nil, nil
		}
		w.mu.Unlock()
	}()
	w.runOnceAndLog(ctx)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.runOnceAndLog(ctx)
		}
	}
}

func (w *ProtectedReasonCleanupWorker) runOnceAndLog(ctx context.Context) {
	purged, err := w.RunOnce(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || w.logger == nil {
			return
		}
		w.logger.Warn("protected operation reason cleanup iteration failed", "error_class", protectedReasonCleanupErrorClass(err))
		return
	}
	if purged > 0 && w.logger != nil {
		w.logger.Info("expired protected operation reasons purged", "count", purged)
	}
}

func protectedReasonCleanupErrorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, errProtectedReasonCleanupInvalidState), errors.Is(err, ErrInvalidRequest):
		return "invalid_worker_state"
	default:
		return "authority_store_failure"
	}
}
