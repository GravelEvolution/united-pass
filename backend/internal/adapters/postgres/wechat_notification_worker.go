package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	defaultWeChatNotificationBatch       = 25
	defaultWeChatNotificationInterval    = 5 * time.Second
	defaultWeChatNotificationSendTimeout = 20 * time.Second
)

type weChatNotificationDispatcher interface {
	ListPending(context.Context, int) ([]WeChatNotificationIntent, error)
	Dispatch(context.Context, WeChatNotificationIntent, WeChatNotificationSender, time.Time) error
}

// WeChatNotificationWorker drains the append-only security_events outbox in
// bounded batches. Busy and not-yet-verified targets remain pending. Other
// errors are returned as a joined value so one poison/transient item does not
// prevent unrelated notifications in the same batch from being attempted.
// Bootstrap starts the worker only when onboarding and SMTP delivery are both
// configured; otherwise durable intents remain pending in PostgreSQL.
type WeChatNotificationWorker struct {
	store  weChatNotificationDispatcher
	sender WeChatNotificationSender
	now    func() time.Time
	logger *slog.Logger

	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
	batch    int
	interval time.Duration
	timeout  time.Duration
}

func NewWeChatNotificationWorker(store *WeChatNotificationStore, sender WeChatNotificationSender, loggers ...*slog.Logger) *WeChatNotificationWorker {
	worker := &WeChatNotificationWorker{
		store: store, sender: sender, now: func() time.Time { return time.Now().UTC() },
		batch: defaultWeChatNotificationBatch, interval: defaultWeChatNotificationInterval,
		timeout: defaultWeChatNotificationSendTimeout,
	}
	if len(loggers) > 0 {
		worker.logger = loggers[0]
	}
	return worker
}

// Start launches one bounded outbox loop. It is safe to call more than once;
// only the first call starts a goroutine. PostgreSQL advisory locks coordinate
// multiple process instances.
func (w *WeChatNotificationWorker) Start() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil || w.store == nil || w.sender == nil || w.batch < 1 || w.batch > 200 || w.interval <= 0 || w.timeout <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.run(ctx, w.done)
}

// Stop cancels in-flight delivery and waits for the worker before the
// PostgreSQL pool and SMTP transport are closed.
func (w *WeChatNotificationWorker) Stop() {
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

func (w *WeChatNotificationWorker) run(ctx context.Context, done chan struct{}) {
	defer close(done)
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

func (w *WeChatNotificationWorker) runOnceAndLog(ctx context.Context) {
	attempted, err := w.RunOnce(ctx, w.batch)
	if err == nil || errors.Is(err, context.Canceled) || w.logger == nil {
		return
	}
	// Never attach err itself: SMTP and store errors may contain recipient or
	// transport details. The bounded class is enough for an operator alert.
	w.logger.Warn("WeChat security notification worker iteration failed",
		"error_class", weChatNotificationWorkerErrorClass(err),
		"attempted", attempted,
	)
}

func weChatNotificationWorkerErrorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, ErrWeChatAuthorityEffectInvalid):
		return "invalid_worker_state"
	default:
		return "delivery_or_store_failure"
	}
}

func (w *WeChatNotificationWorker) RunOnce(ctx context.Context, limit int) (int, error) {
	if w == nil || w.store == nil || w.sender == nil || w.now == nil || limit < 1 || limit > 200 {
		return 0, ErrWeChatAuthorityEffectInvalid
	}
	intents, err := w.store.ListPending(ctx, limit)
	if err != nil {
		return 0, err
	}
	attempted := 0
	errs := make([]error, 0)
	for _, intent := range intents {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		dispatchCtx := ctx
		cancel := func() {}
		if w.timeout > 0 {
			dispatchCtx, cancel = context.WithTimeout(ctx, w.timeout)
		}
		dispatchErr := w.store.Dispatch(dispatchCtx, intent, w.sender, w.now())
		cancel()
		if errors.Is(dispatchErr, ErrWeChatNotificationBusy) || errors.Is(dispatchErr, ErrWeChatNotificationNotReady) {
			continue
		}
		attempted++
		if dispatchErr != nil {
			errs = append(errs, fmt.Errorf("dispatch %s: %w", intent.NotificationID, dispatchErr))
		}
	}
	return attempted, errors.Join(errs...)
}
