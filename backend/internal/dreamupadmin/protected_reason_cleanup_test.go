package dreamupadmin

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
)

func TestProtectedReasonCleanupWorkerRunOnceUsesBoundedBatchAndTimeout(t *testing.T) {
	now := time.Date(2026, 9, 4, 19, 0, 0, 0, time.FixedZone("test", 8*60*60))
	repository := &protectedReasonCleanupRepositoryStub{purged: 17}
	worker, err := NewProtectedReasonCleanupWorker(
		ProtectedReasonCleanupDependencies{UnitOfWork: protectedReasonCleanupUOWStub{repository: repository}},
		ProtectedReasonCleanupConfig{Interval: time.Minute, BatchSize: 37, Timeout: time.Second, Now: func() time.Time { return now }},
	)
	if err != nil {
		t.Fatal(err)
	}

	purged, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if purged != 17 || repository.calls != 1 || repository.limit != 37 {
		t.Fatalf("purged=%d calls=%d limit=%d", purged, repository.calls, repository.limit)
	}
	if !repository.now.Equal(now.UTC()) || repository.now.Location() != time.UTC {
		t.Fatalf("cleanup time=%v, want UTC %v", repository.now, now.UTC())
	}
	if !repository.sawDeadline {
		t.Fatal("repository call was not bounded by a context deadline")
	}
}

func TestProtectedReasonCleanupWorkerPropagatesFailureWithoutLoggingSensitiveDetails(t *testing.T) {
	secret := "reason_id=review_identity_secret owner=alice@example.test ciphertext=private"
	repository := &protectedReasonCleanupRepositoryStub{err: errors.New(secret)}
	var logs bytes.Buffer
	worker, err := NewProtectedReasonCleanupWorker(
		ProtectedReasonCleanupDependencies{
			UnitOfWork: protectedReasonCleanupUOWStub{repository: repository},
			Logger:     slog.New(slog.NewJSONHandler(&logs, nil)),
		},
		ProtectedReasonCleanupConfig{Interval: time.Minute, BatchSize: 10, Timeout: time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := worker.RunOnce(context.Background()); err == nil || err.Error() != secret {
		t.Fatalf("RunOnce error=%v, want repository failure", err)
	}
	worker.runOnceAndLog(context.Background())
	output := logs.String()
	if !strings.Contains(output, "authority_store_failure") {
		t.Fatalf("missing bounded error class: %s", output)
	}
	for _, sensitive := range []string{"review_identity_secret", "alice@example.test", "ciphertext", "private"} {
		if strings.Contains(output, sensitive) {
			t.Fatalf("worker log leaked %q: %s", sensitive, output)
		}
	}
}

func TestProtectedReasonCleanupWorkerDeadlineCancelsRepository(t *testing.T) {
	repository := &protectedReasonCleanupRepositoryStub{waitForCancellation: true}
	worker := &ProtectedReasonCleanupWorker{
		uow: protectedReasonCleanupUOWStub{repository: repository}, now: time.Now,
		batch: 10, timeout: 15 * time.Millisecond,
	}

	started := time.Now()
	_, err := worker.RunOnce(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunOnce error=%v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cleanup did not honor timeout: %v", elapsed)
	}
}

func TestProtectedReasonCleanupWorkerStartStopAreIdempotentAndRestartable(t *testing.T) {
	repository := &protectedReasonCleanupRepositoryStub{called: make(chan struct{}, 4)}
	worker, err := NewProtectedReasonCleanupWorker(
		ProtectedReasonCleanupDependencies{UnitOfWork: protectedReasonCleanupUOWStub{repository: repository}},
		ProtectedReasonCleanupConfig{Interval: time.Hour, BatchSize: 20, Timeout: time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}

	var starts sync.WaitGroup
	for range 10 {
		starts.Add(1)
		go func() {
			defer starts.Done()
			worker.Start(context.Background())
		}()
	}
	starts.Wait()
	waitForCleanupCall(t, repository.called)
	if calls := repository.callCount(); calls != 1 {
		t.Fatalf("duplicate Start launched %d immediate sweeps", calls)
	}
	var stops sync.WaitGroup
	for range 10 {
		stops.Add(1)
		go func() {
			defer stops.Done()
			worker.Stop()
		}()
	}
	stops.Wait()
	worker.Stop()

	worker.Start(context.Background())
	waitForCleanupCall(t, repository.called)
	worker.Stop()
	if calls := repository.callCount(); calls != 2 {
		t.Fatalf("restart calls=%d, want 2", calls)
	}
}

func TestProtectedReasonCleanupWorkerCanRestartAfterParentCancellation(t *testing.T) {
	repository := &protectedReasonCleanupRepositoryStub{called: make(chan struct{}, 4)}
	worker, err := NewProtectedReasonCleanupWorker(
		ProtectedReasonCleanupDependencies{UnitOfWork: protectedReasonCleanupUOWStub{repository: repository}},
		ProtectedReasonCleanupConfig{Interval: time.Hour, BatchSize: 20, Timeout: time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}

	firstContext, cancelFirst := context.WithCancel(context.Background())
	worker.Start(firstContext)
	waitForCleanupCall(t, repository.called)
	worker.mu.Lock()
	firstDone := worker.done
	worker.mu.Unlock()
	cancelFirst()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("worker did not exit after parent cancellation")
	}

	worker.Start(context.Background())
	waitForCleanupCall(t, repository.called)
	worker.Stop()
	if calls := repository.callCount(); calls != 2 {
		t.Fatalf("restart after parent cancellation calls=%d, want 2", calls)
	}
}

func TestProtectedReasonCleanupWorkerRunsImmediatelyThenOnInterval(t *testing.T) {
	repository := &protectedReasonCleanupRepositoryStub{called: make(chan struct{}, 4)}
	worker := &ProtectedReasonCleanupWorker{
		uow: protectedReasonCleanupUOWStub{repository: repository}, now: time.Now,
		interval: 10 * time.Millisecond, batch: 20, timeout: 100 * time.Millisecond,
	}

	worker.Start(context.Background())
	waitForCleanupCall(t, repository.called)
	waitForCleanupCall(t, repository.called)
	worker.Stop()
	if calls := repository.callCount(); calls < 2 {
		t.Fatalf("cleanup calls=%d, want immediate and interval sweeps", calls)
	}
}

func TestNewProtectedReasonCleanupWorkerRejectsUnsafeBounds(t *testing.T) {
	uow := protectedReasonCleanupUOWStub{repository: &protectedReasonCleanupRepositoryStub{}}
	for _, config := range []ProtectedReasonCleanupConfig{
		{Interval: -time.Second},
		{Interval: 25 * time.Hour},
		{BatchSize: 101},
		{Timeout: 6 * time.Minute},
	} {
		if _, err := NewProtectedReasonCleanupWorker(ProtectedReasonCleanupDependencies{UnitOfWork: uow}, config); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("config=%+v error=%v, want invalid request", config, err)
		}
	}
}

func waitForCleanupCall(t *testing.T, called <-chan struct{}) {
	t.Helper()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for immediate cleanup sweep")
	}
}

type protectedReasonCleanupUOWStub struct {
	repository adminstore.ProtectedReasonRepository
}

func (u protectedReasonCleanupUOWStub) Within(ctx context.Context, fn func(adminstore.Repositories) error) error {
	return fn(adminstore.Repositories{Reasons: u.repository})
}

type protectedReasonCleanupRepositoryStub struct {
	mu                  sync.Mutex
	calls               int
	limit               int
	now                 time.Time
	sawDeadline         bool
	purged              int
	err                 error
	waitForCancellation bool
	called              chan struct{}
}

func (*protectedReasonCleanupRepositoryStub) Create(context.Context, string, string, string, []byte, []byte, time.Time) error {
	panic("unexpected create")
}

func (*protectedReasonCleanupRepositoryStub) CreateOrReplay(context.Context, adminstore.ProtectedReason) (adminstore.ProtectedReason, bool, error) {
	panic("unexpected create or replay")
}

func (*protectedReasonCleanupRepositoryStub) MarkTerminal(context.Context, string, time.Time, time.Time) error {
	panic("unexpected terminalization")
}

func (r *protectedReasonCleanupRepositoryStub) PurgeExpired(ctx context.Context, now time.Time, limit int) (int, error) {
	r.mu.Lock()
	r.calls++
	r.now = now
	r.limit = limit
	_, r.sawDeadline = ctx.Deadline()
	called := r.called
	wait := r.waitForCancellation
	purged, err := r.purged, r.err
	r.mu.Unlock()
	if called != nil {
		select {
		case called <- struct{}{}:
		default:
		}
	}
	if wait {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return purged, err
}

func (r *protectedReasonCleanupRepositoryStub) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}
