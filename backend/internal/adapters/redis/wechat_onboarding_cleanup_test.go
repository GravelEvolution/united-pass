package redis

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeWeChatOnboardingCleanupEntry struct {
	payload   weChatOnboardingCleanupPayload
	claimID   string
	completed bool
	retries   int
}

type fakeWeChatOnboardingCleanupQueue struct {
	mu      sync.Mutex
	entries map[string]*fakeWeChatOnboardingCleanupEntry
	listErr error
	lists   int
}

func (q *fakeWeChatOnboardingCleanupQueue) dueCleanupHashes(context.Context, int) ([]string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.lists++
	if q.listErr != nil {
		return nil, q.listErr
	}
	hashes := make([]string, 0, len(q.entries))
	for hash, entry := range q.entries {
		if !entry.completed {
			hashes = append(hashes, hash)
		}
	}
	return hashes, nil
}

func (q *fakeWeChatOnboardingCleanupQueue) claimCleanup(_ context.Context, hash, claimID string, _ time.Duration) (weChatOnboardingCleanupPayload, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entry := q.entries[hash]
	if entry == nil || entry.completed || entry.claimID != "" {
		return weChatOnboardingCleanupPayload{}, false, nil
	}
	entry.claimID = claimID
	return entry.payload, true, nil
}

func (q *fakeWeChatOnboardingCleanupQueue) completeCleanup(_ context.Context, hash, claimID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	entry := q.entries[hash]
	if entry == nil || entry.claimID != claimID {
		return nil
	}
	entry.completed = true
	entry.claimID = ""
	return nil
}

func (q *fakeWeChatOnboardingCleanupQueue) retryCleanup(_ context.Context, hash, claimID string, _ time.Duration) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	entry := q.entries[hash]
	if entry == nil || entry.claimID != claimID {
		return nil
	}
	entry.claimID = ""
	entry.retries++
	return nil
}

type fakeWeChatOnboardingRevoker struct {
	mu        sync.Mutex
	calls     []string
	failures  int
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
}

func (r *fakeWeChatOnboardingRevoker) RevokeProviderSession(ctx context.Context, providerSessionID string) error {
	r.mu.Lock()
	r.calls = append(r.calls, providerSessionID)
	shouldFail := r.failures > 0
	if shouldFail {
		r.failures--
	}
	r.mu.Unlock()
	if r.started != nil {
		r.startOnce.Do(func() { close(r.started) })
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if shouldFail {
		return errors.New("provider failure containing private-provider-session")
	}
	return nil
}

func (r *fakeWeChatOnboardingRevoker) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func newCleanupWorkerForTest(t *testing.T, queue weChatOnboardingCleanupQueue, revoker weChatOnboardingSessionRevoker) *WeChatOnboardingCleanupWorker {
	t.Helper()
	worker, err := newWeChatOnboardingCleanupWorker(queue, revoker, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	worker.interval = time.Hour
	worker.lease = time.Second
	worker.retryDelay = time.Millisecond
	worker.revokeTimeout = time.Second
	return worker
}

func TestWeChatOnboardingCleanupWorkerRevokesExpiredChallenge(t *testing.T) {
	hash := cleanupTestHash('a')
	queue := &fakeWeChatOnboardingCleanupQueue{entries: map[string]*fakeWeChatOnboardingCleanupEntry{
		hash: {payload: weChatOnboardingCleanupPayload{ProviderSessionID: "provider-session-expired"}},
	}}
	revoker := &fakeWeChatOnboardingRevoker{}
	worker := newCleanupWorkerForTest(t, queue, revoker)

	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := revoker.callCount(); got != 1 {
		t.Fatalf("revocation calls = %d, want 1", got)
	}
	queue.mu.Lock()
	completed := queue.entries[hash].completed
	queue.mu.Unlock()
	if !completed {
		t.Fatal("expired cleanup obligation was not completed")
	}
}

func TestWeChatOnboardingCleanupWorkerSuccessfulConsumeDoesNotRevoke(t *testing.T) {
	hash := cleanupTestHash('b')
	queue := &fakeWeChatOnboardingCleanupQueue{entries: map[string]*fakeWeChatOnboardingCleanupEntry{
		hash: {payload: weChatOnboardingCleanupPayload{ProviderSessionID: "provider-session-consumed"}, completed: true},
	}}
	revoker := &fakeWeChatOnboardingRevoker{}
	worker := newCleanupWorkerForTest(t, queue, revoker)

	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := revoker.callCount(); got != 0 {
		t.Fatalf("successful challenge consumption triggered %d revocations", got)
	}
}

func TestWeChatOnboardingCleanupWorkerHAClaimPreventsConcurrentRevocation(t *testing.T) {
	hash := cleanupTestHash('c')
	queue := &fakeWeChatOnboardingCleanupQueue{entries: map[string]*fakeWeChatOnboardingCleanupEntry{
		hash: {payload: weChatOnboardingCleanupPayload{ProviderSessionID: "provider-session-ha"}},
	}}
	revoker := &fakeWeChatOnboardingRevoker{started: make(chan struct{}), release: make(chan struct{})}
	workerA := newCleanupWorkerForTest(t, queue, revoker)
	workerB := newCleanupWorkerForTest(t, queue, revoker)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = workerA.RunOnce(context.Background())
	}()
	<-revoker.started
	go func() {
		defer wg.Done()
		_ = workerB.RunOnce(context.Background())
	}()
	close(revoker.release)
	wg.Wait()

	if got := revoker.callCount(); got != 1 {
		t.Fatalf("concurrent workers issued %d revocations, want 1", got)
	}
}

func TestWeChatOnboardingCleanupWorkerRetriesProviderFailure(t *testing.T) {
	hash := cleanupTestHash('d')
	queue := &fakeWeChatOnboardingCleanupQueue{entries: map[string]*fakeWeChatOnboardingCleanupEntry{
		hash: {payload: weChatOnboardingCleanupPayload{ProviderSessionID: "private-provider-session"}},
	}}
	revoker := &fakeWeChatOnboardingRevoker{failures: 1}
	worker := newCleanupWorkerForTest(t, queue, revoker)

	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	queue.mu.Lock()
	firstCompleted := queue.entries[hash].completed
	firstRetries := queue.entries[hash].retries
	queue.mu.Unlock()
	if firstCompleted || firstRetries != 1 {
		t.Fatalf("after failure completed=%v retries=%d, want false/1", firstCompleted, firstRetries)
	}
	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	queue.mu.Lock()
	completed := queue.entries[hash].completed
	queue.mu.Unlock()
	if !completed || revoker.callCount() != 2 {
		t.Fatalf("retry completed=%v calls=%d, want true/2", completed, revoker.callCount())
	}
}

func TestWeChatOnboardingCleanupWorkerStartStopIsIdempotent(t *testing.T) {
	queue := &fakeWeChatOnboardingCleanupQueue{entries: map[string]*fakeWeChatOnboardingCleanupEntry{}}
	revoker := &fakeWeChatOnboardingRevoker{}
	worker := newCleanupWorkerForTest(t, queue, revoker)
	worker.Stop()
	worker.Start()
	worker.Start()

	deadline := time.Now().Add(time.Second)
	for {
		queue.mu.Lock()
		lists := queue.lists
		queue.mu.Unlock()
		if lists > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not run its immediate pass")
		}
		time.Sleep(time.Millisecond)
	}

	var stopped atomic.Int32
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			worker.Stop()
			stopped.Add(1)
		}()
	}
	wg.Wait()
	if stopped.Load() != 2 {
		t.Fatalf("concurrent Stop completions = %d, want 2", stopped.Load())
	}

	queue.mu.Lock()
	listsBeforeRestart := queue.lists
	queue.mu.Unlock()
	worker.Start()
	deadline = time.Now().Add(time.Second)
	for {
		queue.mu.Lock()
		lists := queue.lists
		queue.mu.Unlock()
		if lists > listsBeforeRestart {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not restart after Stop")
		}
		time.Sleep(time.Millisecond)
	}
	worker.Stop()
}

func TestWeChatOnboardingCleanupWorkerDoesNotLogSensitiveFailureDetails(t *testing.T) {
	hash := cleanupTestHash('e')
	queue := &fakeWeChatOnboardingCleanupQueue{entries: map[string]*fakeWeChatOnboardingCleanupEntry{
		hash: {payload: weChatOnboardingCleanupPayload{ProviderSessionID: "private-provider-session"}},
	}}
	revoker := &fakeWeChatOnboardingRevoker{failures: 1}
	var output bytes.Buffer
	worker, err := newWeChatOnboardingCleanupWorker(queue, revoker, slog.New(slog.NewTextHandler(&output, nil)))
	if err != nil {
		t.Fatal(err)
	}
	worker.lease = time.Second
	worker.retryDelay = time.Millisecond
	worker.revokeTimeout = time.Second
	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	logged := output.String()
	for _, sensitive := range []string{"private-provider-session", "provider failure containing"} {
		if strings.Contains(logged, sensitive) {
			t.Fatalf("cleanup log leaked %q: %s", sensitive, logged)
		}
	}
}

func cleanupTestHash(fill byte) string {
	value := make([]byte, 64)
	for i := range value {
		value[i] = fill
	}
	return string(value)
}
