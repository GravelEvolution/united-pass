package registration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingMailResolver struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int64
	active  atomic.Int64
	peak    atomic.Int64
}

func newBlockingMailResolver(capacity int) *blockingMailResolver {
	return &blockingMailResolver{started: make(chan struct{}, capacity), release: make(chan struct{})}
}

func (r *blockingMailResolver) LookupMX(ctx context.Context, _ string) ([]*net.MX, error) {
	r.calls.Add(1)
	current := r.active.Add(1)
	for {
		peak := r.peak.Load()
		if current <= peak || r.peak.CompareAndSwap(peak, current) {
			break
		}
	}
	r.started <- struct{}{}
	select {
	case <-r.release:
		r.active.Add(-1)
		return []*net.MX{{Host: "mx.accepted.example.", Pref: 10}}, nil
	case <-ctx.Done():
		r.active.Add(-1)
		return nil, ctx.Err()
	}
}

func (*blockingMailResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, errors.New("unexpected address fallback")
}

func TestEmailDeliveryCoalescesConcurrentColdMissesForOneDomain(t *testing.T) {
	const workers = 32
	resolver := newBlockingMailResolver(workers)
	validator := newEmailDeliveryValidator(resolver, 2*time.Second, time.Minute)
	errorsOut := make(chan error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsOut <- validator.Validate(t.Context(), fmt.Sprintf("person-%d@one-domain.example", index))
		}()
	}
	select {
	case <-resolver.started:
	case <-time.After(time.Second):
		t.Fatal("resolver did not start")
	}
	time.Sleep(25 * time.Millisecond)
	if calls := resolver.calls.Load(); calls != 1 {
		t.Fatalf("same-domain resolver calls = %d, want 1", calls)
	}
	close(resolver.release)
	wait.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatalf("validation error = %v", err)
		}
	}
}

func TestEmailDeliveryBoundsUniqueDomainLookupsAndRecovers(t *testing.T) {
	const workers = maxEmailLookupsInFlight + maxEmailLookupsQueued
	resolver := newBlockingMailResolver(workers + 1)
	validator := newEmailDeliveryValidator(resolver, 2*time.Second, time.Minute)
	errorsOut := make(chan error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsOut <- validator.Validate(t.Context(), fmt.Sprintf("person@domain-%d.example", index))
		}()
	}
	deadline := time.After(time.Second)
	started := 0
	for started < maxEmailLookupsInFlight {
		select {
		case <-resolver.started:
			started++
		case <-deadline:
			t.Fatalf("resolver starts = %d, want %d", started, maxEmailLookupsInFlight)
		}
	}
	time.Sleep(25 * time.Millisecond)
	if peak := resolver.peak.Load(); peak > maxEmailLookupsInFlight {
		t.Fatalf("unique-domain resolver peak = %d, max = %d", peak, maxEmailLookupsInFlight)
	}
	close(resolver.release)
	wait.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatalf("validation error = %v", err)
		}
	}
	if err := validator.Validate(t.Context(), "person@after-pressure.example"); err != nil {
		t.Fatalf("post-pressure validation = %v", err)
	}
	if active := resolver.active.Load(); active != 0 {
		t.Fatalf("resolver active after recovery = %d", active)
	}
}
