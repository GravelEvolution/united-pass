package registration

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testAdmissionController(t *testing.T, cfg AdmissionConfig) *AdmissionController {
	t.Helper()
	controller, err := NewAdmissionController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func TestAdmissionQueueIsBoundedAndRecovers(t *testing.T) {
	controller := testAdmissionController(t, AdmissionConfig{
		MaxInFlight: 1, MaxQueued: 1, WaitTimeout: 25 * time.Millisecond,
		UnfamiliarMaxInFlight: 1, UnfamiliarMaxQueued: 1, UnfamiliarPerDomain: 1,
	})
	release, err := controller.Acquire(t.Context(), "example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	waiting := make(chan error, 1)
	go func() {
		_, acquireErr := controller.Acquire(context.Background(), "example.net", false)
		waiting <- acquireErr
	}()
	time.Sleep(5 * time.Millisecond)
	if _, err := controller.Acquire(t.Context(), "example.org", false); !errors.Is(err, ErrAdmissionBusy) {
		t.Fatalf("third admission error = %v, want busy", err)
	}
	if err := <-waiting; !errors.Is(err, ErrAdmissionBusy) {
		t.Fatalf("queued timeout error = %v, want busy", err)
	}
	release()
	if recovered, err := controller.Acquire(t.Context(), "example.org", false); err != nil {
		t.Fatalf("queue did not recover: %v", err)
	} else {
		recovered()
	}
}

func TestAdmissionReservesCapacityFromUnfamiliarFlood(t *testing.T) {
	controller := testAdmissionController(t, AdmissionConfig{
		MaxInFlight: 2, MaxQueued: 2, WaitTimeout: 20 * time.Millisecond,
		UnfamiliarMaxInFlight: 1, UnfamiliarMaxQueued: 0, UnfamiliarPerDomain: 1,
	})
	releaseRare, err := controller.Acquire(t.Context(), "rare.invalid", true)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRare()
	if _, err := controller.Acquire(t.Context(), "rotated.invalid", true); !errors.Is(err, ErrAdmissionBusy) {
		t.Fatalf("second unfamiliar admission error = %v, want busy", err)
	}
	releaseEstablished, err := controller.Acquire(t.Context(), "gmail.com", false)
	if err != nil {
		t.Fatalf("unfamiliar traffic consumed reserved established capacity: %v", err)
	}
	releaseEstablished()
}

func TestAdmissionSerializesOneUnfamiliarDomainAndReleaseIsIdempotent(t *testing.T) {
	controller := testAdmissionController(t, AdmissionConfig{
		MaxInFlight: 3, MaxQueued: 3, WaitTimeout: 20 * time.Millisecond,
		UnfamiliarMaxInFlight: 3, UnfamiliarMaxQueued: 1, UnfamiliarPerDomain: 1,
	})
	release, err := controller.Acquire(t.Context(), "rare.invalid", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Acquire(t.Context(), "rare.invalid", true); !errors.Is(err, ErrAdmissionBusy) {
		t.Fatalf("same-domain concurrent admission error = %v, want busy", err)
	}
	release()
	release()
	second, err := controller.Acquire(t.Context(), "rare.invalid", true)
	if err != nil {
		t.Fatalf("same-domain lane did not recover: %v", err)
	}
	second()
}

func TestSameDomainWaiterDoesNotConsumeAnotherDomainsInFlightCapacity(t *testing.T) {
	controller := testAdmissionController(t, AdmissionConfig{
		MaxInFlight: 3, MaxQueued: 4, WaitTimeout: 80 * time.Millisecond,
		UnfamiliarMaxInFlight: 2, UnfamiliarMaxQueued: 3, UnfamiliarPerDomain: 1,
	})
	releaseA, err := controller.Acquire(t.Context(), "domain-a.example", true)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseA()
	waiting := make(chan error, 1)
	go func() {
		release, acquireErr := controller.Acquire(context.Background(), "domain-a.example", true)
		if release != nil {
			release()
		}
		waiting <- acquireErr
	}()
	time.Sleep(10 * time.Millisecond)
	releaseB, err := controller.Acquire(t.Context(), "domain-b.example", true)
	if err != nil {
		t.Fatalf("same-domain waiter blocked independent domain: %v", err)
	}
	releaseB()
	if err := <-waiting; !errors.Is(err, ErrAdmissionBusy) {
		t.Fatalf("same-domain waiter error = %v, want busy timeout", err)
	}
}

func TestAdmissionRejectsInvalidConfiguration(t *testing.T) {
	_, err := NewAdmissionController(AdmissionConfig{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid config error = %v", err)
	}
}

func TestAdmissionRejectsOversizedConfigurationWithoutIntegerOverflow(t *testing.T) {
	valid := AdmissionConfig{
		MaxInFlight: 8, MaxQueued: 32, WaitTimeout: time.Second,
		UnfamiliarMaxInFlight: 2, UnfamiliarMaxQueued: 8, UnfamiliarPerDomain: 1,
	}
	maxInt := int(^uint(0) >> 1)
	tests := []struct {
		name   string
		mutate func(*AdmissionConfig)
	}{
		{name: "in flight", mutate: func(cfg *AdmissionConfig) { cfg.MaxInFlight = maxInt }},
		{name: "queued", mutate: func(cfg *AdmissionConfig) { cfg.MaxQueued = maxInt }},
		{name: "total slots", mutate: func(cfg *AdmissionConfig) {
			cfg.MaxInFlight = maxAdmissionInFlight
			cfg.MaxQueued = maxAdmissionTotalSlots
		}},
		{name: "unfamiliar total slots", mutate: func(cfg *AdmissionConfig) {
			cfg.UnfamiliarMaxInFlight = 2
			cfg.UnfamiliarMaxQueued = maxAdmissionTotalSlots
		}},
		{name: "per domain", mutate: func(cfg *AdmissionConfig) {
			cfg.MaxInFlight = maxAdmissionInFlight
			cfg.UnfamiliarMaxInFlight = maxAdmissionInFlight
			cfg.UnfamiliarPerDomain = maxAdmissionPerDomain + 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if _, err := NewAdmissionController(cfg); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("oversized config error = %v, want ErrUnavailable", err)
			}
		})
	}
}
