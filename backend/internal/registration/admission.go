package registration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrAdmissionBusy = errors.New("registration: admission queue busy")

const (
	maxAdmissionInFlight     = 4096
	maxAdmissionTotalSlots   = 65536
	maxAdmissionPerDomain    = 1024
	maxAdmissionWaitDuration = 10 * time.Second
)

// AdmissionConfig bounds the process-local work admitted to the expensive
// registration path. Redis remains authoritative for distributed abuse
// budgets; this controller protects one API process from DNS/provider fan-out.
type AdmissionConfig struct {
	MaxInFlight           int
	MaxQueued             int
	WaitTimeout           time.Duration
	UnfamiliarMaxInFlight int
	UnfamiliarMaxQueued   int
	UnfamiliarPerDomain   int
}

// AdmissionController reserves capacity for established mailbox providers and
// serializes work for an unfamiliar exact domain. Every queue is bounded.
type AdmissionController struct {
	global          chan struct{}
	totalSlots      chan struct{}
	unfamiliar      chan struct{}
	unfamiliarSlots chan struct{}
	perDomain       int
	waitTimeout     time.Duration

	mu    sync.Mutex
	lanes map[string]*admissionLane
}

type admissionLane struct {
	semaphore  chan struct{}
	references int
}

func NewAdmissionController(cfg AdmissionConfig) (*AdmissionController, error) {
	if cfg.MaxInFlight <= 0 || cfg.MaxQueued < 0 || cfg.WaitTimeout <= 0 ||
		cfg.UnfamiliarMaxInFlight <= 0 || cfg.UnfamiliarMaxQueued < 0 ||
		cfg.UnfamiliarPerDomain <= 0 || cfg.UnfamiliarMaxInFlight > cfg.MaxInFlight ||
		cfg.UnfamiliarPerDomain > cfg.UnfamiliarMaxInFlight ||
		cfg.MaxInFlight > maxAdmissionInFlight || cfg.UnfamiliarMaxInFlight > maxAdmissionInFlight ||
		cfg.UnfamiliarPerDomain > maxAdmissionPerDomain || cfg.WaitTimeout > maxAdmissionWaitDuration {
		return nil, fmt.Errorf("%w: invalid admission configuration", ErrUnavailable)
	}
	// Convert only after sign checks. uint64 addition cannot overflow for Go's
	// int range and avoids the MaxInFlight+MaxQueued wrap that would otherwise
	// reach make(chan, negative) and panic during startup.
	if uint64(cfg.MaxInFlight)+uint64(cfg.MaxQueued) > maxAdmissionTotalSlots ||
		uint64(cfg.UnfamiliarMaxInFlight)+uint64(cfg.UnfamiliarMaxQueued) > maxAdmissionTotalSlots {
		return nil, fmt.Errorf("%w: invalid admission configuration", ErrUnavailable)
	}
	return &AdmissionController{
		global:          make(chan struct{}, cfg.MaxInFlight),
		totalSlots:      make(chan struct{}, cfg.MaxInFlight+cfg.MaxQueued),
		unfamiliar:      make(chan struct{}, cfg.UnfamiliarMaxInFlight),
		unfamiliarSlots: make(chan struct{}, cfg.UnfamiliarMaxInFlight+cfg.UnfamiliarMaxQueued),
		perDomain:       cfg.UnfamiliarPerDomain,
		waitTimeout:     cfg.WaitTimeout,
		lanes:           make(map[string]*admissionLane),
	}, nil
}

// Acquire enters the bounded registration work queue. The returned release
// function is idempotent and must be deferred by the caller.
func (a *AdmissionController) Acquire(ctx context.Context, domain string, unfamiliar bool) (func(), error) {
	if a == nil || domain == "" || len(domain) > 253 {
		return nil, ErrUnavailable
	}
	if !tryReserve(a.totalSlots) {
		return nil, ErrAdmissionBusy
	}
	totalReserved := true
	unfamiliarReserved := false
	if unfamiliar {
		if !tryReserve(a.unfamiliarSlots) {
			<-a.totalSlots
			return nil, ErrAdmissionBusy
		}
		unfamiliarReserved = true
	}

	waitCtx, cancel := context.WithTimeout(ctx, a.waitTimeout)
	defer cancel()
	var (
		unfamiliarHeld bool
		lane           *admissionLane
		laneHeld       bool
		globalHeld     bool
	)
	cleanup := func() {
		if globalHeld {
			<-a.global
			globalHeld = false
		}
		if laneHeld {
			<-lane.semaphore
			laneHeld = false
		}
		if lane != nil {
			a.releaseLane(domain, lane)
			lane = nil
		}
		if unfamiliarHeld {
			<-a.unfamiliar
			unfamiliarHeld = false
		}
		if unfamiliarReserved {
			<-a.unfamiliarSlots
			unfamiliarReserved = false
		}
		if totalReserved {
			<-a.totalSlots
			totalReserved = false
		}
	}

	if unfamiliar {
		lane = a.retainLane(domain)
		if !acquireWithin(waitCtx, lane.semaphore) {
			cleanup()
			return nil, ErrAdmissionBusy
		}
		laneHeld = true
		if !acquireWithin(waitCtx, a.unfamiliar) {
			cleanup()
			return nil, ErrAdmissionBusy
		}
		unfamiliarHeld = true
	}
	if !acquireWithin(waitCtx, a.global) {
		cleanup()
		return nil, ErrAdmissionBusy
	}
	globalHeld = true

	var once sync.Once
	return func() { once.Do(cleanup) }, nil
}

func tryReserve(semaphore chan struct{}) bool {
	select {
	case semaphore <- struct{}{}:
		return true
	default:
		return false
	}
}

func acquireWithin(ctx context.Context, semaphore chan struct{}) bool {
	select {
	case semaphore <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (a *AdmissionController) retainLane(domain string) *admissionLane {
	a.mu.Lock()
	defer a.mu.Unlock()
	lane := a.lanes[domain]
	if lane == nil {
		lane = &admissionLane{semaphore: make(chan struct{}, a.perDomain)}
		a.lanes[domain] = lane
	}
	lane.references++
	return lane
}

func (a *AdmissionController) releaseLane(domain string, lane *admissionLane) {
	a.mu.Lock()
	defer a.mu.Unlock()
	current := a.lanes[domain]
	if current != lane {
		return
	}
	lane.references--
	if lane.references == 0 {
		delete(a.lanes, domain)
	}
}
