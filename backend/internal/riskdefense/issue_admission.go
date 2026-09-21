package riskdefense

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	maxIssueAdmissionInFlight = 128
	maxIssueAdmissionSlots    = 4096
)

// issueAdmission bounds only InteractiveVerifier.Begin. It deliberately does
// not cover the later DNS/account provisioning path, which has its own queue.
// The total-slots channel makes both the running set and waiter set finite.
type issueAdmission struct {
	active      chan struct{}
	total       chan struct{}
	waitTimeout time.Duration
}

func newIssueAdmission(maxInFlight, maxQueued int, waitTimeout time.Duration) (*issueAdmission, error) {
	if maxInFlight <= 0 || maxInFlight > maxIssueAdmissionInFlight || maxQueued < 0 ||
		uint64(maxInFlight)+uint64(maxQueued) > maxIssueAdmissionSlots || waitTimeout <= 0 || waitTimeout > 10*time.Second {
		return nil, errors.New("risk defense: invalid registration issue admission")
	}
	return &issueAdmission{
		active:      make(chan struct{}, maxInFlight),
		total:       make(chan struct{}, maxInFlight+maxQueued),
		waitTimeout: waitTimeout,
	}, nil
}

func (a *issueAdmission) acquire(ctx context.Context) (func(), bool) {
	if a == nil {
		return nil, false
	}
	select {
	case a.total <- struct{}{}:
	default:
		return nil, false
	}
	waitCtx, cancel := context.WithTimeout(ctx, a.waitTimeout)
	defer cancel()
	select {
	case a.active <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-a.active
				<-a.total
			})
		}, true
	case <-waitCtx.Done():
		<-a.total
		return nil, false
	}
}
