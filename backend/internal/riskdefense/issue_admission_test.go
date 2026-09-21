package riskdefense

import (
	"context"
	"testing"
	"time"
)

func TestIssueAdmissionBoundsWaitersAndRecovers(t *testing.T) {
	gate, err := newIssueAdmission(1, 1, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	release, ok := gate.acquire(t.Context())
	if !ok {
		t.Fatal("first acquire was rejected")
	}
	waiting := make(chan bool, 1)
	go func() {
		secondRelease, acquired := gate.acquire(context.Background())
		if acquired {
			secondRelease()
		}
		waiting <- acquired
	}()
	time.Sleep(5 * time.Millisecond)
	if _, acquired := gate.acquire(t.Context()); acquired {
		t.Fatal("request beyond the bounded waiter set was admitted")
	}
	if acquired := <-waiting; acquired {
		t.Fatal("queued request should time out while the active slot is held")
	}
	release()
	release()
	recovered, ok := gate.acquire(t.Context())
	if !ok {
		t.Fatal("gate did not recover after release")
	}
	recovered()
}

func TestIssueAdmissionRejectsOversizedConfiguration(t *testing.T) {
	for _, tc := range []struct {
		active int
		queued int
	}{
		{0, 0}, {maxIssueAdmissionInFlight + 1, 0}, {1, maxIssueAdmissionSlots}, {1, -1},
	} {
		if _, err := newIssueAdmission(tc.active, tc.queued, time.Second); err == nil {
			t.Fatalf("newIssueAdmission(%d, %d) unexpectedly succeeded", tc.active, tc.queued)
		}
	}
}
