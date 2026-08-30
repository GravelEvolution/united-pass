package postgres

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestWeChatNotificationWorkerContinuesBatchAndLeavesBusyOrNotReadyOpen(t *testing.T) {
	intents := []WeChatNotificationIntent{
		testWorkerNotificationIntent("busy"),
		testWorkerNotificationIntent("waiting"),
		testWorkerNotificationIntent("failed"),
		testWorkerNotificationIntent("delivered"),
	}
	dispatchFailure := errors.New("temporary transport outage")
	store := &fakeWeChatNotificationDispatcher{
		intents: intents,
		errors: map[string]error{
			intents[0].NotificationID: ErrWeChatNotificationBusy,
			intents[1].NotificationID: ErrWeChatNotificationNotReady,
			intents[2].NotificationID: dispatchFailure,
		},
	}
	worker := &WeChatNotificationWorker{
		store: store, sender: fakeWeChatNotificationSender{},
		now: func() time.Time { return time.Date(2026, 8, 28, 5, 0, 0, 0, time.UTC) },
	}

	attempted, err := worker.RunOnce(context.Background(), 20)
	if attempted != 2 {
		t.Fatalf("attempted = %d, want 2 terminal/error attempts", attempted)
	}
	if !errors.Is(err, dispatchFailure) {
		t.Fatalf("worker error = %v, want wrapped dispatch error", err)
	}
	if len(store.dispatched) != len(intents) {
		t.Fatalf("worker stopped early: dispatched %d of %d", len(store.dispatched), len(intents))
	}
}

func TestWeChatNotificationWorkerRejectsUnsafeBounds(t *testing.T) {
	worker := &WeChatNotificationWorker{
		store: &fakeWeChatNotificationDispatcher{}, sender: fakeWeChatNotificationSender{},
		now: time.Now,
	}
	for _, limit := range []int{0, 201} {
		if _, err := worker.RunOnce(context.Background(), limit); !errors.Is(err, ErrWeChatAuthorityEffectInvalid) {
			t.Fatalf("limit %d error = %v, want invalid effect", limit, err)
		}
	}
}

func TestWeChatNotificationWorkerReportsFailureWithoutSensitiveDetails(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	store := &fakeWeChatNotificationDispatcher{
		listErr: errors.New("smtp recipient alice@example.test credential=secret-token"),
	}
	worker := &WeChatNotificationWorker{
		store: store, sender: fakeWeChatNotificationSender{}, logger: logger,
		now: time.Now, batch: 20,
	}
	worker.runOnceAndLog(context.Background())
	output := logs.String()
	if !strings.Contains(output, "delivery_or_store_failure") {
		t.Fatalf("missing bounded error class: %s", output)
	}
	for _, secret := range []string{"alice@example.test", "secret-token", "smtp recipient"} {
		if strings.Contains(output, secret) {
			t.Fatalf("worker log leaked %q: %s", secret, output)
		}
	}
}

func testWorkerNotificationIntent(seed string) WeChatNotificationIntent {
	target := identityUserIDForWorker(seed)
	digest, _ := DeriveWeChatAuthorityReplayDigest(WeChatAuthorityReplayMaterial{
		Flow: WeChatAuthorityFlowExisting, TenantID: "tenant", Subject: "subject-" + seed,
		TargetUserID: target, AuthorityVersion: 1, SecurityEpoch: 0,
	})
	effect := WeChatAuthorityEffect{
		ReplayDigest: digest, Kind: WeChatAuthorityEffectExistingLink,
		TargetUserID: target, OccurredAt: time.Date(2026, 8, 28, 5, 0, 0, 0, time.UTC),
	}
	receipt := deriveWeChatAuthorityEffectReceipt(effect)
	return WeChatNotificationIntent{
		PendingEventID: receipt.PendingEventID, OperationID: receipt.OperationID,
		RequestID: receipt.RequestID, NotificationID: receipt.NotificationID,
		Fingerprint: receipt.Fingerprint, EffectKind: effect.Kind,
		TargetUserID: effect.TargetUserID, OccurredAt: effect.OccurredAt,
	}
}

func identityUserIDForWorker(seed string) identity.UserID {
	return identity.UserID("usr_worker_" + seed)
}

type fakeWeChatNotificationDispatcher struct {
	intents    []WeChatNotificationIntent
	errors     map[string]error
	dispatched []string
	listErr    error
}

func (f *fakeWeChatNotificationDispatcher) ListPending(context.Context, int) ([]WeChatNotificationIntent, error) {
	return f.intents, f.listErr
}

func (f *fakeWeChatNotificationDispatcher) Dispatch(_ context.Context, intent WeChatNotificationIntent, _ WeChatNotificationSender, _ time.Time) error {
	f.dispatched = append(f.dispatched, intent.NotificationID)
	return f.errors[intent.NotificationID]
}

type fakeWeChatNotificationSender struct{}

func (fakeWeChatNotificationSender) Send(context.Context, WeChatNotificationDelivery) error {
	return nil
}
