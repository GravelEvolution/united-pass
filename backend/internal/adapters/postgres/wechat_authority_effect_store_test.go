package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestDeriveWeChatAuthorityReplayDigestIsDeterministicAndRevisionBound(t *testing.T) {
	material := WeChatAuthorityReplayMaterial{
		Flow:             WeChatAuthorityFlowExisting,
		TenantID:         "tenant-production-like",
		Subject:          "openid-production-like",
		TargetUserID:     "usr_wechat_effect_test",
		AuthorityVersion: 7,
		SecurityEpoch:    3,
	}

	first, err := DeriveWeChatAuthorityReplayDigest(material)
	if err != nil {
		t.Fatalf("derive first digest: %v", err)
	}
	second, err := DeriveWeChatAuthorityReplayDigest(material)
	if err != nil {
		t.Fatalf("derive replay digest: %v", err)
	}
	if first != second {
		t.Fatal("same replay material produced different digests")
	}

	material.AuthorityVersion++
	differentRevision, err := DeriveWeChatAuthorityReplayDigest(material)
	if err != nil {
		t.Fatalf("derive changed-revision digest: %v", err)
	}
	if first == differentRevision {
		t.Fatal("authority revision was not bound into replay digest")
	}

	material.AuthorityVersion--
	material.Flow = WeChatAuthorityFlowPending
	material.AuthorityVersion = 0
	material.SecurityEpoch = 0
	differentFlow, err := DeriveWeChatAuthorityReplayDigest(material)
	if err != nil {
		t.Fatalf("derive changed-flow digest: %v", err)
	}
	if first == differentFlow {
		t.Fatal("authority flow was not domain-separated in replay digest")
	}
	material.AuthorityVersion = 1
	if _, err := DeriveWeChatAuthorityReplayDigest(material); !errors.Is(err, ErrWeChatAuthorityEffectInvalid) {
		t.Fatalf("pending non-zero revision error = %v, want invalid effect", err)
	}

	material.Flow = WeChatAuthorityFlowPendingPhoneVerified
	material.AuthorityVersion = 7
	material.SecurityEpoch = 3
	pendingPhone, err := DeriveWeChatAuthorityReplayDigest(material)
	if err != nil {
		t.Fatalf("derive pending-phone digest: %v", err)
	}
	if pendingPhone == first {
		t.Fatal("pending-phone flow was not domain-separated from existing-account flow")
	}
	material.AuthorityVersion++
	changedPendingPhone, err := DeriveWeChatAuthorityReplayDigest(material)
	if err != nil {
		t.Fatalf("derive changed pending-phone revision: %v", err)
	}
	if changedPendingPhone == pendingPhone {
		t.Fatal("pending-phone digest was not bound to the pre-write authority revision")
	}
	material.SecurityEpoch = 0
	if _, err := DeriveWeChatAuthorityReplayDigest(material); !errors.Is(err, ErrWeChatAuthorityEffectInvalid) {
		t.Fatalf("pending-phone zero revision error = %v, want invalid effect", err)
	}
}

func TestWeChatAuthorityEffectStoreRecordTxAppendsAuditAndIntentWithoutPII(t *testing.T) {
	const (
		rawTenant   = "tenant-secret-do-not-persist"
		rawSubject  = "openid-secret-do-not-persist"
		rawPhone    = "+8613800138000"
		rawPassword = "correct-horse-battery-staple"
		rawSession  = "session-secret-do-not-persist"
	)
	digest, err := DeriveWeChatAuthorityReplayDigest(WeChatAuthorityReplayMaterial{
		Flow:             WeChatAuthorityFlowExisting,
		TenantID:         rawTenant,
		Subject:          rawSubject,
		TargetUserID:     "usr_wechat_effect_existing",
		AuthorityVersion: 11,
		SecurityEpoch:    4,
	})
	if err != nil {
		t.Fatalf("derive replay digest: %v", err)
	}
	effect := WeChatAuthorityEffect{
		ReplayDigest: digest,
		Kind:         WeChatAuthorityEffectExistingLinkPhone,
		TargetUserID: "usr_wechat_effect_existing",
		OccurredAt:   time.Date(2026, 8, 28, 3, 0, 0, 0, time.UTC),
	}
	tx := newWeChatAuthorityFakeTx()

	receipt, err := NewWeChatAuthorityEffectStore().RecordTx(context.Background(), tx, effect)
	if err != nil {
		t.Fatalf("record authority effect: %v", err)
	}
	if receipt.Replayed || receipt.ForwardRepaired {
		t.Fatalf("first write has unexpected replay flags: %+v", receipt)
	}
	if len(tx.events) != 2 {
		t.Fatalf("expected one audit and one pending event, got %d", len(tx.events))
	}
	if got := tx.events[receipt.AuditEventID].EventType; got != string(effect.Kind) {
		t.Fatalf("audit event type = %q, want %q", got, effect.Kind)
	}
	if got := tx.events[receipt.PendingEventID].EventType; got != wechatNotificationPendingEvent {
		t.Fatalf("pending event type = %q", got)
	}
	for _, event := range tx.events {
		if event.TargetUserID != effect.TargetUserID {
			t.Fatalf("event target = %q, want %q", event.TargetUserID, effect.TargetUserID)
		}
		if event.Fingerprint != receipt.Fingerprint || event.NotificationID != receipt.NotificationID {
			t.Fatalf("event durable identifiers do not match receipt: %+v", event)
		}
	}

	// Scan the exact SQL arguments, including the decoded JSONB payload. The
	// effect API cannot accept phone/password/session values, and neither the
	// raw provider tenant nor raw provider subject may escape digest derivation.
	persisted := strings.Join(tx.persistedRepresentations, "\n")
	for _, forbidden := range []string{rawTenant, rawSubject, rawPhone, rawPassword, rawSession} {
		if strings.Contains(persisted, forbidden) {
			t.Fatalf("persisted event arguments contain forbidden value %q", forbidden)
		}
	}
}

func TestWeChatAuthorityEffectStoreExactReplayAndForwardRepair(t *testing.T) {
	effect := testWeChatAuthorityEffect(t, WeChatAuthorityEffectPendingReserved, "usr_wechat_effect_pending")
	tx := newWeChatAuthorityFakeTx()
	store := NewWeChatAuthorityEffectStore()

	first, err := store.RecordTx(context.Background(), tx, effect)
	if err != nil {
		t.Fatalf("record first effect: %v", err)
	}
	effect.OccurredAt = effect.OccurredAt.Add(15 * time.Minute)
	replay, err := store.RecordTx(context.Background(), tx, effect)
	if err != nil {
		t.Fatalf("record exact replay: %v", err)
	}
	if !replay.Replayed || replay.ForwardRepaired {
		t.Fatalf("exact replay flags = %+v", replay)
	}
	if replay.OperationID != first.OperationID || len(tx.events) != 2 {
		t.Fatalf("exact replay was not idempotent: first=%+v replay=%+v rows=%d", first, replay, len(tx.events))
	}

	delete(tx.events, first.PendingEventID)
	repaired, err := store.RecordTx(context.Background(), tx, effect)
	if err != nil {
		t.Fatalf("forward repair pending event: %v", err)
	}
	if repaired.Replayed || !repaired.ForwardRepaired || len(tx.events) != 2 {
		t.Fatalf("forward repair flags/rows = %+v/%d", repaired, len(tx.events))
	}
	if tx.events[first.AuditEventID].ActorUserID != "" || tx.events[first.PendingEventID].ActorUserID != "" {
		t.Fatal("pending reservation must not claim that the not-yet-active target was an authenticated actor")
	}
}

func TestWeChatAuthorityEffectStorePendingPhoneEffectIsIndependentFromReservationReplay(t *testing.T) {
	store := NewWeChatAuthorityEffectStore()
	tx := newWeChatAuthorityFakeTx()
	target := identity.UserID("usr_wechat_pending_phone")
	reservation := testWeChatAuthorityEffect(t, WeChatAuthorityEffectPendingReserved, target)
	phone := testWeChatAuthorityEffect(t, WeChatAuthorityEffectPendingPhoneVerified, target)

	reserved, err := store.RecordTx(context.Background(), tx, reservation)
	if err != nil {
		t.Fatalf("record pending reservation: %v", err)
	}
	reservationReplay, err := store.RecordTx(context.Background(), tx, reservation)
	if err != nil || !reservationReplay.Replayed {
		t.Fatalf("replay pending reservation: receipt=%+v err=%v", reservationReplay, err)
	}
	phoneReceipt, err := store.RecordTx(context.Background(), tx, phone)
	if err != nil {
		t.Fatalf("record pending phone verification: %v", err)
	}
	if phoneReceipt.Replayed || phoneReceipt.OperationID == reserved.OperationID || len(tx.events) != 4 {
		t.Fatalf("pending phone effect was swallowed by reservation replay: reserved=%+v phone=%+v rows=%d", reserved, phoneReceipt, len(tx.events))
	}
	if audit := tx.events[phoneReceipt.AuditEventID]; audit.EventType != string(WeChatAuthorityEffectPendingPhoneVerified) || audit.ActorUserID != "" {
		t.Fatalf("pending phone audit=%+v", audit)
	}
	if pending := tx.events[phoneReceipt.PendingEventID]; pending.EffectKind != WeChatAuthorityEffectPendingPhoneVerified || pending.ActorUserID != "" {
		t.Fatalf("pending phone notification=%+v", pending)
	}

	phoneReplay, err := store.RecordTx(context.Background(), tx, phone)
	if err != nil || !phoneReplay.Replayed || phoneReplay.OperationID != phoneReceipt.OperationID || len(tx.events) != 4 {
		t.Fatalf("pending phone replay was not idempotent: receipt=%+v err=%v rows=%d", phoneReplay, err, len(tx.events))
	}
	for _, forbidden := range []string{"tenant-test", "openid-test", "+8613800138000"} {
		if strings.Contains(strings.Join(tx.persistedRepresentations, "\n"), forbidden) {
			t.Fatalf("pending phone events contain forbidden value %q", forbidden)
		}
	}
}

func TestWeChatAuthorityEffectStoreRejectsConflictingReplay(t *testing.T) {
	effect := testWeChatAuthorityEffect(t, WeChatAuthorityEffectExistingLink, "usr_wechat_effect_conflict")
	tx := newWeChatAuthorityFakeTx()
	store := NewWeChatAuthorityEffectStore()
	receipt, err := store.RecordTx(context.Background(), tx, effect)
	if err != nil {
		t.Fatalf("record first effect: %v", err)
	}

	conflicting := tx.events[receipt.AuditEventID]
	conflicting.Fingerprint = strings.Repeat("0", 64)
	tx.events[receipt.AuditEventID] = conflicting
	_, err = store.RecordTx(context.Background(), tx, effect)
	if !errors.Is(err, ErrWeChatAuthorityEffectReplayConflict) {
		t.Fatalf("conflicting replay error = %v, want %v", err, ErrWeChatAuthorityEffectReplayConflict)
	}
}

func TestWeChatAuthorityEffectStorePropagatesSecondAppendFailure(t *testing.T) {
	effect := testWeChatAuthorityEffect(t, WeChatAuthorityEffectExistingPhone, "usr_wechat_effect_rollback")
	tx := newWeChatAuthorityFakeTx()
	tx.failExecAt = 2
	_, err := NewWeChatAuthorityEffectStore().RecordTx(context.Background(), tx, effect)
	if err == nil {
		t.Fatal("second append failure was ignored")
	}
	// RecordTx deliberately cannot commit. A real caller transaction must be
	// rolled back on this error, atomically removing this first staged row and
	// the authority mutation that preceded it.
}

func TestValidWeChatNotificationIntentRejectsForgedDurableFacts(t *testing.T) {
	effect := testWeChatAuthorityEffect(t, WeChatAuthorityEffectPendingPhoneVerified, "usr_wechat_intent_validation")
	receipt := deriveWeChatAuthorityEffectReceipt(effect)
	intent := WeChatNotificationIntent{
		PendingEventID: receipt.PendingEventID,
		OperationID:    receipt.OperationID,
		RequestID:      receipt.RequestID,
		NotificationID: receipt.NotificationID,
		Fingerprint:    receipt.Fingerprint,
		EffectKind:     effect.Kind,
		TargetUserID:   effect.TargetUserID,
		OccurredAt:     effect.OccurredAt,
	}
	if !validWeChatNotificationIntent(intent) {
		t.Fatal("derived intent was rejected")
	}
	intent.Fingerprint = strings.Repeat("f", 64)
	if validWeChatNotificationIntent(intent) {
		t.Fatal("forged fingerprint was accepted")
	}
}

func testWeChatAuthorityEffect(t *testing.T, kind WeChatAuthorityEffectKind, target identity.UserID) WeChatAuthorityEffect {
	t.Helper()
	flow := WeChatAuthorityFlowExisting
	version := int64(2)
	epoch := int64(1)
	switch kind {
	case WeChatAuthorityEffectPendingReserved:
		flow = WeChatAuthorityFlowPending
		version = 0
		epoch = 0
	case WeChatAuthorityEffectPendingPhoneVerified:
		flow = WeChatAuthorityFlowPendingPhoneVerified
	}
	digest, err := DeriveWeChatAuthorityReplayDigest(WeChatAuthorityReplayMaterial{
		Flow: flow, TenantID: "tenant-test", Subject: "openid-test", TargetUserID: target,
		AuthorityVersion: version, SecurityEpoch: epoch,
	})
	if err != nil {
		t.Fatalf("derive test replay digest: %v", err)
	}
	return WeChatAuthorityEffect{
		ReplayDigest: digest, Kind: kind, TargetUserID: target,
		OccurredAt: time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC),
	}
}

type weChatAuthorityFakeTx struct {
	events                   map[string]durableWeChatAuthorityEvent
	persistedRepresentations []string
	execCalls                int
	failExecAt               int
}

func newWeChatAuthorityFakeTx() *weChatAuthorityFakeTx {
	return &weChatAuthorityFakeTx{events: make(map[string]durableWeChatAuthorityEvent)}
}

func (f *weChatAuthorityFakeTx) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	f.execCalls++
	if f.execCalls == f.failExecAt {
		return pgconn.CommandTag{}, errors.New("injected append failure")
	}
	if len(args) != 9 {
		return pgconn.CommandTag{}, fmt.Errorf("fake tx: got %d insert args, want 9", len(args))
	}
	for _, arg := range args {
		if raw, ok := arg.([]byte); ok {
			f.persistedRepresentations = append(f.persistedRepresentations, string(raw))
			continue
		}
		f.persistedRepresentations = append(f.persistedRepresentations, fmt.Sprint(arg))
	}

	eventID, ok := args[0].(string)
	if !ok {
		return pgconn.CommandTag{}, fmt.Errorf("fake tx: event id has type %T", args[0])
	}
	if _, exists := f.events[eventID]; exists {
		return pgconn.NewCommandTag("INSERT 0 0"), nil
	}
	payload := make(map[string]string)
	if err := json.Unmarshal(args[6].([]byte), &payload); err != nil {
		return pgconn.CommandTag{}, err
	}
	event := durableWeChatAuthorityEvent{
		EventID:        eventID,
		EventType:      args[1].(string),
		ActorUserID:    identity.UserID(args[2].(string)),
		RequestID:      args[3].(string),
		OperationID:    args[4].(string),
		Result:         args[5].(string),
		OccurredAt:     args[7].(time.Time),
		TargetUserID:   identity.UserID(args[8].(string)),
		Fingerprint:    payload["operation_fingerprint"],
		EffectKind:     WeChatAuthorityEffectKind(payload["effect_kind"]),
		NotificationID: payload["notification_id"],
		FailureClass:   payload["failure_class"],
	}
	f.events[eventID] = event
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (f *weChatAuthorityFakeTx) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	if len(args) != 1 {
		return &fakeRow{err: fmt.Errorf("fake tx: got %d select args, want 1", len(args))}
	}
	event, ok := f.events[args[0].(string)]
	if !ok {
		return &fakeRow{err: pgx.ErrNoRows}
	}
	return &fakeRow{values: []any{
		event.EventType, event.ActorUserID, event.RequestID, event.OperationID,
		event.Result, "user_id", event.TargetUserID, event.Fingerprint,
		event.EffectKind, event.NotificationID, event.FailureClass,
	}}
}
