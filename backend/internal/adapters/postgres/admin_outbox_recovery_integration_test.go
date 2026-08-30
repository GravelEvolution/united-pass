//go:build integration

package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
)

func TestIntegration_AdminOutboxReclaimsExpiredReceiptClaimAndPersistsAuthoritativeOutcome(t *testing.T) {
	pool := setupTestPool(t, 5)
	uow := NewAdminUnitOfWork(pool.PgxPool(), nil)
	ctx := context.Background()
	base := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	key := "0123456789abcdef0123456789abcdef"
	created := adminstore.OutboxItem{
		ID: "aop_recovery_integration", Kind: adminstore.OperationCrossSystem, IdempotencyKey: key,
		Fingerprint: adminstore.Fingerprint{Version: adminstore.FingerprintVersion, KeyID: "integration-key", Digest: strings.Repeat("d", 64)},
		Result: adminstore.AllowlistedResult{Code: "operation.pending", Payload: map[string]string{
			"event_id": "evt_shanghai", "operation_request_id": "req_recovery_integration", "actor_id": "user_integration",
			"receipt_action": "application.review_saved", "receipt_target_type": "application", "receipt_target_id": "app_integration",
		}},
		State: "pending", DeliveryPhase: adminstore.DeliveryPhaseNotSent, Version: 1, NextAttemptAt: base, CreatedAt: base, UpdatedAt: base,
	}
	var claimed adminstore.OutboxItem
	if err := uow.Within(ctx, func(repositories adminstore.Repositories) error {
		stored, replay, err := repositories.Outbox.CreateOrReplay(ctx, created)
		if err != nil || replay {
			if err != nil {
				return err
			}
			t.Fatal("new operation unexpectedly replayed")
		}
		claimed, err = repositories.Outbox.ClaimExact(ctx, stored.ID, stored.Version, base, time.Second)
		if err != nil {
			return err
		}
		return repositories.Outbox.MarkDeliveryPhase(ctx, claimed.ID, claimed.Version, claimed.ClaimToken, adminstore.DeliveryPhaseIndeterminate, base)
	}); err != nil {
		t.Fatalf("create and claim operation: %v", err)
	}

	var recovered []adminstore.OutboxItem
	if err := uow.Within(ctx, func(repositories adminstore.Repositories) error {
		var err error
		recovered, err = repositories.Outbox.ClaimReceiptsDue(ctx, base.Add(2*time.Second), 10, 30*time.Second)
		return err
	}); err != nil {
		t.Fatalf("reclaim expired claim: %v", err)
	}
	if len(recovered) != 1 || recovered[0].ID != created.ID || recovered[0].DeliveryPhase != adminstore.DeliveryPhaseIndeterminate || recovered[0].ClaimToken == "" {
		t.Fatalf("recovered=%+v", recovered)
	}
	recoveredItem := recovered[0]
	settled := adminstore.AllowlistedResult{Code: "operation.settled", Digest: strings.Repeat("a", 64), Payload: map[string]string{
		"event_id": "evt_shanghai", "operation_request_id": "req_recovery_integration", "actor_id": "user_integration",
		"receipt_action": "application.review_saved", "receipt_target_type": "application", "receipt_target_id": "app_integration", "result_version": "3",
	}}
	if err := uow.Within(ctx, func(repositories adminstore.Repositories) error {
		if err := repositories.Outbox.MarkDeliveryPhase(ctx, recoveredItem.ID, recoveredItem.Version, recoveredItem.ClaimToken, adminstore.DeliveryPhaseSent, base.Add(2*time.Second)); err != nil {
			return err
		}
		return repositories.Outbox.Settle(ctx, recoveredItem.ID, recoveredItem.Version+1, recoveredItem.ClaimToken, settled, base.Add(2*time.Second))
	}); err != nil {
		t.Fatalf("settle recovered receipt: %v", err)
	}
	var loaded adminstore.OutboxItem
	if err := uow.Within(ctx, func(repositories adminstore.Repositories) error {
		var err error
		loaded, err = repositories.Outbox.GetByIdempotencyKey(ctx, key)
		return err
	}); err != nil {
		t.Fatalf("load settled operation: %v", err)
	}
	if loaded.State != "succeeded" || loaded.TerminalAt == nil || loaded.Result.Digest != strings.Repeat("a", 64) || loaded.Result.Payload["actor_id"] != "user_integration" || loaded.ClaimToken != "" || loaded.ClaimTokenHash != "" || loaded.ClaimLeaseUntil != nil {
		t.Fatalf("loaded settled operation=%+v", loaded)
	}
}

func TestIntegration_AdminOutboxPersistsDeterministicDreamUPFailure(t *testing.T) {
	pool := setupTestPool(t, 5)
	uow := NewAdminUnitOfWork(pool.PgxPool(), nil)
	ctx := context.Background()
	now := time.Date(2026, 8, 27, 10, 30, 0, 0, time.UTC)
	key := "fedcba9876543210fedcba9876543210"
	item := adminstore.OutboxItem{
		ID: "aop_failure_integration", Kind: adminstore.OperationCrossSystem, IdempotencyKey: key,
		Fingerprint: adminstore.Fingerprint{Version: adminstore.FingerprintVersion, KeyID: "integration-key", Digest: strings.Repeat("e", 64)},
		Result: adminstore.AllowlistedResult{Code: "operation.pending", Payload: map[string]string{
			"event_id": "evt_shanghai", "operation_request_id": "req_failure_integration", "actor_id": "user_integration",
			"receipt_action": "application.review_saved", "receipt_target_type": "application", "receipt_target_id": "app_integration",
		}},
		State: "pending", DeliveryPhase: adminstore.DeliveryPhaseNotSent, Version: 1, NextAttemptAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := uow.Within(ctx, func(repositories adminstore.Repositories) error {
		stored, _, err := repositories.Outbox.CreateOrReplay(ctx, item)
		if err != nil {
			return err
		}
		claimed, err := repositories.Outbox.ClaimExact(ctx, stored.ID, stored.Version, now, 30*time.Second)
		if err != nil {
			return err
		}
		if err := repositories.Outbox.MarkDeliveryPhase(ctx, claimed.ID, claimed.Version, claimed.ClaimToken, adminstore.DeliveryPhaseIndeterminate, now); err != nil {
			return err
		}
		if err := repositories.Outbox.MarkDeliveryPhase(ctx, claimed.ID, claimed.Version+1, claimed.ClaimToken, adminstore.DeliveryPhaseSent, now); err != nil {
			return err
		}
		failed := adminstore.AllowlistedResult{Code: "operation.failed", Payload: map[string]string{
			"event_id": "evt_shanghai", "operation_request_id": "req_failure_integration", "actor_id": "user_integration",
			"receipt_action": "application.review_saved", "receipt_target_type": "application", "receipt_target_id": "app_integration", "response_status": "409",
		}}
		return repositories.Outbox.Fail(ctx, claimed.ID, claimed.Version+2, claimed.ClaimToken, failed, now)
	}); err != nil {
		t.Fatalf("persist deterministic failure: %v", err)
	}
	if err := uow.Within(ctx, func(repositories adminstore.Repositories) error {
		loaded, err := repositories.Outbox.GetByIdempotencyKey(ctx, key)
		if err != nil {
			return err
		}
		if loaded.State != "failed" || loaded.TerminalAt == nil || loaded.Result.Code != "operation.failed" || loaded.Result.Payload["response_status"] != "409" {
			t.Fatalf("failed operation=%+v", loaded)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
