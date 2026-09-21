package dreamupadmin

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
)

type reconcileSignerStub struct {
	input dreamupdelegation.ServiceAssertion
}

func (s *reconcileSignerStub) SignService(input dreamupdelegation.ServiceAssertion) (dreamupdelegation.SignedAssertion, error) {
	s.input = input
	return dreamupdelegation.SignedAssertion{Token: "service", NotBefore: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(20 * time.Second)}, nil
}

type reconcileClientStub struct{ input UpstreamRequest }

func (s *reconcileClientStub) Execute(_ context.Context, input UpstreamRequest) (UpstreamResponse, error) {
	s.input = input
	return UpstreamResponse{StatusCode: http.StatusOK, Body: json.RawMessage(`{"receipt":{"event_id":"evt_shanghai","action":"application.review_saved","target_type":"application","target_id":"app_1","outcome":"success","result_version":2,"receipt_hash":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890","request_id":"req_operation_1","created_at":1786960800000}}`)}, nil
}

type reconcileUOW struct{ outbox *reconcileOutbox }

func (u reconcileUOW) Within(ctx context.Context, fn func(adminstore.Repositories) error) error {
	return fn(adminstore.Repositories{Outbox: u.outbox})
}

type reconcileOutbox struct {
	item    adminstore.OutboxItem
	settled bool
	phase   adminstore.DeliveryPhase
	result  adminstore.AllowlistedResult
}

func (r *reconcileOutbox) ClaimReceiptsDue(context.Context, time.Time, int, time.Duration) ([]adminstore.OutboxItem, error) {
	return []adminstore.OutboxItem{r.item}, nil
}
func (r *reconcileOutbox) MarkDeliveryPhase(_ context.Context, _ string, _ int64, _ string, p adminstore.DeliveryPhase, _ time.Time) error {
	r.phase = p
	return nil
}
func (*reconcileOutbox) RenewClaim(context.Context, string, int64, string, time.Duration) error {
	panic("unexpected")
}
func (r *reconcileOutbox) Settle(_ context.Context, _ string, _ int64, _ string, result adminstore.AllowlistedResult, _ time.Time) error {
	r.settled = true
	r.result = result
	return nil
}
func (*reconcileOutbox) CreateOrReplay(context.Context, adminstore.OutboxItem) (adminstore.OutboxItem, bool, error) {
	panic("unexpected")
}
func (*reconcileOutbox) GetByIdempotencyKey(context.Context, string) (adminstore.OutboxItem, error) {
	panic("unexpected")
}
func (*reconcileOutbox) CompleteLocal(context.Context, string, int64, adminstore.AllowlistedResult, time.Time) error {
	panic("unexpected")
}
func (*reconcileOutbox) ClaimDue(context.Context, time.Time, int) ([]adminstore.OutboxItem, error) {
	panic("unexpected")
}
func (*reconcileOutbox) ClaimExact(context.Context, string, int64, time.Time, time.Duration) (adminstore.OutboxItem, error) {
	panic("unexpected")
}
func (*reconcileOutbox) DeferReceipt(context.Context, string, int64, string, time.Time, time.Time) error {
	panic("unexpected")
}
func (*reconcileOutbox) MarkNeedsOperator(context.Context, string, int64, string, time.Time) error {
	panic("unexpected")
}
func (*reconcileOutbox) Fail(context.Context, string, int64, string, adminstore.AllowlistedResult, time.Time) error {
	panic("unexpected")
}
func (*reconcileOutbox) AbortBeforeSend(context.Context, string, int64, string, adminstore.AllowlistedResult, time.Time) error {
	panic("unexpected")
}
func (*reconcileOutbox) MarkAuditReconciled(context.Context, string, int64, time.Time) error {
	panic("unexpected")
}
func (*reconcileOutbox) ReleaseExpiredClaim(context.Context, string, int64, time.Time) error {
	panic("unexpected")
}
func (*reconcileOutbox) PurgePayload(context.Context, string, int64, time.Time) error {
	panic("unexpected")
}

func TestReconcilePendingUsesServiceReceiptOnlyAndSettles(t *testing.T) {
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	outbox := &reconcileOutbox{item: adminstore.OutboxItem{ID: "aop_12345678", Kind: adminstore.OperationCrossSystem, IdempotencyKey: "0123456789abcdef0123456789abcdef", State: "claimed", DeliveryPhase: adminstore.DeliveryPhaseIndeterminate, Version: 3, ClaimToken: "claim", CreatedAt: now.Add(-time.Minute), UpdatedAt: now, Result: adminstore.AllowlistedResult{Code: "operation.pending", Payload: map[string]string{"event_id": "evt_shanghai", "operation_request_id": "req_operation_1", "actor_id": "user_1", "receipt_action": "application.review_saved", "receipt_target_type": "application", "receipt_target_id": "app_1"}}}}
	signer, client := &reconcileSignerStub{}, &reconcileClientStub{}
	reconciler, err := NewReconciler(ReconcilerDependencies{UnitOfWork: reconcileUOW{outbox}, Signer: signer, Client: client}, ReconcilerConfig{Interval: time.Second, BatchSize: 10, Lease: 30 * time.Second, ServiceSubject: "united-pass:dreamup-reconciler", ServiceVersion: 1, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := reconciler.RunOnce(context.Background())
	if err != nil || processed != 1 {
		t.Fatalf("processed=%d err=%v", processed, err)
	}
	if signer.input.Capability != dreamupdelegation.ServiceCapabilityOperationReceiptRead || signer.input.EventID != "evt_shanghai" || signer.input.OperationRequestID != "req_operation_1" {
		t.Fatalf("assertion=%+v", signer.input)
	}
	if client.input.Method != http.MethodGet || client.input.Path != "/internal/v1/events/evt_shanghai/operation-receipts/req_operation_1" {
		t.Fatalf("request=%+v", client.input)
	}
	if outbox.phase != adminstore.DeliveryPhaseSent || !outbox.settled {
		t.Fatalf("phase=%s settled=%v", outbox.phase, outbox.settled)
	}
	if outbox.result.Digest != "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" || outbox.result.Payload["result_version"] != "2" || outbox.result.Payload["actor_id"] != "user_1" {
		t.Fatalf("settled result=%+v", outbox.result)
	}
}

func TestReceiptProjectionRejectsUnboundOrNonCanonicalOutcomeEvidence(t *testing.T) {
	valid := `{"receipt":{"event_id":"evt_shanghai","action":"application.review_saved","target_type":"application","target_id":"app_1","outcome":"success","result_version":null,"receipt_hash":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890","request_id":"req_operation_1","created_at":1786960800000}}`
	if receipt, ok := parseReceiptResponse(json.RawMessage(valid), "evt_shanghai", "req_operation_1"); !ok || receipt.ResultVersion != nil {
		t.Fatalf("valid receipt=%+v ok=%v", receipt, ok)
	}
	for name, raw := range map[string]string{
		"missing event":    strings.Replace(valid, `"event_id":"evt_shanghai",`, "", 1),
		"wrong event":      strings.Replace(valid, "evt_shanghai", "evt_beijing", 1),
		"wrong request":    strings.Replace(valid, "req_operation_1", "req_operation_2", 1),
		"short digest":     strings.Replace(valid, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "abcdef12", 1),
		"bad outcome":      strings.Replace(valid, `"success"`, `"failure"`, 1),
		"unknown field":    strings.Replace(valid, `"created_at"`, `"unexpected":true,"created_at"`, 1),
		"string timestamp": strings.Replace(valid, `1786960800000`, `"2026-08-17T10:00:00Z"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := parseReceiptResponse(json.RawMessage(raw), "evt_shanghai", "req_operation_1"); ok {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
}

func TestReceiptReconciliationFailsClosedOnCorruptLedgerState(t *testing.T) {
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	valid := adminstore.OutboxItem{
		ID: "aop_12345678", Kind: adminstore.OperationCrossSystem, IdempotencyKey: "0123456789abcdef0123456789abcdef",
		State: "claimed", DeliveryPhase: adminstore.DeliveryPhaseIndeterminate, Version: 3, ClaimToken: "claim",
		CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
		Result: adminstore.AllowlistedResult{Code: "operation.pending", Payload: map[string]string{
			"event_id": "evt_shanghai", "operation_request_id": "req_operation_1", "actor_id": "user_1",
			"receipt_action": "application.review_saved", "receipt_target_type": "application", "receipt_target_id": "app_1",
		}},
	}
	if !validReceiptReconciliationItem(valid, "evt_shanghai", "req_operation_1") {
		t.Fatal("valid receipt reconciliation item rejected")
	}
	tests := map[string]func(*adminstore.OutboxItem){
		"not claimed":       func(item *adminstore.OutboxItem) { item.State = "pending" },
		"missing claim":     func(item *adminstore.OutboxItem) { item.ClaimToken = "" },
		"terminal":          func(item *adminstore.OutboxItem) { item.TerminalAt = &now },
		"settled code":      func(item *adminstore.OutboxItem) { item.Result.Code = "operation.settled" },
		"existing digest":   func(item *adminstore.OutboxItem) { item.Result.Digest = strings.Repeat("a", 64) },
		"response metadata": func(item *adminstore.OutboxItem) { item.Result.Payload["response_status"] = "200" },
		"missing action":    func(item *adminstore.OutboxItem) { delete(item.Result.Payload, "receipt_action") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			item := valid
			item.Result.Payload = maps.Clone(valid.Result.Payload)
			mutate(&item)
			if validReceiptReconciliationItem(item, item.Result.Payload["event_id"], item.Result.Payload["operation_request_id"]) {
				t.Fatal("corrupt ledger item accepted for receipt reconciliation")
			}
		})
	}
}

func TestReceiptProjectionRequiresExactPersistedActionAndTarget(t *testing.T) {
	item := adminstore.OutboxItem{Result: adminstore.AllowlistedResult{Payload: map[string]string{
		"event_id": "evt_shanghai", "receipt_action": "application.review_saved", "receipt_target_type": "application", "receipt_target_id": "app_1",
	}}}
	receipt := operationReceipt{EventID: "evt_shanghai", Action: "application.review_saved", TargetType: "application", TargetID: "app_1"}
	if !receiptMatchesOperation(item, receipt) {
		t.Fatal("exact receipt binding rejected")
	}
	for name, mutate := range map[string]func(*operationReceipt){
		"event":  func(receipt *operationReceipt) { receipt.EventID = "evt_beijing" },
		"action": func(receipt *operationReceipt) { receipt.Action = "identity_access.consumed" },
		"type":   func(receipt *operationReceipt) { receipt.TargetType = "restricted_identity" },
		"id":     func(receipt *operationReceipt) { receipt.TargetID = "app_2" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := receipt
			mutate(&candidate)
			if receiptMatchesOperation(item, candidate) {
				t.Fatal("mismatched receipt settled unrelated operation")
			}
		})
	}
}
