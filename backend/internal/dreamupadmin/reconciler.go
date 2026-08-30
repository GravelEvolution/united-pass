package dreamupadmin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminstore"
	"github.com/GravelEvolution/united-pass/backend/internal/dreamupdelegation"
)

const reconcileOperationalDeadline = 15 * time.Minute

type ReconcilerDependencies struct {
	UnitOfWork adminstore.UnitOfWork
	Signer     ServiceSigner
	Client     UpstreamClient
}

type ReconcilerConfig struct {
	Interval       time.Duration
	BatchSize      int
	Lease          time.Duration
	ServiceSubject string
	ServiceVersion int64
	Now            func() time.Time
}

type Reconciler struct {
	uow    adminstore.UnitOfWork
	signer ServiceSigner
	client UpstreamClient
	config ReconcilerConfig
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewReconciler(dependencies ReconcilerDependencies, config ReconcilerConfig) (*Reconciler, error) {
	if dependencies.UnitOfWork == nil || dependencies.Signer == nil || dependencies.Client == nil || config.Interval < time.Second || config.Interval > 5*time.Minute || config.BatchSize < 1 || config.BatchSize > 100 || config.Lease < config.Interval || config.Lease > 10*time.Minute || config.ServiceSubject != dreamupdelegation.ReconcilerServiceSubject || config.ServiceVersion <= 0 {
		return nil, ErrInvalidRequest
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Reconciler{uow: dependencies.UnitOfWork, signer: dependencies.Signer, client: dependencies.Client, config: config}, nil
}

func (r *Reconciler) RunOnce(ctx context.Context) (int, error) {
	now := r.config.Now().UTC()
	var items []adminstore.OutboxItem
	if err := r.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		var err error
		items, err = repositories.Outbox.ClaimReceiptsDue(ctx, now, r.config.BatchSize, r.config.Lease)
		return err
	}); err != nil {
		return 0, err
	}
	processed := 0
	var failures []error
	for _, item := range items {
		if err := r.reconcileOne(ctx, item, now); err != nil {
			failures = append(failures, err)
			continue
		}
		processed++
	}
	return processed, errors.Join(failures...)
}

func (r *Reconciler) reconcileOne(ctx context.Context, item adminstore.OutboxItem, now time.Time) error {
	eventID := item.Result.Payload["event_id"]
	operationRequestID := item.Result.Payload["operation_request_id"]
	if !validReceiptReconciliationItem(item, eventID, operationRequestID) {
		return r.markNeedsOperator(ctx, item, now)
	}
	requestID, err := randomReconcileRequestID()
	if err != nil {
		return err
	}
	path := "/internal/v1/events/" + eventID + "/operation-receipts/" + operationRequestID
	assertion, err := r.signer.SignService(dreamupdelegation.ServiceAssertion{
		Subject: r.config.ServiceSubject, ServiceVersion: r.config.ServiceVersion, JWTID: requestID,
		Capability: dreamupdelegation.ServiceCapabilityOperationReceiptRead, Method: http.MethodGet,
		PathAndQuery: path, BodySHA256: dreamupdelegation.SHA256Digest(nil), EventID: eventID,
		OutboxID: item.ID, OperationRequestID: operationRequestID, IdempotencyKey: item.IdempotencyKey,
	})
	if err != nil {
		return r.markNeedsOperator(ctx, item, now)
	}
	response, err := r.client.Execute(ctx, UpstreamRequest{Method: http.MethodGet, Path: path, Assertion: assertion, RequestID: requestID, IdempotencyKey: item.IdempotencyKey})
	if err != nil {
		if now.Sub(item.CreatedAt) >= reconcileOperationalDeadline {
			return r.markNeedsOperator(ctx, item, now)
		}
		return r.deferReceipt(ctx, item, now)
	}
	receipt, valid := parseReceiptResponse(response.Body, operationRequestID)
	receiptCreatedAt := time.UnixMilli(receipt.CreatedAtUnixMS).UTC()
	if response.StatusCode != http.StatusOK || !valid || !receiptMatchesOperation(item, receipt) || receiptCreatedAt.Before(item.CreatedAt.Add(-dreamupdelegation.MaxClockSkew)) || receiptCreatedAt.After(now.Add(dreamupdelegation.MaxClockSkew)) {
		return r.markNeedsOperator(ctx, item, now)
	}
	return r.settle(ctx, item, receipt, now)
}

func validReceiptReconciliationItem(item adminstore.OutboxItem, eventID, operationRequestID string) bool {
	return item.Kind == adminstore.OperationCrossSystem && item.State == "claimed" && item.ID != "" && item.Version > 0 && item.ClaimToken != "" && item.TerminalAt == nil && !item.CreatedAt.IsZero() && !item.UpdatedAt.IsZero() &&
		item.Result.Code == "operation.pending" && item.Result.Digest == "" && item.Result.Payload["response_status"] == "" && item.Result.Payload["result_version"] == "" &&
		opaqueValuePattern.MatchString(eventID) && requestIDPattern.MatchString(operationRequestID) && validResultActorID(item.Result.Payload["actor_id"]) && idempotencyPattern.MatchString(item.IdempotencyKey) &&
		receiptMetadataPattern.MatchString(item.Result.Payload["receipt_action"]) && receiptMetadataPattern.MatchString(item.Result.Payload["receipt_target_type"]) &&
		(item.Result.Payload["receipt_target_id"] == "" || receiptMetadataPattern.MatchString(item.Result.Payload["receipt_target_id"])) &&
		(item.DeliveryPhase == adminstore.DeliveryPhaseIndeterminate || item.DeliveryPhase == adminstore.DeliveryPhaseSent)
}

func receiptMatchesOperation(item adminstore.OutboxItem, receipt operationReceipt) bool {
	expectedTargetID := item.Result.Payload["receipt_target_id"]
	return receipt.Action == item.Result.Payload["receipt_action"] && receipt.TargetType == item.Result.Payload["receipt_target_type"] &&
		(expectedTargetID == "" || receipt.TargetID == expectedTargetID)
}

func (r *Reconciler) settle(ctx context.Context, item adminstore.OutboxItem, receipt operationReceipt, now time.Time) error {
	return r.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		expected := item.Version
		if item.DeliveryPhase == adminstore.DeliveryPhaseIndeterminate {
			if err := repositories.Outbox.MarkDeliveryPhase(ctx, item.ID, expected, item.ClaimToken, adminstore.DeliveryPhaseSent, now); err != nil {
				return err
			}
			expected++
		}
		payload := operationResultPayload(item)
		if receipt.ResultVersion != nil {
			payload["result_version"] = strconv.FormatInt(*receipt.ResultVersion, 10)
		}
		return repositories.Outbox.Settle(ctx, item.ID, expected, item.ClaimToken, adminstore.AllowlistedResult{Code: "operation.settled", Digest: receipt.ReceiptHash, Payload: payload}, now)
	})
}

func (r *Reconciler) deferReceipt(ctx context.Context, item adminstore.OutboxItem, now time.Time) error {
	delay := time.Second << min(item.Attempts, 6)
	return r.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		return repositories.Outbox.DeferReceipt(ctx, item.ID, item.Version, item.ClaimToken, now.Add(delay), now)
	})
}

func (r *Reconciler) markNeedsOperator(ctx context.Context, item adminstore.OutboxItem, now time.Time) error {
	return r.uow.Within(ctx, func(repositories adminstore.Repositories) error {
		return repositories.Outbox.MarkNeedsOperator(ctx, item.ID, item.Version, item.ClaimToken, now)
	})
}

type operationReceipt struct {
	Action          string `json:"action"`
	TargetType      string `json:"target_type"`
	TargetID        string `json:"target_id"`
	Outcome         string `json:"outcome"`
	ResultVersion   *int64 `json:"result_version"`
	ReceiptHash     string `json:"receipt_hash"`
	RequestID       string `json:"request_id"`
	CreatedAtUnixMS int64  `json:"created_at"`
}

func parseReceiptResponse(raw json.RawMessage, operationRequestID string) (operationReceipt, bool) {
	var response struct {
		Receipt operationReceipt `json:"receipt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return operationReceipt{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return operationReceipt{}, false
	}
	receipt := response.Receipt
	validVersion := receipt.ResultVersion == nil || *receipt.ResultVersion > 0
	valid := receipt.RequestID == operationRequestID && receiptMetadataPattern.MatchString(receipt.Action) && receiptMetadataPattern.MatchString(receipt.TargetType) && receiptMetadataPattern.MatchString(receipt.TargetID) && receipt.Outcome == "success" && validVersion && receiptHashPattern.MatchString(receipt.ReceiptHash) && receipt.CreatedAtUnixMS > 0
	return receipt, valid
}

func validResultActorID(value string) bool {
	return len(value) > len("user_") && len(value) <= 160 && strings.HasPrefix(value, "user_") && opaqueValuePattern.MatchString(value)
}

func randomReconcileRequestID() (string, error) {
	buffer := make([]byte, 18)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "req_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (r *Reconciler) Start(parent context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	r.cancel, r.done = cancel, make(chan struct{})
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(r.config.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = r.RunOnce(ctx)
			}
		}
	}()
}

func (r *Reconciler) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
