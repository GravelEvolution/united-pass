package adminstore

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestResolveIdempotentReplay(t *testing.T) {
	existing := OperationReceipt{IdempotencyKey: "idem_1", Fingerprint: Fingerprint{Version: FingerprintVersion, KeyID: "k1", Digest: "digest-a"}, Result: AllowlistedResult{Code: "role.created", Digest: "result-digest"}}
	got, err := ResolveIdempotentReplay(existing, existing.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Result, existing.Result) {
		t.Fatalf("replay=%+v, want stored allowlisted result", got)
	}
	_, err = ResolveIdempotentReplay(existing, Fingerprint{Version: FingerprintVersion, KeyID: "k1", Digest: "digest-b"})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different input error=%v", err)
	}
}

func TestPayloadRetentionDeadlineIsNinetyDaysAfterAuditReconciliation(t *testing.T) {
	reconciled := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	if got, want := PayloadRetentionDeadline(reconciled), reconciled.Add(90*24*time.Hour); !got.Equal(want) {
		t.Fatalf("deadline=%s, want %s", got, want)
	}
}

func TestEncodeAllowlistedPayloadUsesEmptyObjectForNoResult(t *testing.T) {
	got, err := EncodeAllowlistedPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{}" {
		t.Fatalf("payload=%s, want empty JSON object", got)
	}
}

func TestAllowlistedResultRejectsSensitivePayloadShape(t *testing.T) {
	for _, result := range []AllowlistedResult{
		{Code: "role.created", Payload: map[string]string{"answer": "secret"}},
		{Code: "role.created", Payload: map[string]string{"reason": "free text"}},
		{Code: "role.created", Payload: map[string]string{"token": "bearer"}},
		{Code: "arbitrary.secret", Payload: map[string]string{"binding_id": "arb_1"}},
		{Code: "role.created", Payload: map[string]string{"binding_id": "raw secret disguised as id"}},
	} {
		if err := result.Validate(); err == nil {
			t.Fatalf("sensitive result accepted: %+v", result)
		}
	}
	if err := (AllowlistedResult{Code: "role.created", Digest: "opaque_digest_01", Payload: map[string]string{"binding_id": "arb_1"}}).Validate(); err != nil {
		t.Fatalf("safe result rejected: %v", err)
	}
}

func TestAllowlistedResultAcceptsOnlyBoundedDreamUPRecoveryMetadata(t *testing.T) {
	valid := AllowlistedResult{Code: "operation.settled", Digest: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", Payload: map[string]string{
		"event_id": "evt_shanghai", "operation_request_id": ":trace-admin_123", "actor_id": "user_1", "response_status": "200", "result_version": "2",
		"receipt_action": "application.review_saved", "receipt_target_type": "application", "receipt_target_id": "app_1",
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid recovery metadata rejected: %v", err)
	}
	for name, payload := range map[string]map[string]string{
		"raw actor":        {"actor_id": "administrator"},
		"bad status":       {"response_status": "099"},
		"fraction version": {"result_version": "1.5"},
		"receipt wildcard": {"receipt_action": "application.*"},
		"secret body":      {"response_body": `{"secret":true}`},
	} {
		t.Run(name, func(t *testing.T) {
			if err := (AllowlistedResult{Code: "operation.failed", Payload: payload}).Validate(); !errors.Is(err, ErrInvalidOperationResult) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestOptionalAllowlistedResultAcceptsOnlyEmptyOrFullyValidResults(t *testing.T) {
	if err := ValidateOptionalAllowlistedResult(AllowlistedResult{}); err != nil {
		t.Fatalf("empty pending result rejected: %v", err)
	}
	if err := ValidateOptionalAllowlistedResult(AllowlistedResult{Code: "arbitrary.secret"}); !errors.Is(err, ErrInvalidOperationResult) {
		t.Fatalf("invalid code without payload error=%v", err)
	}
	if err := ValidateOptionalAllowlistedResult(AllowlistedResult{Code: "role.created", Payload: map[string]string{"binding_id": "arb_1"}}); err != nil {
		t.Fatalf("valid terminal result rejected: %v", err)
	}
}

func TestSanitizeOutboxReplayReturnsNoBearerOrEncryptedPayload(t *testing.T) {
	item := OutboxItem{
		ID: "op_1", PayloadKeyID: "key_1", PayloadNonce: []byte("nonce"), PayloadCiphertext: []byte("ciphertext"),
		ClaimTokenHash: "hash", ClaimToken: "bearer", Result: AllowlistedResult{Code: "role.created", Payload: map[string]string{"binding_id": "arb_1"}},
	}
	got := SanitizeOutboxReplay(item)
	if got.PayloadKeyID != "" || len(got.PayloadNonce) != 0 || len(got.PayloadCiphertext) != 0 || got.ClaimTokenHash != "" || got.ClaimToken != "" {
		t.Fatalf("replay exposed protected material: %+v", got)
	}
	if got.Result.Code != "role.created" || got.Result.Payload["binding_id"] != "arb_1" {
		t.Fatalf("allowlisted result lost: %+v", got.Result)
	}
}

func TestDeliveryPhaseValidation(t *testing.T) {
	for _, phase := range []DeliveryPhase{DeliveryPhaseNotSent, DeliveryPhaseIndeterminate, DeliveryPhaseSent} {
		if !phase.Valid() {
			t.Fatalf("valid delivery phase rejected: %q", phase)
		}
	}
	for _, phase := range []DeliveryPhase{"", "pending", "unknown"} {
		if phase.Valid() {
			t.Fatalf("invalid delivery phase accepted: %q", phase)
		}
	}
}
