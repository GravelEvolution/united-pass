//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for the security event JSONB payload serialization
//

package postgres

import (
	"encoding/json"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
)

func mustDecodePayload(t *testing.T, ev applications.SecurityEvent) map[string]string {
	t.Helper()
	raw, err := eventPayload(ev)
	if err != nil {
		t.Fatalf("eventPayload: %v", err)
	}
	decoded := map[string]string{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("payload must be a JSON object: %v (raw=%s)", err, raw)
	}
	return decoded
}

// TestEventPayloadCarriesFailureClassAndTarget proves the durable payload
// keeps both the provider-cleanup failure class and the generic target pair
// (session revocations carry {"session_id": "…"}, ADR-0006 §2).
func TestEventPayloadCarriesFailureClassAndTarget(t *testing.T) {
	payload := mustDecodePayload(t, applications.SecurityEvent{
		FailureClass: "network",
		TargetKey:    "session_id",
		TargetID:     "sess_target",
	})
	if payload["failure_class"] != "network" {
		t.Errorf("failure_class = %q, want network", payload["failure_class"])
	}
	if payload["session_id"] != "sess_target" {
		t.Errorf("session_id = %q, want sess_target", payload["session_id"])
	}
	if len(payload) != 2 {
		t.Errorf("payload = %v, want exactly failure_class and session_id", payload)
	}
}

// TestEventPayloadOmitsEmptySeams proves events without a failure class or
// target persist an empty object — never null keys or empty identifiers.
func TestEventPayloadOmitsEmptySeams(t *testing.T) {
	payload := mustDecodePayload(t, applications.SecurityEvent{})
	if len(payload) != 0 {
		t.Errorf("payload = %v, want empty object", payload)
	}
}

// TestEventPayloadRequiresBothTargetFields proves a half-populated target
// seam is omitted rather than persisted with an empty key or value.
func TestEventPayloadRequiresBothTargetFields(t *testing.T) {
	payload := mustDecodePayload(t, applications.SecurityEvent{TargetKey: "session_id"})
	if len(payload) != 0 {
		t.Errorf("payload = %v, want empty object for half-populated target seam", payload)
	}
}
