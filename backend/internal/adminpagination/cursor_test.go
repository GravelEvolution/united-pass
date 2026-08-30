package adminpagination

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCursorBindsActorScopeListAndNormalizedQuery(t *testing.T) {
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	codec, err := NewCursorCodec(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := State{
		ActorID: "user_admin", ScopeKind: "event", EventID: "evt_shanghai",
		ListKind: "role_bindings", Filters: map[string]string{"status": " active ", "query": " Alice  Chen "},
		Sort: "createdAt:desc", LastPosition: map[string]string{"createdAt": "2026-08-17T08:00:00Z", "id": "arb_1"},
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Limit: 50, DownstreamCursor: "opaque-dreamup-cursor",
	}
	raw, err := codec.Encode(state)
	if err != nil {
		t.Fatal(err)
	}
	got, err := codec.Decode(raw, Expectation{
		ActorID: "user_admin", ScopeKind: "event", EventID: "evt_shanghai", ListKind: "role_bindings",
		Filters: map[string]string{"query": "Alice Chen", "status": "active"}, Sort: "createdAt:desc", Limit: 50,
	})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.DownstreamCursor != state.DownstreamCursor || got.LastPosition["id"] != "arb_1" {
		t.Fatalf("decoded state = %+v", got)
	}

	mutations := []Expectation{
		{ActorID: "other", ScopeKind: "event", EventID: "evt_shanghai", ListKind: "role_bindings", Filters: map[string]string{"status": "active", "query": "Alice Chen"}, Sort: "createdAt:desc", Limit: 50},
		{ActorID: "user_admin", ScopeKind: "event", EventID: "evt_beijing", ListKind: "role_bindings", Filters: map[string]string{"status": "active", "query": "Alice Chen"}, Sort: "createdAt:desc", Limit: 50},
		{ActorID: "user_admin", ScopeKind: "event", EventID: "evt_shanghai", ListKind: "applications", Filters: map[string]string{"status": "active", "query": "Alice Chen"}, Sort: "createdAt:desc", Limit: 50},
		{ActorID: "user_admin", ScopeKind: "event", EventID: "evt_shanghai", ListKind: "role_bindings", Filters: map[string]string{"status": "disabled", "query": "Alice Chen"}, Sort: "createdAt:desc", Limit: 50},
		{ActorID: "user_admin", ScopeKind: "event", EventID: "evt_shanghai", ListKind: "role_bindings", Filters: map[string]string{"status": "active", "query": "Alice Chen"}, Sort: "name:asc", Limit: 50},
	}
	for i, expectation := range mutations {
		if _, err := codec.Decode(raw, expectation); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("replay mutation %d error=%v, want ErrInvalidCursor", i, err)
		}
	}
}

func TestCursorRejectsTamperingExpiryOversizeAndInvalidPageSize(t *testing.T) {
	now := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	codec, err := NewCursorCodec(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := State{ActorID: "u", ScopeKind: "system", ListKind: "events", Sort: "id:asc", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Limit: MaxPageSize}
	raw, err := codec.Encode(state)
	if err != nil {
		t.Fatal(err)
	}
	index := len(raw) / 2
	replacement := byte('A')
	if raw[index] == replacement {
		replacement = 'B'
	}
	tampered := raw[:index] + string(replacement) + raw[index+1:]
	expect := Expectation{ActorID: "u", ScopeKind: "system", ListKind: "events", Sort: "id:asc", Limit: MaxPageSize}
	if _, err := codec.Decode(tampered, expect); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("tamper error=%v", err)
	}
	if _, err := codec.Decode(strings.Repeat("A", MaxEncodedCursorBytes+1), expect); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("oversize error=%v", err)
	}

	now = now.Add(2 * time.Minute)
	if _, err := codec.Decode(raw, expect); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("expiry error=%v", err)
	}
	if _, err := codec.Encode(State{ActorID: "u", ScopeKind: "system", ListKind: "events", Sort: "id:asc", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Limit: MaxPageSize + 1}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("page-size error=%v", err)
	}
}
