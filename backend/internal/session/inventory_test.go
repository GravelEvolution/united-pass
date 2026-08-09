//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-08
// Description: Unit tests for the session inventory domain and service
//

package session

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestEffectiveExpiry(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	record := SessionRecord{
		LastSeenAt: now,
		ExpiresAt:  now.Add(12 * time.Hour),
	}

	// Idle TTL dominates when tighter than the absolute deadline.
	if got, want := record.EffectiveExpiry(2*time.Hour), now.Add(2*time.Hour); !got.Equal(want) {
		t.Errorf("idle-bound effective expiry = %v, want %v", got, want)
	}

	// Absolute TTL dominates when tighter than the idle deadline.
	if got, want := record.EffectiveExpiry(24*time.Hour), record.ExpiresAt; !got.Equal(want) {
		t.Errorf("absolute-bound effective expiry = %v, want %v", got, want)
	}

	// No idle TTL configured: the absolute deadline is the effective expiry.
	if got, want := record.EffectiveExpiry(0), record.ExpiresAt; !got.Equal(want) {
		t.Errorf("no-idle effective expiry = %v, want %v", got, want)
	}

	// Effective expiry tracks LastSeenAt, never ExpiresAt movement.
	seen := record
	seen.LastSeenAt = now.Add(1 * time.Hour)
	if got, want := seen.EffectiveExpiry(2*time.Hour), now.Add(3*time.Hour); !got.Equal(want) {
		t.Errorf("refreshed effective expiry = %v, want %v", got, want)
	}
}

func TestEffectiveExpiryAgreesWithIsExpired(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	idleTTL := 2 * time.Hour
	record := SessionRecord{
		LastSeenAt: now,
		ExpiresAt:  now.Add(12 * time.Hour),
	}

	// Just past the effective expiry the record is expired; just before it is
	// live. The index score and the authoritative replay must never disagree.
	past := record.EffectiveExpiry(idleTTL).Add(time.Second)
	if !record.IsExpired(past, idleTTL) {
		t.Error("record must be expired one second past its effective expiry")
	}
	before := record.EffectiveExpiry(idleTTL).Add(-time.Second)
	if record.IsExpired(before, idleTTL) {
		t.Error("record must be live one second before its effective expiry")
	}
}

func TestNormalizeUserAgent(t *testing.T) {
	cases := []struct {
		name   string
		ua     string
		device string
		client string
	}{
		{"chrome on macos", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36", "macOS", "Chrome"},
		{"safari on iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", "iOS", "Safari"},
		{"edge on windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 Edg/126.0", "Windows", "Edge"},
		{"firefox on android", "Mozilla/5.0 (Android 14; Mobile; rv:127.0) Gecko/127.0 Firefox/127.0", "Android", "Firefox"},
		{"chrome on linux", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36", "Linux", "Chrome"},
		{"unknown", "custom-agent/1.0", "", ""},
		{"empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device, client := NormalizeUserAgent(tc.ua)
			if device != tc.device || client != tc.client {
				t.Errorf("NormalizeUserAgent = (%q, %q), want (%q, %q)", device, client, tc.device, tc.client)
			}
		})
	}
}

func TestMaskIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"203.0.113.42", "203.0.113.*"},
		{"203.0.113.42:51234", "203.0.113.*"},
		{"127.0.0.1", "127.0.0.*"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2:*"},
		{"[2001:db8:1:2:3:4:5:6]:443", "2001:db8:1:2:*"},
		{"::1", "0:0:0:0:*"},
		{"", ""},
		{"not-an-ip", ""},
	}
	for _, tc := range cases {
		if got := MaskIP(tc.in); got != tc.want {
			t.Errorf("MaskIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGenerateSessionIDRandomAndFailClosed(t *testing.T) {
	first, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID: %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("session id length = %d, want 32 hex chars", len(first))
	}
	if _, err := hex.DecodeString(string(first)); err != nil {
		t.Fatalf("session id is not hex: %v", err)
	}

	// Two consecutive IDs must differ (probability of collision ~2^-128).
	second, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID: %v", err)
	}
	if first == second {
		t.Fatal("consecutive session ids must not repeat")
	}
}

// fakeRevoker records provider revocation calls for inventory tests.
type fakeRevoker struct {
	refs    []string
	failRef string
}

func (f *fakeRevoker) RevokeProviderSession(_ context.Context, ref string) error {
	f.refs = append(f.refs, ref)
	if f.failRef != "" && ref == f.failRef {
		return errors.New("provider unavailable")
	}
	return nil
}

// inventoryService builds a Service over a fakeStore with fixed clocks.
func inventoryService(t *testing.T) (*Service, *fakeStore, *fakeRevoker) {
	t.Helper()
	store := newFakeStore()
	revoker := &fakeRevoker{}
	svc := NewService(store, SystemClock{},
		12*time.Hour, 720*time.Hour, 15*time.Minute, 5*time.Minute,
		testEncryptor(),
		WithProviderRevoker(revoker))
	return svc, store, revoker
}

// inventoryInput builds a session creation input for one user.
func inventoryInput(userID identity.UserID, remember bool) CreateSessionInput {
	return CreateSessionInput{
		UserID:                userID,
		Provider:              "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
		Remember:              remember,
		UserAgent:             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0 Safari/537.36",
		ClientIP:              "203.0.113.42",
	}
}

func TestCreateSessionPopulatesDisplayMetadata(t *testing.T) {
	svc, store, _ := inventoryService(t)

	result, err := svc.CreateSession(context.Background(), inventoryInput("user_display", false))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	stored := store.sessions[result.TokenHash]

	if stored.DeviceDisplay != "macOS" {
		t.Errorf("DeviceDisplay = %q, want macOS", stored.DeviceDisplay)
	}
	if stored.ClientDisplay != "Chrome" {
		t.Errorf("ClientDisplay = %q, want Chrome", stored.ClientDisplay)
	}
	if stored.IPAddressMasked != "203.0.113.*" {
		t.Errorf("IPAddressMasked = %q, want 203.0.113.*", stored.IPAddressMasked)
	}
	if result.Record.SessionID == "" {
		t.Error("session id must be populated")
	}
}

func TestListUserSessionsIsolatesUsersAndExpiry(t *testing.T) {
	svc, _, _ := inventoryService(t)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := svc.CreateSession(ctx, inventoryInput("user_list_a", false)); err != nil {
			t.Fatalf("create a%d: %v", i, err)
		}
	}
	if _, err := svc.CreateSession(ctx, inventoryInput("user_list_b", false)); err != nil {
		t.Fatalf("create b: %v", err)
	}

	records, err := svc.ListUserSessions(ctx, "user_list_a")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("list returned %d sessions, want 2", len(records))
	}
	for _, r := range records {
		if r.UserID != "user_list_a" {
			t.Fatalf("listed foreign session of %q", r.UserID)
		}
	}
}

func TestRevokeSessionContracts(t *testing.T) {
	svc, store, _ := inventoryService(t)
	ctx := context.Background()

	current, err := svc.CreateSession(ctx, inventoryInput("user_revoke", false))
	if err != nil {
		t.Fatalf("create current: %v", err)
	}
	other, err := svc.CreateSession(ctx, inventoryInput("user_revoke", false))
	if err != nil {
		t.Fatalf("create other: %v", err)
	}

	// Revoking the current session is refused with the stable conflict error.
	if err := svc.RevokeSession(ctx, "user_revoke", current.Record.SessionID, current.Record.SessionID); !errors.Is(err, ErrSessionIsCurrent) {
		t.Fatalf("current revoke must yield ErrSessionIsCurrent, got %v", err)
	}

	// Unknown and foreign targets are indistinguishable.
	if err := svc.RevokeSession(ctx, "user_revoke", current.Record.SessionID, "deadbeef"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown revoke must yield ErrSessionNotFound, got %v", err)
	}
	if err := svc.RevokeSession(ctx, "user_revoke", current.Record.SessionID, other.Record.SessionID); err != nil {
		t.Fatalf("revoke other: %v", err)
	}
	if len(store.sessions) != 1 {
		t.Fatalf("%d sessions remain, want 1", len(store.sessions))
	}

	// A second revoke reports not found (idempotent non-enumeration).
	if err := svc.RevokeSession(ctx, "user_revoke", current.Record.SessionID, other.Record.SessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("repeat revoke must yield ErrSessionNotFound, got %v", err)
	}
}

func TestRevokeSessionRevokesProviderSession(t *testing.T) {
	svc, _, revoker := inventoryService(t)
	ctx := context.Background()

	current, err := svc.CreateSession(ctx, inventoryInput("user_prov", false))
	if err != nil {
		t.Fatalf("create current: %v", err)
	}
	input := inventoryInput("user_prov", false)
	input.ProviderSessionReference = "provider-ref-victim"
	victim, err := svc.CreateSession(ctx, input)
	if err != nil {
		t.Fatalf("create victim: %v", err)
	}

	if err := svc.RevokeSession(ctx, "user_prov", current.Record.SessionID, victim.Record.SessionID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(revoker.refs) != 1 || revoker.refs[0] != "provider-ref-victim" {
		t.Fatalf("provider refs revoked = %v, want [provider-ref-victim]", revoker.refs)
	}
}

func TestRevokeAllOtherSessionsPreservesCurrent(t *testing.T) {
	svc, store, _ := inventoryService(t)
	ctx := context.Background()

	current, err := svc.CreateSession(ctx, inventoryInput("user_bulk", false))
	if err != nil {
		t.Fatalf("create current: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.CreateSession(ctx, inventoryInput("user_bulk", false)); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if _, err := svc.CreateSession(ctx, inventoryInput("user_bulk_other", false)); err != nil {
		t.Fatalf("create foreign: %v", err)
	}

	count, err := svc.RevokeAllOtherSessions(ctx, "user_bulk", current.Record.SessionID)
	if err != nil {
		t.Fatalf("revoke all others: %v", err)
	}
	if count != 3 {
		t.Fatalf("revoked %d sessions, want 3", count)
	}

	// The current session and the foreign user's session survive.
	if len(store.sessions) != 2 {
		t.Fatalf("%d sessions remain, want 2", len(store.sessions))
	}
	if _, err := svc.ListUserSessions(ctx, "user_bulk"); err != nil {
		t.Fatalf("list: %v", err)
	}
	remaining, err := svc.ListUserSessions(ctx, "user_bulk")
	if err != nil || len(remaining) != 1 || remaining[0].SessionID != current.Record.SessionID {
		t.Fatalf("remaining = %v (err %v), want only the current session", remaining, err)
	}
}

func TestTouchSessionKeepsAbsoluteExpiryFixed(t *testing.T) {
	clock := &mutableClock{now: time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)}
	store := newFakeStore()
	svc := NewService(store, clock,
		12*time.Hour, 720*time.Hour, 2*time.Hour, 5*time.Minute, testEncryptor())
	ctx := context.Background()

	result, err := svc.CreateSession(ctx, inventoryInput("user_touch", false))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	originalExpiry := store.sessions[result.TokenHash].ExpiresAt

	// Advance past the touch interval and touch.
	clock.now = clock.now.Add(10 * time.Minute)
	if err := svc.TouchSession(ctx, result.SessionToken); err != nil {
		t.Fatalf("touch: %v", err)
	}
	touched := store.sessions[result.TokenHash]
	if !touched.LastSeenAt.Equal(clock.now) {
		t.Errorf("LastSeenAt = %v, want %v", touched.LastSeenAt, clock.now)
	}
	// ADR-0006 §1 rule 6 / P1 semantics: the absolute deadline never slides.
	if !touched.ExpiresAt.Equal(originalExpiry) {
		t.Errorf("ExpiresAt moved from %v to %v", originalExpiry, touched.ExpiresAt)
	}
}

// mutableClock is a controllable Clock for service tests.
type mutableClock struct {
	now time.Time
}

func (c *mutableClock) Now() time.Time { return c.now }

// infraFailingStore wraps a fakeStore and simulates a Redis infrastructure
// outage on the inventory revoke paths (R1): infrastructure errors must
// propagate instead of being collapsed into ErrSessionNotFound. victims
// simulates the partial-failure case where earlier victims were already
// locally removed before the walk failed.
type infraFailingStore struct {
	*fakeStore
	resolveErr error
	revokeErr  error
	victims    []SessionRecord
}

func (s *infraFailingStore) GetBySessionID(_ context.Context, _ identity.UserID, _ SessionID, _ time.Time, _ time.Duration) (SessionRecord, error) {
	return SessionRecord{}, s.resolveErr
}

func (s *infraFailingStore) RevokeAllOtherSessions(_ context.Context, _ identity.UserID, _ SessionID, _ time.Time, _ time.Duration) ([]SessionRecord, int, error) {
	return s.victims, len(s.victims), s.revokeErr
}

func TestRevokeSessionPropagatesInfrastructureFailure(t *testing.T) {
	store := &infraFailingStore{
		fakeStore:  newFakeStore(),
		resolveErr: errors.New("redis: resolve session: connection refused"),
	}
	svc := NewService(store, SystemClock{},
		12*time.Hour, 720*time.Hour, 15*time.Minute, 5*time.Minute, testEncryptor())

	err := svc.RevokeSession(context.Background(), "user_infra", "sess_current", "sess_target")
	if err == nil {
		t.Fatal("revoke must fail closed on an infrastructure failure")
	}
	if errors.Is(err, ErrSessionNotFound) {
		t.Fatal("infrastructure failure must not be collapsed into ErrSessionNotFound (false success)")
	}
}

func TestRevokeAllOtherSessionsPropagatesInfrastructureFailure(t *testing.T) {
	store := &infraFailingStore{
		fakeStore: newFakeStore(),
		revokeErr: errors.New("redis: range session index: connection refused"),
	}
	auditor := &fakeAuditor{}
	svc := NewService(store, SystemClock{},
		12*time.Hour, 720*time.Hour, 15*time.Minute, 5*time.Minute, testEncryptor(),
		WithSecurityAuditor(auditor))

	_, err := svc.RevokeAllOtherSessions(context.Background(), "user_infra", "sess_current")
	if err == nil {
		t.Fatal("bulk revoke must fail closed on an infrastructure failure")
	}
	if errors.Is(err, ErrSessionNotFound) {
		t.Fatal("infrastructure failure must not be collapsed into ErrSessionNotFound")
	}
	if len(auditor.events) != 0 {
		t.Fatalf("zero-victim failure durable audit events = %d, want 0", len(auditor.events))
	}
}

func TestRevokeAllOtherSessionsPartialFailureStillCleansVictims(t *testing.T) {
	enc := testEncryptor()
	refA, err := enc.Encrypt("provider-ref-a")
	if err != nil {
		t.Fatalf("encrypt refA: %v", err)
	}
	refB, err := enc.Encrypt("provider-ref-b")
	if err != nil {
		t.Fatalf("encrypt refB: %v", err)
	}
	store := &infraFailingStore{
		fakeStore: newFakeStore(),
		revokeErr: errors.New("redis: delete victim c: connection refused"),
		victims: []SessionRecord{
			{SessionID: "sess_victim_a", ProviderSessionReference: refA},
			{SessionID: "sess_victim_b", ProviderSessionReference: refB},
		},
	}
	revoker := &fakeRevoker{failRef: "provider-ref-b"}
	auditor := &fakeAuditor{}
	svc := NewService(store, SystemClock{},
		12*time.Hour, 720*time.Hour, 15*time.Minute, 5*time.Minute, enc,
		WithProviderRevoker(revoker), WithSecurityAuditor(auditor))

	count, err := svc.RevokeAllOtherSessions(context.Background(), "user_partial", "sess_current")
	if err == nil {
		t.Fatal("bulk revoke must fail closed on a partial infrastructure failure")
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0 on failure", count)
	}
	// R1 partial failure: victims already removed locally keep their
	// provider cleanup even though a later victim's deletion failed.
	if len(revoker.refs) != 2 || revoker.refs[0] != "provider-ref-a" || revoker.refs[1] != "provider-ref-b" {
		t.Fatalf("provider cleanup = %v, want both partial victims cleaned up", revoker.refs)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("partial durable audit events = %d, want 1", len(auditor.events))
	}
	ev := auditor.events[0]
	if ev.EventType != EventSessionsRevokedOthers || ev.Result != AuditOutcomeDenied {
		t.Errorf("partial audit event/result = %q/%q", ev.EventType, ev.Result)
	}
	if ev.AffectedCount != 2 {
		t.Errorf("partial audit affected count = %d, want 2", ev.AffectedCount)
	}
	if ev.FailureClass != "internal" {
		t.Errorf("partial audit store failure class = %q, want internal", ev.FailureClass)
	}
	if ev.ProviderFailureClass != "internal" {
		t.Errorf("partial audit provider failure class = %q, want internal", ev.ProviderFailureClass)
	}
}

func TestBulkRevokeHonoursIdleExpiry(t *testing.T) {
	clock := &mutableClock{now: time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)}
	store := newFakeStore()
	svc := NewService(store, clock,
		12*time.Hour, 720*time.Hour, 30*time.Minute, 5*time.Minute, testEncryptor())
	ctx := context.Background()

	current, err := svc.CreateSession(ctx, inventoryInput("user_idle_bulk", false))
	if err != nil {
		t.Fatalf("create current: %v", err)
	}
	other, err := svc.CreateSession(ctx, inventoryInput("user_idle_bulk", false))
	if err != nil {
		t.Fatalf("create other: %v", err)
	}

	// Advance past the idle TTL: the other session is dead and must neither
	// be counted as a bulk victim nor be revokable as a live target (R2).
	clock.now = clock.now.Add(time.Hour)

	count, err := svc.RevokeAllOtherSessions(ctx, "user_idle_bulk", current.Record.SessionID)
	if err != nil {
		t.Fatalf("bulk revoke: %v", err)
	}
	if count != 0 {
		t.Fatalf("bulk revoke reported %d victims, want 0 for idle-expired sessions", count)
	}
	if err := svc.RevokeSession(ctx, "user_idle_bulk", current.Record.SessionID, other.Record.SessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("targeted revoke of idle-expired session must yield ErrSessionNotFound, got %v", err)
	}
}

// fakeAuditor captures durable session audit events for service tests.
type fakeAuditor struct {
	events        []SecurityAuditEvent
	err           error
	contextErrors []error
}

func (f *fakeAuditor) RecordSessionEvent(ctx context.Context, ev SecurityAuditEvent) error {
	f.events = append(f.events, ev)
	f.contextErrors = append(f.contextErrors, ctx.Err())
	return f.err
}

func TestRevokeRecordsDurableSecurityAudit(t *testing.T) {
	auditor := &fakeAuditor{}
	svc := NewService(newFakeStore(), SystemClock{},
		12*time.Hour, 720*time.Hour, 15*time.Minute, 5*time.Minute, testEncryptor(),
		WithSecurityAuditor(auditor))
	ctx := context.Background()

	current, err := svc.CreateSession(ctx, inventoryInput("user_audit", false))
	if err != nil {
		t.Fatalf("create current: %v", err)
	}
	other, err := svc.CreateSession(ctx, inventoryInput("user_audit", false))
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	if _, err := svc.CreateSession(ctx, inventoryInput("user_audit", false)); err != nil {
		t.Fatalf("create third: %v", err)
	}

	if err := svc.RevokeSession(ctx, "user_audit", current.Record.SessionID, other.Record.SessionID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.RevokeAllOtherSessions(ctx, "user_audit", current.Record.SessionID); err != nil {
		t.Fatalf("bulk revoke: %v", err)
	}

	if len(auditor.events) != 2 {
		t.Fatalf("recorded %d audit events, want 2", len(auditor.events))
	}
	targeted := auditor.events[0]
	if targeted.EventType != EventSessionRevokedOther {
		t.Errorf("targeted event type = %q, want %q", targeted.EventType, EventSessionRevokedOther)
	}
	if targeted.ActorUserID != "user_audit" || targeted.SessionID != other.Record.SessionID {
		t.Errorf("targeted audit actor/session = %q/%q, want user_audit/%q", targeted.ActorUserID, targeted.SessionID, other.Record.SessionID)
	}
	if targeted.Operation != "session.revoke" || targeted.Result != AuditOutcomeSuccess {
		t.Errorf("targeted audit operation/result = %q/%q", targeted.Operation, targeted.Result)
	}
	if targeted.FailureClass != "" {
		t.Errorf("targeted audit failure class = %q, want empty on a clean outcome", targeted.FailureClass)
	}
	if targeted.OccurredAt.IsZero() {
		t.Error("targeted audit OccurredAt must be set")
	}
	bulk := auditor.events[1]
	if bulk.EventType != EventSessionsRevokedOthers || bulk.Operation != "session.revoke_all_others" {
		t.Errorf("bulk audit event/operation = %q/%q", bulk.EventType, bulk.Operation)
	}
	if bulk.SessionID != current.Record.SessionID {
		t.Errorf("bulk audit session = %q, want the current session", bulk.SessionID)
	}
	if bulk.AffectedCount != 1 {
		t.Errorf("bulk audit affected count = %d, want 1", bulk.AffectedCount)
	}
}

func TestRevokeAuditAttemptDetachedFromCallerCancellation(t *testing.T) {
	auditor := &fakeAuditor{}
	store := newFakeStore()
	svc := NewService(store, SystemClock{},
		12*time.Hour, 720*time.Hour, 15*time.Minute, 5*time.Minute, testEncryptor(),
		WithSecurityAuditor(auditor))
	ctx := context.Background()
	current, err := svc.CreateSession(ctx, inventoryInput("user_detached_audit", false))
	if err != nil {
		t.Fatalf("create current: %v", err)
	}
	victim, err := svc.CreateSession(ctx, inventoryInput("user_detached_audit", false))
	if err != nil {
		t.Fatalf("create victim: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := svc.RevokeSession(cancelled, "user_detached_audit", current.Record.SessionID, victim.Record.SessionID); err != nil {
		t.Fatalf("revoke under cancelled caller context: %v", err)
	}
	if len(auditor.contextErrors) != 1 || auditor.contextErrors[0] != nil {
		t.Fatalf("audit inherited caller cancellation: %v", auditor.contextErrors)
	}
}

func TestRevokeAuditRecordsProviderFailureClass(t *testing.T) {
	auditor := &fakeAuditor{}
	revoker := &fakeRevoker{failRef: "provider-ref-degraded"}
	svc := NewService(newFakeStore(), SystemClock{},
		12*time.Hour, 720*time.Hour, 15*time.Minute, 5*time.Minute, testEncryptor(),
		WithProviderRevoker(revoker), WithSecurityAuditor(auditor))
	ctx := context.Background()

	current, err := svc.CreateSession(ctx, inventoryInput("user_audit_fc", false))
	if err != nil {
		t.Fatalf("create current: %v", err)
	}
	input := inventoryInput("user_audit_fc", false)
	input.ProviderSessionReference = "provider-ref-degraded"
	victim, err := svc.CreateSession(ctx, input)
	if err != nil {
		t.Fatalf("create victim: %v", err)
	}

	// Local revocation succeeds even though the provider cleanup degraded;
	// the durable audit row must record the failure class (ADR-0006 §2).
	if err := svc.RevokeSession(ctx, "user_audit_fc", current.Record.SessionID, victim.Record.SessionID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("recorded %d audit events, want 1", len(auditor.events))
	}
	ev := auditor.events[0]
	if ev.EventType != EventSessionRevokedOther || ev.Result != AuditOutcomeSuccess {
		t.Errorf("audit event/result = %q/%q, want %q/%q", ev.EventType, ev.Result, EventSessionRevokedOther, AuditOutcomeSuccess)
	}
	if ev.FailureClass == "" {
		t.Error("a degraded provider cleanup must be recorded as a durable failure class")
	}
}

func TestBulkRevokeAuditRecordsProviderFailureClass(t *testing.T) {
	auditor := &fakeAuditor{}
	revoker := &fakeRevoker{failRef: "provider-ref-degraded-bulk"}
	svc := NewService(newFakeStore(), SystemClock{},
		12*time.Hour, 720*time.Hour, 15*time.Minute, 5*time.Minute, testEncryptor(),
		WithProviderRevoker(revoker), WithSecurityAuditor(auditor))
	ctx := context.Background()

	current, err := svc.CreateSession(ctx, inventoryInput("user_audit_fc_bulk", false))
	if err != nil {
		t.Fatalf("create current: %v", err)
	}
	input := inventoryInput("user_audit_fc_bulk", false)
	input.ProviderSessionReference = "provider-ref-degraded-bulk"
	if _, err := svc.CreateSession(ctx, input); err != nil {
		t.Fatalf("create victim: %v", err)
	}

	if _, err := svc.RevokeAllOtherSessions(ctx, "user_audit_fc_bulk", current.Record.SessionID); err != nil {
		t.Fatalf("bulk revoke: %v", err)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("recorded %d audit events, want 1", len(auditor.events))
	}
	ev := auditor.events[0]
	if ev.EventType != EventSessionsRevokedOthers || ev.Result != AuditOutcomeSuccess {
		t.Errorf("audit event/result = %q/%q", ev.EventType, ev.Result)
	}
	if ev.FailureClass == "" {
		t.Error("a degraded victim provider cleanup must surface in the bulk audit failure class")
	}
	if ev.AffectedCount != 1 {
		t.Errorf("bulk audit affected count = %d, want 1", ev.AffectedCount)
	}
}

func TestRevokeSucceedsWhenAuditRecorderFails(t *testing.T) {
	auditor := &fakeAuditor{err: errors.New("postgres: insert security event: connection refused")}
	store := newFakeStore()
	svc := NewService(store, SystemClock{},
		12*time.Hour, 720*time.Hour, 15*time.Minute, 5*time.Minute, testEncryptor(),
		WithSecurityAuditor(auditor))
	ctx := context.Background()

	current, err := svc.CreateSession(ctx, inventoryInput("user_audit_fail", false))
	if err != nil {
		t.Fatalf("create current: %v", err)
	}
	other, err := svc.CreateSession(ctx, inventoryInput("user_audit_fail", false))
	if err != nil {
		t.Fatalf("create other: %v", err)
	}

	// Audit is best-effort at the call site: the revocation already
	// succeeded, so a recorder outage must never mask its outcome.
	if err := svc.RevokeSession(ctx, "user_audit_fail", current.Record.SessionID, other.Record.SessionID); err != nil {
		t.Fatalf("revoke must succeed despite audit failure, got %v", err)
	}
	if len(store.sessions) != 1 {
		t.Fatalf("%d sessions remain, want 1", len(store.sessions))
	}
}
