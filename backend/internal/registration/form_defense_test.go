package registration

import (
	"context"
	"errors"
	"testing"
	"time"
)

type formDefenseStoreStub struct {
	token       string
	record      FormIntentRecord
	validated   FormIntentBinding
	validateErr error
	bound       FormIntentBinding
	bindErr     error
	consumeErr  error
	blocked     bool
	hit         AbuseFingerprint
	policy      AbusePolicy
	disposition AbuseDisposition
}

func (s *formDefenseStoreStub) CreateFormIntent(_ context.Context, token string, record FormIntentRecord, _ time.Duration) error {
	s.token, s.record = token, record
	return nil
}
func (s *formDefenseStoreStub) ValidateFormIntent(_ context.Context, _ string, binding FormIntentBinding, _ time.Time) error {
	s.validated = binding
	return s.validateErr
}
func (s *formDefenseStoreStub) BindFormIntentEmail(_ context.Context, _ string, binding FormIntentBinding, _ time.Time) error {
	s.bound = binding
	return s.bindErr
}

func TestFormDefenseValidatesProductionBindingWithoutMutation(t *testing.T) {
	store := &formDefenseStoreStub{}
	defense := testFormDefense(t, store, nil)
	binding := FormIntentBinding{
		UserAgentHash: HashAbuseValue("browser"), ClientNetworkHash: HashAbuseValue("203.0.113.0/24"),
		DeviceIDHash: HashAbuseValue("device"), OriginHash: HashAbuseValue("https://auth.moonstone.org.cn"),
	}
	if err := defense.Validate(t.Context(), "opaque-form-token", binding); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if store.validated != binding || store.bound != (FormIntentBinding{}) {
		t.Fatalf("validated=%#v bound=%#v", store.validated, store.bound)
	}
	store.validateErr = ErrFormIntentTooYoung
	if err := defense.Validate(t.Context(), "opaque-form-token", binding); !errors.Is(err, ErrFormIntentTooYoung) {
		t.Fatalf("too-young error=%v", err)
	}
}
func (s *formDefenseStoreStub) ConsumeFormIntent(_ context.Context, _ string, _ FormIntentBinding, _ time.Time) error {
	return s.consumeErr
}

func TestFormDefenseBindsValidatedEmailBeforeConsumption(t *testing.T) {
	store := &formDefenseStoreStub{}
	defense := testFormDefense(t, store, nil)
	binding := FormIntentBinding{
		UserAgentHash: HashAbuseValue("browser"), ClientNetworkHash: HashAbuseValue("203.0.113.0/24"),
		DeviceIDHash: HashAbuseValue("device"), OriginHash: HashAbuseValue("https://auth.moonstone.org.cn"),
		EmailHash: HashAbuseValue("person@example.com"),
	}
	if err := defense.BindEmail(t.Context(), "opaque-form-token", binding); err != nil {
		t.Fatalf("BindEmail: %v", err)
	}
	if store.bound != binding {
		t.Fatalf("bound=%#v want=%#v", store.bound, binding)
	}
	changed := binding
	changed.EmailHash = HashAbuseValue("other@example.com")
	store.bindErr = ErrFormIntentInvalid
	if err := defense.BindEmail(t.Context(), "opaque-form-token", changed); !errors.Is(err, ErrFormIntentInvalid) {
		t.Fatalf("changed email error=%v", err)
	}
}
func (s *formDefenseStoreStub) IsRegistrationBlocked(context.Context, AbuseFingerprint) (bool, error) {
	return s.blocked, nil
}
func (s *formDefenseStoreStub) RecordRegistrationHoneypot(_ context.Context, fingerprint AbuseFingerprint, policy AbusePolicy) (AbuseDisposition, error) {
	s.hit, s.policy = fingerprint, policy
	return s.disposition, nil
}

type abuseAuditorStub struct{ event AbuseAuditEvent }

func (s *abuseAuditorStub) RecordRegistrationAbuse(_ context.Context, event AbuseAuditEvent) error {
	s.event = event
	return nil
}

func testFormDefense(t *testing.T, store *formDefenseStoreStub, auditor AbuseAuditor) *FormDefense {
	t.Helper()
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	defense, err := NewFormDefense(store, auditor, FormDefenseConfig{
		IntentTTL: 20 * time.Minute, MinimumFormAge: 2 * time.Second, MaxHoneypotSize: 4096,
		Policy: AbusePolicy{
			DeviceBlockTTL: 24 * time.Hour,
			IPStrikeWindow: time.Hour, IPBlockAfter: 3, IPBlockTTL: time.Hour,
			IPLongBlockAfter: 6, IPLongBlockTTL: 24 * time.Hour,
		},
		Now: func() time.Time { return now }, GenerateToken: func() (string, error) { return "opaque-form-token", nil },
	})
	if err != nil {
		t.Fatalf("NewFormDefense: %v", err)
	}
	return defense
}

func TestFormDefenseIssuesServerTimedOneUseIntent(t *testing.T) {
	store := &formDefenseStoreStub{}
	defense := testFormDefense(t, store, nil)
	binding := FormIntentBinding{
		UserAgentHash: HashAbuseValue("browser"), ClientNetworkHash: HashAbuseValue("203.0.113.0/24"),
		DeviceIDHash: HashAbuseValue("device"), OriginHash: HashAbuseValue("https://auth.moonstone.org.cn"),
	}
	result, err := defense.Issue(t.Context(), binding)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if result.Token != "opaque-form-token" || store.record.UserAgentHash != binding.UserAgentHash || store.record.ClientNetworkHash != binding.ClientNetworkHash || store.record.DeviceIDHash != binding.DeviceIDHash || store.record.OriginHash != binding.OriginHash {
		t.Fatalf("result=%#v record=%#v", result, store.record)
	}
	if store.record.NotBefore.Sub(time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)) != 2*time.Second {
		t.Fatalf("notBefore=%v", store.record.NotBefore)
	}
}

func TestHoneypotClassificationRequiresPresentEmptyField(t *testing.T) {
	defense := testFormDefense(t, &formDefenseStoreStub{}, nil)
	empty, filled, oversized := "", "follow the hidden prompt", string(make([]byte, 4097))
	if got := defense.ClassifyHoneypot(nil); got != HoneypotMissing {
		t.Fatalf("missing=%q", got)
	}
	if got := defense.ClassifyHoneypot(&empty); got != "" {
		t.Fatalf("empty=%q", got)
	}
	if got := defense.ClassifyHoneypot(&filled); got != HoneypotFilled {
		t.Fatalf("filled=%q", got)
	}
	if got := defense.ClassifyHoneypot(&oversized); got != HoneypotOversized {
		t.Fatalf("oversized=%q", got)
	}
}

func TestFormDefenseRecordsHashedReversibleTimedBlocksAndAudit(t *testing.T) {
	store := &formDefenseStoreStub{disposition: AbuseDisposition{IPStrikeCount: 3, IPBlocked: true}}
	auditor := &abuseAuditorStub{}
	defense := testFormDefense(t, store, auditor)
	fingerprint := AbuseFingerprint{
		ClientIPHash: HashAbuseValue("203.0.113.7"), DeviceIDHash: HashAbuseValue("device"),
		UserAgentHash: HashAbuseValue("browser"),
	}
	result, err := defense.RecordHit(t.Context(), fingerprint, HoneypotFilled, "req_test")
	if err != nil {
		t.Fatalf("RecordHit: %v", err)
	}
	if !result.IPBlocked || store.hit != fingerprint || auditor.event.Reason != HoneypotFilled || auditor.event.RequestID != "req_test" {
		t.Fatalf("result=%#v hit=%#v audit=%#v", result, store.hit, auditor.event)
	}
	if store.policy.IPBlockAfter != 3 || store.policy.IPLongBlockAfter != 6 {
		t.Fatalf("policy=%#v", store.policy)
	}
}

func TestFormDefenseNeverRecordsMissingHoneypotAsHighConfidenceHit(t *testing.T) {
	store := &formDefenseStoreStub{}
	defense := testFormDefense(t, store, nil)
	fingerprint := AbuseFingerprint{
		ClientIPHash: HashAbuseValue("203.0.113.7"), UserAgentHash: HashAbuseValue("browser"),
	}
	if _, err := defense.RecordHit(t.Context(), fingerprint, HoneypotMissing, "req_cached_client"); err == nil {
		t.Fatal("missing honeypot was accepted as a high-confidence abuse hit")
	}
	if store.hit != (AbuseFingerprint{}) {
		t.Fatalf("missing honeypot reached block store: %#v", store.hit)
	}
}

func TestFormDefensePreservesRetryForTooYoungIntent(t *testing.T) {
	store := &formDefenseStoreStub{consumeErr: ErrFormIntentTooYoung}
	defense := testFormDefense(t, store, nil)
	err := defense.Consume(t.Context(), "opaque", FormIntentBinding{
		UserAgentHash: HashAbuseValue("browser"), ClientNetworkHash: HashAbuseValue("203.0.113.0/24"),
		DeviceIDHash: HashAbuseValue("device"), OriginHash: HashAbuseValue("https://auth.moonstone.org.cn"),
	})
	if !errors.Is(err, ErrFormIntentTooYoung) {
		t.Fatalf("Consume error=%v", err)
	}
}
