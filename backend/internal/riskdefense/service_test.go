package riskdefense

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type memoryStore struct {
	devices     map[string]bool
	attempts    map[string]int
	challenges  map[string]ChallengeRecord
	claims      map[string]string
	trust       map[string]TrustRecord
	completions map[string]int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		devices: map[string]bool{}, attempts: map[string]int{}, challenges: map[string]ChallengeRecord{},
		claims: map[string]string{}, trust: map[string]TrustRecord{}, completions: map[string]int{},
	}
}

func (s *memoryStore) RegisterDevice(_ context.Context, hash string, _ time.Duration) error {
	s.devices[hash] = true
	return nil
}
func (s *memoryStore) DeviceExists(_ context.Context, hash string) (bool, error) {
	return s.devices[hash], nil
}
func (s *memoryStore) Observe(_ context.Context, operation Operation, deviceHash, _ string, _ time.Duration) (Activity, error) {
	key := string(operation) + ":" + deviceHash
	s.attempts[key]++
	return Activity{Attempts: s.attempts[key]}, nil
}
func (s *memoryStore) CreateChallenge(_ context.Context, hash string, record ChallengeRecord, _ time.Duration) error {
	s.challenges[hash] = record
	return nil
}
func (s *memoryStore) ClaimChallenge(_ context.Context, hash, claimID string) (ChallengeRecord, error) {
	record, ok := s.challenges[hash]
	if !ok {
		return ChallengeRecord{}, ErrChallengeNotFound
	}
	if s.claims[hash] != "" {
		return ChallengeRecord{}, ErrChallengeClaimed
	}
	s.claims[hash] = claimID
	return record, nil
}
func (s *memoryStore) ReleaseChallenge(_ context.Context, hash, claimID string) error {
	if s.claims[hash] != claimID {
		return ErrChallengeNotHeld
	}
	delete(s.claims, hash)
	return nil
}
func (s *memoryStore) ConsumeChallenge(_ context.Context, hash, claimID string) error {
	if s.claims[hash] != claimID {
		return ErrChallengeNotHeld
	}
	if _, ok := s.challenges[hash]; !ok {
		return ErrChallengeNotFound
	}
	delete(s.challenges, hash)
	delete(s.claims, hash)
	return nil
}
func (s *memoryStore) PutTrust(_ context.Context, hash string, record TrustRecord, _ time.Duration) error {
	s.trust[hash] = record
	return nil
}
func (s *memoryStore) GetTrust(_ context.Context, hash string) (TrustRecord, error) {
	record, ok := s.trust[hash]
	if !ok {
		return TrustRecord{}, ErrTrustNotFound
	}
	return record, nil
}
func (s *memoryStore) CheckCompletionRate(_ context.Context, hash string, limit int, _ time.Duration) (bool, time.Duration, error) {
	s.completions[hash]++
	if s.completions[hash] > limit {
		return false, time.Minute, nil
	}
	return true, 0, nil
}

type interactiveFake struct{ beginCalls, verifyCalls int }

func (p *interactiveFake) Begin(_ context.Context, _ Operation) (ProviderChallenge, error) {
	p.beginCalls++
	return ProviderChallenge{ID: "provider-challenge", Provider: "aliyun_captcha2", PublicPayload: []byte(`{"scene":"register"}`)}, nil
}
func (p *interactiveFake) Verify(_ context.Context, id, proof string) error {
	p.verifyCalls++
	if id != "provider-challenge" || proof != "provider-proof" {
		return ErrInvalidProof
	}
	return nil
}

type unavailableInteractiveFake struct{ beginCalls int }

func (p *unavailableInteractiveFake) Begin(context.Context, Operation) (ProviderChallenge, error) {
	p.beginCalls++
	return ProviderChallenge{}, ErrUnavailable
}
func (*unavailableInteractiveFake) Verify(context.Context, string, string) error {
	return ErrUnavailable
}

func testConfig(now time.Time) Config {
	sequence := 0
	return Config{
		Enabled: true, ObservationWindow: time.Minute, LoginMediumAfter: 2, LoginHighAfter: 3,
		RegistrationMediumAfter: 2, RegistrationHighAfter: 3, ChallengeTTL: time.Minute,
		DeviceIDTTL: time.Hour, TrustTTL: 5 * time.Minute, AutomationCostDifficulty: 1,
		CompletionLimit: 3, CompletionWindow: time.Minute, Now: func() time.Time { return now },
		GenerateToken: func() (string, error) { sequence++; return fmt.Sprintf("token-%d", sequence), nil },
	}
}

func TestLowRiskIsTransparentAndMediumUsesAutomationCost(t *testing.T) {
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	svc, err := NewService(store, nil, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	signal := Signal{Operation: OperationLogin, IdentifierHash: hash("alice@example.com"), UserAgentHash: hash("ua")}

	first, err := svc.Assess(t.Context(), signal)
	if err != nil || !first.Allow || first.DeviceIDToken == "" || first.Challenge != nil {
		t.Fatalf("first decision = %#v, err=%v", first, err)
	}
	signal.DeviceIDToken = first.DeviceIDToken
	signal.ProtocolAnomaly = true
	second, err := svc.Assess(t.Context(), signal)
	if err != nil || second.Allow || second.Challenge == nil || second.Challenge.Method != MethodAutomationCost || second.Challenge.Level != LevelMedium {
		t.Fatalf("second decision = %#v, err=%v", second, err)
	}

	nonce := solveAutomationCost(second.Challenge.Token, second.Challenge.Difficulty)
	completed, err := svc.Complete(t.Context(), Completion{
		ChallengeToken: second.Challenge.Token, Nonce: nonce,
		DeviceIDToken: signal.DeviceIDToken, UserAgentHash: signal.UserAgentHash,
	})
	if err != nil || completed.TrustToken == "" {
		t.Fatalf("complete=%#v err=%v", completed, err)
	}

	signal.DeviceTrustToken = completed.TrustToken
	trusted, err := svc.Assess(t.Context(), signal)
	if err != nil || !trusted.Allow || trusted.Challenge != nil {
		t.Fatalf("trusted decision = %#v, err=%v", trusted, err)
	}
	if _, err := svc.Complete(t.Context(), Completion{ChallengeToken: second.Challenge.Token, Nonce: nonce, DeviceIDToken: signal.DeviceIDToken, UserAgentHash: signal.UserAgentHash}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replay err=%v, want challenge-not-found", err)
	}
}

func TestRegistrationFrequencyProgressesFromTransparentToCostToInteractive(t *testing.T) {
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	provider := &interactiveFake{}
	svc, err := NewService(store, provider, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	signal := Signal{Operation: OperationRegistration, IdentifierHash: hash("new@example.com"), UserAgentHash: hash("ua")}
	first, err := svc.Assess(t.Context(), signal)
	if err != nil || !first.Allow || first.Challenge != nil {
		t.Fatalf("first decision=%#v err=%v", first, err)
	}
	signal.DeviceIDToken = first.DeviceIDToken
	medium, err := svc.Assess(t.Context(), signal)
	if err != nil || medium.Allow || medium.Challenge == nil || medium.Challenge.Level != LevelMedium || medium.Challenge.Method != MethodAutomationCost || !medium.Challenge.ProviderReady {
		t.Fatalf("medium decision=%#v err=%v", medium, err)
	}
	high, err := svc.Assess(t.Context(), signal)
	if err != nil || high.Challenge == nil || high.Challenge.Level != LevelHigh || high.Challenge.Method != MethodInteractiveCAPTCHA || high.Challenge.Provider != "aliyun_captcha2" || !high.Challenge.ProviderReady {
		t.Fatalf("high decision=%#v err=%v", high, err)
	}
	if _, err := svc.Complete(t.Context(), Completion{ChallengeToken: high.Challenge.Token, ProviderProof: "provider-proof", DeviceIDToken: signal.DeviceIDToken, UserAgentHash: signal.UserAgentHash}); err != nil {
		t.Fatalf("interactive completion: %v", err)
	}
	if provider.beginCalls != 1 || provider.verifyCalls != 1 {
		t.Fatalf("provider calls=%d/%d", provider.beginCalls, provider.verifyCalls)
	}
}

func TestHighRiskWithoutInteractiveProviderFallsBackToStrongerAutomationCost(t *testing.T) {
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store2 := newMemoryStore()
	cfg := testConfig(now)
	svc2, _ := NewService(store2, nil, cfg)
	signal := Signal{Operation: OperationRegistration, IdentifierHash: hash("new@example.com"), UserAgentHash: hash("ua")}
	first, _ := svc2.Assess(t.Context(), signal)
	signal.DeviceIDToken = first.DeviceIDToken
	_, _ = svc2.Assess(t.Context(), signal)
	high, err := svc2.Assess(t.Context(), signal)
	if err != nil || high.Challenge == nil || high.Challenge.Level != LevelHigh || high.Challenge.Method != MethodAutomationCost || !high.Challenge.ProviderReady || high.Challenge.Difficulty <= cfg.AutomationCostDifficulty {
		t.Fatalf("fallback high decision=%#v err=%v", high, err)
	}
	nonce := solveAutomationCost(high.Challenge.Token, high.Challenge.Difficulty)
	if _, err := svc2.Complete(t.Context(), Completion{ChallengeToken: high.Challenge.Token, Nonce: nonce, DeviceIDToken: signal.DeviceIDToken, UserAgentHash: signal.UserAgentHash}); err != nil {
		t.Fatalf("fallback completion err=%v", err)
	}

	store3 := newMemoryStore()
	unavailable := &unavailableInteractiveFake{}
	svc3, _ := NewService(store3, unavailable, cfg)
	signal = Signal{Operation: OperationRegistration, IdentifierHash: hash("other@example.com"), UserAgentHash: hash("ua")}
	first, _ = svc3.Assess(t.Context(), signal)
	signal.DeviceIDToken = first.DeviceIDToken
	_, _ = svc3.Assess(t.Context(), signal)
	high, err = svc3.Assess(t.Context(), signal)
	if err != nil || high.Challenge == nil || high.Challenge.Method != MethodAutomationCost || !high.Challenge.ProviderReady || unavailable.beginCalls != 1 {
		t.Fatalf("unavailable-provider fallback=%#v calls=%d err=%v", high, unavailable.beginCalls, err)
	}
}

func TestRegistrationTrustOnlyRetriesTheChallengedIdentifier(t *testing.T) {
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	svc, err := NewService(store, nil, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	signal := Signal{Operation: OperationRegistration, IdentifierHash: hash("first@example.com"), UserAgentHash: hash("ua")}
	first, _ := svc.Assess(t.Context(), signal)
	signal.DeviceIDToken = first.DeviceIDToken
	medium, _ := svc.Assess(t.Context(), signal)
	nonce := solveAutomationCost(medium.Challenge.Token, medium.Challenge.Difficulty)
	completed, err := svc.Complete(t.Context(), Completion{
		ChallengeToken: medium.Challenge.Token, Nonce: nonce,
		DeviceIDToken: signal.DeviceIDToken, UserAgentHash: signal.UserAgentHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	signal.DeviceTrustToken = completed.TrustToken
	retry, err := svc.Assess(t.Context(), signal)
	if err != nil || !retry.Allow || retry.Challenge != nil {
		t.Fatalf("same-identifier retry=%#v err=%v", retry, err)
	}

	signal.IdentifierHash = hash("second@example.com")
	different, err := svc.Assess(t.Context(), signal)
	if err != nil || different.Allow || different.Challenge == nil || different.Challenge.Level != LevelHigh {
		t.Fatalf("different-identifier decision=%#v err=%v", different, err)
	}
}

func TestLoginAttemptRateAloneNeverTriggersStepUp(t *testing.T) {
	now := time.Now().UTC()
	store := newMemoryStore()
	svc, err := NewService(store, nil, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	signal := Signal{Operation: OperationLogin, IdentifierHash: hash("human@example.com"), UserAgentHash: hash("ua")}
	for attempt := 0; attempt < 12; attempt++ {
		decision, assessErr := svc.Assess(t.Context(), signal)
		if assessErr != nil || !decision.Allow || decision.Challenge != nil {
			t.Fatalf("rate-only attempt %d decision=%#v err=%v", attempt+1, decision, assessErr)
		}
		signal.DeviceIDToken = decision.DeviceIDToken
	}
}

func TestChallengeFailuresAreRateLimited(t *testing.T) {
	now := time.Now().UTC()
	store := newMemoryStore()
	cfg := testConfig(now)
	cfg.CompletionLimit = 1
	svc, err := NewService(store, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	signal := Signal{Operation: OperationLogin, IdentifierHash: hash("user@example.com"), UserAgentHash: hash("ua")}
	first, _ := svc.Assess(t.Context(), signal)
	signal.DeviceIDToken = first.DeviceIDToken
	signal.ProtocolAnomaly = true
	challenge, _ := svc.Assess(t.Context(), signal)
	input := Completion{ChallengeToken: challenge.Challenge.Token, DeviceIDToken: signal.DeviceIDToken, UserAgentHash: signal.UserAgentHash}
	if _, err := svc.Complete(t.Context(), input); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("first failure err=%v", err)
	}
	if _, err := svc.Complete(t.Context(), input); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second failure err=%v, want rate limited", err)
	}
}

func TestAllowlistAndSessionTrustBypassObservation(t *testing.T) {
	now := time.Now().UTC()
	store := newMemoryStore()
	cfg := testConfig(now)
	allowlisted := hash("allowed@example.com")
	cfg.AllowlistedHashes = []string{allowlisted}
	svc, err := NewService(store, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}

	decision, err := svc.Assess(t.Context(), Signal{Operation: OperationLogin, IdentifierHash: allowlisted, UserAgentHash: hash("ua")})
	if err != nil || !decision.Allow || len(store.attempts) != 0 {
		t.Fatalf("allowlist decision=%#v err=%v attempts=%v", decision, err, store.attempts)
	}
	decision, err = svc.Assess(t.Context(), Signal{Operation: OperationLogin, IdentifierHash: hash("other"), UserAgentHash: hash("ua"), SessionTrusted: true})
	if err != nil || !decision.Allow || len(store.attempts) != 0 {
		t.Fatalf("session decision=%#v err=%v attempts=%v", decision, err, store.attempts)
	}
}

func solveAutomationCost(token string, difficulty uint8) string {
	for n := 0; ; n++ {
		nonce := fmt.Sprintf("%d", n)
		if validAutomationCost(token, nonce, difficulty) {
			return nonce
		}
	}
}

func phoneChangeSignal(identifier string) Signal {
	return Signal{
		Operation: OperationPhoneChange, IdentifierHash: hash(identifier),
		UserAgentHash: hash("ua"), SessionTrusted: true,
	}
}

func TestPhoneChangeAlwaysDemandsHumanVerificationBoundToTheTargetNumber(t *testing.T) {
	now := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	provider := &interactiveFake{}
	svc, err := NewService(newMemoryStore(), provider, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	signal := phoneChangeSignal("user-1\x00+37257013843")

	first, err := svc.Assess(t.Context(), signal)
	if err != nil {
		t.Fatal(err)
	}
	if first.Allow || first.Challenge == nil || first.Challenge.Method != MethodInteractiveCAPTCHA ||
		first.Challenge.Level != LevelHigh || !first.Challenge.ProviderReady {
		t.Fatalf("first decision=%#v", first)
	}
	if provider.beginCalls != 1 {
		t.Fatalf("provider begin calls=%d", provider.beginCalls)
	}
	signal.DeviceIDToken = first.DeviceIDToken
	completed, err := svc.Complete(t.Context(), Completion{
		ChallengeToken: first.Challenge.Token, ProviderProof: "provider-proof",
		DeviceIDToken: signal.DeviceIDToken, UserAgentHash: signal.UserAgentHash,
	})
	if err != nil || completed.TrustToken == "" {
		t.Fatalf("complete=%#v err=%v", completed, err)
	}

	signal.DeviceTrustToken = completed.TrustToken
	retry, err := svc.Assess(t.Context(), signal)
	if err != nil || !retry.Allow {
		t.Fatalf("retry decision=%#v err=%v", retry, err)
	}

	signal.IdentifierHash = hash("user-1\x00+8613800138000")
	other, err := svc.Assess(t.Context(), signal)
	if err != nil {
		t.Fatal(err)
	}
	if other.Allow || other.Challenge == nil || other.Challenge.Method != MethodInteractiveCAPTCHA {
		t.Fatalf("other number decision=%#v", other)
	}
}

func TestPhoneChangeFailsClosedWhenTheInteractiveProviderIsUnavailable(t *testing.T) {
	now := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	provider := &unavailableInteractiveFake{}
	svc, err := NewService(newMemoryStore(), provider, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}

	decision, err := svc.Assess(t.Context(), phoneChangeSignal("user-1\x00+37257013843"))
	if !errors.Is(err, ErrUnavailable) || decision.Challenge != nil {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	if provider.beginCalls != 1 {
		t.Fatalf("provider begin calls=%d", provider.beginCalls)
	}
}
