package riskdefense

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryRegistrationReservation struct {
	challengeHash string
	expiresAt     time.Time
}

type memoryStore struct {
	mu                      sync.Mutex
	devices                 map[string]bool
	attempts                map[string]int
	challenges              map[string]ChallengeRecord
	claims                  map[string]string
	trust                   map[string]TrustRecord
	completions             map[string]int
	activeRegistration      map[string]memoryRegistrationReservation
	registrationIssues      map[string]int
	registrationCompletions map[string]int
	now                     func() time.Time
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		devices: map[string]bool{}, attempts: map[string]int{}, challenges: map[string]ChallengeRecord{},
		claims: map[string]string{}, trust: map[string]TrustRecord{}, completions: map[string]int{},
		activeRegistration: map[string]memoryRegistrationReservation{}, registrationIssues: map[string]int{},
		registrationCompletions: map[string]int{}, now: time.Now,
	}
}

func (s *memoryStore) RegisterDevice(_ context.Context, hash string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[hash] = true
	return nil
}
func (s *memoryStore) DeviceExists(_ context.Context, hash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devices[hash], nil
}
func (s *memoryStore) Observe(_ context.Context, operation Operation, deviceHash, _ string, _ time.Duration) (Activity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(operation) + ":" + deviceHash
	s.attempts[key]++
	return Activity{Attempts: s.attempts[key]}, nil
}
func (s *memoryStore) CreateChallenge(_ context.Context, hash string, record ChallengeRecord, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[hash] = record
	return nil
}
func (s *memoryStore) ReserveRegistrationChallenge(_ context.Context, scopeHash, challengeHash string, ttl time.Duration) (bool, time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if active, ok := s.activeRegistration[scopeHash]; ok && now.Before(active.expiresAt) {
		return false, active.expiresAt.Sub(now), nil
	}
	s.activeRegistration[scopeHash] = memoryRegistrationReservation{challengeHash: challengeHash, expiresAt: now.Add(ttl)}
	return true, 0, nil
}
func (s *memoryStore) FinalizeRegistrationChallenge(_ context.Context, scopeHash, challengeHash string, record ChallengeRecord, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	active, ok := s.activeRegistration[scopeHash]
	if !ok || !s.now().Before(active.expiresAt) || active.challengeHash != challengeHash {
		return ErrChallengeNotHeld
	}
	if _, exists := s.challenges[challengeHash]; exists {
		return errors.New("duplicate challenge")
	}
	s.challenges[challengeHash] = record
	s.activeRegistration[scopeHash] = memoryRegistrationReservation{challengeHash: challengeHash, expiresAt: s.now().Add(ttl)}
	return nil
}
func (s *memoryStore) ReleaseRegistrationChallenge(_ context.Context, scopeHash, challengeHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	active, ok := s.activeRegistration[scopeHash]
	if !ok || active.challengeHash != challengeHash {
		return ErrChallengeNotHeld
	}
	delete(s.activeRegistration, scopeHash)
	return nil
}
func (s *memoryStore) ClaimChallenge(_ context.Context, hash, claimID string) (ChallengeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claims[hash] != claimID {
		return ErrChallengeNotHeld
	}
	delete(s.claims, hash)
	return nil
}
func (s *memoryStore) ConsumeChallenge(_ context.Context, hash, claimID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.consumeChallenge(hash, claimID, "")
}
func (s *memoryStore) ConsumeRegistrationChallenge(_ context.Context, hash, claimID, scopeHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.consumeChallenge(hash, claimID, scopeHash)
}
func (s *memoryStore) consumeChallenge(hash, claimID, scopeHash string) error {
	if s.claims[hash] != claimID {
		return ErrChallengeNotHeld
	}
	if _, ok := s.challenges[hash]; !ok {
		return ErrChallengeNotFound
	}
	delete(s.challenges, hash)
	delete(s.claims, hash)
	if active, ok := s.activeRegistration[scopeHash]; ok && active.challengeHash == hash {
		delete(s.activeRegistration, scopeHash)
	}
	return nil
}
func (s *memoryStore) PutTrust(_ context.Context, hash string, record TrustRecord, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trust[hash] = record
	return nil
}
func (s *memoryStore) GetTrust(_ context.Context, hash string) (TrustRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.trust[hash]
	if !ok {
		return TrustRecord{}, ErrTrustNotFound
	}
	return record, nil
}
func (s *memoryStore) CheckCompletionRate(_ context.Context, hash string, limit int, _ time.Duration) (bool, time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completions[hash]++
	if s.completions[hash] > limit {
		return false, time.Minute, nil
	}
	return true, 0, nil
}
func (s *memoryStore) CheckRegistrationIssueRate(_ context.Context, deviceHash, networkHash string, policy RegistrationIssueRatePolicy) (bool, time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := []string{"device:" + deviceHash, "network:" + networkHash, "global:burst", "global:sustained"}
	limits := []int{policy.Device.Max, policy.Network.Max, policy.GlobalBurst.Max, policy.GlobalSustained.Max}
	for index, key := range keys {
		if limits[index] <= 0 || s.registrationIssues[key] >= limits[index] {
			return false, time.Minute, nil
		}
	}
	for _, key := range keys {
		s.registrationIssues[key]++
	}
	return true, 0, nil
}
func (s *memoryStore) CheckRegistrationCompletionRate(_ context.Context, deviceHash, networkHash string, deviceLimit, networkLimit int, _ time.Duration) (bool, time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return checkDualMemoryRate(s.registrationCompletions, deviceHash, networkHash, deviceLimit, networkLimit)
}
func checkDualMemoryRate(counts map[string]int, deviceHash, networkHash string, deviceLimit, networkLimit int) (bool, time.Duration, error) {
	deviceKey, networkKey := "device:"+deviceHash, "network:"+networkHash
	if counts[deviceKey] >= deviceLimit || counts[networkKey] >= networkLimit {
		return false, time.Minute, nil
	}
	counts[deviceKey]++
	counts[networkKey]++
	return true, 0, nil
}

type interactiveFake struct {
	mu                      sync.Mutex
	beginCalls, verifyCalls int
}

func (p *interactiveFake) Begin(_ context.Context, _ Operation) (ProviderChallenge, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.beginCalls++
	return ProviderChallenge{ID: "provider-challenge", Provider: "aliyun_captcha2", PublicPayload: []byte(`{"scene":"register"}`)}, nil
}
func (p *interactiveFake) Verify(_ context.Context, id, proof string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
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
	var sequence atomic.Uint64
	return Config{
		Enabled: true, ObservationWindow: time.Minute, LoginMediumAfter: 2, LoginHighAfter: 3,
		RegistrationMediumAfter: 2, RegistrationHighAfter: 3, ChallengeTTL: time.Minute,
		DeviceIDTTL: time.Hour, TrustTTL: 5 * time.Minute, AutomationCostDifficulty: 1,
		CompletionLimit: 3, CompletionWindow: time.Minute, Now: func() time.Time { return now },
		GenerateToken: func() (string, error) { return fmt.Sprintf("token-%d", sequence.Add(1)), nil },
	}
}

func registrationSignal(identifier string) Signal {
	return Signal{
		Operation: OperationRegistration, IdentifierHash: hash(identifier),
		UserAgentHash: hash("ua"), ClientNetworkHash: hash("203.0.113.0/24"),
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

func TestNewServiceHonorsExplicitZeroRegistrationIssueQueue(t *testing.T) {
	cfg := testConfig(time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC))
	cfg.RegistrationIssueMaxInFlight = 1
	cfg.RegistrationIssueMaxQueued = 0
	svc, err := NewService(newMemoryStore(), &interactiveFake{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := cap(svc.registrationIssueAdmission.total); got != 1 {
		t.Fatalf("total admission capacity=%d, want one active slot and no queue", got)
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

func TestFirstRegistrationAlwaysRequiresInteractiveChallenge(t *testing.T) {
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	provider := &interactiveFake{}
	cfg := testConfig(now)
	cfg.AllowlistedHashes = []string{hash("new@example.com")}
	svc, err := NewService(store, provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	signal := registrationSignal("new@example.com")
	signal.SessionTrusted = true
	first, err := svc.Assess(t.Context(), signal)
	if err != nil || first.Allow || first.Challenge == nil || first.Challenge.Level != LevelHigh || first.Challenge.Method != MethodInteractiveCAPTCHA || first.Challenge.Provider != "aliyun_captcha2" {
		t.Fatalf("first decision=%#v err=%v", first, err)
	}
	signal.DeviceIDToken = first.DeviceIDToken
	completed, err := svc.Complete(t.Context(), Completion{ChallengeToken: first.Challenge.Token, ProviderProof: "provider-proof", DeviceIDToken: signal.DeviceIDToken, UserAgentHash: signal.UserAgentHash})
	if err != nil {
		t.Fatalf("interactive completion: %v", err)
	}
	signal.DeviceTrustToken = completed.TrustToken
	retry, err := svc.Assess(t.Context(), signal)
	if err != nil || !retry.Allow || retry.Challenge != nil {
		t.Fatalf("trusted retry=%#v err=%v", retry, err)
	}
	if provider.beginCalls != 1 || provider.verifyCalls != 1 {
		t.Fatalf("provider calls=%d/%d", provider.beginCalls, provider.verifyCalls)
	}
	if len(store.activeRegistration) != 0 {
		t.Fatalf("completed challenge left active registration scope=%v", store.activeRegistration)
	}
}

func TestEnsureDeviceReusesKnownTokenAndReplacesUnknownToken(t *testing.T) {
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	svc, err := NewService(store, &interactiveFake{}, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := svc.EnsureDevice(t.Context(), "")
	if err != nil || issued == "" || !store.devices[hash(issued)] {
		t.Fatalf("issued=%q registered=%v err=%v", issued, store.devices[hash(issued)], err)
	}
	reused, err := svc.EnsureDevice(t.Context(), issued)
	if err != nil || reused != issued {
		t.Fatalf("reused=%q want=%q err=%v", reused, issued, err)
	}
	replacement, err := svc.EnsureDevice(t.Context(), "caller-invented-device")
	if err != nil || replacement == "" || replacement == "caller-invented-device" || replacement == issued || !store.devices[hash(replacement)] {
		t.Fatalf("replacement=%q issued=%q registered=%v err=%v", replacement, issued, store.devices[hash(replacement)], err)
	}
}

func TestRegistrationFailsClosedWithoutInteractiveProviderWhileLoginRetainsCostFallback(t *testing.T) {
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store2 := newMemoryStore()
	cfg := testConfig(now)
	svc2, _ := NewService(store2, nil, cfg)
	signal := registrationSignal("new@example.com")
	if decision, err := svc2.Assess(t.Context(), signal); !errors.Is(err, ErrUnavailable) || decision.Allow || decision.Challenge != nil {
		t.Fatalf("registration without provider=%#v err=%v", decision, err)
	}

	store3 := newMemoryStore()
	unavailable := &unavailableInteractiveFake{}
	svc3, _ := NewService(store3, unavailable, cfg)
	signal = registrationSignal("other@example.com")
	if decision, err := svc3.Assess(t.Context(), signal); !errors.Is(err, ErrUnavailable) || decision.Challenge != nil || unavailable.beginCalls != 1 || len(store3.activeRegistration) != 0 {
		t.Fatalf("unavailable registration provider=%#v calls=%d active=%d err=%v", decision, unavailable.beginCalls, len(store3.activeRegistration), err)
	}

	loginStore := newMemoryStore()
	loginService, _ := NewService(loginStore, nil, cfg)
	loginSignal := Signal{Operation: OperationLogin, IdentifierHash: hash("login@example.com"), UserAgentHash: hash("ua"), ReplayAnomaly: true}
	first, _ := loginService.Assess(t.Context(), loginSignal)
	loginSignal.DeviceIDToken = first.DeviceIDToken
	_, _ = loginService.Assess(t.Context(), loginSignal)
	high, err := loginService.Assess(t.Context(), loginSignal)
	if err != nil || high.Challenge == nil || high.Challenge.Method != MethodAutomationCost || high.Challenge.Difficulty <= cfg.AutomationCostDifficulty {
		t.Fatalf("login fallback=%#v err=%v", high, err)
	}
}

func TestRegistrationTrustOnlyRetriesTheChallengedIdentifier(t *testing.T) {
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	provider := &interactiveFake{}
	svc, err := NewService(store, provider, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	signal := registrationSignal("first@example.com")
	first, _ := svc.Assess(t.Context(), signal)
	signal.DeviceIDToken = first.DeviceIDToken
	completed, err := svc.Complete(t.Context(), Completion{
		ChallengeToken: first.Challenge.Token, ProviderProof: "provider-proof",
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

func TestRegistrationConcurrentAssessCreatesOnlyOneActiveChallenge(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	store.now = func() time.Time { return now }
	provider := &interactiveFake{}
	svc, err := NewService(store, provider, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	device, err := svc.EnsureDevice(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	signal := registrationSignal("same-intent@example.com")
	signal.DeviceIDToken = device

	start := make(chan struct{})
	type result struct {
		decision Decision
		err      error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			decision, assessErr := svc.Assess(t.Context(), signal)
			results <- result{decision: decision, err: assessErr}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	issued, limited := 0, 0
	for got := range results {
		switch {
		case got.err == nil && got.decision.Challenge != nil:
			issued++
		case errors.Is(got.err, ErrRateLimited):
			limited++
		default:
			t.Fatalf("unexpected concurrent result=%#v err=%v", got.decision, got.err)
		}
	}
	if issued != 1 || limited != 1 || provider.beginCalls != 1 || len(store.challenges) != 1 {
		t.Fatalf("issued=%d limited=%d providerBegins=%d challenges=%d", issued, limited, provider.beginCalls, len(store.challenges))
	}
}

func TestRegistrationActiveChallengeExpiresThenReissuesWithinBudget(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	store.now = func() time.Time { return now }
	provider := &interactiveFake{}
	cfg := testConfig(now)
	cfg.Now = func() time.Time { return now }
	svc, err := NewService(store, provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	signal := registrationSignal("expiring-intent@example.com")
	first, err := svc.Assess(t.Context(), signal)
	if err != nil || first.Challenge == nil {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	signal.DeviceIDToken = first.DeviceIDToken
	if repeated, repeatErr := svc.Assess(t.Context(), signal); !errors.Is(repeatErr, ErrRateLimited) || repeated.Challenge != nil {
		t.Fatalf("repeat=%#v err=%v, want rate limit", repeated, repeatErr)
	}
	now = now.Add(cfg.ChallengeTTL + time.Nanosecond)
	reissued, err := svc.Assess(t.Context(), signal)
	if err != nil || reissued.Challenge == nil || reissued.Challenge.Token == first.Challenge.Token || provider.beginCalls != 2 {
		t.Fatalf("reissued=%#v err=%v providerBegins=%d", reissued, err, provider.beginCalls)
	}
}

func TestRegistrationDifferentIntentsHaveIndependentActiveChallenges(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	provider := &interactiveFake{}
	svc, err := NewService(store, provider, testConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	device, err := svc.EnsureDevice(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	firstSignal := registrationSignal("intent-a@example.com")
	firstSignal.DeviceIDToken = device
	secondSignal := registrationSignal("intent-b@example.com")
	secondSignal.DeviceIDToken = device
	first, firstErr := svc.Assess(t.Context(), firstSignal)
	second, secondErr := svc.Assess(t.Context(), secondSignal)
	if firstErr != nil || secondErr != nil || first.Challenge == nil || second.Challenge == nil || first.Challenge.Token == second.Challenge.Token {
		t.Fatalf("first=%#v err=%v second=%#v err=%v", first, firstErr, second, secondErr)
	}
	if provider.beginCalls != 2 || len(store.activeRegistration) != 2 {
		t.Fatalf("providerBegins=%d activeScopes=%d", provider.beginCalls, len(store.activeRegistration))
	}
}

func TestRegistrationIssueBudgetBlocksBeforeAllocatingAnotherProviderAnswer(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	provider := &interactiveFake{}
	cfg := testConfig(now)
	cfg.RegistrationIssueDeviceLimit = 1
	cfg.RegistrationIssueNetworkLimit = 10
	svc, err := NewService(store, provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	device, err := svc.EnsureDevice(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	firstSignal := registrationSignal("budget-a@example.com")
	firstSignal.DeviceIDToken = device
	if first, firstErr := svc.Assess(t.Context(), firstSignal); firstErr != nil || first.Challenge == nil {
		t.Fatalf("first=%#v err=%v", first, firstErr)
	}
	secondSignal := registrationSignal("budget-b@example.com")
	secondSignal.DeviceIDToken = device
	second, secondErr := svc.Assess(t.Context(), secondSignal)
	if !errors.Is(secondErr, ErrRateLimited) || second.Challenge != nil {
		t.Fatalf("second=%#v err=%v, want issuance rate limit", second, secondErr)
	}
	if provider.beginCalls != 1 || len(store.activeRegistration) != 1 {
		t.Fatalf("providerBegins=%d activeScopes=%d", provider.beginCalls, len(store.activeRegistration))
	}
}

func TestRegistrationCompletionBudgetCannotResetWithNewChallenge(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	store.now = func() time.Time { return now }
	provider := &interactiveFake{}
	cfg := testConfig(now)
	cfg.Now = func() time.Time { return now }
	cfg.RegistrationCompletionDeviceLimit = 2
	cfg.RegistrationCompletionNetworkLimit = 10
	svc, err := NewService(store, provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	signal := registrationSignal("completion-budget@example.com")
	for attempt := 1; attempt <= 3; attempt++ {
		decision, assessErr := svc.Assess(t.Context(), signal)
		if assessErr != nil || decision.Challenge == nil {
			t.Fatalf("issue %d decision=%#v err=%v", attempt, decision, assessErr)
		}
		signal.DeviceIDToken = decision.DeviceIDToken
		_, completeErr := svc.Complete(t.Context(), Completion{
			ChallengeToken: decision.Challenge.Token, ProviderProof: "wrong-proof",
			DeviceIDToken: signal.DeviceIDToken, UserAgentHash: signal.UserAgentHash,
		})
		if attempt < 3 && !errors.Is(completeErr, ErrInvalidProof) {
			t.Fatalf("completion %d err=%v, want invalid proof", attempt, completeErr)
		}
		if attempt == 3 && !errors.Is(completeErr, ErrRateLimited) {
			t.Fatalf("completion %d err=%v, want aggregate rate limit", attempt, completeErr)
		}
		now = now.Add(cfg.ChallengeTTL + time.Nanosecond)
	}
	if provider.verifyCalls != 2 {
		t.Fatalf("provider verify calls=%d, third attempt must be blocked before verification", provider.verifyCalls)
	}
}

func TestTrustCannotCrossOperationOrLoginIdentifier(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	cfg := testConfig(now)
	cfg.LoginMediumAfter = 1
	cfg.LoginHighAfter = 2

	t.Run("registration trust cannot enter login", func(t *testing.T) {
		store := newMemoryStore()
		provider := &interactiveFake{}
		svc, _ := NewService(store, provider, cfg)
		registration := registrationSignal("shared-identifier")
		challenge, err := svc.Assess(t.Context(), registration)
		if err != nil || challenge.Challenge == nil {
			t.Fatalf("registration challenge=%#v err=%v", challenge, err)
		}
		registration.DeviceIDToken = challenge.DeviceIDToken
		completed, err := svc.Complete(t.Context(), Completion{
			ChallengeToken: challenge.Challenge.Token, ProviderProof: "provider-proof",
			DeviceIDToken: registration.DeviceIDToken, UserAgentHash: registration.UserAgentHash,
		})
		if err != nil {
			t.Fatal(err)
		}
		login := Signal{
			Operation: OperationLogin, IdentifierHash: registration.IdentifierHash,
			DeviceIDToken: registration.DeviceIDToken, DeviceTrustToken: completed.TrustToken,
			UserAgentHash: registration.UserAgentHash, ReplayAnomaly: true,
		}
		decision, err := svc.Assess(t.Context(), login)
		if err != nil || decision.Allow || decision.Challenge == nil {
			t.Fatalf("login with registration trust=%#v err=%v", decision, err)
		}
	})

	t.Run("login trust cannot enter registration", func(t *testing.T) {
		store := newMemoryStore()
		provider := &interactiveFake{}
		svc, _ := NewService(store, provider, cfg)
		login := Signal{Operation: OperationLogin, IdentifierHash: hash("login-a"), UserAgentHash: hash("ua"), ReplayAnomaly: true}
		challenge, err := svc.Assess(t.Context(), login)
		if err != nil || challenge.Challenge == nil {
			t.Fatalf("login challenge=%#v err=%v", challenge, err)
		}
		login.DeviceIDToken = challenge.DeviceIDToken
		completed, err := svc.Complete(t.Context(), Completion{
			ChallengeToken: challenge.Challenge.Token,
			Nonce:          solveAutomationCost(challenge.Challenge.Token, challenge.Challenge.Difficulty),
			DeviceIDToken:  login.DeviceIDToken, UserAgentHash: login.UserAgentHash,
		})
		if err != nil {
			t.Fatal(err)
		}
		registration := registrationSignal("login-a")
		registration.DeviceIDToken = login.DeviceIDToken
		registration.DeviceTrustToken = completed.TrustToken
		decision, err := svc.Assess(t.Context(), registration)
		if err != nil || decision.Allow || decision.Challenge == nil {
			t.Fatalf("registration with login trust=%#v err=%v", decision, err)
		}
	})

	t.Run("login trust cannot change identifier", func(t *testing.T) {
		store := newMemoryStore()
		svc, _ := NewService(store, nil, cfg)
		loginA := Signal{Operation: OperationLogin, IdentifierHash: hash("login-a"), UserAgentHash: hash("ua"), ReplayAnomaly: true}
		challenge, err := svc.Assess(t.Context(), loginA)
		if err != nil || challenge.Challenge == nil {
			t.Fatalf("login A challenge=%#v err=%v", challenge, err)
		}
		loginA.DeviceIDToken = challenge.DeviceIDToken
		completed, err := svc.Complete(t.Context(), Completion{
			ChallengeToken: challenge.Challenge.Token,
			Nonce:          solveAutomationCost(challenge.Challenge.Token, challenge.Challenge.Difficulty),
			DeviceIDToken:  loginA.DeviceIDToken, UserAgentHash: loginA.UserAgentHash,
		})
		if err != nil {
			t.Fatal(err)
		}
		loginB := loginA
		loginB.IdentifierHash = hash("login-b")
		loginB.DeviceTrustToken = completed.TrustToken
		decision, err := svc.Assess(t.Context(), loginB)
		if err != nil || decision.Allow || decision.Challenge == nil {
			t.Fatalf("login B with login A trust=%#v err=%v", decision, err)
		}
	})
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

func TestUnknownChallengeCannotAllocateCompletionRateKeys(t *testing.T) {
	store := newMemoryStore()
	svc, err := NewService(store, nil, testConfig(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Complete(t.Context(), Completion{
		ChallengeToken: "caller-invented-challenge", DeviceIDToken: "caller-device", UserAgentHash: hash("ua"),
	})
	if !errors.Is(err, ErrChallengeNotFound) || len(store.completions) != 0 || len(store.registrationCompletions) != 0 {
		t.Fatalf("err=%v perChallenge=%v aggregate=%v", err, store.completions, store.registrationCompletions)
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
