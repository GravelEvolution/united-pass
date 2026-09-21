package adminstepup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
	"github.com/GravelEvolution/united-pass/backend/internal/securitystate"
)

func TestNormalizeChallengeTextUsesNFKCAndUAX29Limits(t *testing.T) {
	combining := "e\u0301"
	question := strings.Repeat(combining, MinQuestionGraphemes)
	normalizedQuestion, err := NormalizeQuestion(question)
	if err != nil {
		t.Fatalf("NormalizeQuestion combining marks: %v", err)
	}
	if normalizedQuestion != strings.Repeat("é", MinQuestionGraphemes) {
		t.Fatalf("question was not NFKC normalized: %q", normalizedQuestion)
	}

	answer := "  " + strings.Repeat("🇨🇳", MinAnswerGraphemes) + "  "
	normalizedAnswer, err := NormalizeAnswer(answer)
	if err != nil {
		t.Fatalf("NormalizeAnswer flags: %v", err)
	}
	if normalizedAnswer != strings.Repeat("🇨🇳", MinAnswerGraphemes) {
		t.Fatalf("answer outer trim/UAX #29 mismatch: %q", normalizedAnswer)
	}

	for _, tc := range []struct {
		name string
		fn   func(string) (string, error)
		text string
	}{
		{"question below minimum", NormalizeQuestion, strings.Repeat("甲", MinQuestionGraphemes-1)},
		{"question above maximum", NormalizeQuestion, strings.Repeat("甲", MaxQuestionGraphemes+1)},
		{"answer below minimum", NormalizeAnswer, strings.Repeat("甲", MinAnswerGraphemes-1)},
		{"answer above maximum", NormalizeAnswer, strings.Repeat("甲", MaxAnswerGraphemes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.fn(tc.text); err == nil {
				t.Fatal("expected deterministic grapheme bound rejection")
			}
		})
	}

	if _, err := NormalizeQuestion(strings.Repeat("甲", MaxQuestionGraphemes)); err != nil {
		t.Fatalf("question exact maximum: %v", err)
	}
	if _, err := NormalizeAnswer(strings.Repeat("甲", MaxAnswerGraphemes)); err != nil {
		t.Fatalf("answer exact maximum: %v", err)
	}
}

func TestNormalizeChallengeTextRejectsControlFormatBidiAndZeroWidth(t *testing.T) {
	for _, forbidden := range []rune{'\x00', '\n', '\u200b', '\u200d', '\u202e', '\u2066', '\ufeff'} {
		text := strings.Repeat("甲", MinAnswerGraphemes) + string(forbidden)
		if _, err := NormalizeAnswer(text); !errors.Is(err, ErrForbiddenChallengeText) {
			t.Fatalf("rune U+%04X error=%v, want forbidden text", forbidden, err)
		}
	}
	if err := ValidateQuestionAnswer("同一个答案同一个", "同一个答案同一个"); !errors.Is(err, ErrQuestionEqualsAnswer) {
		t.Fatalf("question=answer error=%v", err)
	}
}

func TestAnswerHasherUsesPepperArgon2idAndRetainedReadKey(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x11}, 32)
	newKey := bytes.Repeat([]byte{0x22}, 32)
	oldRing, err := NewKeyring("old", map[string][]byte{"old": oldKey})
	if err != nil {
		t.Fatal(err)
	}
	params := Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
	hasher, err := NewAnswerHasher(oldRing, params, 1)
	if err != nil {
		t.Fatal(err)
	}
	phc, keyID, err := hasher.Hash(context.Background(), "  答案答案答案答案答案答案答案  ")
	if err != nil {
		t.Fatal(err)
	}
	if keyID != "old" || !strings.HasPrefix(phc, "$argon2id$") || strings.Contains(phc, "答案") {
		t.Fatalf("unsafe or unexpected hash metadata: key=%q phc=%q", keyID, phc)
	}

	rotatedRing, err := NewKeyring("new", map[string][]byte{"old": oldKey, "new": newKey})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewAnswerHasher(rotatedRing, params, 1)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := rotated.Verify(context.Background(), "答案答案答案答案答案答案答案", phc, keyID)
	if err != nil || !ok {
		t.Fatalf("verify retained key: ok=%v err=%v", ok, err)
	}
	ok, err = rotated.Verify(context.Background(), "错误错误错误错误错误错误错误", phc, keyID)
	if err != nil || ok {
		t.Fatalf("verify wrong answer: ok=%v err=%v", ok, err)
	}
	if _, err := rotated.Verify(context.Background(), "答案答案答案答案答案答案答案", phc, "missing"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("unknown pepper key error=%v", err)
	}
}

func TestAnswerHasherRejectsNonCanonicalPHCParameters(t *testing.T) {
	ring, err := NewKeyring("pepper", map[string][]byte{"pepper": bytes.Repeat([]byte{0x23}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := NewAnswerHasher(ring, Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}, 1)
	if err != nil {
		t.Fatal(err)
	}
	phc, keyID, err := hasher.Hash(context.Background(), "答案答案答案答案答案答案答案")
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical := strings.Replace(phc, "p=1$", "p=1junk$", 1)
	if ok, err := hasher.Verify(context.Background(), "答案答案答案答案答案答案答案", nonCanonical, keyID); err == nil || ok {
		t.Fatalf("non-canonical PHC accepted: ok=%v err=%v", ok, err)
	}
}

func TestAESGCMCipherBindsPurposeOwnerRecordAndCredentialVersion(t *testing.T) {
	oldRing, err := NewKeyring("enc-1", map[string][]byte{"enc-1": bytes.Repeat([]byte{0x31}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	oldCipher, err := NewAESGCMCipher(oldRing)
	if err != nil {
		t.Fatal(err)
	}
	oldSealed, err := oldCipher.Encrypt(PurposeChallengeQuestion, "user_1", "challenge_1", 2, "旧问题仍可读取吗？")
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewKeyring("enc-2", map[string][]byte{
		"enc-1": bytes.Repeat([]byte{0x31}, 32),
		"enc-2": bytes.Repeat([]byte{0x32}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := NewAESGCMCipher(ring)
	if err != nil {
		t.Fatal(err)
	}
	oldPlain, err := cipher.Decrypt(PurposeChallengeQuestion, "user_1", "challenge_1", 2, oldSealed)
	if err != nil || oldPlain != "旧问题仍可读取吗？" {
		t.Fatalf("decrypt retained encryption key: %q %v", oldPlain, err)
	}
	sealed, err := cipher.Encrypt(PurposeChallengeQuestion, "user_1", "challenge_1", 3, "你最想解决什么问题？")
	if err != nil {
		t.Fatal(err)
	}
	if sealed.KeyID != "enc-2" || bytes.Contains(sealed.Ciphertext, []byte("最想解决")) {
		t.Fatalf("unexpected sealed value: %+v", sealed)
	}
	plain, err := cipher.Decrypt(PurposeChallengeQuestion, "user_1", "challenge_1", 3, sealed)
	if err != nil || plain != "你最想解决什么问题？" {
		t.Fatalf("decrypt: %q %v", plain, err)
	}
	for _, mismatch := range []struct {
		purpose EncryptionPurpose
		owner   string
		record  string
		version int64
	}{
		{PurposeProtectedReason, "user_1", "challenge_1", 3},
		{PurposeChallengeQuestion, "user_2", "challenge_1", 3},
		{PurposeChallengeQuestion, "user_1", "challenge_2", 3},
		{PurposeChallengeQuestion, "user_1", "challenge_1", 4},
	} {
		if _, err := cipher.Decrypt(mismatch.purpose, mismatch.owner, mismatch.record, mismatch.version, sealed); err == nil {
			t.Fatalf("AAD mismatch unexpectedly decrypted: %+v", mismatch)
		}
	}
}

func TestHasherHonorsCancelledContextBeforeExpensiveWork(t *testing.T) {
	ring, _ := NewKeyring("pepper", map[string][]byte{"pepper": bytes.Repeat([]byte{7}, 32)})
	hasher, _ := NewAnswerHasher(ring, Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, _, err := hasher.Hash(ctx, "答案答案答案答案答案答案答案"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("cancelled hash did not return promptly")
	}
}

type stepupMemoryState struct {
	challenges    map[identity.UserID]CredentialMaterial
	accountEpochs map[identity.UserID]securitystate.Epoch
	stepups       map[string]StepUpState
	receipts      map[string]LocalOperationReceipt
	approvals     map[identity.UserID]int
	purges        []identity.UserID
	audits        []AuditEvent
}

func newStepupMemoryState() *stepupMemoryState {
	return &stepupMemoryState{
		challenges: map[identity.UserID]CredentialMaterial{}, stepups: map[string]StepUpState{},
		accountEpochs: map[identity.UserID]securitystate.Epoch{},
		receipts:      map[string]LocalOperationReceipt{}, approvals: map[identity.UserID]int{},
	}
}

func (s *stepupMemoryState) clone() *stepupMemoryState {
	next := newStepupMemoryState()
	for key, value := range s.challenges {
		value.QuestionNonce = append([]byte(nil), value.QuestionNonce...)
		value.QuestionCiphertext = append([]byte(nil), value.QuestionCiphertext...)
		next.challenges[key] = value
	}
	for key, value := range s.accountEpochs {
		next.accountEpochs[key] = value
	}
	for key, value := range s.stepups {
		next.stepups[key] = value
	}
	for key, value := range s.receipts {
		next.receipts[key] = value
	}
	for key, value := range s.approvals {
		next.approvals[key] = value
	}
	next.purges = append([]identity.UserID(nil), s.purges...)
	next.audits = append([]AuditEvent(nil), s.audits...)
	return next
}

type stepupMemory struct {
	mu       sync.Mutex
	state    *stepupMemoryState
	failNext error
}

func newStepupMemory() *stepupMemory { return &stepupMemory{state: newStepupMemoryState()} }

func (m *stepupMemory) WithinStepUpMutation(ctx context.Context, fn func(StepUpMutationRepositories) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	working := m.state.clone()
	repositories := StepUpMutationRepositories{
		Challenges: &stepupMemoryRepository{state: working}, AccountSecurity: stepupMemoryAccountSecurity{state: working}, Receipts: &stepupMemoryReceipts{state: working},
		Approvals: &stepupMemoryApprovals{state: working}, Purges: &stepupMemoryPurges{state: working},
		Audit: &stepupMemoryAudit{state: working},
	}
	if err := fn(repositories); err != nil {
		return err
	}
	if m.failNext != nil {
		err := m.failNext
		m.failNext = nil
		return err
	}
	m.state = working
	return nil
}

type stepupMemoryAccountSecurity struct{ state *stepupMemoryState }

func (r stepupMemoryAccountSecurity) CurrentEpoch(_ context.Context, userID identity.UserID) (securitystate.Epoch, error) {
	if epoch := r.state.accountEpochs[userID]; epoch > 0 {
		return epoch, nil
	}
	return 1, nil
}

func (m *stepupMemory) Get(ctx context.Context, userID identity.UserID) (Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return (&stepupMemoryRepository{state: m.state}).Get(ctx, userID)
}
func (m *stepupMemory) GetCredentialForVerification(ctx context.Context, userID identity.UserID) (CredentialMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return (&stepupMemoryRepository{state: m.state}).GetCredentialForVerification(ctx, userID)
}
func (*stepupMemory) PutCredential(context.Context, CredentialMaterial, int64) (Challenge, error) {
	return Challenge{}, errors.New("write outside transaction")
}
func (*stepupMemory) RecordFailure(context.Context, identity.UserID, int64, time.Time) (Challenge, error) {
	return Challenge{}, errors.New("write outside transaction")
}
func (*stepupMemory) PutStepUp(context.Context, StepUpState) error {
	return errors.New("write outside transaction")
}
func (*stepupMemory) RevokeForUser(context.Context, identity.UserID, time.Time) error {
	return errors.New("write outside transaction")
}

type stepupMemoryRepository struct{ state *stepupMemoryState }

func (r *stepupMemoryRepository) Get(_ context.Context, userID identity.UserID) (Challenge, error) {
	material, ok := r.state.challenges[userID]
	if !ok {
		return Challenge{}, ErrNotFound
	}
	return material.Challenge, nil
}
func (r *stepupMemoryRepository) GetCredentialForVerification(_ context.Context, userID identity.UserID) (CredentialMaterial, error) {
	material, ok := r.state.challenges[userID]
	if !ok || material.Challenge.Status != ChallengeActive {
		return CredentialMaterial{}, ErrNotFound
	}
	return material, nil
}
func (r *stepupMemoryRepository) PutCredential(_ context.Context, material CredentialMaterial, expected int64) (Challenge, error) {
	current, exists := r.state.challenges[material.Challenge.UserID]
	if expected == 0 {
		if exists {
			return Challenge{}, ErrConflict
		}
		material.Challenge.Version = 1
		material.Challenge.CredentialVersion = 1
		material.Challenge.SecurityEpoch = 1
	} else {
		if !exists || current.Challenge.Version != expected {
			return Challenge{}, ErrConflict
		}
		material.Challenge.Version = expected + 1
		material.Challenge.CredentialVersion = current.Challenge.CredentialVersion + 1
		material.Challenge.SecurityEpoch = current.Challenge.SecurityEpoch + 1
	}
	material.Challenge.Status = ChallengeActive
	r.state.challenges[material.Challenge.UserID] = material
	return material.Challenge, nil
}
func (r *stepupMemoryRepository) RecordFailure(_ context.Context, userID identity.UserID, expected int64, now time.Time) (Challenge, error) {
	material, exists := r.state.challenges[userID]
	if !exists || material.Challenge.Version != expected {
		return Challenge{}, ErrConflict
	}
	c := material.Challenge
	if c.FailureWindowStartedAt == nil || c.FailureWindowStartedAt.Before(now.Add(-15*time.Minute)) {
		c.FailureCount = 1
		started := now
		c.FailureWindowStartedAt = &started
	} else {
		c.FailureCount++
	}
	if c.FailureCount >= 5 {
		locked := now.Add(30 * time.Minute)
		c.LockedUntil = &locked
	}
	c.Version++
	material.Challenge = c
	r.state.challenges[userID] = material
	return c, nil
}
func (r *stepupMemoryRepository) PutStepUp(_ context.Context, state StepUpState) error {
	if _, exists := r.state.stepups[state.ID]; exists {
		return ErrConflict
	}
	for id, existing := range r.state.stepups {
		if existing.SessionID == state.SessionID && existing.UserID == state.UserID && existing.RevokedAt == nil {
			revokedAt := state.VerifiedAt
			existing.RevokedAt = &revokedAt
			r.state.stepups[id] = existing
		}
	}
	r.state.stepups[state.ID] = state
	return nil
}
func (r *stepupMemoryRepository) RevokeForUser(_ context.Context, userID identity.UserID, now time.Time) error {
	for id, state := range r.state.stepups {
		if state.UserID == userID && state.RevokedAt == nil {
			copy := now
			state.RevokedAt = &copy
			r.state.stepups[id] = state
		}
	}
	return nil
}

type stepupMemoryReceipts struct{ state *stepupMemoryState }

func (r *stepupMemoryReceipts) CreateOrReplay(_ context.Context, receipt LocalOperationReceipt) (LocalOperationReceipt, bool, error) {
	if existing, ok := r.state.receipts[receipt.IdempotencyKey]; ok {
		if existing.Fingerprint != receipt.Fingerprint {
			return LocalOperationReceipt{}, false, ErrIdempotencyConflict
		}
		return existing, true, nil
	}
	r.state.receipts[receipt.IdempotencyKey] = receipt
	return receipt, false, nil
}
func (r *stepupMemoryReceipts) CompleteLocal(_ context.Context, id string, expected int64, result LocalReceiptResult, at time.Time) error {
	for key, receipt := range r.state.receipts {
		if receipt.ID == id && receipt.Version == expected && receipt.State == "pending" {
			receipt.State = "succeeded"
			receipt.Result = result
			receipt.Version++
			receipt.TerminalAt = &at
			r.state.receipts[key] = receipt
			return nil
		}
	}
	return ErrIdempotencyConflict
}

type stepupMemoryApprovals struct{ state *stepupMemoryState }

func (a *stepupMemoryApprovals) RevokeForUser(_ context.Context, userID identity.UserID, _ time.Time) error {
	a.state.approvals[userID] = 0
	return nil
}

type stepupMemoryPurges struct{ state *stepupMemoryState }

func (p *stepupMemoryPurges) Enqueue(_ context.Context, _ string, userID identity.UserID, _ RequestFingerprint, _ time.Time) error {
	p.state.purges = append(p.state.purges, userID)
	return nil
}

type stepupMemoryAudit struct{ state *stepupMemoryState }

func (a *stepupMemoryAudit) Record(_ context.Context, event AuditEvent) error {
	a.state.audits = append(a.state.audits, event)
	return nil
}

type stepupBindings struct{ values map[string]adminroles.Binding }

func (b stepupBindings) GetForScope(_ context.Context, userID identity.UserID, scope adminroles.Scope) (adminroles.Binding, error) {
	key, _ := scope.Key()
	binding, ok := b.values[string(userID)+":"+string(scope.Kind)+":"+key]
	if !ok || !binding.Enabled || binding.DisabledAt != nil {
		return adminroles.Binding{}, adminroles.ErrBindingNotFound
	}
	return binding, nil
}

type stepupFingerprinter struct{ key []byte }

func (f stepupFingerprinter) Fingerprint(purpose string, canonical []byte) (RequestFingerprint, error) {
	mac := hmac.New(sha256.New, f.key)
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(canonical)
	return RequestFingerprint{Version: "hmac-sha256-v1", KeyID: "fp-1", Digest: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}, nil
}

type stepupLimiter struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (l *stepupLimiter) Check(_ context.Context, _ identity.UserID, _ string) (time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return time.Minute, l.err
}

type countingHasher struct {
	base        *AnswerHasher
	verifyCalls int
}

func (h *countingHasher) Hash(ctx context.Context, answer string) (string, string, error) {
	return h.base.Hash(ctx, answer)
}
func (h *countingHasher) Verify(ctx context.Context, answer, phc, keyID string) (bool, error) {
	h.verifyCalls++
	return h.base.Verify(ctx, answer, phc, keyID)
}

type stepupGrantStore struct {
	mu       sync.Mutex
	grants   map[string]auth.ReauthGrantData
	calls    int
	failNext error
}

func (s *stepupGrantStore) CreateGrant(_ context.Context, tokenHash string, data auth.ReauthGrantData, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext != nil {
		err := s.failNext
		s.failNext = nil
		return err
	}
	if s.grants == nil {
		s.grants = map[string]auth.ReauthGrantData{}
	}
	if _, exists := s.grants[tokenHash]; exists {
		return errors.New("duplicate grant")
	}
	s.grants[tokenHash] = data
	s.calls++
	return nil
}

func (s *stepupGrantStore) ConsumeGrant(_ context.Context, tokenHash string) (auth.ReauthGrantData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.grants[tokenHash]
	if !ok {
		return auth.ReauthGrantData{}, auth.ErrReauthGrantNotFound
	}
	delete(s.grants, tokenHash)
	return data, nil
}

func newServiceFixture(t *testing.T) (*Service, *stepupMemory, *stepupBindings, *stepupLimiter, *countingHasher, *stepupGrantStore) {
	t.Helper()
	memory := newStepupMemory()
	bindings := &stepupBindings{values: map[string]adminroles.Binding{}}
	limiter := &stepupLimiter{}
	pepper, _ := NewKeyring("pepper-1", map[string][]byte{"pepper-1": bytes.Repeat([]byte{0x41}, 32)})
	baseHasher, _ := NewAnswerHasher(pepper, Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}, 1)
	hasher := &countingHasher{base: baseHasher}
	encryption, _ := NewKeyring("enc-1", map[string][]byte{"enc-1": bytes.Repeat([]byte{0x42}, 32)})
	cipher, _ := NewAESGCMCipher(encryption)
	grants := &stepupGrantStore{}
	now := time.Date(2026, 8, 17, 18, 0, 0, 0, time.UTC)
	var idSequence int
	service, err := NewService(ServiceDependencies{
		Repository: memory, Bindings: bindings, UnitOfWork: memory, Limiter: limiter,
		Hasher: hasher, QuestionCipher: cipher, Fingerprinter: stepupFingerprinter{key: bytes.Repeat([]byte{0x43}, 32)},
		GrantStore: grants,
	}, ServiceConfig{GeneralFreshness: 30 * time.Minute, HighRiskFreshness: 5 * time.Minute, GrantTTL: 5 * time.Minute},
		WithClock(func() time.Time { return now }),
		WithIDGenerator(func(prefix string) (string, error) {
			idSequence++
			return fmt.Sprintf("%sfixed-%d", prefix, idSequence), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service, memory, bindings, limiter, hasher, grants
}

func enableBinding(bindings *stepupBindings, userID identity.UserID, eventID string) {
	scope := adminroles.Scope{Kind: adminroles.ScopeEvent, EventID: eventID}
	key, _ := scope.Key()
	bindings.values[string(userID)+":"+string(scope.Kind)+":"+key] = adminroles.Binding{ID: "arb_" + eventID, UserID: userID, Role: adminroles.RoleAdmin, Scope: scope, Enabled: true, Version: 1}
}

func enableSystemBinding(bindings *stepupBindings, userID identity.UserID, role adminroles.Role) {
	scope := adminroles.Scope{Kind: adminroles.ScopeSystem}
	key, _ := scope.Key()
	bindings.values[string(userID)+":"+string(scope.Kind)+":"+key] = adminroles.Binding{ID: "arb_system", UserID: userID, Role: role, Scope: scope, Enabled: true, Version: 1}
}

func validEnrollment(userID identity.UserID, eventID, key string) EnrollInput {
	return EnrollInput{UserID: userID, EventID: eventID, Question: "你最想长期解决的问题是什么？", Answer: "答案答案答案答案答案答案答案", IdempotencyKey: key, RequestID: "req_1"}
}

func dreamUPTestGrantTarget(eventID, resourceKind, resourceID string) string {
	target, _ := json.Marshal([]string{"dreamup-admin-target/v1", eventID, resourceKind, resourceID})
	return string(target)
}

func TestInitialEnrollmentAllowedOnlyForSystemSuperAndTopWithoutChallenge(t *testing.T) {
	for _, role := range []adminroles.Role{adminroles.RoleSuperAdmin, adminroles.RoleTopAdmin} {
		t.Run(string(role), func(t *testing.T) {
			service, _, bindings, _, _, _ := newServiceFixture(t)
			userID := identity.UserID("user_" + string(role))
			enableSystemBinding(bindings, userID, role)
			allowed, err := service.InitialEnrollmentAllowed(context.Background(), userID, "evt_a")
			if err != nil || !allowed {
				t.Fatalf("allowed=%t err=%v", allowed, err)
			}
		})
	}
}

func TestInitialEnrollmentAllowedRejectsOrdinaryEventAndMissingBindings(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*stepupBindings, identity.UserID)
	}{
		{name: "no binding"},
		{name: "event administrator", setup: func(bindings *stepupBindings, userID identity.UserID) {
			enableBinding(bindings, userID, "evt_a")
		}},
		{name: "ordinary role in system scope", setup: func(bindings *stepupBindings, userID identity.UserID) {
			enableSystemBinding(bindings, userID, adminroles.RoleAdmin)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, _, bindings, _, _, _ := newServiceFixture(t)
			userID := identity.UserID("user_1")
			if test.setup != nil {
				test.setup(bindings, userID)
			}
			allowed, err := service.InitialEnrollmentAllowed(context.Background(), userID, "evt_a")
			if err != nil || allowed {
				t.Fatalf("allowed=%t err=%v", allowed, err)
			}
		})
	}
}

func TestInitialEnrollmentAllowedCannotBypassExistingChallenge(t *testing.T) {
	service, _, bindings, _, _, _ := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableSystemBinding(bindings, userID, adminroles.RoleSuperAdmin)
	allowed, err := service.InitialEnrollmentAllowed(context.Background(), userID, "evt_a")
	if err != nil || !allowed {
		t.Fatalf("before enrollment allowed=%t err=%v", allowed, err)
	}
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	allowed, err = service.InitialEnrollmentAllowed(context.Background(), userID, "evt_a")
	if err != nil || allowed {
		t.Fatalf("after enrollment allowed=%t err=%v", allowed, err)
	}
}

func TestEffectiveStateAcrossEventBindings(t *testing.T) {
	service, memory, bindings, _, _, _ := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	state, err := service.State(context.Background(), userID, "evt_a")
	if err != nil || state != StatePendingEnrollment {
		t.Fatalf("pending state=%q err=%v", state, err)
	}
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	enableBinding(bindings, userID, "evt_b")
	state, err = service.State(context.Background(), userID, "evt_b")
	if err != nil || state != StateActive {
		t.Fatalf("shared active state=%q err=%v", state, err)
	}
	delete(bindings.values, "user_1:event:evt_a")
	state, err = service.State(context.Background(), userID, "evt_a")
	if err != nil || state != StateDisabled {
		t.Fatalf("disabled event state=%q err=%v", state, err)
	}
	if len(memory.state.receipts) != 1 {
		t.Fatalf("enrollment receipts=%d", len(memory.state.receipts))
	}
}

func TestVerifyRateLimitFailsClosedBeforeArgon2AndIPChangeCannotBypassUserKey(t *testing.T) {
	service, _, bindings, limiter, hasher, _ := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	limiter.err = errors.New("redis unavailable")
	_, err := service.Verify(context.Background(), VerifyRequest{UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案", Action: auth.ReauthActionAdminRoleManagement, Target: "evt_a", ClientFingerprint: "ip-1|ua", IdempotencyKey: strings.Repeat("B", 32), RequestID: "req_2"})
	if !errors.Is(err, ErrRateLimitUnavailable) {
		t.Fatalf("error=%v", err)
	}
	if hasher.verifyCalls != 0 || limiter.calls != 1 {
		t.Fatalf("limiter calls=%d hash calls=%d", limiter.calls, hasher.verifyCalls)
	}
	// A new client fingerprint still presents the immutable same user ID to
	// the limiter; the limiter owns independent user and client counters.
	_, _ = service.Verify(context.Background(), VerifyRequest{UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案", Action: auth.ReauthActionAdminRoleManagement, Target: "evt_a", ClientFingerprint: "ip-2|ua", IdempotencyKey: strings.Repeat("C", 32), RequestID: "req_3"})
	if limiter.calls != 2 || hasher.verifyCalls != 0 {
		t.Fatalf("changed fingerprint bypassed order: limiter=%d hash=%d", limiter.calls, hasher.verifyCalls)
	}
}

func TestVerifyRejectsEmptyOrCrossScopeActionTargetBeforeRateLimit(t *testing.T) {
	service, _, bindings, limiter, hasher, _ := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		action string
		target string
		want   error
	}{
		{"empty legacy target", auth.ReauthActionAdminRoleManagement, "", ErrInvalidActionTarget},
		{"cross-event legacy target", auth.ReauthActionAdminRoleManagement, "evt_b", ErrInvalidActionTarget},
		{"cross-user challenge target", auth.ReauthActionAdminChallengeRotate, "user_other", ErrInvalidActionTarget},
		{"unsupported canonical action", string(permissions.ActionIdentityAccessApprove), dreamUPTestGrantTarget("evt_a", "event", "evt_a"), ErrUnsupportedAction},
		{"plain high-risk target", string(permissions.ActionCheckinScan), "evt_a", ErrInvalidActionTarget},
		{"cross-event canonical tuple", string(permissions.ActionContentManage), dreamUPTestGrantTarget("evt_b", "event", "evt_b"), ErrInvalidActionTarget},
		{"wrong event-scoped kind", string(permissions.ActionCheckinManageWindow), dreamUPTestGrantTarget("evt_a", "application", "app_1"), ErrInvalidActionTarget},
		{"wrong application kind", string(permissions.ActionApplicationReview), dreamUPTestGrantTarget("evt_a", "event", "evt_a"), ErrInvalidActionTarget},
		{"wrong identity grant kind", string(permissions.ActionIdentityGrantConsume), dreamUPTestGrantTarget("evt_a", "application", "app_1"), ErrInvalidActionTarget},
		{"non-canonical JSON", string(permissions.ActionAuditRead), " " + dreamUPTestGrantTarget("evt_a", "event", "evt_a"), ErrInvalidActionTarget},
		{"extra tuple member", string(permissions.ActionLegalRead), `["dreamup-admin-target/v1","evt_a","application","app_1","extra"]`, ErrInvalidActionTarget},
		{"unsafe resource identifier", string(permissions.ActionContactSubmissionManage), dreamUPTestGrantTarget("evt_a", "contact_submission", "bad id"), ErrInvalidActionTarget},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := VerifyRequest{
				UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案",
				Action: test.action, Target: test.target, ClientFingerprint: "client",
				IdempotencyKey: fmt.Sprintf("%032d", index+500), RequestID: fmt.Sprintf("req_invalid_%02d", index),
			}
			if _, err := service.Verify(context.Background(), request); !errors.Is(err, test.want) {
				t.Errorf("action=%q target=%q error=%v want=%v", request.Action, request.Target, err, test.want)
			}
		})
	}
	if limiter.calls != 0 || hasher.verifyCalls != 0 {
		t.Fatalf("invalid target reached limiter/hash: limiter=%d hash=%d", limiter.calls, hasher.verifyCalls)
	}
}

func TestVerifyIdempotentReplayNeverRemintsBearer(t *testing.T) {
	service, memory, bindings, _, _, grants := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	request := VerifyRequest{UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案", Action: auth.ReauthActionAdminRoleManagement, Target: "evt_a", ClientFingerprint: "client", IdempotencyKey: strings.Repeat("B", 32), RequestID: "req_2"}
	first, err := service.Verify(context.Background(), request)
	if err != nil || first.ReauthGrant == "" || first.GrantID == "" || first.ChallengeVersion != 1 {
		t.Fatalf("first result=%+v err=%v", first, err)
	}
	second, err := service.Verify(context.Background(), request)
	if err != nil || second.ReauthGrant != "" || !second.Replayed {
		t.Fatalf("replay result=%+v err=%v", second, err)
	}
	if grants.calls != 1 || len(memory.state.stepups) != 1 {
		t.Fatalf("grant calls=%d stepups=%d", grants.calls, len(memory.state.stepups))
	}
	request.ClientFingerprint = "different-client"
	if _, err := service.Verify(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key different client fingerprint error=%v", err)
	}
	request.ClientFingerprint = "client"
	request.Answer = "另一个答案另一个答案"
	if _, err := service.Verify(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key different factor error=%v", err)
	}
}

func TestVerifyUsesThirtyMinuteFreshnessForNormalActionAndFiveForHighRisk(t *testing.T) {
	service, memory, bindings, _, _, grants := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	normal, err := service.Verify(context.Background(), VerifyRequest{
		UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案",
		Action: string(permissions.ActionDashboardRead), Target: "evt_a", ClientFingerprint: "client",
		IdempotencyKey: strings.Repeat("B", 32), RequestID: "req_2",
	})
	if err != nil || normal.ReauthGrant != "" || normal.ExpiresAt.Sub(normal.VerifiedAt) != 30*time.Minute {
		t.Fatalf("normal verification=%+v err=%v", normal, err)
	}
	highRisk, err := service.Verify(context.Background(), VerifyRequest{
		UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案",
		Action: string(permissions.ActionApplicationReview), Target: dreamUPTestGrantTarget("evt_a", "application", "app_1"), ClientFingerprint: "client",
		IdempotencyKey: strings.Repeat("C", 32), RequestID: "req_3",
	})
	if err != nil || highRisk.ReauthGrant == "" || highRisk.ExpiresAt.Sub(highRisk.VerifiedAt) != 5*time.Minute {
		t.Fatalf("high-risk verification=%+v err=%v", highRisk, err)
	}
	if grants.calls != 1 {
		t.Fatalf("grant calls=%d want one high-risk grant", grants.calls)
	}
	active := 0
	for _, state := range memory.state.stepups {
		if state.SessionID == "sess_1" && state.UserID == userID && state.RevokedAt == nil {
			active++
			if state.ExpiresAt.Sub(state.VerifiedAt) != 30*time.Minute {
				t.Fatalf("high-risk verification shortened durable general proof: %+v", state)
			}
		}
	}
	if active != 1 {
		t.Fatalf("active session proofs=%d want 1", active)
	}
}

func TestVerifyGrantStoreFailureRollsBackReceiptAndSameKeyCanRetry(t *testing.T) {
	service, memory, bindings, _, _, grants := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	request := VerifyRequest{
		UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案",
		Action: string(permissions.ActionContentManage), Target: dreamUPTestGrantTarget("evt_a", "event", "evt_a"), ClientFingerprint: "client",
		IdempotencyKey: strings.Repeat("G", 32), RequestID: "req_grant_retry",
	}
	beforeReceipts, beforeStepUps := len(memory.state.receipts), len(memory.state.stepups)
	grants.failNext = errors.New("redis unavailable")
	if _, err := service.Verify(context.Background(), request); err == nil {
		t.Fatal("grant store failure unexpectedly succeeded")
	}
	if len(memory.state.receipts) != beforeReceipts || len(memory.state.stepups) != beforeStepUps {
		t.Fatalf("failed grant escaped transaction: receipts=%d/%d stepups=%d/%d", len(memory.state.receipts), beforeReceipts, len(memory.state.stepups), beforeStepUps)
	}
	result, err := service.Verify(context.Background(), request)
	if err != nil || result.ReauthGrant == "" || result.GrantID == "" || result.Replayed || grants.calls != 1 {
		t.Fatalf("same-key retry result=%+v calls=%d err=%v", result, grants.calls, err)
	}
}

func TestEveryDreamUPHighRiskDelegationCapabilityMintsAndConsumesExactOneShotGrant(t *testing.T) {
	service, _, bindings, _, _, grants := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		action permissions.Action
		target string
	}{
		{permissions.ActionApplicationReview, dreamUPTestGrantTarget("evt_a", "application", "app_1")},
		{permissions.ActionApplicationApproveAdmission, dreamUPTestGrantTarget("evt_a", "application", "app_1")},
		{permissions.ActionApplicationDecide, dreamUPTestGrantTarget("evt_a", "application", "app_1")},
		{permissions.ActionRegistrationManage, dreamUPTestGrantTarget("evt_a", "event", "evt_a")},
		{permissions.ActionCheckinScan, dreamUPTestGrantTarget("evt_a", "event", "evt_a")},
		{permissions.ActionCheckinManageWindow, dreamUPTestGrantTarget("evt_a", "event", "evt_a")},
		{permissions.ActionIdentityGrantConsume, dreamUPTestGrantTarget("evt_a", "identity_access_grant", "iag_1")},
		{permissions.ActionIdentityReadRestricted, dreamUPTestGrantTarget("evt_a", "application", "app_1")},
		{permissions.ActionLegalRead, dreamUPTestGrantTarget("evt_a", "application", "app_1")},
		{permissions.ActionApplicationExport, dreamUPTestGrantTarget("evt_a", "event", "evt_a")},
		{permissions.ActionAuditRead, dreamUPTestGrantTarget("evt_a", "event", "evt_a")},
		{permissions.ActionContactSubmissionManage, dreamUPTestGrantTarget("evt_a", "contact_submission", "contact_1")},
		{permissions.ActionContentManage, dreamUPTestGrantTarget("evt_a", "event", "evt_a")},
		{permissions.ActionInspectionPointManage, dreamUPTestGrantTarget("evt_a", "inspection_point", "point_1")},
		{permissions.ActionInspectionPerform, dreamUPTestGrantTarget("evt_a", "inspection_point", "point_1")},
		{permissions.ActionInspectionReview, dreamUPTestGrantTarget("evt_a", "inspection_record", "inspection_1")},
		{permissions.ActionAssetManage, dreamUPTestGrantTarget("evt_a", "event_asset", "asset_1")},
		{permissions.ActionAssetReservationManage, dreamUPTestGrantTarget("evt_a", "asset_reservation", "reservation_1")},
		{permissions.ActionAssetCustodyTransfer, dreamUPTestGrantTarget("evt_a", "asset_unit", "unit_1")},
		{permissions.ActionAssetInventoryAdjust, dreamUPTestGrantTarget("evt_a", "event_asset", "asset_1")},
		{permissions.ActionPersonalAssetAssignment, dreamUPTestGrantTarget("evt_a", "personal_asset_assignment", "assignment_1")},
		{permissions.ActionAssetCodeRotate, dreamUPTestGrantTarget("evt_a", "asset_unit", "unit_1")},
		{permissions.ActionQRPrintSingle, dreamUPTestGrantTarget("evt_a", "entity_code", "code_1")},
		{permissions.ActionQRPrintBulk, dreamUPTestGrantTarget("evt_a", "event", "evt_a")},
		{permissions.ActionRoleMigrationRead, dreamUPTestGrantTarget("evt_a", "event", "evt_a")},
	}
	for index, test := range tests {
		t.Run(string(test.action), func(t *testing.T) {
			if !permissions.IsDreamUPHighRiskDelegatedAdministratorAction(test.action) || !isSupportedAdminAction(string(test.action)) || !isHighRiskAdminAction(string(test.action)) {
				t.Fatalf("high-risk action contract drift for %q", test.action)
			}
			result, err := service.Verify(context.Background(), VerifyRequest{
				UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案",
				Action: string(test.action), Target: test.target, ClientFingerprint: "client",
				IdempotencyKey: fmt.Sprintf("%032d", index+100), RequestID: fmt.Sprintf("req_capability_%02d", index),
			})
			if err != nil || result.ReauthGrant == "" || result.GrantID == "" || result.ExpiresAt.Sub(result.VerifiedAt) != 5*time.Minute {
				t.Fatalf("verification=%+v err=%v", result, err)
			}
			consumed, err := grants.ConsumeGrant(context.Background(), hashBearer(result.ReauthGrant))
			if err != nil || consumed.Action != string(test.action) || consumed.Target != test.target || consumed.UserID != userID || consumed.SessionID != "sess_1" || consumed.GrantID != result.GrantID || consumed.SecurityEpoch < 1 || consumed.ChallengeVersion < 1 {
				t.Fatalf("consumed=%+v err=%v", consumed, err)
			}
			if _, err := grants.ConsumeGrant(context.Background(), hashBearer(result.ReauthGrant)); !errors.Is(err, auth.ErrReauthGrantNotFound) {
				t.Fatalf("grant was reusable: %v", err)
			}
		})
	}
	if grants.calls != len(tests) {
		t.Fatalf("grant mints=%d want=%d", grants.calls, len(tests))
	}
}

func TestContentManagementUsesHighRiskStepUpAndGrant(t *testing.T) {
	service, _, bindings, _, _, grants := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	result, err := service.Verify(context.Background(), VerifyRequest{
		UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案",
		Action: string(permissions.ActionContentManage), Target: dreamUPTestGrantTarget("evt_a", "event", "evt_a"), ClientFingerprint: "client",
		IdempotencyKey: strings.Repeat("E", 32), RequestID: "req_content_manage",
	})
	if err != nil || result.ReauthGrant == "" || result.GrantID == "" || result.ExpiresAt.Sub(result.VerifiedAt) != 5*time.Minute || grants.calls != 1 {
		t.Fatalf("content management verification=%+v grants=%d err=%v", result, grants.calls, err)
	}
}

func TestHighRiskGrantUsesAuthoritativeAccountEpochNotChallengeGeneration(t *testing.T) {
	service, memory, bindings, _, _, grants := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	memory.mu.Lock()
	memory.state.accountEpochs[userID] = 7
	challengeEpoch := memory.state.challenges[userID].Challenge.SecurityEpoch
	memory.mu.Unlock()
	result, err := service.Verify(context.Background(), VerifyRequest{
		UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案",
		Action: string(permissions.ActionContentManage), Target: dreamUPTestGrantTarget("evt_a", "event", "evt_a"), ClientFingerprint: "client",
		IdempotencyKey: strings.Repeat("Y", 32), RequestID: "req_account_epoch",
	})
	if err != nil || result.ReauthGrant == "" {
		t.Fatalf("verify result=%+v err=%v", result, err)
	}
	grants.mu.Lock()
	var stamped auth.ReauthGrantData
	for _, grant := range grants.grants {
		stamped = grant
	}
	grants.mu.Unlock()
	if stamped.SecurityEpoch != 7 || int64(stamped.SecurityEpoch) == challengeEpoch {
		t.Fatalf("grant security epoch=%d challenge epoch=%d, want independent account epoch 7", stamped.SecurityEpoch, challengeEpoch)
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	var durable StepUpState
	for _, state := range memory.state.stepups {
		if state.SessionID == "sess_1" && state.UserID == userID && state.RevokedAt == nil {
			durable = state
			break
		}
	}
	if durable.ID == "" || durable.SecurityEpoch != 7 || durable.ChallengeVersion != stamped.ChallengeVersion {
		t.Fatalf("durable state=%+v grant=%+v", durable, stamped)
	}
}

func TestContactSubmissionManagementUsesHighRiskStepUpAndGrant(t *testing.T) {
	service, _, bindings, _, _, grants := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	result, err := service.Verify(context.Background(), VerifyRequest{
		UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案",
		Action: string(permissions.ActionContactSubmissionManage), Target: dreamUPTestGrantTarget("evt_a", "contact_submission", "contact_1"), ClientFingerprint: "client",
		IdempotencyKey: strings.Repeat("D", 32), RequestID: "req_contact_manage",
	})
	if err != nil || result.ReauthGrant == "" || result.GrantID == "" || result.ExpiresAt.Sub(result.VerifiedAt) != 5*time.Minute || grants.calls != 1 {
		t.Fatalf("contact management verification=%+v grants=%d err=%v", result, grants.calls, err)
	}
}

func TestRotateRejectedAnswerReplaysTerminalReceiptWithoutRehashing(t *testing.T) {
	service, _, bindings, _, hasher, _ := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	input := RotateInput{
		UserID: userID, EventID: "evt_a", OldAnswer: "错误错误错误错误错误错误错误",
		NewQuestion: "你下一阶段最想解决的问题是什么？", NewAnswer: "新答案新答案新答案新答案",
		ClientFingerprint: "client", IdempotencyKey: strings.Repeat("B", 32), RequestID: "req_2", ExpectedVersion: 1,
	}
	if _, err := service.Rotate(context.Background(), input); !errors.Is(err, ErrInvalidChallengeAnswer) {
		t.Fatalf("first error=%v", err)
	}
	verifyCalls := hasher.verifyCalls
	if _, err := service.Rotate(context.Background(), input); !errors.Is(err, ErrInvalidChallengeAnswer) {
		t.Fatalf("replay error=%v", err)
	}
	if hasher.verifyCalls != verifyCalls {
		t.Fatalf("terminal replay rehashed answer: before=%d after=%d", verifyCalls, hasher.verifyCalls)
	}
	input.ClientFingerprint = "different-client"
	if _, err := service.Rotate(context.Background(), input); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key different client fingerprint error=%v", err)
	}
}

func TestEnrollAndRotateReplaysPreserveRowAndCredentialVersions(t *testing.T) {
	service, _, bindings, _, _, _ := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	enrollment := validEnrollment(userID, "evt_a", strings.Repeat("A", 32))
	firstEnrollment, err := service.Enroll(context.Background(), enrollment)
	if err != nil {
		t.Fatal(err)
	}
	replayedEnrollment, err := service.Enroll(context.Background(), enrollment)
	if err != nil || replayedEnrollment.Version != firstEnrollment.Version || replayedEnrollment.CredentialVersion != firstEnrollment.CredentialVersion {
		t.Fatalf("enrollment first=%+v replay=%+v err=%v", firstEnrollment, replayedEnrollment, err)
	}

	rotation := RotateInput{
		UserID: userID, EventID: "evt_a", OldAnswer: "答案答案答案答案答案答案答案",
		NewQuestion: "你下一阶段最想解决的问题是什么？", NewAnswer: "新答案新答案新答案新答案",
		ClientFingerprint: "client", IdempotencyKey: strings.Repeat("B", 32), RequestID: "req_2", ExpectedVersion: firstEnrollment.Version,
	}
	firstRotation, err := service.Rotate(context.Background(), rotation)
	if err != nil {
		t.Fatal(err)
	}
	replayedRotation, err := service.Rotate(context.Background(), rotation)
	if err != nil || replayedRotation.Version != firstRotation.Version || replayedRotation.CredentialVersion != firstRotation.CredentialVersion {
		t.Fatalf("rotation first=%+v replay=%+v err=%v", firstRotation, replayedRotation, err)
	}
}

func TestMustRotateOnlyAllowsRotationAndRotationIsAtomic(t *testing.T) {
	service, memory, bindings, _, _, _ := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	memory.mu.Lock()
	material := memory.state.challenges[userID]
	material.Challenge.MustRotate = true
	memory.state.challenges[userID] = material
	memory.state.approvals[userID] = 2
	memory.mu.Unlock()
	_, err := service.Verify(context.Background(), VerifyRequest{UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案", Action: auth.ReauthActionAdminRoleManagement, Target: "evt_a", ClientFingerprint: "client", IdempotencyKey: strings.Repeat("B", 32), RequestID: "req_2"})
	if !errors.Is(err, ErrRotationRequired) {
		t.Fatalf("ordinary action error=%v", err)
	}
	rotationProof, err := service.Verify(context.Background(), VerifyRequest{UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "答案答案答案答案答案答案答案", Action: auth.ReauthActionAdminChallengeRotate, Target: "user_1", ClientFingerprint: "client", IdempotencyKey: strings.Repeat("C", 32), RequestID: "req_3"})
	if err != nil || rotationProof.ReauthGrant == "" {
		t.Fatalf("rotation proof=%+v err=%v", rotationProof, err)
	}

	memory.failNext = errors.New("forced audit rollback")
	_, err = service.Rotate(context.Background(), RotateInput{UserID: userID, EventID: "evt_a", OldAnswer: "答案答案答案答案答案答案答案", NewQuestion: "你下一阶段最想解决的问题是什么？", NewAnswer: "新答案新答案新答案新答案", ClientFingerprint: "client", IdempotencyKey: strings.Repeat("D", 32), RequestID: "req_4", ExpectedVersion: 1})
	if err == nil {
		t.Fatal("expected forced transaction rollback")
	}
	afterRollback, _ := memory.Get(context.Background(), userID)
	if afterRollback.Version != 1 || afterRollback.SecurityEpoch != 1 || memory.state.approvals[userID] != 2 || len(memory.state.purges) != 0 {
		t.Fatalf("partial rotation escaped rollback: challenge=%+v approvals=%d purges=%d", afterRollback, memory.state.approvals[userID], len(memory.state.purges))
	}

	rotated, err := service.Rotate(context.Background(), RotateInput{UserID: userID, EventID: "evt_a", OldAnswer: "答案答案答案答案答案答案答案", NewQuestion: "你下一阶段最想解决的问题是什么？", NewAnswer: "新答案新答案新答案新答案", ClientFingerprint: "client", IdempotencyKey: strings.Repeat("E", 32), RequestID: "req_5", ExpectedVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Version != 2 || rotated.SecurityEpoch != 2 || rotated.MustRotate || memory.state.approvals[userID] != 0 || len(memory.state.purges) != 1 {
		t.Fatalf("rotation result=%+v approvals=%d purges=%d", rotated, memory.state.approvals[userID], len(memory.state.purges))
	}
	for _, state := range memory.state.stepups {
		if state.RevokedAt == nil {
			t.Fatalf("step-up not revoked: %+v", state)
		}
	}
}

func TestFiveFailuresLockForThirtyMinutes(t *testing.T) {
	service, memory, bindings, _, _, _ := newServiceFixture(t)
	userID := identity.UserID("user_1")
	enableBinding(bindings, userID, "evt_a")
	if _, err := service.Enroll(context.Background(), validEnrollment(userID, "evt_a", strings.Repeat("A", 32))); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		_, err := service.Verify(context.Background(), VerifyRequest{UserID: userID, SessionID: "sess_1", EventID: "evt_a", Answer: "错误错误错误错误错误错误错误", Action: auth.ReauthActionAdminRoleManagement, Target: "evt_a", ClientFingerprint: "client", IdempotencyKey: fmt.Sprintf("%032d", attempt+10), RequestID: fmt.Sprintf("req_%d", attempt)})
		if attempt < 4 && !errors.Is(err, ErrInvalidChallengeAnswer) {
			t.Fatalf("attempt %d error=%v", attempt+1, err)
		}
		if attempt == 4 && !errors.Is(err, ErrLocked) {
			t.Fatalf("fifth attempt error=%v", err)
		}
	}
	challenge, _ := memory.Get(context.Background(), userID)
	if challenge.LockedUntil == nil || !challenge.LockedUntil.Equal(time.Date(2026, 8, 17, 18, 30, 0, 0, time.UTC)) {
		t.Fatalf("locked until=%v", challenge.LockedUntil)
	}
}
