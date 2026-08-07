package consent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// fakeGrantStore is an in-memory GrantStore for decision-orchestration
// unit tests. It mirrors the PostgreSQL semantics the orchestration
// relies on: single-winner claim by key, pending-only CAS transitions,
// and the provider_succeeded proof gate before any commit.
type fakeGrantStore struct {
	mu   sync.Mutex
	ops  map[DecisionOperationID]DecisionOperation
	keys map[string]DecisionOperationID

	grants map[string]Grant

	// injection
	recordProofErr error
	commitAllowErr error
	commitDenyErr  error

	allowCommits  int
	denyCommits   int
	errorCommits  int
	failed        map[DecisionOperationID]ErrorClass
	providerProof map[DecisionOperationID]time.Time
}

func newFakeGrantStore() *fakeGrantStore {
	return &fakeGrantStore{
		ops:           make(map[DecisionOperationID]DecisionOperation),
		keys:          make(map[string]DecisionOperationID),
		grants:        make(map[string]Grant),
		failed:        make(map[DecisionOperationID]ErrorClass),
		providerProof: make(map[DecisionOperationID]time.Time),
	}
}

func decisionKeyStr(k DecisionOperationKey) string {
	return k.Provider + "|" + k.ProviderTenantID + "|" + k.AuthRequestID
}

func (s *fakeGrantStore) ClaimDecisionOperation(_ context.Context, op DecisionOperation) (DecisionOperation, bool, error) {
	if err := op.ValidateForClaim(); err != nil {
		return DecisionOperation{}, false, err
	}
	scopes, err := NormalizeScopes(op.Scopes)
	if err != nil {
		return DecisionOperation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := decisionKeyStr(DecisionOperationKey{Provider: op.Provider, ProviderTenantID: op.ProviderTenantID, AuthRequestID: op.AuthRequestID})
	if existingID, ok := s.keys[key]; ok {
		return s.ops[existingID], false, ErrDecisionConflict
	}
	stored := op
	stored.Scopes = append([]string(nil), scopes...)
	stored.Status = DecisionOperationPending
	stored.CreatedAt = testNow
	stored.UpdatedAt = testNow
	s.ops[stored.ID] = stored
	s.keys[key] = stored.ID
	return stored, true, nil
}

func (s *fakeGrantStore) GetDecisionOperation(_ context.Context, key DecisionOperationKey) (DecisionOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.keys[decisionKeyStr(key)]
	if !ok {
		return DecisionOperation{}, ErrDecisionNotFound
	}
	return s.ops[id], nil
}

func (s *fakeGrantStore) RecordProviderSucceeded(_ context.Context, opID DecisionOperationID, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recordProofErr != nil {
		return s.recordProofErr
	}
	op, ok := s.ops[opID]
	if !ok || op.Status != DecisionOperationPending {
		return ErrDecisionStateConflict
	}
	op.Status = DecisionOperationProviderSucceeded
	op.ProviderSucceededAt = at
	s.ops[opID] = op
	s.providerProof[opID] = at
	return nil
}

func (s *fakeGrantStore) commit(opID DecisionOperationID, kind CompletionKind) error {
	op, ok := s.ops[opID]
	if !ok {
		return ErrDecisionNotFound
	}
	if op.Status != DecisionOperationProviderSucceeded || op.CompletionKind != kind {
		return ErrDecisionStateConflict
	}
	op.Status = DecisionOperationSucceeded
	s.ops[opID] = op
	return nil
}

func (s *fakeGrantStore) CommitAllowDecision(_ context.Context, commit AllowCommit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commitAllowErr != nil {
		return s.commitAllowErr
	}
	if err := s.commit(commit.OperationID, CompletionAllow); err != nil {
		return err
	}
	s.allowCommits++
	return nil
}

func (s *fakeGrantStore) CommitDenyDecision(_ context.Context, commit DenyCommit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commitDenyErr != nil {
		return s.commitDenyErr
	}
	if err := s.commit(commit.OperationID, CompletionAccessDenied); err != nil {
		return err
	}
	s.denyCommits++
	return nil
}

func (s *fakeGrantStore) CommitErrorCompletion(_ context.Context, commit ErrorCompletionCommit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.commit(commit.OperationID, s.ops[commit.OperationID].CompletionKind); err != nil {
		return err
	}
	s.errorCommits++
	return nil
}

func (s *fakeGrantStore) FailDecisionOperation(_ context.Context, opID DecisionOperationID, class ErrorClass) error {
	if !class.Valid() {
		return errors.New("fake: unknown error class")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.ops[opID]
	if !ok || op.Status != DecisionOperationPending {
		return ErrDecisionStateConflict
	}
	op.Status = DecisionOperationFailed
	op.ErrorClass = class
	s.ops[opID] = op
	s.failed[opID] = class
	return nil
}

func (s *fakeGrantStore) GetGrant(_ context.Context, userID identity.UserID, clientID applications.OAuthClientID) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[string(userID)+"|"+string(clientID)]
	if !ok {
		return Grant{}, ErrGrantNotFound
	}
	return grant, nil
}

func (s *fakeGrantStore) ListInFlightDecisionOperations(_ context.Context, staleBefore time.Time, limit int) ([]DecisionOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DecisionOperation, 0)
	for _, op := range s.ops {
		if op.Status == DecisionOperationProviderSucceeded ||
			(op.Status == DecisionOperationPending && op.CreatedAt.Before(staleBefore)) {
			out = append(out, op)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// operationOf returns the single stored operation (test helper).
func (s *fakeGrantStore) operationOf(t *testing.T) DecisionOperation {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ops) != 1 {
		t.Fatalf("stored operations = %d, want 1", len(s.ops))
	}
	for _, op := range s.ops {
		return op
	}
	return DecisionOperation{}
}

// fakeCredentialReader returns a canned credential (or error) and records
// the session ID it was asked for.
type fakeCredentialReader struct {
	cred          session.ProviderSessionCredential
	err           error
	lastSessionID session.SessionID
	calls         int
}

func (f *fakeCredentialReader) ReadProviderSessionCredential(_ context.Context, sessionID session.SessionID) (session.ProviderSessionCredential, error) {
	f.lastSessionID = sessionID
	f.calls++
	return f.cred, f.err
}

func v2Credential() session.ProviderSessionCredential {
	return session.NewProviderSessionCredential(
		session.ProviderSessionCredentialVersion2,
		"zitadel",
		"provider-session-1",
		"provider-token-1",
	)
}

func newDecisionService(t *testing.T, provider AuthRequestProvider, clients ConsentClientResolver, grants GrantStore) *DecisionService {
	t.Helper()
	svc, err := NewDecisionService(provider, clients, grants, "zitadel", "tenant-test", testClock())
	if err != nil {
		t.Fatalf("NewDecisionService: %v", err)
	}
	return svc
}

func decisionSession(authenticatedAt time.Time) *DecisionSession {
	return &DecisionSession{
		UserID:             identity.UserID("user_01TEST"),
		AuthenticationTime: authenticatedAt,
		SessionID:          session.SessionID("up-session-1"),
	}
}

func allowInput(authRequestID string) DecisionInput {
	return DecisionInput{
		AuthRequestID: authRequestID,
		Decision:      DecisionAllow,
		Session:       decisionSession(testNow.Add(-5 * time.Minute)),
	}
}

func newDecisionFixture(t *testing.T) (*DecisionService, *FakeAuthRequestProvider, *fakeGrantStore, *fakeCredentialReader) {
	t.Helper()
	provider := NewFakeAuthRequestProvider()
	view := baseView()
	provider.AddRequest(view)
	store := newFakeGrantStore()
	reader := &fakeCredentialReader{cred: v2Credential()}
	svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)
	return svc, provider, store, reader
}

func TestDecideAllowHappyPath(t *testing.T) {
	svc, provider, store, reader := newDecisionFixture(t)

	outcome, err := svc.Decide(context.Background(), allowInput("V2-request-1"), reader)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !strings.Contains(outcome.RedirectURL(), "code=fake-code-V2-request-1") {
		t.Fatalf("redirectUrl = %q", outcome.RedirectURL())
	}
	if provider.Completions("V2-request-1") != 1 {
		t.Fatal("provider completion count != 1")
	}
	if reader.lastSessionID != session.SessionID("up-session-1") || reader.calls != 1 {
		t.Fatalf("credential reader usage: %+v", reader)
	}
	op := store.operationOf(t)
	if op.Status != DecisionOperationSucceeded || op.CompletionKind != CompletionAllow {
		t.Fatalf("operation = %+v", op)
	}
	if op.LocalUserID != "user_01TEST" || op.ClientID != "cli_test" {
		t.Fatalf("bindings: %+v", op)
	}
	if strings.Join(op.Scopes, ",") != "openid,profile" {
		t.Fatalf("scope snapshot = %v", op.Scopes)
	}
	if store.allowCommits != 1 || store.denyCommits != 0 {
		t.Fatalf("commits: allow=%d deny=%d", store.allowCommits, store.denyCommits)
	}
	if _, ok := store.providerProof[op.ID]; !ok {
		t.Fatal("provider success proof not persisted")
	}
}

func TestDecideDenyHappyPath(t *testing.T) {
	svc, provider, store, reader := newDecisionFixture(t)

	input := allowInput("V2-request-1")
	input.Decision = DecisionDeny
	outcome, err := svc.Decide(context.Background(), input, reader)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !strings.Contains(outcome.RedirectURL(), "error=access_denied") {
		t.Fatalf("redirectUrl = %q", outcome.RedirectURL())
	}
	// Deny still completes through the provider (access_denied callback).
	if provider.Completions("V2-request-1") != 1 {
		t.Fatal("provider completion count != 1")
	}
	// Deny never reads the session credential.
	if reader.calls != 0 {
		t.Fatalf("deny must not read the credential, calls=%d", reader.calls)
	}
	op := store.operationOf(t)
	if op.Status != DecisionOperationSucceeded || op.CompletionKind != CompletionAccessDenied {
		t.Fatalf("operation = %+v", op)
	}
	if len(op.Scopes) != 0 {
		t.Fatalf("deny scope snapshot = %v", op.Scopes)
	}
	if store.denyCommits != 1 || store.allowCommits != 0 {
		t.Fatalf("commits: allow=%d deny=%d", store.allowCommits, store.denyCommits)
	}
}

func TestDecideRejectsPromptNone(t *testing.T) {
	svc, provider, store, reader := newDecisionFixture(t)
	provider.AddRequest(&AuthRequestView{
		ID: "V2-request-none", ClientID: "provider-client-1",
		Scopes: []string{"openid"}, RedirectURI: "https://rp.example/callback",
		Prompts: []Prompt{PromptNone}, CreatedAt: testNow.Add(-time.Minute),
	})

	if _, err := svc.Decide(context.Background(), allowInput("V2-request-none"), reader); !errors.Is(err, ErrResolutionNotInteractive) {
		t.Fatalf("err = %v, want ErrResolutionNotInteractive", err)
	}
	if provider.Completions("V2-request-none") != 0 || len(store.ops) != 0 {
		t.Fatal("prompt=none must never claim or complete")
	}
}

func TestDecideExpiredOnVanishedRequest(t *testing.T) {
	svc, provider, store, reader := newDecisionFixture(t)

	if _, err := svc.Decide(context.Background(), allowInput("V2-gone"), reader); !errors.Is(err, ErrDecisionRequestExpired) {
		t.Fatalf("err = %v, want ErrDecisionRequestExpired", err)
	}
	if provider.Completions("V2-gone") != 0 || len(store.ops) != 0 {
		t.Fatal("vanished request must never claim or complete")
	}
}

func TestDecideProviderReadFailurePropagates(t *testing.T) {
	svc, provider, store, reader := newDecisionFixture(t)
	provider.InjectGetError(NewProviderError(ClassProviderUnavailable, nil))

	_, err := svc.Decide(context.Background(), allowInput("V2-request-1"), reader)
	if !IsClass(err, ClassProviderUnavailable) {
		t.Fatalf("err = %v, want provider_unavailable", err)
	}
	if len(store.ops) != 0 {
		t.Fatal("read failure must not claim")
	}
}

func TestDecideRevalidationFailuresTerminateAsExpired(t *testing.T) {
	// Each case registers a request the re-validation must reject AFTER
	// the provider read succeeds: unknown client, redirect mismatch,
	// scope outside the catalog, scope flood and an unknown prompt.
	cases := []struct {
		name string
		view *AuthRequestView
	}{
		{"unknown client", &AuthRequestView{
			ID: "V2-d-unknown-client", ClientID: "other-provider-client",
			Scopes: []string{"openid"}, RedirectURI: "https://rp.example/callback",
			CreatedAt: testNow.Add(-time.Minute),
		}},
		{"redirect mismatch", &AuthRequestView{
			ID: "V2-d-evil-redirect", ClientID: "provider-client-1",
			Scopes: []string{"openid"}, RedirectURI: "https://evil.example/steal",
			CreatedAt: testNow.Add(-time.Minute),
		}},
		{"scope not in catalog", &AuthRequestView{
			ID: "V2-d-bad-scope", ClientID: "provider-client-1",
			Scopes: []string{"openid", "admin:read"}, RedirectURI: "https://rp.example/callback",
			CreatedAt: testNow.Add(-time.Minute),
		}},
		{"unknown prompt", &AuthRequestView{
			ID: "V2-d-unspec-prompt", ClientID: "provider-client-1",
			Scopes: []string{"openid"}, RedirectURI: "https://rp.example/callback",
			Prompts: []Prompt{PromptUnspecified}, CreatedAt: testNow.Add(-time.Minute),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := NewFakeAuthRequestProvider()
			provider.AddRequest(tc.view)
			store := newFakeGrantStore()
			reader := &fakeCredentialReader{cred: v2Credential()}

			// Unknown client needs the resolver to report ErrClientUnknown;
			// the shared stub returns base facts, so swap it per case.
			resolver := &stubClientResolver{facts: baseFacts()}
			if tc.name == "unknown client" {
				resolver.err = ErrClientUnknown
			}
			svc := newDecisionService(t, provider, resolver, store)

			if _, err := svc.Decide(context.Background(), allowInput(tc.view.ID), reader); !errors.Is(err, ErrDecisionRequestExpired) {
				t.Fatalf("err = %v, want ErrDecisionRequestExpired", err)
			}
			if provider.Completions(tc.view.ID) != 0 || len(store.ops) != 0 {
				t.Fatal("failed re-validation must never claim or complete")
			}
		})
	}

	// Scope flood shares the P3.2 canonicalization limit: 33 tokens fail
	// closed even though they normalize to a single scope.
	t.Run("scope flood", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		flood := make([]string, 33)
		for i := range flood {
			flood[i] = "openid"
		}
		provider.AddRequest(&AuthRequestView{
			ID: "V2-d-scope-flood", ClientID: "provider-client-1",
			Scopes: flood, RedirectURI: "https://rp.example/callback",
			CreatedAt: testNow.Add(-time.Minute),
		})
		store := newFakeGrantStore()
		svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)
		if _, err := svc.Decide(context.Background(), allowInput("V2-d-scope-flood"), &fakeCredentialReader{cred: v2Credential()}); !errors.Is(err, ErrDecisionRequestExpired) {
			t.Fatalf("err = %v, want ErrDecisionRequestExpired", err)
		}
		if len(store.ops) != 0 {
			t.Fatal("scope flood must never claim")
		}
	})
}

func TestDecideFreshnessSharesTheResolutionPredicate(t *testing.T) {
	// prompt=login with a pre-request authentication is rejected; a
	// genuine re-authentication after CreatedAt proceeds — the exact
	// authenticationSatisfied behavior resolution uses.
	t.Run("stale authentication fails closed", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		provider.AddRequest(&AuthRequestView{
			ID: "V2-d-login-stale", ClientID: "provider-client-1",
			Scopes: []string{"openid", "profile"}, RedirectURI: "https://rp.example/callback",
			Prompts: []Prompt{PromptLogin}, CreatedAt: testNow.Add(-time.Minute),
		})
		store := newFakeGrantStore()
		svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		input := allowInput("V2-d-login-stale")
		input.Session.AuthenticationTime = testNow.Add(-5 * time.Minute) // before CreatedAt
		if _, err := svc.Decide(context.Background(), input, &fakeCredentialReader{cred: v2Credential()}); !errors.Is(err, ErrDecisionRequestExpired) {
			t.Fatalf("err = %v, want ErrDecisionRequestExpired", err)
		}
		if provider.Completions("V2-d-login-stale") != 0 || len(store.ops) != 0 {
			t.Fatal("stale session must never claim or complete")
		}
	})

	t.Run("re-authentication after creation proceeds", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		provider.AddRequest(&AuthRequestView{
			ID: "V2-d-reauth", ClientID: "provider-client-1",
			Scopes: []string{"openid", "profile"}, RedirectURI: "https://rp.example/callback",
			Prompts: []Prompt{PromptLogin}, CreatedAt: testNow.Add(-10 * time.Minute),
		})
		store := newFakeGrantStore()
		svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		input := allowInput("V2-d-reauth")
		input.Session.AuthenticationTime = testNow.Add(-time.Minute) // after CreatedAt
		if _, err := svc.Decide(context.Background(), input, &fakeCredentialReader{cred: v2Credential()}); err != nil {
			t.Fatalf("Decide: %v", err)
		}
	})

	t.Run("exceeded max_age fails closed", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		fiveMinutes := 5 * time.Minute
		provider.AddRequest(&AuthRequestView{
			ID: "V2-d-maxage", ClientID: "provider-client-1",
			Scopes: []string{"openid"}, RedirectURI: "https://rp.example/callback",
			MaxAge: &fiveMinutes, CreatedAt: testNow.Add(-time.Hour),
		})
		store := newFakeGrantStore()
		svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		// Authenticated 30 minutes ago: fresh enough for nothing, stale
		// for max_age=5m.
		input := allowInput("V2-d-maxage")
		input.Session.AuthenticationTime = testNow.Add(-30 * time.Minute)
		if _, err := svc.Decide(context.Background(), input, &fakeCredentialReader{cred: v2Credential()}); !errors.Is(err, ErrDecisionRequestExpired) {
			t.Fatalf("err = %v, want ErrDecisionRequestExpired", err)
		}
	})
}

func TestDecideAllowCredentialFailures(t *testing.T) {
	cases := []struct {
		name   string
		reader *fakeCredentialReader
	}{
		{"missing credential", &fakeCredentialReader{err: session.ErrProviderSessionCredentialMissing}},
		{"legacy v1 credential", &fakeCredentialReader{cred: session.NewProviderSessionCredential(
			session.ProviderSessionCredentialVersion1, "zitadel", "provider-session-1", "",
		)}},
		{"foreign provider credential", &fakeCredentialReader{cred: session.NewProviderSessionCredential(
			session.ProviderSessionCredentialVersion2, "other-provider", "provider-session-1", "token",
		)}},
		{"reader failure", &fakeCredentialReader{err: errors.New("redis exploded")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := NewFakeAuthRequestProvider()
			provider.AddRequest(baseView())
			store := newFakeGrantStore()
			svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

			_, err := svc.Decide(context.Background(), allowInput("V2-request-1"), tc.reader)
			if tc.name == "reader failure" {
				if err == nil || errors.Is(err, ErrDecisionCredentialRequired) {
					t.Fatalf("err = %v, want the raw reader failure", err)
				}
			} else if !errors.Is(err, ErrDecisionCredentialRequired) {
				t.Fatalf("err = %v, want ErrDecisionCredentialRequired", err)
			}
			// Credential failures happen BEFORE the claim: no pending row,
			// no provider call.
			if len(store.ops) != 0 || provider.Completions("V2-request-1") != 0 {
				t.Fatal("credential failure must not claim or complete")
			}
		})
	}
}

func TestDecideClaimConflict(t *testing.T) {
	t.Run("existing provider_succeeded row repairs forward", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		provider.AddRequest(baseView())
		store := newFakeGrantStore()
		svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		// Seed the winner: claimed, proof persisted, local commit lost
		// (the 4→5 crash window).
		winner, won, err := store.ClaimDecisionOperation(context.Background(), DecisionOperation{
			ID: NewDecisionOperationID(), Provider: "zitadel", ProviderTenantID: "tenant-test",
			AuthRequestID: "V2-request-1", CompletionKind: CompletionAllow,
			LocalUserID: "user_winner", ClientID: "cli_test", Scopes: []string{"openid"},
		})
		if err != nil || !won {
			t.Fatalf("seed claim: won=%v err=%v", won, err)
		}
		if err := store.RecordProviderSucceeded(context.Background(), winner.ID, testNow); err != nil {
			t.Fatalf("seed proof: %v", err)
		}

		if _, err := svc.Decide(context.Background(), allowInput("V2-request-1"), &fakeCredentialReader{cred: v2Credential()}); !errors.Is(err, ErrDecisionAlreadyDecided) {
			t.Fatalf("err = %v, want ErrDecisionAlreadyDecided", err)
		}
		if provider.Completions("V2-request-1") != 0 {
			t.Fatal("claim loser must never call the provider")
		}
		// The repair completed the winner's local commit.
		if store.allowCommits != 1 || store.ops[winner.ID].Status != DecisionOperationSucceeded {
			t.Fatalf("forward repair: commits=%d status=%s", store.allowCommits, store.ops[winner.ID].Status)
		}
	})

	t.Run("existing pending row is a plain conflict", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		provider.AddRequest(baseView())
		store := newFakeGrantStore()
		svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		winner, won, err := store.ClaimDecisionOperation(context.Background(), DecisionOperation{
			ID: NewDecisionOperationID(), Provider: "zitadel", ProviderTenantID: "tenant-test",
			AuthRequestID: "V2-request-1", CompletionKind: CompletionAccessDenied,
			LocalUserID: "user_winner", ClientID: "cli_test",
		})
		if err != nil || !won {
			t.Fatalf("seed claim: won=%v err=%v", won, err)
		}

		if _, err := svc.Decide(context.Background(), allowInput("V2-request-1"), &fakeCredentialReader{cred: v2Credential()}); !errors.Is(err, ErrDecisionAlreadyDecided) {
			t.Fatalf("err = %v, want ErrDecisionAlreadyDecided", err)
		}
		if provider.Completions("V2-request-1") != 0 {
			t.Fatal("claim loser must never call the provider")
		}
		// Pending rows are never repaired from the decision path.
		if store.ops[winner.ID].Status != DecisionOperationPending || store.denyCommits != 0 {
			t.Fatalf("pending row mutated: %+v", store.ops[winner.ID])
		}
	})
}

func TestDecideProviderFailureClassification(t *testing.T) {
	t.Run("user not eligible", func(t *testing.T) {
		svc, _, store, reader := newDecisionFixture(t)
		provider := NewFakeAuthRequestProvider()
		provider.AddRequest(baseView())
		provider.InjectCompleteError(NewProviderError(ClassUserNotEligible, nil))
		svc = newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		_, err := svc.Decide(context.Background(), allowInput("V2-request-1"), reader)
		if !IsClass(err, ClassUserNotEligible) {
			t.Fatalf("err = %v, want user_not_eligible", err)
		}
		op := store.operationOf(t)
		if op.Status != DecisionOperationFailed || op.ErrorClass != ClassUserNotEligible {
			t.Fatalf("operation = %+v", op)
		}
	})

	t.Run("provider unavailable fails the claim", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		provider.AddRequest(baseView())
		provider.InjectCompleteError(NewProviderError(ClassProviderUnavailable, nil))
		store := newFakeGrantStore()
		svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		_, err := svc.Decide(context.Background(), allowInput("V2-request-1"), &fakeCredentialReader{cred: v2Credential()})
		if !IsClass(err, ClassProviderUnavailable) {
			t.Fatalf("err = %v, want provider_unavailable", err)
		}
		op := store.operationOf(t)
		if op.Status != DecisionOperationFailed || op.ErrorClass != ClassProviderUnavailable {
			t.Fatalf("operation = %+v", op)
		}
	})

	t.Run("lost completion response leaves pending without proof", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		provider.AddRequest(baseView())
		provider.InjectLostCompletionResponse(NewProviderError(ClassProviderUnavailable, nil))
		store := newFakeGrantStore()
		svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		_, err := svc.Decide(context.Background(), allowInput("V2-request-1"), &fakeCredentialReader{cred: v2Credential()})
		if !IsClass(err, ClassProviderUnavailable) {
			t.Fatalf("err = %v, want provider_unavailable", err)
		}
		// The provider consumed the request but no proof exists: the row
		// was failed without a grant and reconciliation must never repair
		// it into one (ADR-0005 §4 crash window 3→4).
		op := store.operationOf(t)
		if op.Status != DecisionOperationFailed || op.ProviderSucceededAt != (time.Time{}) {
			t.Fatalf("operation = %+v", op)
		}
		if store.allowCommits != 0 {
			t.Fatal("lost response must never commit a grant")
		}
	})

	t.Run("one-shot replay surfaces as already decided", func(t *testing.T) {
		provider := NewFakeAuthRequestProvider()
		provider.AddRequest(baseView())
		provider.InjectCompleteError(NewProviderError(ClassAlreadyCompleted, nil))
		store := newFakeGrantStore()
		svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

		if _, err := svc.Decide(context.Background(), allowInput("V2-request-1"), &fakeCredentialReader{cred: v2Credential()}); !errors.Is(err, ErrDecisionAlreadyDecided) {
			t.Fatalf("err = %v, want ErrDecisionAlreadyDecided", err)
		}
		op := store.operationOf(t)
		if op.Status != DecisionOperationFailed || op.ErrorClass != ClassAlreadyCompleted {
			t.Fatalf("operation = %+v", op)
		}
	})
}

func TestDecideProofConflictHidesTheCallback(t *testing.T) {
	svc, provider, store, reader := newDecisionFixture(t)
	store.recordProofErr = ErrDecisionStateConflict

	if _, err := svc.Decide(context.Background(), allowInput("V2-request-1"), reader); !errors.Is(err, ErrDecisionAlreadyDecided) {
		t.Fatalf("err = %v, want ErrDecisionAlreadyDecided", err)
	}
	// The provider call happened, but the credential-grade callback URL
	// must never surface when the proof cannot be persisted.
	if provider.Completions("V2-request-1") != 1 {
		t.Fatal("provider completion expected")
	}
}

func TestDecideCommitFailureStillReturnsRedirect(t *testing.T) {
	svc, provider, store, reader := newDecisionFixture(t)
	store.commitAllowErr = errors.New("commit exploded")

	outcome, err := svc.Decide(context.Background(), allowInput("V2-request-1"), reader)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !strings.Contains(outcome.RedirectURL(), "code=fake-code-V2-request-1") {
		t.Fatalf("redirectUrl = %q", outcome.RedirectURL())
	}
	if provider.Completions("V2-request-1") != 1 {
		t.Fatal("provider completion count != 1")
	}
	// Proof persisted (reconciliation repairs forward) even though the
	// local commit failed.
	op := store.operationOf(t)
	if op.Status != DecisionOperationProviderSucceeded {
		t.Fatalf("operation = %+v", op)
	}
}

func TestDecideAdvisoryReuseNeverSkipsExecution(t *testing.T) {
	// A reusable grant (the already_authorized GET outcome) gives no
	// exemption: the decision still re-validates, claims and completes.
	svc, provider, store, reader := newDecisionFixture(t)
	store.grants["user_01TEST|cli_test"] = Grant{
		ID: NewGrantID(), UserID: "user_01TEST", ClientID: "cli_test",
		Status: GrantActive, Scopes: []string{"openid", "profile", "offline_access"},
	}

	outcome, err := svc.Decide(context.Background(), allowInput("V2-request-1"), reader)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if outcome.RedirectURL() == "" || provider.Completions("V2-request-1") != 1 || store.allowCommits != 1 {
		t.Fatal("reusable grant must not short-circuit the decision")
	}
}

// TestDecisionOutcomeNeverLeaks pins the P3.1 callback redaction on the
// decision result: the credential-grade callback URL stays wrapped until
// the HTTP serialization boundary unwraps it via RedirectURL, and every
// rendering path of the outcome itself stays redacted.
func TestDecisionOutcomeNeverLeaks(t *testing.T) {
	callback, err := NewCallbackResult("https://rp.example/callback?code=secret-code&state=secret-state")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	outcome := NewDecisionOutcome(callback)

	renderings := []string{
		outcome.String(),
		outcome.GoString(),
		fmt.Sprintf("%v", outcome),
		fmt.Sprintf("%+v", outcome),
		fmt.Sprintf("%#v", outcome),
		fmt.Sprintf("%q", outcome),
		fmt.Sprintf("%v", &outcome),
		fmt.Sprintf("%+v", &outcome),
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("outcome", "outcome", outcome)
	renderings = append(renderings, buf.String())

	marshaled, err := json.Marshal(outcome)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renderings = append(renderings, string(marshaled))

	for _, rendered := range renderings {
		if strings.Contains(rendered, "secret-code") || strings.Contains(rendered, "secret-state") {
			t.Fatalf("decision outcome leaked: %q", rendered)
		}
	}

	// The HTTP serialization seam still reaches the raw URL exactly once.
	if outcome.RedirectURL() != "https://rp.example/callback?code=secret-code&state=secret-state" {
		t.Fatal("redirect URL seam broken")
	}
}

func TestDecideInputValidation(t *testing.T) {
	svc, _, store, reader := newDecisionFixture(t)

	if _, err := svc.Decide(context.Background(), DecisionInput{Decision: DecisionAllow, Session: decisionSession(testNow)}, reader); err == nil {
		t.Fatal("empty auth request id must fail")
	}
	if _, err := svc.Decide(context.Background(), DecisionInput{AuthRequestID: "V2-request-1", Decision: "maybe", Session: decisionSession(testNow)}, reader); err == nil {
		t.Fatal("unknown decision kind must fail")
	}
	if _, err := svc.Decide(context.Background(), DecisionInput{AuthRequestID: "V2-request-1", Decision: DecisionAllow}, reader); err == nil {
		t.Fatal("missing session must fail")
	}
	if _, err := svc.Decide(context.Background(), allowInput("V2-request-1"), nil); err == nil {
		t.Fatal("missing credential reader must fail")
	}
	if len(store.ops) != 0 {
		t.Fatal("invalid inputs must never claim")
	}
}

func TestNewDecisionServiceRequiresAllSeams(t *testing.T) {
	provider := NewFakeAuthRequestProvider()
	clients := &stubClientResolver{}
	store := newFakeGrantStore()
	if _, err := NewDecisionService(nil, clients, store, "zitadel", "t", testClock()); err == nil {
		t.Fatal("nil provider accepted")
	}
	if _, err := NewDecisionService(provider, nil, store, "zitadel", "t", testClock()); err == nil {
		t.Fatal("nil client resolver accepted")
	}
	if _, err := NewDecisionService(provider, clients, nil, "zitadel", "t", testClock()); err == nil {
		t.Fatal("nil grant store accepted")
	}
	if _, err := NewDecisionService(provider, clients, store, "", "t", testClock()); err == nil {
		t.Fatal("empty provider name accepted")
	}
	if _, err := NewDecisionService(provider, clients, store, "zitadel", "t", nil); err == nil {
		t.Fatal("nil clock accepted")
	}
}
