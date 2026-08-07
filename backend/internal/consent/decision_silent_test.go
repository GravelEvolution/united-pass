//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the silent execution and error-callback completion seams
//

package consent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// newSilentFixture wires a decision service on a prompt=none request with
// one active grant seeded for (user_01TEST, cli_test).
func newSilentFixture(t *testing.T) (*DecisionService, *FakeAuthRequestProvider, *fakeGrantStore, *fakeCredentialReader) {
	t.Helper()
	provider := NewFakeAuthRequestProvider()
	view := baseView()
	view.Prompts = []Prompt{PromptNone}
	provider.AddRequest(view)
	store := newFakeGrantStore()
	store.grants["user_01TEST|cli_test"] = Grant{
		ID:       GrantID("grant_silent_1"),
		UserID:   identity.UserID("user_01TEST"),
		ClientID: applications.OAuthClientID("cli_test"),
		Status:   GrantActive,
		Scopes:   []string{"openid", "profile"},
	}
	reader := &fakeCredentialReader{cred: v2Credential()}
	svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)
	return svc, provider, store, reader
}

func TestDecideSilentlyHappyPath(t *testing.T) {
	svc, provider, store, reader := newSilentFixture(t)

	outcome, err := svc.DecideSilently(context.Background(), allowInput("V2-request-1"), reader)
	if err != nil {
		t.Fatalf("DecideSilently: %v", err)
	}
	if !strings.Contains(outcome.RedirectURL(), "code=fake-code-V2-request-1") {
		t.Fatalf("redirectUrl = %q", outcome.RedirectURL())
	}
	if provider.Completions("V2-request-1") != 1 {
		t.Fatal("provider completion count != 1")
	}
	op := store.operationOf(t)
	if op.Status != DecisionOperationSucceeded || op.CompletionKind != CompletionAllow {
		t.Fatalf("operation = %+v", op)
	}
	if op.LocalUserID != "user_01TEST" || op.ClientID != "cli_test" {
		t.Fatalf("bindings = %+v", op)
	}
	if strings.Join(op.Scopes, ",") != "openid,profile" {
		t.Fatalf("scope snapshot = %v", op.Scopes)
	}
	if store.allowCommits != 1 {
		t.Fatalf("allow commits = %d, want 1", store.allowCommits)
	}
	if _, ok := store.providerProof[op.ID]; !ok {
		t.Fatal("provider success proof not persisted")
	}
}

func TestDecideSilentlyRejectsNonAllowDecision(t *testing.T) {
	svc, provider, store, reader := newSilentFixture(t)
	input := allowInput("V2-request-1")
	input.Decision = DecisionDeny

	if _, err := svc.DecideSilently(context.Background(), input, reader); err == nil {
		t.Fatal("deny accepted by the silent seam")
	}
	if len(store.ops) != 0 || provider.Completions("V2-request-1") != 0 {
		t.Fatal("rejected silent input must not claim or complete anything")
	}
}

func TestDecideSilentlyRejectsInteractivePrompts(t *testing.T) {
	cases := []struct {
		name    string
		prompts []Prompt
	}{
		{"no prompts", nil},
		{"prompt=login", []Prompt{PromptLogin}},
		{"out-of-range prompt value", []Prompt{Prompt(42)}},
		{"none combined", []Prompt{PromptNone, PromptLogin}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := NewFakeAuthRequestProvider()
			view := baseView()
			view.Prompts = tc.prompts
			provider.AddRequest(view)
			store := newFakeGrantStore()
			reader := &fakeCredentialReader{cred: v2Credential()}
			svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

			_, err := svc.DecideSilently(context.Background(), allowInput(view.ID), reader)
			if !errors.Is(err, ErrResolutionNotInteractive) {
				t.Fatalf("err = %v, want ErrResolutionNotInteractive", err)
			}
			if len(store.ops) != 0 {
				t.Fatal("non-none request must never claim an operation")
			}
		})
	}
}

func TestDecideSilentlyAuthoritativeReuseRecheckBeforeClaim(t *testing.T) {
	svc, provider, store, reader := newSilentFixture(t)
	// Revoke between the gateway pre-check and this authoritative call.
	delete(store.grants, "user_01TEST|cli_test")

	_, err := svc.DecideSilently(context.Background(), allowInput("V2-request-1"), reader)
	if !errors.Is(err, ErrSilentReuseUnavailable) {
		t.Fatalf("err = %v, want ErrSilentReuseUnavailable", err)
	}
	// The re-check runs BEFORE the claim: no operation row, no provider
	// completion, no allow commit — the revoked consent is never silently
	// used (ADR-0005 §7, §12).
	if len(store.ops) != 0 {
		t.Fatal("reuse failure must exit before the claim")
	}
	if provider.Completions("V2-request-1") != 0 {
		t.Fatal("reuse failure must never reach the provider")
	}
	if store.allowCommits != 0 {
		t.Fatal("reuse failure must never commit an allow")
	}
}

func TestDecideSilentlyFreshnessThroughSharedPredicate(t *testing.T) {
	provider := NewFakeAuthRequestProvider()
	view := baseView()
	view.Prompts = []Prompt{PromptNone}
	zero := time.Duration(0) // max_age=0: authentication must postdate the request
	view.MaxAge = &zero
	provider.AddRequest(view)
	store := newFakeGrantStore()
	store.grants["user_01TEST|cli_test"] = Grant{
		ID:       GrantID("grant_silent_2"),
		UserID:   identity.UserID("user_01TEST"),
		ClientID: applications.OAuthClientID("cli_test"),
		Status:   GrantActive,
		Scopes:   []string{"openid", "profile"},
	}
	reader := &fakeCredentialReader{cred: v2Credential()}
	svc := newDecisionService(t, provider, &stubClientResolver{facts: baseFacts()}, store)

	// Session authenticated BEFORE the request: never satisfies the force
	// flag through the single shared predicate.
	_, err := svc.DecideSilently(context.Background(), allowInput(view.ID), reader)
	if !errors.Is(err, ErrDecisionRequestExpired) {
		t.Fatalf("err = %v, want ErrDecisionRequestExpired", err)
	}
	if provider.Completions(view.ID) != 0 || len(store.ops) != 0 {
		t.Fatal("stale session must never claim or complete")
	}
}

func TestCompleteWithErrorCallbackHappyPath(t *testing.T) {
	svc, provider, store, _ := newDecisionFixture(t)

	outcome, err := svc.CompleteWithErrorCallback(
		context.Background(), "V2-request-1", CompletionLoginRequired, nil, "")
	if err != nil {
		t.Fatalf("CompleteWithErrorCallback: %v", err)
	}
	if !strings.Contains(outcome.RedirectURL(), "error=login_required") {
		t.Fatalf("redirectUrl = %q", outcome.RedirectURL())
	}
	if provider.Completions("V2-request-1") != 1 {
		t.Fatal("provider completion count != 1")
	}
	op := store.operationOf(t)
	if op.CompletionKind != CompletionLoginRequired || op.Status != DecisionOperationSucceeded {
		t.Fatalf("operation = %+v", op)
	}
	if op.LocalUserID != "" || op.ClientID != "" {
		t.Fatalf("unbound completion must carry no bindings: %+v", op)
	}
	if store.errorCommits != 1 || store.allowCommits != 0 {
		t.Fatalf("commits: error=%d allow=%d", store.errorCommits, store.allowCommits)
	}
}

func TestCompleteWithErrorCallbackBindsKnownFacts(t *testing.T) {
	svc, _, store, _ := newDecisionFixture(t)

	_, err := svc.CompleteWithErrorCallback(
		context.Background(), "V2-request-1", CompletionConsentRequired,
		decisionSession(testNow), applications.OAuthClientID("cli_test"))
	if err != nil {
		t.Fatalf("CompleteWithErrorCallback: %v", err)
	}
	op := store.operationOf(t)
	if op.LocalUserID != "user_01TEST" || op.ClientID != "cli_test" {
		t.Fatalf("bindings = %+v", op)
	}
}

func TestCompleteWithErrorCallbackRejectsUserDecisions(t *testing.T) {
	svc, provider, store, _ := newDecisionFixture(t)

	for _, kind := range []CompletionKind{CompletionAllow, CompletionAccessDenied, "", CompletionKind("bogus")} {
		if _, err := svc.CompleteWithErrorCallback(context.Background(), "V2-request-1", kind, nil, ""); err == nil {
			t.Fatalf("kind %q accepted by the error-callback seam", kind)
		}
	}
	if len(store.ops) != 0 || provider.Completions("V2-request-1") != 0 {
		t.Fatal("rejected kinds must never claim or complete anything")
	}
}

func TestCompleteWithErrorCallbackExpiredRequest(t *testing.T) {
	svc, _, store, _ := newDecisionFixture(t)

	_, err := svc.CompleteWithErrorCallback(
		context.Background(), "V2-missing", CompletionLoginRequired, nil, "")
	if !errors.Is(err, ErrDecisionRequestExpired) {
		t.Fatalf("err = %v, want ErrDecisionRequestExpired", err)
	}
	if len(store.ops) != 0 {
		t.Fatal("vanished request must never claim an operation")
	}
}

func TestCompleteWithErrorCallbackProviderFailureFailsOperation(t *testing.T) {
	svc, provider, store, _ := newDecisionFixture(t)
	provider.InjectCompleteError(NewProviderError(ClassProviderUnavailable, nil))

	_, err := svc.CompleteWithErrorCallback(
		context.Background(), "V2-request-1", CompletionLoginRequired, nil, "")
	if err == nil {
		t.Fatal("provider failure must propagate")
	}
	op := store.operationOf(t)
	if op.Status != DecisionOperationFailed {
		t.Fatalf("operation = %+v, want failed", op)
	}
}
