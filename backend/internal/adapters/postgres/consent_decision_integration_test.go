//go:build integration

package postgres

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/session"
)

// staticCredentialReader is the integration-test stand-in for the
// per-request httpapi reader: it always returns a sealed Version-2
// credential for the configured provider.
type staticCredentialReader struct {
	cred session.ProviderSessionCredential
	err  error
}

func (r staticCredentialReader) ReadProviderSessionCredential(context.Context, session.SessionID) (session.ProviderSessionCredential, error) {
	return r.cred, r.err
}

func integrationCredential() staticCredentialReader {
	return staticCredentialReader{cred: session.ProviderSessionCredential{
		Version:      session.ProviderSessionCredentialVersion2,
		Provider:     "zitadel",
		SessionID:    "provider-session-int",
		SessionToken: "provider-token-int",
	}}
}

// decisionFixture wires the real repositories with the fake provider.
func decisionFixture(t *testing.T) (*consent.DecisionService, *consent.FakeAuthRequestProvider, *GrantRepository, *ApplicationRepository, identity.UserID, applications.OAuthClientID, string) {
	t.Helper()
	grants, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "decision-owner")
	userID := createConsentUser(t, users, "decision-user", "decision-user@example.com")
	_, clientID := provisionTestApp(t, appRepo, "decision-app", ownerID)
	providerClientID := "prov-client-" + string(clientID)

	provider := consent.NewFakeAuthRequestProvider()
	svc, err := consent.NewDecisionService(provider, appRepo, grants, "zitadel", "tenant-int",
		func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatalf("NewDecisionService: %v", err)
	}
	return svc, provider, grants, appRepo, userID, clientID, providerClientID
}

// reconcileLogger discards reconciler log output in integration tests.
func reconcileLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func decisionInputFor(authRequestID string, kind consent.DecisionKind, userID identity.UserID) consent.DecisionInput {
	return consent.DecisionInput{
		AuthRequestID: authRequestID,
		Decision:      kind,
		Session: &consent.DecisionSession{
			UserID:             userID,
			AuthenticationTime: time.Now().UTC().Add(-time.Minute),
			SessionID:          session.SessionID("up-session-int"),
		},
	}
}

// decisionKeyFor is the global operation key under the fixture tenant.
func decisionKeyFor(authRequestID string) consent.DecisionOperationKey {
	return consent.DecisionOperationKey{
		Provider: "zitadel", ProviderTenantID: "tenant-int", AuthRequestID: authRequestID,
	}
}

func TestIntegration_DecisionAllowEndToEnd(t *testing.T) {
	svc, provider, grants, _, userID, clientID, providerClientID := decisionFixture(t)
	ctx := context.Background()
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-allow", ClientID: providerClientID,
		Scopes: []string{"profile", "openid"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC().Add(-2 * time.Minute),
	})

	outcome, err := svc.Decide(ctx, decisionInputFor("V2-int-allow", consent.DecisionAllow, userID), integrationCredential())
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !strings.Contains(outcome.RedirectURL, "code=fake-code-V2-int-allow") {
		t.Fatalf("redirectUrl = %q", outcome.RedirectURL)
	}
	if provider.Completions("V2-int-allow") != 1 {
		t.Fatal("provider completion count != 1")
	}

	// The operation row reached its terminal state from the immutable plan.
	stored, err := grants.GetDecisionOperation(ctx, decisionKeyFor("V2-int-allow"))
	if err != nil {
		t.Fatalf("GetDecisionOperation: %v", err)
	}
	if stored.Status != consent.DecisionOperationSucceeded || stored.CompletionKind != consent.CompletionAllow {
		t.Fatalf("operation = %+v", stored)
	}
	if stored.ProviderSucceededAt.IsZero() {
		t.Fatal("provider success proof not persisted")
	}
	if len(stored.Scopes) != 2 || stored.Scopes[0] != "openid" || stored.Scopes[1] != "profile" {
		t.Fatalf("scope snapshot not canonical: %+v", stored.Scopes)
	}

	// The canonical commit produced exactly one active grant with the
	// consented scopes and a correlated audit trail.
	grant, err := grants.GetGrant(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if grant.Status != consent.GrantActive || len(grant.Scopes) != 2 {
		t.Fatalf("grant = %+v", grant)
	}
	records := readAuditRecords(t, grants, stored.ID)
	if len(records) != 1 || records[0].EventType != string(applications.EventConsentGrantAllowed) ||
		records[0].ActorUserID != string(userID) || records[0].ClientID != string(clientID) {
		t.Fatalf("audit records = %+v", records)
	}
}

func TestIntegration_DecisionDenyEndToEnd(t *testing.T) {
	svc, provider, grants, _, userID, clientID, providerClientID := decisionFixture(t)
	ctx := context.Background()
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-deny", ClientID: providerClientID,
		Scopes: []string{"openid", "profile"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC().Add(-2 * time.Minute),
	})

	outcome, err := svc.Decide(ctx, decisionInputFor("V2-int-deny", consent.DecisionDeny, userID), integrationCredential())
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !strings.Contains(outcome.RedirectURL, "error=access_denied") {
		t.Fatalf("redirectUrl = %q", outcome.RedirectURL)
	}

	stored, err := grants.GetDecisionOperation(ctx, decisionKeyFor("V2-int-deny"))
	if err != nil {
		t.Fatalf("GetDecisionOperation: %v", err)
	}
	if stored.Status != consent.DecisionOperationSucceeded || stored.CompletionKind != consent.CompletionAccessDenied {
		t.Fatalf("operation = %+v", stored)
	}
	if len(stored.Scopes) != 0 {
		t.Fatalf("deny must persist no scope snapshot: %+v", stored.Scopes)
	}
	if stored.ClientID != clientID {
		t.Fatalf("deny must bind the client: %+v", stored)
	}

	// Deny writes an audit trail but never a grant.
	if _, err := grants.GetGrant(ctx, userID, clientID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("deny must not produce a grant, got %v", err)
	}
	records := readAuditRecords(t, grants, stored.ID)
	if len(records) != 1 || records[0].EventType != string(applications.EventConsentAccessDenied) {
		t.Fatalf("audit records = %+v", records)
	}
}

func TestIntegration_DecisionNeverSkipsRevalidation(t *testing.T) {
	// An already_authorized GET is advisory: the decision still claims a
	// fresh operation, re-completes the provider and commits again.
	svc, provider, grants, _, userID, clientID, providerClientID := decisionFixture(t)
	ctx := context.Background()

	seed := allowOperationFor("V2-int-reuse-seed", consent.CompletionAllow, userID, clientID,
		[]string{"openid", "profile", "offline_access"})
	seed.ProviderTenantID = "tenant-int"
	stored := claimAndProve(t, grants, seed)
	if err := grants.CommitAllowDecision(ctx, consent.AllowCommit{OperationID: stored.ID}); err != nil {
		t.Fatalf("seed commit: %v", err)
	}

	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-reuse", ClientID: providerClientID,
		Scopes: []string{"openid", "profile"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	outcome, err := svc.Decide(ctx, decisionInputFor("V2-int-reuse", consent.DecisionAllow, userID), integrationCredential())
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if outcome.RedirectURL == "" || provider.Completions("V2-int-reuse") != 1 {
		t.Fatal("reusable grant must not short-circuit the decision")
	}
	var opCount int
	if err := grants.pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_authorization_decision_operations`).Scan(&opCount); err != nil {
		t.Fatalf("count operations: %v", err)
	}
	if opCount != 2 {
		t.Fatalf("operations = %d, want the seeded one plus the decision's own", opCount)
	}
}

func TestIntegration_DecisionConcurrentRaceSingleWinner(t *testing.T) {
	svc, provider, grants, _, userID, _, providerClientID := decisionFixture(t)
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-race", ClientID: providerClientID,
		Scopes: []string{"openid"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC().Add(-2 * time.Minute),
	})

	const racers = 8
	var (
		wg        sync.WaitGroup
		start     sync.WaitGroup
		mu        sync.Mutex
		wins      int
		conflicts int
	)
	start.Add(1)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait()
			outcome, err := svc.Decide(context.Background(),
				decisionInputFor("V2-int-race", consent.DecisionAllow, userID), integrationCredential())
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && outcome.RedirectURL != "":
				wins++
			case errors.Is(err, consent.ErrDecisionAlreadyDecided), errors.Is(err, consent.ErrDecisionRequestExpired):
				conflicts++
			default:
				t.Errorf("unexpected decision outcome: %v", err)
			}
		}()
	}
	start.Done()
	wg.Wait()

	if wins != 1 || conflicts != racers-1 {
		t.Fatalf("wins = %d, conflicts = %d, want exactly one winner", wins, conflicts)
	}
	// The one-shot provider call happened exactly once despite the race.
	if provider.Completions("V2-int-race") != 1 {
		t.Fatalf("provider completions = %d", provider.Completions("V2-int-race"))
	}
	var opCount int
	if err := grants.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oauth_authorization_decision_operations`).Scan(&opCount); err != nil {
		t.Fatalf("count operations: %v", err)
	}
	if opCount != 1 {
		t.Fatalf("operations = %d, want exactly the winner's claim", opCount)
	}
}

func TestIntegration_DecisionClaimConflictRepairsForward(t *testing.T) {
	// Crash window: a previous attempt claimed and proved but died before
	// the local commit. The next decision loses the global claim, must
	// repair the winner forward and never call the provider itself.
	svc, provider, grants, _, userID, clientID, providerClientID := decisionFixture(t)
	ctx := context.Background()

	winner := allowOperationFor("V2-int-conflict", consent.CompletionAllow, userID, clientID,
		[]string{"openid", "profile"})
	winner.ProviderTenantID = "tenant-int"
	stored := claimAndProve(t, grants, winner)

	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-conflict", ClientID: providerClientID,
		Scopes: []string{"openid", "profile"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	if _, err := svc.Decide(ctx, decisionInputFor("V2-int-conflict", consent.DecisionAllow, userID), integrationCredential()); !errors.Is(err, consent.ErrDecisionAlreadyDecided) {
		t.Fatalf("err = %v, want ErrDecisionAlreadyDecided", err)
	}
	if provider.Completions("V2-int-conflict") != 0 {
		t.Fatal("claim loser must never call the provider")
	}
	reread, err := grants.GetDecisionOperation(ctx, decisionKeyFor("V2-int-conflict"))
	if err != nil {
		t.Fatalf("GetDecisionOperation: %v", err)
	}
	if reread.Status != consent.DecisionOperationSucceeded || reread.ID != stored.ID {
		t.Fatalf("winner not repaired: %+v", reread)
	}
	if _, err := grants.GetGrant(ctx, userID, clientID); err != nil {
		t.Fatalf("repair must produce the grant: %v", err)
	}
}

func TestIntegration_DecisionLostResponseFailsClosed(t *testing.T) {
	// The outcome_unknown window: the provider consumed the request but
	// the response was lost. The operation must terminate fail-closed —
	// never a grant, and the staleness reconciler has nothing to repair.
	svc, provider, grants, _, userID, _, providerClientID := decisionFixture(t)
	ctx := context.Background()
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-int-lost", ClientID: providerClientID,
		Scopes: []string{"openid"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	provider.InjectLostCompletionResponse(consent.NewProviderError(consent.ClassProviderUnavailable, nil))

	_, err := svc.Decide(ctx, decisionInputFor("V2-int-lost", consent.DecisionAllow, userID), integrationCredential())
	if !consent.IsClass(err, consent.ClassProviderUnavailable) {
		t.Fatalf("err = %v, want provider_unavailable", err)
	}
	stored, err := grants.GetDecisionOperation(ctx, decisionKeyFor("V2-int-lost"))
	if err != nil {
		t.Fatalf("GetDecisionOperation: %v", err)
	}
	if stored.Status != consent.DecisionOperationFailed || stored.ErrorClass != consent.ClassProviderUnavailable {
		t.Fatalf("operation = %+v", stored)
	}
	if !stored.ProviderSucceededAt.IsZero() {
		t.Fatal("lost response must leave no provider success proof")
	}
}

func TestIntegration_ReconcilerRepairsRealOperations(t *testing.T) {
	_, _, grants, _, userID, clientID, _ := decisionFixture(t)
	ctx := context.Background()

	// A proof-bearing row whose local commit was lost.
	proven := allowOperationFor("V2-int-recon-proven", consent.CompletionAllow, userID, clientID,
		[]string{"openid", "profile"})
	proven.ProviderTenantID = "tenant-int"
	stored := claimAndProve(t, grants, proven)

	reconciler, err := consent.NewReconciler(grants, grants, 0, 5*time.Minute, 10,
		reconcileLogger())
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	if err := reconciler.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	reread, err := grants.GetDecisionOperation(ctx, decisionKeyFor("V2-int-recon-proven"))
	if err != nil {
		t.Fatalf("GetDecisionOperation: %v", err)
	}
	if reread.Status != consent.DecisionOperationSucceeded || reread.ID != stored.ID {
		t.Fatalf("proven row not repaired: %+v", reread)
	}
	if _, err := grants.GetGrant(ctx, userID, clientID); err != nil {
		t.Fatalf("forward repair must produce the grant: %v", err)
	}

	// A second pass over the same (now listed-terminal) state is a no-op.
	if err := reconciler.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
}

func TestIntegration_ReconcilerFailsStalePendingOperations(t *testing.T) {
	_, _, grants, _, userID, clientID, _ := decisionFixture(t)
	ctx := context.Background()

	// Pending without proof, aged past the staleness horizon.
	stale := allowOperationFor("V2-int-recon-stale", consent.CompletionAllow, userID, clientID,
		[]string{"openid"})
	stale.ProviderTenantID = "tenant-int"
	storedStale, won, err := grants.ClaimDecisionOperation(ctx, stale)
	if err != nil || !won {
		t.Fatalf("claim stale: won=%v err=%v", won, err)
	}
	if _, err := grants.pool.Exec(ctx,
		`UPDATE oauth_authorization_decision_operations SET created_at = now() - interval '10 minutes' WHERE operation_id = $1`,
		string(storedStale.ID)); err != nil {
		t.Fatalf("age stale row: %v", err)
	}

	// Pending without proof but fresh: must stay untouched.
	fresh := allowOperationFor("V2-int-recon-fresh", consent.CompletionAllow, userID, clientID,
		[]string{"openid"})
	fresh.ProviderTenantID = "tenant-int"
	storedFresh, won, err := grants.ClaimDecisionOperation(ctx, fresh)
	if err != nil || !won {
		t.Fatalf("claim fresh: won=%v err=%v", won, err)
	}

	reconciler, err := consent.NewReconciler(grants, grants, 0, 5*time.Minute, 10,
		reconcileLogger())
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	if err := reconciler.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	reread, err := grants.GetDecisionOperation(ctx, decisionKeyFor("V2-int-recon-stale"))
	if err != nil {
		t.Fatalf("GetDecisionOperation(stale): %v", err)
	}
	if reread.Status != consent.DecisionOperationFailed || reread.ErrorClass != consent.ClassProviderUnavailable {
		t.Fatalf("stale pending not failed closed: %+v", reread)
	}
	rereadFresh, err := grants.GetDecisionOperation(ctx, decisionKeyFor("V2-int-recon-fresh"))
	if err != nil {
		t.Fatalf("GetDecisionOperation(fresh): %v", err)
	}
	if rereadFresh.Status != consent.DecisionOperationPending || rereadFresh.ID != storedFresh.ID {
		t.Fatalf("fresh pending row disturbed: %+v", rereadFresh)
	}
	// Neither unproven row may ever become a grant.
	if _, err := grants.GetGrant(ctx, userID, clientID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("reconciliation must not fabricate grants, got %v", err)
	}
}

func TestIntegration_ListInFlightDecisionOperationsFiltering(t *testing.T) {
	_, _, grants, _, userID, clientID, _ := decisionFixture(t)
	ctx := context.Background()

	// provider_succeeded is always listed.
	proven := allowOperationFor("V2-int-list-proven", consent.CompletionAllow, userID, clientID,
		[]string{"openid"})
	proven.ProviderTenantID = "tenant-int"
	claimAndProve(t, grants, proven)

	// Fresh pending is not listed.
	fresh := allowOperationFor("V2-int-list-fresh", consent.CompletionAllow, userID, clientID,
		[]string{"openid"})
	fresh.ProviderTenantID = "tenant-int"
	if _, won, err := grants.ClaimDecisionOperation(ctx, fresh); err != nil || !won {
		t.Fatalf("claim fresh: won=%v err=%v", won, err)
	}

	// Aged pending is listed.
	stale := allowOperationFor("V2-int-list-stale", consent.CompletionAllow, userID, clientID,
		[]string{"openid"})
	stale.ProviderTenantID = "tenant-int"
	storedStale, won, err := grants.ClaimDecisionOperation(ctx, stale)
	if err != nil || !won {
		t.Fatalf("claim stale: won=%v err=%v", won, err)
	}
	if _, err := grants.pool.Exec(ctx,
		`UPDATE oauth_authorization_decision_operations SET created_at = now() - interval '10 minutes' WHERE operation_id = $1`,
		string(storedStale.ID)); err != nil {
		t.Fatalf("age stale row: %v", err)
	}

	ops, err := grants.ListInFlightDecisionOperations(ctx, time.Now().UTC().Add(-5*time.Minute), 100)
	if err != nil {
		t.Fatalf("ListInFlightDecisionOperations: %v", err)
	}
	got := map[string]consent.DecisionOperationStatus{}
	for _, op := range ops {
		got[op.AuthRequestID] = op.Status
	}
	if len(got) != 2 ||
		got["V2-int-list-proven"] != consent.DecisionOperationProviderSucceeded ||
		got["V2-int-list-stale"] != consent.DecisionOperationPending {
		t.Fatalf("in-flight listing = %+v", got)
	}
	if _, ok := got["V2-int-list-fresh"]; ok {
		t.Fatal("fresh pending must not be listed")
	}
}
