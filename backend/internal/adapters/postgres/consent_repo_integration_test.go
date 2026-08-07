//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// setupConsentRepo builds the grant repository plus the helpers needed to
// create owner users and provisioned clients in the migrated test schema.
func setupConsentRepo(t *testing.T) (*GrantRepository, *ApplicationRepository, *UserRepository) {
	t.Helper()
	pool := setupTestPool(t, 5)
	appRepo, err := NewApplicationRepository(pool.PgxPool(), testCursorKey(t))
	if err != nil {
		t.Fatalf("create application repository: %v", err)
	}
	return NewGrantRepository(pool.PgxPool()), appRepo, NewUserRepository(pool.PgxPool())
}

func createConsentUser(t *testing.T, users *UserRepository, id, email string) identity.UserID {
	t.Helper()
	if err := users.Create(context.Background(), identity.User{
		ID: identity.UserID(id), Status: identity.UserStatusActive,
		DisplayName: "Consent User " + id, Email: email, Version: 1,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return identity.UserID(id)
}

func allowOperationFor(authRequestID string, kind consent.CompletionKind, user identity.UserID, clientID applications.OAuthClientID, scopes []string) consent.DecisionOperation {
	return consent.DecisionOperation{
		ID:             consent.NewDecisionOperationID(),
		Provider:       "zitadel",
		AuthRequestID:  authRequestID,
		CompletionKind: kind,
		LocalUserID:    user,
		ClientID:       clientID,
		Scopes:         scopes,
	}
}

func consentAuditEvent(clientID applications.OAuthClientID, actor identity.UserID, result applications.SecurityEventResult) applications.SecurityEvent {
	return applications.SecurityEvent{
		EventID:     applications.NewSecurityEventID(),
		EventType:   "consent.decision",
		ActorUserID: actor,
		ClientID:    clientID,
		RequestID:   "req-test",
		Operation:   "consent_decision",
		Result:      result,
		OccurredAt:  time.Now().UTC(),
	}
}

// claimAndProve runs the §5 steps 2 and 4 for a fresh completion plan and
// returns the stored operation.
func claimAndProve(t *testing.T, repo *GrantRepository, op consent.DecisionOperation) consent.DecisionOperation {
	t.Helper()
	stored, won, err := repo.ClaimDecisionOperation(context.Background(), op)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	if err := repo.RecordProviderSucceeded(context.Background(), stored.ID, time.Now().UTC()); err != nil {
		t.Fatalf("record proof: %v", err)
	}
	return stored
}

func TestClaimDecisionOperationSingleWinner(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-owner")
	_, clientID := provisionTestApp(t, appRepo, "consent-app", ownerID)
	user := createConsentUser(t, users, "consent-user-1", "consent-1@example.com")
	ctx := context.Background()

	first := allowOperationFor("V2-auth-1", consent.CompletionAllow, user, clientID, []string{"openid", "profile"})
	stored, won, err := repo.ClaimDecisionOperation(ctx, first)
	if err != nil || !won {
		t.Fatalf("first claim: won=%v err=%v", won, err)
	}
	if stored.Status != consent.DecisionOperationPending || stored.ID != first.ID {
		t.Fatalf("unexpected stored operation: %+v", stored)
	}

	// A second completion for the same auth request — even from another
	// user or with the opposite kind — must lose and never reach the
	// provider.
	otherUser := createConsentUser(t, users, "consent-user-2", "consent-2@example.com")
	second := allowOperationFor("V2-auth-1", consent.CompletionAccessDenied, otherUser, clientID, nil)
	existing, won, err := repo.ClaimDecisionOperation(ctx, second)
	if !errors.Is(err, consent.ErrDecisionConflict) || won {
		t.Fatalf("second claim: won=%v err=%v", won, err)
	}
	if existing.ID != first.ID || existing.CompletionKind != consent.CompletionAllow {
		t.Fatalf("loser must see the winner row: %+v", existing)
	}

	// The key includes the auth request: a different request claims fine.
	other := allowOperationFor("V2-auth-2", consent.CompletionAllow, user, clientID, []string{"openid"})
	if _, won, err := repo.ClaimDecisionOperation(ctx, other); err != nil || !won {
		t.Fatalf("distinct request claim: won=%v err=%v", won, err)
	}
}

func TestClaimReturnsDatabaseTruth(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-truth")
	_, clientID := provisionTestApp(t, appRepo, "consent-truth-app", ownerID)
	user := createConsentUser(t, users, "consent-user-truth", "consent-truth@example.com")

	// The caller's in-memory fields must not leak into the claim result:
	// status, timestamps and proof time come from the database row.
	op := allowOperationFor("V2-truth-1", consent.CompletionAllow, user, clientID, []string{"openid"})
	op.Status = consent.DecisionOperationSucceeded
	op.ProviderSucceededAt = time.Now().UTC().Add(time.Hour)
	op.CreatedAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	op.UpdatedAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	before := time.Now().UTC().Add(-time.Second)
	stored, won, err := repo.ClaimDecisionOperation(context.Background(), op)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	if stored.Status != consent.DecisionOperationPending {
		t.Fatalf("status must come from the database, got %q", stored.Status)
	}
	if !stored.ProviderSucceededAt.IsZero() {
		t.Fatalf("proof time must be unset after claim, got %v", stored.ProviderSucceededAt)
	}
	if stored.CreatedAt.Before(before) || stored.UpdatedAt.Before(before) {
		t.Fatalf("timestamps must come from the database: %v / %v", stored.CreatedAt, stored.UpdatedAt)
	}
	if stored.LocalUserID != user || stored.ClientID != clientID {
		t.Fatalf("plan bindings not persisted: %+v", stored)
	}
}

func TestClaimPersistsImmutableScopeSnapshot(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-snap")
	_, clientID := provisionTestApp(t, appRepo, "consent-snap-app", ownerID)
	user := createConsentUser(t, users, "consent-user-snap", "consent-snap@example.com")
	ctx := context.Background()

	// Duplicates and request order must not matter: the stored snapshot is
	// normalized; scopes never persist for non-allow kinds.
	op := allowOperationFor("V2-snap-1", consent.CompletionAllow, user, clientID,
		[]string{"profile", "openid", "profile"})
	stored, won, err := repo.ClaimDecisionOperation(ctx, op)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	if len(stored.Scopes) != 2 || stored.Scopes[0] != "openid" || stored.Scopes[1] != "profile" {
		t.Fatalf("snapshot not normalized: %+v", stored.Scopes)
	}

	reread, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-snap-1",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if len(reread.Scopes) != 2 || reread.Scopes[0] != "openid" || reread.Scopes[1] != "profile" {
		t.Fatalf("snapshot not durable: %+v", reread.Scopes)
	}
}

func TestClaimValidationRejectsMalformedPlans(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-bad")
	_, clientID := provisionTestApp(t, appRepo, "consent-bad-app", ownerID)
	user := createConsentUser(t, users, "consent-user-bad", "consent-bad@example.com")
	ctx := context.Background()

	bad := allowOperationFor("", consent.CompletionAllow, user, clientID, []string{"openid"})
	if _, _, err := repo.ClaimDecisionOperation(ctx, bad); err == nil {
		t.Fatal("empty auth request id must be rejected")
	}
	bad = allowOperationFor("V2-bad", consent.CompletionKind("maybe"), user, clientID, []string{"openid"})
	if _, _, err := repo.ClaimDecisionOperation(ctx, bad); err == nil {
		t.Fatal("unknown completion kind must be rejected")
	}
	bad = allowOperationFor("V2-bad", consent.CompletionAllow, user, clientID, nil)
	if _, _, err := repo.ClaimDecisionOperation(ctx, bad); err == nil {
		t.Fatal("allow without scope snapshot must be rejected")
	}
	bad = allowOperationFor("V2-bad", consent.CompletionLoginRequired, "", "", nil)
	bad.Scopes = []string{"openid"}
	if _, _, err := repo.ClaimDecisionOperation(ctx, bad); err == nil {
		t.Fatal("error callback with scopes must be rejected")
	}
	bad = allowOperationFor("V2-bad", consent.CompletionAllow, user, clientID, []string{"openid"})
	bad.ID = "op_foreign-id"
	if _, _, err := repo.ClaimDecisionOperation(ctx, bad); err == nil {
		t.Fatal("foreign operation id must be rejected")
	}
}

func TestConcurrentClaimHasExactlyOneWinner(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-race")
	_, clientID := provisionTestApp(t, appRepo, "consent-race-app", ownerID)
	userA := createConsentUser(t, users, "consent-user-race-a", "consent-race-a@example.com")
	userB := createConsentUser(t, users, "consent-user-race-b", "consent-race-b@example.com")
	ctx := context.Background()

	// Two user agents racing the same auth request at the same instant:
	// exactly one may obtain the provider qualification.
	const racers = 8
	var (
		wg      sync.WaitGroup
		start   sync.WaitGroup
		mu      sync.Mutex
		winners int
		losers  int
	)
	start.Add(1)
	for i := 0; i < racers; i++ {
		user := userA
		if i%2 == 1 {
			user = userB
		}
		op := allowOperationFor("V2-race-1", consent.CompletionAllow, user, clientID, []string{"openid"})
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait()
			_, won, err := repo.ClaimDecisionOperation(ctx, op)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case won && err == nil:
				winners++
			case errors.Is(err, consent.ErrDecisionConflict):
				losers++
			default:
				t.Errorf("unexpected claim outcome: won=%v err=%v", won, err)
			}
		}()
	}
	start.Done()
	wg.Wait()
	if winners != 1 || losers != racers-1 {
		t.Fatalf("expected exactly one winner, got winners=%d losers=%d", winners, losers)
	}

	// The single winner's plan is what the row carries.
	stored, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-race-1",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if stored.Status != consent.DecisionOperationPending || stored.LocalUserID == "" {
		t.Fatalf("winner row incomplete: %+v", stored)
	}
}

func TestCommitAllowUsesOnlyTheBoundPlan(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-bound")
	_, clientID := provisionTestApp(t, appRepo, "consent-bound-app", ownerID)
	user := createConsentUser(t, users, "consent-user-bound", "consent-bound@example.com")
	ctx := context.Background()

	// Forward-repair shape: the commit carries only the operation ID and
	// audit; user, client and scopes must come from the row bound at claim
	// time. Simulate the crash window by re-reading the operation through
	// the store (fresh process) before committing.
	plan := allowOperationFor("V2-bound-1", consent.CompletionAllow, user, clientID,
		[]string{"openid", "profile"})
	claimed := claimAndProve(t, repo, plan)

	recovered, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-bound-1",
	})
	if err != nil {
		t.Fatalf("recover operation: %v", err)
	}
	if recovered.Status != consent.DecisionOperationProviderSucceeded ||
		recovered.LocalUserID != user || recovered.ClientID != clientID ||
		len(recovered.Scopes) != 2 {
		t.Fatalf("operation row alone must be sufficient for repair: %+v", recovered)
	}

	err = repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: claimed.ID,
		Audit:       []applications.SecurityEvent{consentAuditEvent(clientID, user, applications.SecurityEventSuccess)},
	})
	if err != nil {
		t.Fatalf("commit allow: %v", err)
	}

	grant, err := repo.GetGrant(ctx, user, clientID)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if grant.Status != consent.GrantActive || grant.UserID != user || grant.ClientID != clientID {
		t.Fatalf("grant must mirror the bound plan: %+v", grant)
	}
	if !grant.ScopesContain([]string{"openid", "profile"}) || len(grant.Scopes) != 2 {
		t.Fatalf("grant scopes must mirror the claim snapshot: %+v", grant.Scopes)
	}

	stored, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-bound-1",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if stored.Status != consent.DecisionOperationSucceeded {
		t.Fatalf("operation not terminalized: %+v", stored)
	}

	// Committing twice is a state conflict: the proof transition is gone.
	err = repo.CommitAllowDecision(ctx, consent.AllowCommit{OperationID: claimed.ID})
	if !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("double commit must conflict, got %v", err)
	}
}

func TestCommitKindAndPlanMismatchFailsClosed(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-mismatch")
	_, clientID := provisionTestApp(t, appRepo, "consent-mismatch-app", ownerID)
	user := createConsentUser(t, users, "consent-user-mismatch", "consent-mismatch@example.com")
	ctx := context.Background()

	// Deny operation through the allow path: must fail, no grant, no audit
	// commit path reached.
	denyPlan := allowOperationFor("V2-mismatch-deny", consent.CompletionAccessDenied, user, clientID, nil)
	denyOp := claimAndProve(t, repo, denyPlan)
	err := repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: denyOp.ID,
		Audit:       []applications.SecurityEvent{consentAuditEvent(clientID, user, applications.SecurityEventSuccess)},
	})
	if !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("allow commit of deny operation must conflict, got %v", err)
	}
	if _, err := repo.GetGrant(ctx, user, clientID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("mismatched commit must leave no grant, got %v", err)
	}

	// Allow operation through the deny path.
	allowPlan := allowOperationFor("V2-mismatch-allow", consent.CompletionAllow, user, clientID, []string{"openid"})
	allowOp := claimAndProve(t, repo, allowPlan)
	err = repo.CommitDenyDecision(ctx, consent.DenyCommit{OperationID: allowOp.ID})
	if !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("deny commit of allow operation must conflict, got %v", err)
	}
	// The allow operation keeps its proof and remains repairable.
	stored, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-mismatch-allow",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if stored.Status != consent.DecisionOperationProviderSucceeded {
		t.Fatalf("proof must survive a mismatched commit: %+v", stored)
	}

	// User decisions through the error-completion path.
	err = repo.CommitErrorCompletion(ctx, consent.ErrorCompletionCommit{OperationID: allowOp.ID})
	if !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("error completion of allow operation must conflict, got %v", err)
	}
	err = repo.CommitErrorCompletion(ctx, consent.ErrorCompletionCommit{OperationID: denyOp.ID})
	if !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("error completion of deny operation must conflict, got %v", err)
	}

	// Unknown operations fail closed everywhere.
	missing := consent.NewDecisionOperationID()
	if err := repo.CommitAllowDecision(ctx, consent.AllowCommit{OperationID: missing}); !errors.Is(err, consent.ErrDecisionNotFound) {
		t.Fatalf("allow commit of unknown operation must be not found, got %v", err)
	}
	if err := repo.CommitDenyDecision(ctx, consent.DenyCommit{OperationID: missing}); !errors.Is(err, consent.ErrDecisionNotFound) {
		t.Fatalf("deny commit of unknown operation must be not found, got %v", err)
	}
}

func TestCommitAllowWithoutProofFailsClosed(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-noproof")
	_, clientID := provisionTestApp(t, appRepo, "consent-noproof-app", ownerID)
	user := createConsentUser(t, users, "consent-user-noproof", "consent-noproof@example.com")
	ctx := context.Background()

	// Claim only — no provider success proof. The local commit must fail
	// and roll back completely: no grant row may survive (ADR-0005 §5).
	plan := allowOperationFor("V2-noproof-1", consent.CompletionAllow, user, clientID, []string{"openid"})
	stored, won, err := repo.ClaimDecisionOperation(ctx, plan)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	err = repo.CommitAllowDecision(ctx, consent.AllowCommit{OperationID: stored.ID})
	if !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("commit without proof must conflict, got %v", err)
	}
	if _, err := repo.GetGrant(ctx, user, clientID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("rolled-back commit must leave no grant, got %v", err)
	}
}

func TestCommitAllowAuditFailureRollsBackEverything(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-audit")
	_, clientID := provisionTestApp(t, appRepo, "consent-audit-app", ownerID)
	user := createConsentUser(t, users, "consent-user-audit", "consent-audit@example.com")
	ctx := context.Background()

	plan := allowOperationFor("V2-audit-1", consent.CompletionAllow, user, clientID, []string{"openid"})
	claimed := claimAndProve(t, repo, plan)

	// Pre-persist an audit event, then reuse its ID inside the commit: the
	// duplicate primary key must abort the whole transaction — grant,
	// terminal transition and audit are one atomic unit.
	dup := consentAuditEvent(clientID, user, applications.SecurityEventSuccess)
	store := NewSecurityEventStore(repo.pool)
	if err := store.Record(ctx, dup); err != nil {
		t.Fatalf("pre-record audit: %v", err)
	}
	err := repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: claimed.ID,
		Audit:       []applications.SecurityEvent{dup},
	})
	if err == nil {
		t.Fatal("commit with duplicate audit event must fail")
	}
	if _, err := repo.GetGrant(ctx, user, clientID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("failed audit must roll back the grant, got %v", err)
	}
	stored, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-audit-1",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if stored.Status != consent.DecisionOperationProviderSucceeded {
		t.Fatalf("failed audit must leave the proof for forward repair: %+v", stored)
	}

	// The repair retry with a fresh audit succeeds.
	err = repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: claimed.ID,
		Audit:       []applications.SecurityEvent{consentAuditEvent(clientID, user, applications.SecurityEventSuccess)},
	})
	if err != nil {
		t.Fatalf("repair commit: %v", err)
	}
	if _, err := repo.GetGrant(ctx, user, clientID); err != nil {
		t.Fatalf("grant after repair: %v", err)
	}
}

func TestCommitAllowDecisionUpsertsScopeSet(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-upsert")
	_, clientID := provisionTestApp(t, appRepo, "consent-upsert-app", ownerID)
	user := createConsentUser(t, users, "consent-user-upsert", "consent-upsert@example.com")
	ctx := context.Background()

	first := claimAndProve(t, repo, allowOperationFor("V2-upsert-1", consent.CompletionAllow, user, clientID,
		[]string{"openid", "profile"}))
	if err := repo.CommitAllowDecision(ctx, consent.AllowCommit{OperationID: first.ID}); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	firstGrant, err := repo.GetGrant(ctx, user, clientID)
	if err != nil {
		t.Fatalf("first grant: %v", err)
	}

	// Scope expansion re-consents the same (user, client) row: same grant
	// ID, replaced scope set, refreshed consent time.
	second := claimAndProve(t, repo, allowOperationFor("V2-upsert-2", consent.CompletionAllow, user, clientID,
		[]string{"openid", "email", "offline_access"}))
	if err := repo.CommitAllowDecision(ctx, consent.AllowCommit{OperationID: second.ID}); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	secondGrant, err := repo.GetGrant(ctx, user, clientID)
	if err != nil {
		t.Fatalf("second grant: %v", err)
	}
	if secondGrant.ID != firstGrant.ID {
		t.Fatalf("upsert must reuse the grant row: %v vs %v", firstGrant.ID, secondGrant.ID)
	}
	if secondGrant.HasScope("profile") || !secondGrant.ScopesContain([]string{"openid", "email", "offline_access"}) {
		t.Fatalf("scope set not replaced: %+v", secondGrant.Scopes)
	}
	if !secondGrant.GrantedAt.After(firstGrant.GrantedAt.Add(-time.Millisecond)) {
		t.Fatalf("granted_at not refreshed: %v -> %v", firstGrant.GrantedAt, secondGrant.GrantedAt)
	}
}

func TestCommitDenyDecisionCreatesNoGrant(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-deny")
	_, clientID := provisionTestApp(t, appRepo, "consent-deny-app", ownerID)
	user := createConsentUser(t, users, "consent-user-deny", "consent-deny@example.com")
	ctx := context.Background()

	denyOp := claimAndProve(t, repo, allowOperationFor("V2-deny-1", consent.CompletionAccessDenied, user, clientID, nil))
	err := repo.CommitDenyDecision(ctx, consent.DenyCommit{
		OperationID: denyOp.ID,
		Audit:       []applications.SecurityEvent{consentAuditEvent(clientID, user, applications.SecurityEventDenied)},
	})
	if err != nil {
		t.Fatalf("commit deny: %v", err)
	}

	if _, err := repo.GetGrant(ctx, user, clientID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("deny must never create a grant, got %v", err)
	}
	got, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-deny-1",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if got.Status != consent.DecisionOperationSucceeded ||
		got.CompletionKind != consent.CompletionAccessDenied || got.LocalUserID != user {
		t.Fatalf("deny operation not terminalized: %+v", got)
	}
}

func TestGatewayErrorCompletionsClaimGloballyAndCommit(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-gateway")
	_, clientID := provisionTestApp(t, appRepo, "consent-gateway-app", ownerID)
	ctx := context.Background()

	// prompt=none without session: login_required with no bound user.
	plan := allowOperationFor("V2-gw-1", consent.CompletionLoginRequired, "", "", nil)
	stored, won, err := repo.ClaimDecisionOperation(ctx, plan)
	if err != nil || !won {
		t.Fatalf("gateway claim: won=%v err=%v", won, err)
	}
	if stored.LocalUserID != "" || stored.CompletionKind != consent.CompletionLoginRequired {
		t.Fatalf("unexpected gateway operation: %+v", stored)
	}

	// Duplicate completions of the same request conflict, whatever their
	// kind — the gateway never calls the provider twice.
	dup := allowOperationFor("V2-gw-1", consent.CompletionConsentRequired, "", "", nil)
	if _, won, err := repo.ClaimDecisionOperation(ctx, dup); !errors.Is(err, consent.ErrDecisionConflict) || won {
		t.Fatalf("duplicate gateway completion must conflict: won=%v err=%v", won, err)
	}

	if err := repo.RecordProviderSucceeded(ctx, stored.ID, time.Now().UTC()); err != nil {
		t.Fatalf("record proof: %v", err)
	}
	err = repo.CommitErrorCompletion(ctx, consent.ErrorCompletionCommit{
		OperationID: stored.ID,
		Audit:       []applications.SecurityEvent{consentAuditEvent(clientID, "", applications.SecurityEventDenied)},
	})
	if err != nil {
		t.Fatalf("commit error completion: %v", err)
	}
	got, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-gw-1",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if got.Status != consent.DecisionOperationSucceeded {
		t.Fatalf("gateway completion not terminalized: %+v", got)
	}
	if _, err := repo.GetGrant(ctx, "nobody", clientID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("gateway completion must never create a grant, got %v", err)
	}

	// prompt=create: request_not_supported follows the same path.
	create := allowOperationFor("V2-gw-2", consent.CompletionRequestNotSupported, "", "", nil)
	createOp := claimAndProve(t, repo, create)
	if err := repo.CommitErrorCompletion(ctx, consent.ErrorCompletionCommit{OperationID: createOp.ID}); err != nil {
		t.Fatalf("commit request_not_supported: %v", err)
	}
}

func TestProviderSuccessProofCompareAndSet(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-proof")
	_, clientID := provisionTestApp(t, appRepo, "consent-proof-app", ownerID)
	user := createConsentUser(t, users, "consent-user-proof", "consent-proof@example.com")
	ctx := context.Background()

	plan := allowOperationFor("V2-proof-1", consent.CompletionAllow, user, clientID, []string{"openid"})
	stored, won, err := repo.ClaimDecisionOperation(ctx, plan)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}

	proofAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := repo.RecordProviderSucceeded(ctx, stored.ID, proofAt); err != nil {
		t.Fatalf("first proof: %v", err)
	}
	// The proof is one-shot: a second record (retry after a lost local
	// commit) must fail instead of rewriting the proof time.
	if err := repo.RecordProviderSucceeded(ctx, stored.ID, proofAt.Add(time.Minute)); !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("second proof must conflict, got %v", err)
	}

	got, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-proof-1",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if got.Status != consent.DecisionOperationProviderSucceeded || !got.ProviderSucceededAt.Equal(proofAt) {
		t.Fatalf("proof not persisted: %+v", got)
	}

	// Unknown operations fail closed.
	if err := repo.RecordProviderSucceeded(ctx, consent.NewDecisionOperationID(), proofAt); !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("unknown operation proof must conflict, got %v", err)
	}
}

func TestFailDecisionOperationFailsClosedOnly(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-fail")
	_, clientID := provisionTestApp(t, appRepo, "consent-fail-app", ownerID)
	user := createConsentUser(t, users, "consent-user-fail", "consent-fail@example.com")
	ctx := context.Background()

	// A pending operation without proof can be terminated.
	plan := allowOperationFor("V2-fail-1", consent.CompletionAllow, user, clientID, []string{"openid"})
	stored, won, err := repo.ClaimDecisionOperation(ctx, plan)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	if err := repo.FailDecisionOperation(ctx, stored.ID, consent.ClassProviderUnavailable); err != nil {
		t.Fatalf("fail pending: %v", err)
	}
	got, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-fail-1",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if got.Status != consent.DecisionOperationFailed || got.ErrorClass != consent.ClassProviderUnavailable {
		t.Fatalf("operation not failed: %+v", got)
	}
	// Terminal states are immutable.
	if err := repo.FailDecisionOperation(ctx, stored.ID, consent.ClassInternal); !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("double fail must conflict, got %v", err)
	}
	// Only known stable classes are accepted.
	plan2 := allowOperationFor("V2-fail-2", consent.CompletionAllow, user, clientID, []string{"openid"})
	stored2, won, err := repo.ClaimDecisionOperation(ctx, plan2)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	if err := repo.FailDecisionOperation(ctx, stored2.ID, consent.ErrorClass("invented")); err == nil {
		t.Fatal("unknown error class must be rejected")
	}

	// A row carrying the provider_succeeded proof must never be failed:
	// reconciliation repairs it forward instead (ADR-0005 §4).
	proven := allowOperationFor("V2-fail-3", consent.CompletionAllow, user, clientID, []string{"openid"})
	storedProven := claimAndProve(t, repo, proven)
	if err := repo.FailDecisionOperation(ctx, storedProven.ID, consent.ClassInternal); !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("proven operation must not be fail-able, got %v", err)
	}
}

func TestGetDecisionOperationNotFound(t *testing.T) {
	repo, _, _ := setupConsentRepo(t)
	_, err := repo.GetDecisionOperation(context.Background(), consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-missing",
	})
	if !errors.Is(err, consent.ErrDecisionNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}
