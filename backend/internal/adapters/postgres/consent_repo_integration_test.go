//go:build integration

package postgres

import (
	"context"
	"errors"
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

func newDecisionOperation(authRequestID string, decision consent.Decision, clientID applications.OAuthClientID) consent.DecisionOperation {
	return consent.DecisionOperation{
		ID:               consent.NewDecisionOperationID(),
		Provider:         "zitadel",
		ProviderTenantID: "",
		AuthRequestID:    authRequestID,
		Decision:         decision,
		Status:           consent.DecisionOperationPending,
		ClientID:         clientID,
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

// claimAndProve runs the §5 steps 2 and 4 for a fresh allow decision and
// returns the operation ID.
func claimAndProve(t *testing.T, repo *GrantRepository, authRequestID string, clientID applications.OAuthClientID) consent.DecisionOperationID {
	t.Helper()
	op := newDecisionOperation(authRequestID, consent.DecisionAllow, clientID)
	stored, won, err := repo.ClaimDecisionOperation(context.Background(), op)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	if err := repo.RecordProviderSucceeded(context.Background(), stored.ID, time.Now().UTC()); err != nil {
		t.Fatalf("record proof: %v", err)
	}
	return stored.ID
}

func TestClaimDecisionOperationSingleWinner(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-owner")
	_, clientID := provisionTestApp(t, appRepo, "consent-app", ownerID)
	ctx := context.Background()

	first := newDecisionOperation("V2-auth-1", consent.DecisionAllow, clientID)
	stored, won, err := repo.ClaimDecisionOperation(ctx, first)
	if err != nil || !won {
		t.Fatalf("first claim: won=%v err=%v", won, err)
	}
	if stored.Status != consent.DecisionOperationPending || stored.ID != first.ID {
		t.Fatalf("unexpected stored operation: %+v", stored)
	}

	// A second decision for the same auth request — even from another user
	// or with the opposite decision — must lose and never reach the
	// provider.
	second := newDecisionOperation("V2-auth-1", consent.DecisionDeny, clientID)
	existing, won, err := repo.ClaimDecisionOperation(ctx, second)
	if !errors.Is(err, consent.ErrDecisionConflict) || won {
		t.Fatalf("second claim: won=%v err=%v", won, err)
	}
	if existing.ID != first.ID || existing.Decision != consent.DecisionAllow {
		t.Fatalf("loser must see the winner row: %+v", existing)
	}

	// The key includes the auth request: a different request claims fine.
	other := newDecisionOperation("V2-auth-2", consent.DecisionAllow, clientID)
	if _, won, err := repo.ClaimDecisionOperation(ctx, other); err != nil || !won {
		t.Fatalf("distinct request claim: won=%v err=%v", won, err)
	}
}

func TestClaimDecisionOperationValidatesInputs(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-owner-v")
	_, clientID := provisionTestApp(t, appRepo, "consent-app-v", ownerID)

	bad := newDecisionOperation("", consent.DecisionAllow, clientID)
	if _, _, err := repo.ClaimDecisionOperation(context.Background(), bad); err == nil {
		t.Fatal("empty auth request id must be rejected")
	}
	bad = newDecisionOperation("V2-auth", consent.Decision("maybe"), clientID)
	if _, _, err := repo.ClaimDecisionOperation(context.Background(), bad); err == nil {
		t.Fatal("unknown decision must be rejected")
	}
}

func TestProviderSuccessProofCompareAndSet(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-proof")
	_, clientID := provisionTestApp(t, appRepo, "consent-proof-app", ownerID)
	ctx := context.Background()

	op := newDecisionOperation("V2-proof-1", consent.DecisionAllow, clientID)
	stored, won, err := repo.ClaimDecisionOperation(ctx, op)
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

func TestCommitAllowDecisionCreatesGrantOnce(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-allow")
	_, clientID := provisionTestApp(t, appRepo, "consent-allow-app", ownerID)
	user := identity.UserID("consent-user-allow")
	if err := users.Create(context.Background(), identity.User{
		ID: user, Status: identity.UserStatusActive, DisplayName: "Consent User",
		Email: "consent-allow@example.com", Version: 1,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	ctx := context.Background()

	opID := claimAndProve(t, repo, "V2-allow-1", clientID)
	err := repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: opID,
		UserID:      user,
		ClientID:    clientID,
		Scopes:      []string{"openid", "profile"},
		Audit:       []applications.SecurityEvent{consentAuditEvent(clientID, user, applications.SecurityEventSuccess)},
	})
	if err != nil {
		t.Fatalf("commit allow: %v", err)
	}

	grant, err := repo.GetGrant(ctx, user, clientID)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if grant.Status != consent.GrantActive || !grant.ScopesContain([]string{"openid", "profile"}) {
		t.Fatalf("unexpected grant: %+v", grant)
	}

	stored, err := repo.GetDecisionOperation(ctx, consent.DecisionOperationKey{
		Provider: "zitadel", AuthRequestID: "V2-allow-1",
	})
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if stored.Status != consent.DecisionOperationSucceeded || stored.LocalUserID != user {
		t.Fatalf("operation not terminalized with winner binding: %+v", stored)
	}

	// Committing twice is a state conflict: the proof transition is gone.
	err = repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: opID, UserID: user, ClientID: clientID,
		Scopes: []string{"openid"},
	})
	if !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("double commit must conflict, got %v", err)
	}
}

func TestCommitAllowDecisionUpsertsScopeSet(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-upsert")
	_, clientID := provisionTestApp(t, appRepo, "consent-upsert-app", ownerID)
	user := identity.UserID("consent-user-upsert")
	if err := users.Create(context.Background(), identity.User{
		ID: user, Status: identity.UserStatusActive, DisplayName: "Consent User",
		Email: "consent-upsert@example.com", Version: 1,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	ctx := context.Background()

	opID := claimAndProve(t, repo, "V2-upsert-1", clientID)
	if err := repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: opID, UserID: user, ClientID: clientID,
		Scopes: []string{"openid", "profile"},
	}); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	first, err := repo.GetGrant(ctx, user, clientID)
	if err != nil {
		t.Fatalf("first grant: %v", err)
	}

	// Scope expansion re-consents the same (user, client) row: same grant
	// ID, replaced scope set, refreshed consent time.
	opID2 := claimAndProve(t, repo, "V2-upsert-2", clientID)
	if err := repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: opID2, UserID: user, ClientID: clientID,
		Scopes: []string{"openid", "email", "offline_access"},
	}); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	second, err := repo.GetGrant(ctx, user, clientID)
	if err != nil {
		t.Fatalf("second grant: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("upsert must reuse the grant row: %v vs %v", first.ID, second.ID)
	}
	if second.HasScope("profile") || !second.ScopesContain([]string{"openid", "email", "offline_access"}) {
		t.Fatalf("scope set not replaced: %+v", second.Scopes)
	}
	if !second.GrantedAt.After(first.GrantedAt.Add(-time.Millisecond)) {
		t.Fatalf("granted_at not refreshed: %v -> %v", first.GrantedAt, second.GrantedAt)
	}
}

func TestCommitAllowWithoutProofFailsClosed(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-noproof")
	_, clientID := provisionTestApp(t, appRepo, "consent-noproof-app", ownerID)
	user := identity.UserID("consent-user-noproof")
	if err := users.Create(context.Background(), identity.User{
		ID: user, Status: identity.UserStatusActive, DisplayName: "Consent User",
		Email: "consent-noproof@example.com", Version: 1,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	ctx := context.Background()

	// Claim only — no provider success proof. The local commit must fail
	// and roll back completely: no grant row may survive (ADR-0005 §5).
	op := newDecisionOperation("V2-noproof-1", consent.DecisionAllow, clientID)
	stored, won, err := repo.ClaimDecisionOperation(ctx, op)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	err = repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: stored.ID, UserID: user, ClientID: clientID,
		Scopes: []string{"openid"},
	})
	if !errors.Is(err, consent.ErrDecisionStateConflict) {
		t.Fatalf("commit without proof must conflict, got %v", err)
	}
	if _, err := repo.GetGrant(ctx, user, clientID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("rolled-back commit must leave no grant, got %v", err)
	}
}

func TestCommitDenyDecisionCreatesNoGrant(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-deny")
	_, clientID := provisionTestApp(t, appRepo, "consent-deny-app", ownerID)
	user := identity.UserID("consent-user-deny")
	if err := users.Create(context.Background(), identity.User{
		ID: user, Status: identity.UserStatusActive, DisplayName: "Consent User",
		Email: "consent-deny@example.com", Version: 1,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	ctx := context.Background()

	op := newDecisionOperation("V2-deny-1", consent.DecisionDeny, clientID)
	stored, won, err := repo.ClaimDecisionOperation(ctx, op)
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	if err := repo.RecordProviderSucceeded(ctx, stored.ID, time.Now().UTC()); err != nil {
		t.Fatalf("record proof: %v", err)
	}
	err = repo.CommitDenyDecision(ctx, consent.DenyCommit{
		OperationID: stored.ID,
		UserID:      user,
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
	if got.Status != consent.DecisionOperationSucceeded || got.LocalUserID != user || got.Decision != consent.DecisionDeny {
		t.Fatalf("deny operation not terminalized: %+v", got)
	}
}

func TestFailDecisionOperationFailsClosedOnly(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-fail")
	_, clientID := provisionTestApp(t, appRepo, "consent-fail-app", ownerID)
	ctx := context.Background()

	// A pending operation without proof can be terminated.
	op := newDecisionOperation("V2-fail-1", consent.DecisionAllow, clientID)
	stored, won, err := repo.ClaimDecisionOperation(ctx, op)
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

	// A row carrying the provider_succeeded proof must never be failed:
	// reconciliation repairs it forward instead (ADR-0005 §4).
	proven := newDecisionOperation("V2-fail-2", consent.DecisionAllow, clientID)
	storedProven, won, err := repo.ClaimDecisionOperation(ctx, proven)
	if err != nil || !won {
		t.Fatalf("claim proven: won=%v err=%v", won, err)
	}
	if err := repo.RecordProviderSucceeded(ctx, storedProven.ID, time.Now().UTC()); err != nil {
		t.Fatalf("record proof: %v", err)
	}
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

func TestGetGrantNotFoundAndScopeOrder(t *testing.T) {
	repo, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "consent-order")
	_, clientID := provisionTestApp(t, appRepo, "consent-order-app", ownerID)
	user := identity.UserID("consent-user-order")
	if err := users.Create(context.Background(), identity.User{
		ID: user, Status: identity.UserStatusActive, DisplayName: "Consent User",
		Email: "consent-order@example.com", Version: 1,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	ctx := context.Background()

	if _, err := repo.GetGrant(ctx, user, clientID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}

	opID := claimAndProve(t, repo, "V2-order-1", clientID)
	if err := repo.CommitAllowDecision(ctx, consent.AllowCommit{
		OperationID: opID, UserID: user, ClientID: clientID,
		Scopes: []string{"profile", "openid", "email"},
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	grant, err := repo.GetGrant(ctx, user, clientID)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	want := []string{"email", "openid", "profile"}
	if len(grant.Scopes) != len(want) {
		t.Fatalf("scope count: %+v", grant.Scopes)
	}
	for i, scope := range want {
		if grant.Scopes[i] != scope {
			t.Fatalf("scopes not deterministic: %+v", grant.Scopes)
		}
	}
}
