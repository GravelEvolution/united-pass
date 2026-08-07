//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the re-authentication cleaner
//

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func newCleanupWorker(t *testing.T, authz *fakeReauthAuth, challenges ReauthChallengeStore, auditor *fakeReauthAuditor) *ReauthCleanupWorker {
	t.Helper()
	return NewReauthCleanupWorker(authz, challenges, auditor, time.Minute, slog.Default())
}

func TestReauthCleanupWorker_RevokesAbandonedSessions(t *testing.T) {
	authz := &fakeReauthAuth{}
	auditor := &fakeReauthAuditor{}
	challenges := newMemReauthChallenges()
	challenges.pending = []auth.ExpiredReauthChallenge{
		{
			TokenHash:         "hash-1",
			ProviderSessionID: "ps-abandoned",
			UserID:            identity.UserID("user_actor"),
			ApplicationID:     "app_test1",
			ClientID:          "clt_test1",
			Action:            auth.ReauthActionClientSecretRotate,
		},
		// Entries without a provider session reference are skipped silently.
		{TokenHash: "hash-2", UserID: identity.UserID("user_actor")},
	}
	worker := newCleanupWorker(t, authz, challenges, auditor)

	if got := worker.sweep(context.Background()); got != 1 {
		t.Fatalf("sweep revoked = %d, want 1", got)
	}
	if len(authz.revoked) != 1 || authz.revoked[0] != "ps-abandoned" {
		t.Errorf("revoked = %v, want [ps-abandoned]", authz.revoked)
	}
	// Successful cleanup records no denial events.
	if auditor.has(applications.EventProviderSessionRevokeFailed, applications.SecurityEventDenied) {
		t.Error("unexpected revoke-failed audit event")
	}
	// The pop consumed the entries: a second sweep finds nothing (idempotent).
	if got := worker.sweep(context.Background()); got != 0 {
		t.Fatalf("second sweep revoked = %d, want 0", got)
	}
}

func TestReauthCleanupWorker_RevokeFailureAudits(t *testing.T) {
	authz := &fakeReauthAuth{revokeErr: errors.New("provider down")}
	auditor := &fakeReauthAuditor{}
	challenges := newMemReauthChallenges()
	challenges.pending = []auth.ExpiredReauthChallenge{
		{
			TokenHash:         "hash-1",
			ProviderSessionID: "ps-abandoned",
			UserID:            identity.UserID("user_actor"),
			ApplicationID:     "app_test1",
			Action:            auth.ReauthActionApplicationDelete,
		},
	}
	worker := newCleanupWorker(t, authz, challenges, auditor)

	if got := worker.sweep(context.Background()); got != 0 {
		t.Fatalf("sweep revoked = %d, want 0", got)
	}
	// Revocation is best-effort, but the failure must be a security event.
	if !auditor.has(applications.EventProviderSessionRevokeFailed, applications.SecurityEventDenied) {
		t.Error("expected provider_session.revoke_failed audit event")
	}
}

func TestReauthCleanupWorker_PopErrorIsTolerated(t *testing.T) {
	authz := &fakeReauthAuth{}
	auditor := &fakeReauthAuditor{}
	store := &failingExpiredChallenges{popErr: errors.New("redis down")}
	worker := newCleanupWorker(t, authz, store, auditor)

	if got := worker.sweep(context.Background()); got != 0 {
		t.Fatalf("sweep revoked = %d, want 0", got)
	}
	if len(authz.revoked) != 0 {
		t.Errorf("revoked = %v, want none after pop failure", authz.revoked)
	}
}

func TestReauthCleanupWorker_StartStop(t *testing.T) {
	authz := &fakeReauthAuth{}
	auditor := &fakeReauthAuditor{}
	challenges := newMemReauthChallenges()
	challenges.pending = []auth.ExpiredReauthChallenge{
		{TokenHash: "hash-1", ProviderSessionID: "ps-abandoned", UserID: identity.UserID("user_actor")},
	}
	worker := NewReauthCleanupWorker(authz, challenges, auditor, time.Hour, slog.Default())

	// Start sweeps once immediately; Stop must terminate without hanging.
	worker.Start()
	worker.Stop()

	if len(authz.revoked) != 1 || authz.revoked[0] != "ps-abandoned" {
		t.Errorf("revoked = %v, want [ps-abandoned] from the startup sweep", authz.revoked)
	}
}

// failingExpiredChallenges is a minimal ReauthChallengeStore whose pop always
// fails; the other methods are unused by the cleanup worker.
type failingExpiredChallenges struct {
	mu     sync.Mutex
	popErr error
}

func (f *failingExpiredChallenges) PopExpiredChallenges(context.Context, int) ([]auth.ExpiredReauthChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return nil, f.popErr
}

func (f *failingExpiredChallenges) CreateChallenge(context.Context, string, auth.ReauthChallengeData, time.Duration) error {
	return nil
}

func (f *failingExpiredChallenges) ClaimChallenge(context.Context, string, string) (auth.ReauthChallengeData, error) {
	return auth.ReauthChallengeData{}, nil
}

func (f *failingExpiredChallenges) ReleaseChallenge(context.Context, string, string) error {
	return nil
}

func (f *failingExpiredChallenges) ConsumeChallenge(context.Context, string, string) error {
	return nil
}

func (f *failingExpiredChallenges) IncrementChallengeAttempts(context.Context, string, int) (int, error) {
	return 0, nil
}
