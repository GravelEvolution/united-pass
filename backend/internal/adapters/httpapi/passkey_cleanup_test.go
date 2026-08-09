//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-09
// Description: Passkey enrollment cleanup worker tests
//

package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type fakePasskeyCleanupStore struct {
	entries   []auth.ExpiredPasskeyEnrollment
	completed []string
	requeued  []auth.ExpiredPasskeyEnrollment
}

func (s *fakePasskeyCleanupStore) ClaimExpiredPasskeyEnrollments(context.Context, int) ([]auth.ExpiredPasskeyEnrollment, error) {
	return s.entries, nil
}

func (s *fakePasskeyCleanupStore) CompletePasskeyEnrollmentCleanup(_ context.Context, tokenHash string) error {
	s.completed = append(s.completed, tokenHash)
	return nil
}

func (s *fakePasskeyCleanupStore) RequeuePasskeyEnrollmentCleanup(_ context.Context, entry auth.ExpiredPasskeyEnrollment, _ time.Duration) error {
	s.requeued = append(s.requeued, entry)
	return nil
}

func cleanupEntry() auth.ExpiredPasskeyEnrollment {
	return auth.ExpiredPasskeyEnrollment{
		TokenHash: "hashed-token", UserID: identity.UserID("user-1"), Target: "pk-target",
	}
}

func TestPasskeyCleanupWorker_PreservesActiveCredential(t *testing.T) {
	factors := &fakeFactorManager{listPasskeys: []auth.PasskeyInfo{{ID: "pk-target", State: auth.PasskeyStateActive}}}
	store := &fakePasskeyCleanupStore{entries: []auth.ExpiredPasskeyEnrollment{cleanupEntry()}}
	worker := NewPasskeyEnrollmentCleanupWorker(factors, store, time.Minute, discardLogger())

	if settled := worker.sweep(t.Context()); settled != 1 {
		t.Fatalf("settled = %d, want 1", settled)
	}
	if len(factors.removedPasskeys) != 0 {
		t.Fatalf("active passkey was removed: %v", factors.removedPasskeys)
	}
	if len(store.completed) != 1 || store.completed[0] != "hashed-token" {
		t.Fatalf("completed = %v, want cleanup marker only", store.completed)
	}
}

func TestPasskeyCleanupWorker_RemovesPendingOrUnlistedTarget(t *testing.T) {
	tests := []struct {
		name     string
		passkeys []auth.PasskeyInfo
	}{
		{name: "pending", passkeys: []auth.PasskeyInfo{{ID: "pk-target", State: auth.PasskeyStatePending}}},
		{name: "unlisted", passkeys: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			factors := &fakeFactorManager{listPasskeys: tc.passkeys}
			store := &fakePasskeyCleanupStore{entries: []auth.ExpiredPasskeyEnrollment{cleanupEntry()}}
			worker := NewPasskeyEnrollmentCleanupWorker(factors, store, time.Minute, discardLogger())

			if settled := worker.sweep(t.Context()); settled != 1 {
				t.Fatalf("settled = %d, want 1", settled)
			}
			if len(factors.removedPasskeys) != 1 || factors.removedPasskeys[0] != "pk-target" {
				t.Fatalf("removed = %v, want [pk-target]", factors.removedPasskeys)
			}
		})
	}
}

func TestPasskeyCleanupWorker_RequeuesProviderFailure(t *testing.T) {
	factors := &fakeFactorManager{listPasskeysErr: auth.ErrProviderUnavailable}
	store := &fakePasskeyCleanupStore{entries: []auth.ExpiredPasskeyEnrollment{cleanupEntry()}}
	worker := NewPasskeyEnrollmentCleanupWorker(factors, store, time.Minute, discardLogger())

	if settled := worker.sweep(t.Context()); settled != 0 {
		t.Fatalf("settled = %d, want 0", settled)
	}
	if len(store.requeued) != 1 || len(store.completed) != 0 {
		t.Fatalf("requeued/completed = %d/%d, want 1/0", len(store.requeued), len(store.completed))
	}
}

func TestPasskeyCleanupBackoffIsCapped(t *testing.T) {
	if got := passkeyCleanupBackoff(0); got != time.Minute {
		t.Fatalf("first backoff = %s, want 1m", got)
	}
	if got := passkeyCleanupBackoff(100); got != 32*time.Minute {
		t.Fatalf("capped backoff = %s, want 32m", got)
	}
}
