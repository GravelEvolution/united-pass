//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 6 Provider persistence invariant integration tests
//

//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/providers"
)

func createProviderTestUser(t *testing.T, repo *UserRepository, id identity.UserID, name, email string) {
	t.Helper()
	now := time.Now().UTC()
	if err := repo.Create(context.Background(), identity.User{
		ID: id, Status: identity.UserStatusActive, DisplayName: name, Email: email,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}); err != nil {
		t.Fatalf("create provider test user %s: %v", id, err)
	}
}

func TestIntegration_ProviderSyncIsIdempotentExplicitAndPartialSafe(t *testing.T) {
	pool := setupTestPool(t, 5)
	ctx := context.Background()
	users := NewUserRepository(pool.PgxPool())
	repo := NewProviderRepository(pool.PgxPool())
	actorID := identity.UserID("user_provider_actor")
	targetID := identity.UserID("user_provider_target")
	createProviderTestUser(t, users, actorID, "Provider Admin", "admin@example.test")
	createProviderTestUser(t, users, targetID, "Feishu Candidate", "candidate@example.test")

	first, err := repo.EnqueueSync(ctx, actorID, providers.FeishuProviderID, "req_provider_1")
	if err != nil {
		t.Fatalf("enqueue first sync: %v", err)
	}
	duplicate, err := repo.EnqueueSync(ctx, actorID, providers.FeishuProviderID, "req_provider_duplicate")
	if err != nil {
		t.Fatalf("enqueue duplicate sync: %v", err)
	}
	if duplicate.SyncID != first.SyncID {
		t.Fatalf("duplicate active sync = %s, want %s", duplicate.SyncID, first.SyncID)
	}

	claimed, err := repo.ClaimSync(ctx, time.Now().Add(-time.Minute))
	if err != nil || claimed == nil {
		t.Fatalf("claim first sync: job=%#v err=%v", claimed, err)
	}
	completed, err := repo.ApplySnapshot(ctx, *claimed, providers.DirectorySnapshot{
		ProviderID: providers.FeishuProviderID,
		TenantID:   "tenant_test",
		Departments: []providers.ExternalDepartment{
			{ExternalID: "od_engineering", Name: "Engineering"},
		},
		Users: []providers.ExternalUser{
			{Subject: "ou_candidate", Name: "Feishu Candidate", Email: "candidate@example.test", Active: true},
			{Subject: "ou_stays_active", Name: "Staged Only", Email: "staged@example.test", Active: true},
		},
	})
	if err != nil {
		t.Fatalf("apply first snapshot: %v", err)
	}
	if completed.Status != providers.SyncStatusPartial || completed.ConflictsDetected != 2 {
		t.Fatalf("first completion = %#v", completed)
	}

	var linkCount int
	if err := pool.PgxPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM identity_links WHERE provider = $1`, string(providers.FeishuProviderID)).Scan(&linkCount); err != nil {
		t.Fatalf("count implicit identity links: %v", err)
	}
	if linkCount != 0 {
		t.Fatalf("directory suggestion created %d implicit identity links", linkCount)
	}

	conflicts, err := repo.ListConflicts(ctx, providers.FeishuProviderID, 20)
	if err != nil {
		t.Fatalf("list conflicts: %v", err)
	}
	var candidateConflict providers.SyncConflict
	for _, item := range conflicts {
		if item.ExternalSubject == "ou_candidate" {
			candidateConflict = item
			break
		}
	}
	if candidateConflict.ConflictID == "" || candidateConflict.MatchedUserID != targetID || candidateConflict.MatchReason != providers.MatchReasonEmail {
		t.Fatalf("candidate conflict = %#v", candidateConflict)
	}
	if err := repo.ResolveConflict(ctx, actorID, candidateConflict.ConflictID, targetID, "req_provider_resolve"); err != nil {
		t.Fatalf("resolve explicit identity link: %v", err)
	}
	linked, err := repo.LinkedUser(ctx, providers.FeishuProviderID, "tenant_test", "ou_candidate")
	if err != nil || linked.ID != targetID {
		t.Fatalf("linked user = %#v err=%v", linked, err)
	}
	var auditCount int
	if err := pool.PgxPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM security_events
		  WHERE event_type = $1 AND actor_user_id = $2 AND payload->>'conflict_id' = $3`,
		providers.EventIdentityConflictResolved, string(actorID), string(candidateConflict.ConflictID)).Scan(&auditCount); err != nil {
		t.Fatalf("count identity link audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("identity link audit rows = %d, want 1", auditCount)
	}

	if err := repo.RecordUnlinkedIdentity(ctx, providers.FeishuProviderID, "tenant_test", providers.OAuthUserInfo{
		Subject: "ou_second_subject", TenantID: "tenant_test", Name: "Feishu Candidate", Email: "candidate@example.test",
	}); err != nil {
		t.Fatalf("record second unlinked identity: %v", err)
	}
	conflicts, err = repo.ListConflicts(ctx, providers.FeishuProviderID, 20)
	if err != nil {
		t.Fatalf("list second conflict: %v", err)
	}
	var secondConflict providers.SyncConflict
	for _, item := range conflicts {
		if item.ExternalSubject == "ou_second_subject" {
			secondConflict = item
			break
		}
	}
	if secondConflict.ConflictID == "" {
		t.Fatal("second conflict not found")
	}
	if err := repo.ResolveConflict(ctx, actorID, secondConflict.ConflictID, targetID, "req_provider_second"); !errors.Is(err, providers.ErrConflict) {
		t.Fatalf("second subject linked to same user: %v", err)
	}

	second, err := repo.EnqueueSync(ctx, actorID, providers.FeishuProviderID, "req_provider_partial")
	if err != nil {
		t.Fatalf("enqueue partial sync: %v", err)
	}
	claimed, err = repo.ClaimSync(ctx, time.Now().Add(-time.Minute))
	if err != nil || claimed == nil || claimed.SyncID != second.SyncID {
		t.Fatalf("claim partial sync: job=%#v err=%v", claimed, err)
	}
	_, err = repo.ApplySnapshot(ctx, *claimed, providers.DirectorySnapshot{
		ProviderID:   providers.FeishuProviderID,
		TenantID:     "tenant_test",
		Partial:      true,
		FailureClass: "provider",
		Users: []providers.ExternalUser{
			{Subject: "ou_candidate", Name: "Feishu Candidate", Email: "candidate@example.test", Active: true},
		},
	})
	if err != nil {
		t.Fatalf("apply partial snapshot: %v", err)
	}
	var stagedActive bool
	if err := pool.PgxPool().QueryRow(ctx,
		`SELECT active FROM provider_directory_users
		  WHERE provider_id = $1 AND provider_tenant_id = $2 AND external_subject = $3`,
		string(providers.FeishuProviderID), "tenant_test", "ou_stays_active").Scan(&stagedActive); err != nil {
		t.Fatalf("read missing row after partial sync: %v", err)
	}
	if !stagedActive {
		t.Fatal("partial snapshot retired an unseen staged user")
	}
	var employeeProfiles int
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM employee_profiles WHERE user_id = $1`, string(targetID)).Scan(&employeeProfiles); err != nil {
		t.Fatalf("count employee profiles: %v", err)
	}
	if employeeProfiles != 0 {
		t.Fatalf("provider sync granted employee status: %d profiles", employeeProfiles)
	}
}
