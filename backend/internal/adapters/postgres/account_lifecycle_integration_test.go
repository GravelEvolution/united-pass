//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Integration coverage for public account and self-service persistence
//

//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/dashboard"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestIntegration_AccountLifecyclePersistence(t *testing.T) {
	pool := setupTestPool(t, 5)
	repo := NewUserRepository(pool.PgxPool())
	ctx := context.Background()

	userID := identity.UserID("user_public_lifecycle")
	providerInfo := identity.ProviderUserInfo{
		Subject:     "zitadel-subject-public",
		DisplayName: "public.user",
		Email:       "public.user@example.com",
	}
	if err := repo.CreatePendingRegistration(
		ctx,
		userID,
		"zitadel",
		"project-public",
		"public.user",
		providerInfo,
	); err != nil {
		t.Fatalf("create pending registration: %v", err)
	}

	pending, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("load pending user: %v", err)
	}
	if pending.Status != identity.UserStatusPending || pending.EmailVerified {
		t.Fatalf("pending state = status %q verified %v", pending.Status, pending.EmailVerified)
	}
	if len(pending.Personas) != 1 || pending.Personas[0] != identity.PersonaConsumer {
		t.Fatalf("pending personas = %v, want [consumer]", pending.Personas)
	}
	if _, err := repo.FindPasswordResetBinding(
		ctx,
		"zitadel",
		"project-public",
		providerInfo.Subject,
	); !errors.Is(err, auth.ErrPublicAccountNotFound) {
		t.Fatalf("pending account password reset lookup = %v, want not found", err)
	}

	binding, err := repo.GetPublicAccountBinding(ctx, userID, "zitadel", "project-public")
	if err != nil {
		t.Fatalf("load public account binding: %v", err)
	}
	if binding.ProviderSubject != providerInfo.Subject || binding.Email != providerInfo.Email {
		t.Fatalf("binding = %+v, want exact provider subject and email", binding)
	}
	if err := repo.ActivatePendingRegistration(ctx, binding); err != nil {
		t.Fatalf("activate pending registration: %v", err)
	}

	active, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("load activated user: %v", err)
	}
	if active.Status != identity.UserStatusActive || !active.EmailVerified {
		t.Fatalf("activated state = status %q verified %v", active.Status, active.EmailVerified)
	}
	resetBinding, err := repo.FindPasswordResetBinding(
		ctx,
		"zitadel",
		"project-public",
		providerInfo.Subject,
	)
	if err != nil {
		t.Fatalf("load password reset binding: %v", err)
	}
	if resetBinding.UserID != userID {
		t.Fatalf("reset binding user = %q, want %q", resetBinding.UserID, userID)
	}
	if err := repo.ActivatePendingRegistration(ctx, binding); !errors.Is(err, auth.ErrLifecycleCodeInvalid) {
		t.Fatalf("replayed activation = %v, want invalid lifecycle code", err)
	}

	conflictingUserID := identity.UserID("user_public_conflict")
	if err := repo.CreatePendingRegistration(
		ctx,
		conflictingUserID,
		"zitadel",
		"project-public",
		"other.user",
		identity.ProviderUserInfo{
			Subject: providerInfo.Subject,
			Email:   "other.user@example.com",
		},
	); !errors.Is(err, auth.ErrRegistrationConflict) {
		t.Fatalf("conflicting registration = %v, want registration conflict", err)
	}
	if _, err := repo.GetByID(ctx, conflictingUserID); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("conflicting registration left local user: %v", err)
	}
}

func TestIntegration_UnverifiedProviderFirstLoginRemainsPending(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	user, err := repo.GetOrCreateUserByProviderSubject(ctx, "zitadel", "tenant_lifecycle", identity.ProviderUserInfo{
		Subject: "subject_unverified_orphan", DisplayName: "Unverified",
		Email: "unverified@example.test", EmailVerified: false,
	})
	if err != nil {
		t.Fatalf("first-login link: %v", err)
	}
	if user.Status != identity.UserStatusPending {
		t.Fatalf("status = %q, want pending", user.Status)
	}
	if user.Status.CanAuthenticate() {
		t.Fatal("unverified provider identity must not authenticate")
	}
}

func TestIntegration_AccountSelfServiceAndDashboard(t *testing.T) {
	pool := setupTestPool(t, 5)
	repo := NewUserRepository(pool.PgxPool())
	ctx := context.Background()
	now := time.Now().UTC()
	userID := identity.UserID("user_self_service")
	if err := repo.Create(ctx, identity.User{
		ID: userID, Status: identity.UserStatusActive,
		DisplayName: "Before", Email: "before@example.com",
		EmailVerified: true, Version: 1, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create self-service user: %v", err)
	}

	displayName, nickname := "After", "A"
	if err := repo.UpdateOwnProfile(ctx, userID, &displayName, &nickname); err != nil {
		t.Fatalf("update profile: %v", err)
	}
	updated, err := repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("load updated profile: %v", err)
	}
	if updated.DisplayName != displayName || updated.Nickname != nickname || updated.Version != 2 {
		t.Fatalf("updated profile = %+v", updated)
	}

	avatarID := "avt_0123456789abcdef0123456789abcdef"
	avatarContent := []byte("server-reencoded-png")
	etag := strings.Repeat("a", 64)
	avatarURL, err := repo.SaveAvatar(ctx, userID, avatarID, avatarContent, etag)
	if err != nil {
		t.Fatalf("save avatar: %v", err)
	}
	if avatarURL != "/api/v1/media/avatars/"+avatarID+".png" {
		t.Fatalf("avatar URL = %q", avatarURL)
	}
	storedContent, storedETag, err := repo.GetAvatar(ctx, avatarID)
	if err != nil {
		t.Fatalf("get avatar: %v", err)
	}
	if string(storedContent) != string(avatarContent) || storedETag != etag {
		t.Fatalf("stored avatar = %q etag %q", storedContent, storedETag)
	}

	requestHash := strings.Repeat("b", 64)
	change := identity.ContactChangeRequest{
		RequestIDHash: requestHash,
		UserID:        userID,
		SessionID:     "session-self-service",
		Kind:          identity.ContactKindEmail,
		Value:         "after@example.com",
		ExpiresAt:     now.Add(10 * time.Minute),
	}
	if err := repo.CreateContactChange(ctx, change); err != nil {
		t.Fatalf("create contact change: %v", err)
	}
	if _, err := repo.ClaimContactChange(
		ctx,
		requestHash,
		userID,
		"wrong-session",
		"wrong-claim",
		time.Minute,
	); !errors.Is(err, identity.ErrContactRequestNotFound) {
		t.Fatalf("cross-session claim = %v, want not found", err)
	}
	claimed, err := repo.ClaimContactChange(
		ctx,
		requestHash,
		userID,
		change.SessionID,
		"claim-one",
		time.Minute,
	)
	if err != nil {
		t.Fatalf("claim contact change: %v", err)
	}
	if claimed.Value != change.Value || claimed.Kind != identity.ContactKindEmail {
		t.Fatalf("claimed contact = %+v", claimed)
	}
	if _, err := repo.ClaimContactChange(
		ctx,
		requestHash,
		userID,
		change.SessionID,
		"claim-two",
		time.Minute,
	); !errors.Is(err, identity.ErrContactRequestClaimed) {
		t.Fatalf("concurrent claim = %v, want already claimed", err)
	}
	if err := repo.CompleteContactChange(ctx, requestHash, "claim-one"); err != nil {
		t.Fatalf("complete contact change: %v", err)
	}
	updated, err = repo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("load verified contact: %v", err)
	}
	if updated.Email != change.Value || !updated.EmailVerified {
		t.Fatalf("verified email = %q verified %v", updated.Email, updated.EmailVerified)
	}
	var storedValue, status string
	if err := pool.PgxPool().QueryRow(ctx, `
		SELECT value, status FROM contact_change_requests WHERE request_id_hash=$1`, requestHash).
		Scan(&storedValue, &status); err != nil {
		t.Fatalf("inspect completed contact request: %v", err)
	}
	if storedValue != "" || status != "completed" {
		t.Fatalf("completed contact request retained value=%q status=%q", storedValue, status)
	}

	if _, err := pool.PgxPool().Exec(ctx, `
		INSERT INTO oauth_applications
		       (application_id, name, audience, owner_user_id, status, provisioning_status)
		VALUES ('app_active', 'Active app', 'external', $1, 'active', 'provisioned'),
		       ('app_disabled', 'Disabled app', 'external', $1, 'disabled', 'provisioned'),
		       ('app_pending', 'Pending app', 'external', $1, 'active', 'provisioning')`,
		string(userID)); err != nil {
		t.Fatalf("seed dashboard applications: %v", err)
	}
	if _, err := pool.PgxPool().Exec(ctx, `
		INSERT INTO security_events
		       (event_id, event_type, actor_user_id, request_id, operation, result, occurred_at)
		VALUES ('evt_denied_recent', 'authorization.denied', $1, 'req_recent', 'test', 'denied', NOW()),
		       ('evt_denied_old', 'authorization.denied', $1, 'req_old', 'test', 'denied', NOW()-INTERVAL '31 days'),
		       ('evt_success', 'account.updated', $1, 'req_success', 'test', 'success', NOW())`,
		string(userID)); err != nil {
		t.Fatalf("seed dashboard audit events: %v", err)
	}

	dashboardRepo := NewDashboardRepository(pool.PgxPool())
	snapshot, err := dashboardRepo.Load(ctx, dashboard.Access{
		Users: true, Applications: true, Audit: true,
	})
	if err != nil {
		t.Fatalf("load dashboard snapshot: %v", err)
	}
	if snapshot.ActiveUsers != 1 || snapshot.PendingUsers != 0 {
		t.Fatalf("dashboard user counts = active %d pending %d", snapshot.ActiveUsers, snapshot.PendingUsers)
	}
	if snapshot.Applications != 2 || snapshot.ActiveApplications != 1 {
		t.Fatalf("dashboard application counts = total %d active %d", snapshot.Applications, snapshot.ActiveApplications)
	}
	if snapshot.DeniedEvents30Days != 1 || len(snapshot.RecentEvents) != 3 {
		t.Fatalf("dashboard audit = denied %d recent %d", snapshot.DeniedEvents30Days, len(snapshot.RecentEvents))
	}
}
