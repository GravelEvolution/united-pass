//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/phoneverify"
)

func TestIntegration_SMSPhoneAuthorityRejectsOwnerAndPreservesProfileWithAuditOutbox(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)
	target := identity.User{
		ID: "user_sms_phone_target", Status: identity.UserStatusActive,
		DisplayName: "SMS Target", Nickname: "保留昵称", AvatarURL: "/avatars/sms-target",
		Email: "sms-target@example.com", EmailVerified: true,
		Phone: "+8613800000011", PhoneVerified: true,
		CreatedAt: now, UpdatedAt: now, Version: 3,
	}
	owner := identity.User{
		ID: "user_sms_phone_owner", Status: identity.UserStatusActive,
		Email: "sms-owner@example.com", EmailVerified: true,
		Phone: "+8613800000022", PhoneVerified: true,
		CreatedAt: now, UpdatedAt: now, Version: 2,
	}
	if err := repo.Create(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, owner); err != nil {
		t.Fatal(err)
	}

	if err := repo.UpdatePhone(ctx, target.ID, owner.Phone); !errors.Is(err, phoneverify.ErrPhoneConflict) {
		t.Fatalf("owner conflict=%v, want ErrPhoneConflict", err)
	}
	assertSMSPhoneAuthorityState(t, repo, target.ID, target.Phone, true, 3, 1)

	const verifiedPhone = "+8613800000033"
	if err := repo.UpdatePhone(ctx, target.ID, verifiedPhone); err != nil {
		t.Fatalf("verify free phone: %v", err)
	}
	assertSMSPhoneAuthorityState(t, repo, target.ID, verifiedPhone, true, 4, 2)
	loaded, err := repo.GetByID(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DisplayName != target.DisplayName || loaded.Nickname != target.Nickname ||
		loaded.AvatarURL != target.AvatarURL || loaded.Email != target.Email {
		t.Fatalf("phone authority mutation overwrote profile: %#v", loaded)
	}

	var auditCount, pendingCount int
	var persisted string
	err = repo.pool.QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE event_type='account.phone_verified'),
       COUNT(*) FILTER (WHERE event_type='notification.pending'),
       COALESCE(STRING_AGG(payload::text, ' '), '')
  FROM security_events
 WHERE target_kind='user_id'
   AND target_id=$1`, string(target.ID)).Scan(&auditCount, &pendingCount, &persisted)
	if err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || pendingCount != 1 {
		t.Fatalf("audit=%d pending=%d", auditCount, pendingCount)
	}
	if strings.Contains(persisted, verifiedPhone) || strings.Contains(persisted, strings.TrimPrefix(verifiedPhone, "+86")) {
		t.Fatalf("authority event payload persisted phone PII: %s", persisted)
	}

	// Replaying the exact already-verified phone is a no-op: it must not churn
	// the account generations or duplicate the outbox.
	if err := repo.UpdatePhone(ctx, target.ID, verifiedPhone); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	assertSMSPhoneAuthorityState(t, repo, target.ID, verifiedPhone, true, 4, 2)
	if err := repo.pool.QueryRow(ctx, `SELECT COUNT(*) FROM security_events WHERE target_kind='user_id' AND target_id=$1`, string(target.ID)).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("event count after replay=%d err=%v", auditCount, err)
	}
}

func TestIntegration_SMSPhoneAuthorityConcurrentClaimHasOneOwner(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	users := []identity.UserID{"user_sms_race_a", "user_sms_race_b"}
	for _, userID := range users {
		if err := repo.Create(ctx, identity.User{
			ID: userID, Status: identity.UserStatusActive,
			Email: string(userID) + "@example.com", EmailVerified: true,
			CreatedAt: now, UpdatedAt: now, Version: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}

	const claimedPhone = "+8613800000044"
	start := make(chan struct{})
	errs := make(chan error, len(users))
	var wg sync.WaitGroup
	for _, userID := range users {
		wg.Add(1)
		go func(userID identity.UserID) {
			defer wg.Done()
			<-start
			errs <- repo.UpdatePhone(ctx, userID, claimedPhone)
		}(userID)
	}
	close(start)
	wg.Wait()
	close(errs)

	successes, conflicts := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, phoneverify.ErrPhoneConflict):
			conflicts++
		default:
			t.Fatalf("concurrent claim error=%v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	var owners int
	if err := repo.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE phone=$1 AND phone_verified`, claimedPhone).Scan(&owners); err != nil || owners != 1 {
		t.Fatalf("owners=%d err=%v", owners, err)
	}
}

func TestIntegration_SMSPhoneAuthorityAuditFailureRollsBackMutation(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()
	userID := identity.UserID("user_sms_audit_rollback")
	now := time.Now().UTC()
	if err := repo.Create(ctx, identity.User{
		ID: userID, Status: identity.UserStatusActive,
		Email: "sms-audit-rollback@example.com", EmailVerified: true,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	const constraint = "test_reject_sms_phone_audit"
	if _, err := repo.pool.Exec(ctx, `ALTER TABLE security_events ADD CONSTRAINT `+constraint+` CHECK (event_type <> 'account.phone_verified')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = repo.pool.Exec(context.Background(), `ALTER TABLE security_events DROP CONSTRAINT IF EXISTS `+constraint)
	})

	if err := repo.UpdatePhone(ctx, userID, "+8613800000055"); err == nil {
		t.Fatal("audit rejection did not abort phone mutation")
	}
	assertSMSPhoneAuthorityState(t, repo, userID, "", false, 1, 1)
}

func assertSMSPhoneAuthorityState(t *testing.T, repo *UserRepository, userID identity.UserID, wantPhone string, wantVerified bool, wantVersion int, wantEpoch int64) {
	t.Helper()
	var phone string
	var verified bool
	var version int
	var epoch int64
	if err := repo.pool.QueryRow(context.Background(), `SELECT phone,phone_verified,version,security_epoch FROM users WHERE id=$1`, string(userID)).Scan(&phone, &verified, &version, &epoch); err != nil {
		t.Fatal(err)
	}
	if phone != wantPhone || verified != wantVerified || version != wantVersion || epoch != wantEpoch {
		t.Fatalf("state phone=%q verified=%v version=%d epoch=%d; want %q %v %d %d", phone, verified, version, epoch, wantPhone, wantVerified, wantVersion, wantEpoch)
	}
}
