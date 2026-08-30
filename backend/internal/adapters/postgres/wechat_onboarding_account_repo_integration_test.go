//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatonboarding"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

func TestIntegration_WeChatOnboardingAuthorityBindingIsExplicitAndNarrow(t *testing.T) {
	pool := setupTestPool(t, 5)
	ctx := context.Background()
	users := NewUserRepository(pool.PgxPool())
	repo := NewWeChatOnboardingAccountRepository(pool.PgxPool())

	create := func(id identity.UserID, status identity.UserStatus, email, phone string, phoneVerified bool, version int) {
		t.Helper()
		now := time.Now().UTC()
		if err := users.Create(ctx, identity.User{
			ID: id, Status: status, DisplayName: "Authoritative Name", Nickname: "Authority",
			AvatarURL: "https://media.example.test/avatar.png", Email: email, EmailVerified: true,
			Phone: phone, PhoneVerified: phoneVerified, CreatedAt: now, UpdatedAt: now, Version: version,
		}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}

	targetID := identity.UserID("user_wechat_onboarding_target")
	create(targetID, identity.UserStatusActive, "Owner@Example.com", "", false, 7)
	if err := users.AddPersona(ctx, targetID, identity.PersonaConsumer); err != nil {
		t.Fatal(err)
	}
	if err := users.AddPersona(ctx, targetID, identity.PersonaEmployee); err != nil {
		t.Fatal(err)
	}

	owner, err := repo.FindByNormalizedEmail(ctx, " owner@example.com ")
	if err != nil || owner.User.ID != targetID || owner.NormalizedEmail != "owner@example.com" || owner.Version != 7 || owner.SecurityEpoch != 1 {
		t.Fatalf("normalized owner=%#v err=%v", owner, err)
	}
	if _, err := repo.FindByNormalizedEmail(ctx, "missing@example.com"); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("missing email error=%v", err)
	}
	create("user_wechat_duplicate_a", identity.UserStatusActive, "duplicate@example.com", "", false, 1)
	create("user_wechat_duplicate_b", identity.UserStatusActive, "DUPLICATE@example.com", "", false, 1)
	if _, err := repo.FindByNormalizedEmail(ctx, "duplicate@example.com"); !errors.Is(err, wechatonboarding.ErrEmailAmbiguous) {
		t.Fatalf("ambiguous email error=%v", err)
	}

	input := wechatonboarding.BindExistingInput{
		UserID: targetID, TenantID: "wx-app", Subject: "openid-owner", Phone: "+8613800000001",
		NormalizedEmail: owner.NormalizedEmail, ExpectedVersion: owner.Version, ExpectedSecurityEpoch: owner.SecurityEpoch,
	}
	bound, err := repo.BindExistingWithWeChat(ctx, input)
	if err != nil {
		t.Fatalf("bind target: %v", err)
	}
	if bound.UserID != targetID || !bound.Linked || !bound.PhoneAdded || bound.Version != 8 || bound.SecurityEpoch != 2 {
		t.Fatalf("bind result=%#v", bound)
	}

	var status, displayName, nickname, avatarURL, email, phone string
	var emailVerified, phoneVerified bool
	var version int
	var epoch int64
	if err := pool.PgxPool().QueryRow(ctx, `
SELECT status,display_name,nickname,avatar_url,email,email_verified,phone,phone_verified,version,security_epoch
  FROM users WHERE id=$1`, string(targetID)).Scan(
		&status, &displayName, &nickname, &avatarURL, &email, &emailVerified,
		&phone, &phoneVerified, &version, &epoch,
	); err != nil {
		t.Fatal(err)
	}
	if status != "active" || displayName != "Authoritative Name" || nickname != "Authority" || avatarURL != "https://media.example.test/avatar.png" || email != "Owner@Example.com" || !emailVerified || phone != input.Phone || !phoneVerified || version != 8 || epoch != 2 {
		t.Fatalf("authority data changed outside allowlist: status=%q display=%q nickname=%q avatar=%q email=%q emailVerified=%v phone=%q phoneVerified=%v version=%d epoch=%d", status, displayName, nickname, avatarURL, email, emailVerified, phone, phoneVerified, version, epoch)
	}
	personas, err := users.GetPersonas(ctx, targetID)
	if err != nil || len(personas) != 2 || personas[0] != identity.PersonaConsumer || personas[1] != identity.PersonaEmployee {
		t.Fatalf("personas=%v err=%v", personas, err)
	}

	input.ExpectedVersion, input.ExpectedSecurityEpoch = bound.Version, bound.SecurityEpoch
	replayed, err := repo.BindExistingWithWeChat(ctx, input)
	if err != nil || replayed.Linked || replayed.PhoneAdded || replayed.Version != 8 || replayed.SecurityEpoch != 2 {
		t.Fatalf("idempotent replay=%#v err=%v", replayed, err)
	}
	if _, err := repo.BindExistingWithWeChat(ctx, wechatonboarding.BindExistingInput{
		UserID: targetID, TenantID: "wx-app", Subject: "openid-other", Phone: input.Phone,
		NormalizedEmail: "owner@example.com", ExpectedVersion: 8, ExpectedSecurityEpoch: 2,
	}); !errors.Is(err, wechatonboarding.ErrIdentityConflict) {
		t.Fatalf("second target subject error=%v", err)
	}
	if _, err := repo.BindExistingWithWeChat(ctx, wechatonboarding.BindExistingInput{
		UserID: targetID, TenantID: "wx-app", Subject: input.Subject, Phone: "+8613800000002",
		NormalizedEmail: "owner@example.com", ExpectedVersion: 8, ExpectedSecurityEpoch: 2,
	}); !errors.Is(err, wechatonboarding.ErrPhoneConflict) {
		t.Fatalf("different phone error=%v", err)
	}

	otherID := identity.UserID("user_wechat_onboarding_other")
	create(otherID, identity.UserStatusActive, "other@example.com", "", false, 1)
	if _, err := repo.BindExistingWithWeChat(ctx, wechatonboarding.BindExistingInput{
		UserID: otherID, TenantID: "wx-app", Subject: input.Subject,
		NormalizedEmail: "other@example.com", ExpectedVersion: 1, ExpectedSecurityEpoch: 1,
	}); !errors.Is(err, wechatonboarding.ErrIdentityConflict) {
		t.Fatalf("subject reassignment error=%v", err)
	}

	phoneOwnerID := identity.UserID("user_wechat_phone_owner")
	phoneTargetID := identity.UserID("user_wechat_phone_target")
	create(phoneOwnerID, identity.UserStatusActive, "phone-owner@example.com", "+8613800000099", true, 1)
	create(phoneTargetID, identity.UserStatusActive, "phone-target@example.com", "", false, 1)
	if _, err := repo.BindExistingWithWeChat(ctx, wechatonboarding.BindExistingInput{
		UserID: phoneTargetID, TenantID: "wx-app", Subject: "openid-phone-target", Phone: "+8613800000099",
		NormalizedEmail: "phone-target@example.com", ExpectedVersion: 1, ExpectedSecurityEpoch: 1,
	}); !errors.Is(err, wechatonboarding.ErrPhoneConflict) {
		t.Fatalf("cross-account phone error=%v", err)
	}
	var unexpectedPhoneLink int
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM identity_links WHERE provider=$1 AND provider_tenant_id=$2 AND provider_subject=$3`, wechat.ProviderName, "wx-app", "openid-phone-target").Scan(&unexpectedPhoneLink); err != nil || unexpectedPhoneLink != 0 {
		t.Fatalf("phone conflict left link count=%d err=%v", unexpectedPhoneLink, err)
	}

	identityOnlyID := identity.UserID("user_wechat_identity_only")
	create(identityOnlyID, identity.UserStatusActive, "identity-only@example.com", "", false, 3)
	identityOnly, err := repo.BindExistingWithWeChat(ctx, wechatonboarding.BindExistingInput{
		UserID: identityOnlyID, TenantID: "wx-app", Subject: "openid-identity-only",
		NormalizedEmail: "identity-only@example.com", ExpectedVersion: 3, ExpectedSecurityEpoch: 1,
	})
	if err != nil || !identityOnly.Linked || identityOnly.PhoneAdded || identityOnly.Version != 4 || identityOnly.SecurityEpoch != 2 {
		t.Fatalf("identity-only result=%#v err=%v", identityOnly, err)
	}
	if err := pool.PgxPool().QueryRow(ctx, `SELECT phone,phone_verified FROM users WHERE id=$1`, string(identityOnlyID)).Scan(&phone, &phoneVerified); err != nil || phone != "" || phoneVerified {
		t.Fatalf("identity-only phone=%q verified=%v err=%v", phone, phoneVerified, err)
	}

	disabledID := identity.UserID("user_wechat_disabled")
	create(disabledID, identity.UserStatusDisabled, "disabled-wechat@example.com", "", false, 1)
	if _, err := repo.BindExistingWithWeChat(ctx, wechatonboarding.BindExistingInput{
		UserID: disabledID, TenantID: "wx-app", Subject: "openid-disabled",
		NormalizedEmail: "disabled-wechat@example.com", ExpectedVersion: 1, ExpectedSecurityEpoch: 1,
	}); !errors.Is(err, wechatonboarding.ErrAccountInactive) {
		t.Fatalf("disabled account error=%v", err)
	}

	legacyID := identity.UserID("user_wechat_legacy_phone")
	create(legacyID, identity.UserStatusActive, "legacy-phone@example.com", "+8613800000088", false, 1)
	legacyResult, err := repo.BindExistingWithWeChat(ctx, wechatonboarding.BindExistingInput{
		UserID: legacyID, TenantID: "wx-app", Subject: "openid-legacy", Phone: "+8613800000088",
		NormalizedEmail: "legacy-phone@example.com", ExpectedVersion: 1, ExpectedSecurityEpoch: 1,
	})
	if err != nil || !legacyResult.PhoneAdded {
		t.Fatalf("legacy unverified phone upgrade result=%#v error=%v", legacyResult, err)
	}
	var legacyPhone string
	var legacyPhoneVerified bool
	if err := pool.PgxPool().QueryRow(ctx, `SELECT phone,phone_verified FROM users WHERE id=$1`, string(legacyID)).Scan(&legacyPhone, &legacyPhoneVerified); err != nil || legacyPhone != "+8613800000088" || !legacyPhoneVerified {
		t.Fatalf("legacy phone=%q verified=%v error=%v", legacyPhone, legacyPhoneVerified, err)
	}
}

func TestIntegration_WeChatOnboardingRejectsAuthorityChangesAfterAuthenticationSnapshot(t *testing.T) {
	pool := setupTestPool(t, 5)
	ctx := context.Background()
	users := NewUserRepository(pool.PgxPool())
	repo := NewWeChatOnboardingAccountRepository(pool.PgxPool())
	tests := []struct {
		name    string
		mutate  func(identity.UserID) error
		wantErr error
	}{
		{name: "email", mutate: func(id identity.UserID) error {
			_, err := pool.PgxPool().Exec(ctx, `UPDATE users SET email='changed@example.com' WHERE id=$1`, string(id))
			return err
		}, wantErr: wechatonboarding.ErrAccountChanged},
		{name: "status", mutate: func(id identity.UserID) error {
			_, err := pool.PgxPool().Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, string(id))
			return err
		}, wantErr: wechatonboarding.ErrAccountInactive},
		{name: "version", mutate: func(id identity.UserID) error {
			_, err := pool.PgxPool().Exec(ctx, `UPDATE users SET version=version+1 WHERE id=$1`, string(id))
			return err
		}, wantErr: wechatonboarding.ErrAccountChanged},
		{name: "security epoch", mutate: func(id identity.UserID) error {
			_, err := pool.PgxPool().Exec(ctx, `UPDATE users SET security_epoch=security_epoch+1 WHERE id=$1`, string(id))
			return err
		}, wantErr: wechatonboarding.ErrAccountChanged},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userID := identity.UserID(fmt.Sprintf("user_wechat_cas_%d", index))
			email := fmt.Sprintf("wechat-cas-%d@example.com", index)
			now := time.Now().UTC()
			if err := users.Create(ctx, identity.User{ID: userID, Status: identity.UserStatusActive, DisplayName: "CAS", Email: email, EmailVerified: true, CreatedAt: now, UpdatedAt: now, Version: 1}); err != nil {
				t.Fatal(err)
			}
			snapshot, err := repo.FindByNormalizedEmail(ctx, email)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(userID); err != nil {
				t.Fatal(err)
			}
			_, err = repo.BindExistingWithWeChat(ctx, wechatonboarding.BindExistingInput{
				UserID: userID, TenantID: "wx-app", Subject: fmt.Sprintf("openid-cas-%d", index),
				NormalizedEmail: snapshot.NormalizedEmail, ExpectedVersion: snapshot.Version, ExpectedSecurityEpoch: snapshot.SecurityEpoch,
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("bind error = %v, want %v", err, test.wantErr)
			}
			var links int
			if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM identity_links WHERE provider=$1 AND provider_tenant_id=$2 AND provider_subject=$3`, wechat.ProviderName, "wx-app", fmt.Sprintf("openid-cas-%d", index)).Scan(&links); err != nil || links != 0 {
				t.Fatalf("stale authentication wrote links=%d err=%v", links, err)
			}
		})
	}
}

type optionalPhoneIntentStore struct{}

func (optionalPhoneIntentStore) ReserveNew(_ context.Context, _, _, proposedUserID string, _ wechatregistration.ProviderIntent) (string, error) {
	return proposedUserID, nil
}

func (optionalPhoneIntentStore) VerifyExisting(context.Context, string, string, string, wechatregistration.ProviderIntent) error {
	return nil
}

func (optionalPhoneIntentStore) Clear(context.Context, string) error { return nil }

func TestIntegration_WeChatRegistrationCanActivateWithoutPhone(t *testing.T) {
	pool := setupTestPool(t, 5)
	ctx := context.Background()
	repo := &RegistrationRepository{
		pool: pool.PgxPool(), provider: "zitadel", tenantID: "project-test", intentStore: optionalPhoneIntentStore{},
	}
	input := wechatregistration.PendingUser{
		User: registration.PendingUser{
			UserID: "user_0123456789abcdef0123456789abcdef", DisplayName: "Identity Only",
			Email: "identity-only-registration@example.com", Status: registration.StatusPending,
		},
		TenantID: "wx-app", Subject: "openid-no-phone",
		ProviderIntent: wechatregistration.ProviderIntent{
			Username: "identity-only", DisplayName: "Identity Only",
			Email: "identity-only-registration@example.com", Password: "Correct-Horse-Battery-Staple9!",
		},
	}
	reserved, err := repo.ReservePendingWithWeChat(ctx, input)
	if err != nil || reserved != input.User.UserID {
		t.Fatalf("reserve identity-only user=%q err=%v", reserved, err)
	}
	var phone string
	var phoneVerified bool
	var version int
	var securityEpoch int64
	var wechatLinks int
	if err := pool.PgxPool().QueryRow(ctx, `SELECT phone,phone_verified,version,security_epoch FROM users WHERE id=$1`, reserved).Scan(&phone, &phoneVerified, &version, &securityEpoch); err != nil {
		t.Fatal(err)
	}
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM identity_links WHERE user_id=$1 AND provider=$2 AND provider_tenant_id=$3 AND provider_subject=$4`, reserved, wechat.ProviderName, input.TenantID, input.Subject).Scan(&wechatLinks); err != nil {
		t.Fatal(err)
	}
	if phone != "" || phoneVerified || version != 1 || securityEpoch != 1 || wechatLinks != 1 {
		t.Fatalf("pending phone=%q verified=%v version=%d epoch=%d links=%d", phone, phoneVerified, version, securityEpoch, wechatLinks)
	}

	retry := input
	retry.Phone = "+8613800000111"
	retry.ExpectedUserID = reserved
	const rejectPhoneAuditConstraint = "test_reject_wechat_pending_phone_audit"
	if _, err := pool.PgxPool().Exec(ctx, `ALTER TABLE security_events ADD CONSTRAINT `+rejectPhoneAuditConstraint+` CHECK (event_type <> 'wechat.pending_phone_verified')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.PgxPool().Exec(context.Background(), `ALTER TABLE security_events DROP CONSTRAINT IF EXISTS `+rejectPhoneAuditConstraint)
	})
	if _, err := repo.ReservePendingWithWeChat(ctx, retry); err == nil {
		t.Fatal("phone reconciliation succeeded after same-transaction audit append was rejected")
	}
	if err := pool.PgxPool().QueryRow(ctx, `SELECT phone,phone_verified,version,security_epoch FROM users WHERE id=$1`, reserved).Scan(&phone, &phoneVerified, &version, &securityEpoch); err != nil {
		t.Fatal(err)
	}
	if phone != "" || phoneVerified || version != 1 || securityEpoch != 1 {
		t.Fatalf("failed audit append committed phone state: phone=%q verified=%v version=%d epoch=%d", phone, phoneVerified, version, securityEpoch)
	}
	if _, err := pool.PgxPool().Exec(ctx, `ALTER TABLE security_events DROP CONSTRAINT `+rejectPhoneAuditConstraint); err != nil {
		t.Fatal(err)
	}

	reconciled, err := repo.ReservePendingWithWeChat(ctx, retry)
	if err != nil || reconciled != reserved {
		t.Fatalf("reconcile verified phone user=%q err=%v", reconciled, err)
	}
	if err := pool.PgxPool().QueryRow(ctx, `SELECT phone,phone_verified,version,security_epoch FROM users WHERE id=$1`, reserved).Scan(&phone, &phoneVerified, &version, &securityEpoch); err != nil {
		t.Fatal(err)
	}
	if phone != retry.Phone || !phoneVerified || version != 2 || securityEpoch != 2 {
		t.Fatalf("reconciled phone=%q verified=%v version=%d epoch=%d", phone, phoneVerified, version, securityEpoch)
	}

	phoneDigest, err := DeriveWeChatAuthorityReplayDigest(WeChatAuthorityReplayMaterial{
		Flow: WeChatAuthorityFlowPendingPhoneVerified, TenantID: retry.TenantID,
		Subject: retry.Subject, TargetUserID: identity.UserID(reserved),
		AuthorityVersion: 1, SecurityEpoch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	phoneReceipt := deriveWeChatAuthorityEffectReceipt(WeChatAuthorityEffect{
		ReplayDigest: phoneDigest, Kind: WeChatAuthorityEffectPendingPhoneVerified,
		TargetUserID: identity.UserID(reserved), OccurredAt: time.Now().UTC(),
	})
	var pendingReservedAudits, pendingPhoneAudits, notificationIntents, distinctOperations, attributedActors int
	var persistedPayload string
	if err := pool.PgxPool().QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE event_type='wechat.pending_reserved'),
       COUNT(*) FILTER (WHERE event_type='wechat.pending_phone_verified'),
       COUNT(*) FILTER (WHERE event_type='notification.pending'),
       COUNT(DISTINCT operation),
       COUNT(*) FILTER (WHERE actor_user_id<>''),
       COALESCE(STRING_AGG(payload::text, E'\n'), '')
  FROM security_events
 WHERE target_kind='user_id'
   AND target_id=$1
   AND event_type IN ('wechat.pending_reserved','wechat.pending_phone_verified','notification.pending')`, reserved).Scan(
		&pendingReservedAudits, &pendingPhoneAudits, &notificationIntents,
		&distinctOperations, &attributedActors, &persistedPayload,
	); err != nil {
		t.Fatal(err)
	}
	if pendingReservedAudits != 1 || pendingPhoneAudits != 1 || notificationIntents != 2 || distinctOperations != 2 || attributedActors != 0 {
		t.Fatalf("authority events reserved=%d phone=%d notifications=%d operations=%d actors=%d", pendingReservedAudits, pendingPhoneAudits, notificationIntents, distinctOperations, attributedActors)
	}
	var phoneAuditCount, phoneNotificationCount int
	if err := pool.PgxPool().QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE event_type='wechat.pending_phone_verified'),
       COUNT(*) FILTER (WHERE event_type='notification.pending')
  FROM security_events
 WHERE operation=$1`, phoneReceipt.OperationID).Scan(&phoneAuditCount, &phoneNotificationCount); err != nil {
		t.Fatal(err)
	}
	if phoneAuditCount != 1 || phoneNotificationCount != 1 {
		t.Fatalf("revision-bound pending phone operation audit=%d notification=%d", phoneAuditCount, phoneNotificationCount)
	}
	for _, forbidden := range []string{retry.TenantID, retry.Subject, retry.Phone, retry.User.Email} {
		if strings.Contains(persistedPayload, forbidden) {
			t.Fatalf("pending phone outbox payload contains forbidden PII %q", forbidden)
		}
	}

	if replayed, err := repo.ReservePendingWithWeChat(ctx, retry); err != nil || replayed != reserved {
		t.Fatalf("replay reconciled phone user=%q err=%v", replayed, err)
	}
	var replayEventCount int
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM security_events WHERE target_kind='user_id' AND target_id=$1 AND event_type IN ('wechat.pending_reserved','wechat.pending_phone_verified','notification.pending')`, reserved).Scan(&replayEventCount); err != nil {
		t.Fatal(err)
	}
	if replayEventCount != 4 {
		t.Fatalf("reconciled phone replay events=%d, want 4", replayEventCount)
	}
	if err := repo.ActivateVerified(ctx, reserved); err != nil {
		t.Fatalf("activate identity-only registration: %v", err)
	}
	var status string
	if err := pool.PgxPool().QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, reserved).Scan(&status); err != nil || status != "active" {
		t.Fatalf("status=%q err=%v", status, err)
	}
}
