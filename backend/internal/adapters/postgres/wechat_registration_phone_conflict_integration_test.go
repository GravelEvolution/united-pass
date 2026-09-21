//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/registration"
	"github.com/GravelEvolution/united-pass/backend/internal/wechat"
	"github.com/GravelEvolution/united-pass/backend/internal/wechatregistration"
)

type phoneConflictIntentStore struct{}

func (phoneConflictIntentStore) ReserveNew(_ context.Context, _, _, proposedUserID string, _ wechatregistration.ProviderIntent) (string, error) {
	return proposedUserID, nil
}

func (phoneConflictIntentStore) VerifyExisting(context.Context, string, string, string, wechatregistration.ProviderIntent) error {
	return nil
}

func (phoneConflictIntentStore) Clear(context.Context, string) error { return nil }

func TestIntegration_WeChatPendingRegistrationReturnsExplicitPhoneOwnerConflict(t *testing.T) {
	pool := setupTestPool(t, 5)
	ctx := context.Background()
	users := NewUserRepository(pool.PgxPool())
	repo := &RegistrationRepository{
		pool: pool.PgxPool(), provider: "zitadel", tenantID: "project-test", intentStore: phoneConflictIntentStore{},
	}
	now := time.Now().UTC()
	const occupiedPhone = "+8613800000666"
	if err := users.Create(ctx, identity.User{
		ID: "user_phone_owner", Status: identity.UserStatusActive, DisplayName: "Phone Owner",
		Email: "phone-owner@example.com", EmailVerified: true, Phone: occupiedPhone, PhoneVerified: true,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}

	base := wechatregistration.PendingUser{
		User: registration.PendingUser{
			UserID: "user_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DisplayName: "New User",
			Email: "new-phone-conflict@example.com", Status: registration.StatusPending,
		},
		Phone: occupiedPhone, TenantID: "wx-app", Subject: "openid-new-phone-conflict",
		ProviderIntent: wechatregistration.ProviderIntent{
			Username: "new_phone_conflict", DisplayName: "New User",
			Email: "new-phone-conflict@example.com", Password: "Correct-Horse-Battery-Staple9!",
		},
	}
	if reserved, err := repo.ReservePendingWithWeChat(ctx, base); !errors.Is(err, registration.ErrPhoneConflict) || reserved != "" {
		t.Fatalf("new reservation result=%q error=%v, want explicit phone conflict", reserved, err)
	}

	historicalID := identity.UserID("user_cccccccccccccccccccccccccccccccc")
	if err := users.Create(ctx, identity.User{
		ID: historicalID, Status: identity.UserStatusPending, DisplayName: "Historical Pending",
		Email: "historical-phone-conflict@example.com", CreatedAt: now, UpdatedAt: now, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := users.CreateIdentityLink(ctx, identity.IdentityLink{
		ID: generateLinkID(), UserID: historicalID, Provider: wechat.ProviderName,
		ProviderTenantID: "wx-app", ProviderSubject: "openid-historical-phone-conflict",
		CreatedAt: now, LastSeenAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	historical := base
	historical.User = registration.PendingUser{
		UserID: string(historicalID), DisplayName: "Historical Pending",
		Email: "historical-phone-conflict@example.com", Status: registration.StatusPending,
	}
	historical.Subject = "openid-historical-phone-conflict"
	historical.ExpectedUserID = string(historicalID)
	historical.ProviderIntent = wechatregistration.ProviderIntent{
		Username: "historical_phone_conflict", DisplayName: "Historical Pending",
		Email: historical.User.Email, Password: "Correct-Horse-Battery-Staple9!",
	}
	if reserved, err := repo.ReservePendingWithWeChat(ctx, historical); !errors.Is(err, registration.ErrPhoneConflict) || reserved != "" {
		t.Fatalf("historical reconciliation result=%q error=%v, want explicit phone conflict", reserved, err)
	}
	var phone string
	var verified bool
	if err := pool.PgxPool().QueryRow(ctx, `SELECT phone,phone_verified FROM users WHERE id=$1`, historicalID).Scan(&phone, &verified); err != nil || phone != "" || verified {
		t.Fatalf("conflict mutated historical target phone=%q verified=%v err=%v", phone, verified, err)
	}
}
