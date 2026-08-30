//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// TestIntegration_UserProfileMutationsPersistAndReadBack pins the account
// overview's storage contract against real PostgreSQL: display name, nickname
// and avatar URL are read from the same durable user row that the self-service
// mutation endpoints update.
func TestIntegration_UserProfileMutationsPersistAndReadBack(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)
	user := identity.User{
		ID:          identity.UserID("user_profile_roundtrip"),
		Status:      identity.UserStatusActive,
		DisplayName: "旧显示名称",
		Nickname:    "旧昵称",
		Email:       "profile-roundtrip@example.com",
		CreatedAt:   now,
		UpdatedAt:   now,
		Version:     1,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create profile user: %v", err)
	}
	if err := repo.AddPersona(ctx, user.ID, identity.PersonaConsumer); err != nil {
		t.Fatalf("add profile user persona: %v", err)
	}

	if err := repo.UpdateProfile(ctx, user.ID, "新显示名称", "新昵称"); err != nil {
		t.Fatalf("update profile: %v", err)
	}
	profileRead, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("read updated profile: %v", err)
	}
	if profileRead.DisplayName != "新显示名称" || profileRead.Nickname != "新昵称" {
		t.Fatalf("profile readback = %q/%q, want persisted values", profileRead.DisplayName, profileRead.Nickname)
	}
	if profileRead.Version != 2 {
		t.Fatalf("profile version = %d, want 2", profileRead.Version)
	}

	wantAvatar := "/api/v1/media/avatars/" + string(user.ID)
	if err := repo.UpdateAvatar(ctx, user.ID, wantAvatar); err != nil {
		t.Fatalf("update avatar: %v", err)
	}
	avatarRead, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("read updated avatar: %v", err)
	}
	if avatarRead.AvatarURL != wantAvatar {
		t.Fatalf("avatar readback = %q, want %q", avatarRead.AvatarURL, wantAvatar)
	}
	if avatarRead.DisplayName != profileRead.DisplayName || avatarRead.Nickname != profileRead.Nickname {
		t.Fatalf("avatar mutation changed profile = %q/%q", avatarRead.DisplayName, avatarRead.Nickname)
	}
	if avatarRead.Version != 3 {
		t.Fatalf("avatar version = %d, want 3", avatarRead.Version)
	}
	if !avatarRead.UpdatedAt.After(user.UpdatedAt) {
		t.Fatalf("updatedAt = %s, want after original %s", avatarRead.UpdatedAt, user.UpdatedAt)
	}
	if len(avatarRead.Personas) != 1 || avatarRead.Personas[0] != identity.PersonaConsumer {
		t.Fatalf("personas = %v, want [consumer]", avatarRead.Personas)
	}
}

func TestIntegration_UserProfileMutationsRejectMissingUser(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()
	missing := identity.UserID("user_profile_missing")
	if err := repo.UpdateProfile(ctx, missing, "name", "nickname"); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("UpdateProfile missing user = %v, want ErrUserNotFound", err)
	}
	if err := repo.UpdateAvatar(ctx, missing, "/api/v1/media/avatars/user_profile_missing"); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("UpdateAvatar missing user = %v, want ErrUserNotFound", err)
	}
}

// Once an identity is linked, the local United Pass profile is authoritative
// for self-service fields. A later ZITADEL login observation must resolve the
// link without replacing a name, nickname, or avatar chosen in the account
// overview with stale provider claims.
func TestIntegration_UserProfileSurvivesLaterProviderLogin(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()
	user, err := repo.GetOrCreateUserByProviderSubject(ctx, "zitadel", "tenant_profile", identity.ProviderUserInfo{
		Subject:       "provider-profile-subject",
		DisplayName:   "Provider Original",
		Email:         "provider-profile@example.com",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("create linked user: %v", err)
	}
	if err := repo.UpdateProfile(ctx, user.ID, "United Pass Display", "本地昵称"); err != nil {
		t.Fatalf("update linked profile: %v", err)
	}
	wantAvatar := "/api/v1/media/avatars/" + string(user.ID)
	if err := repo.UpdateAvatar(ctx, user.ID, wantAvatar); err != nil {
		t.Fatalf("update linked avatar: %v", err)
	}

	again, err := repo.GetOrCreateUserByProviderSubject(ctx, "zitadel", "tenant_profile", identity.ProviderUserInfo{
		Subject:       "provider-profile-subject",
		DisplayName:   "Stale Provider Display",
		Email:         "provider-profile@example.com",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("resolve later provider login: %v", err)
	}
	if again.ID != user.ID || again.DisplayName != "United Pass Display" || again.Nickname != "本地昵称" || again.AvatarURL != wantAvatar {
		t.Fatalf("later provider login changed local profile: %#v", again)
	}
}
