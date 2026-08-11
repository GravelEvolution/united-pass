//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 5 administrator session revocation isolation tests
//

package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func createAdminRevokeSession(t *testing.T, service *Service, userID identity.UserID) CreateSessionResult {
	t.Helper()
	result, err := service.CreateSession(context.Background(), CreateSessionInput{
		UserID: userID, Provider: "fake",
		AuthenticationMethods: []auth.AuthenticationMethod{auth.MethodPassword},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return result
}

func TestAdminBulkRevokeUsesOnlyTargetUserIndex(t *testing.T) {
	store := newFakeStore()
	service := NewService(store, SystemClock{}, time.Hour, 30*time.Hour,
		15*time.Minute, 5*time.Minute, nil)
	targetOne := createAdminRevokeSession(t, service, "user_target")
	targetTwo := createAdminRevokeSession(t, service, "user_target")
	foreign := createAdminRevokeSession(t, service, "user_foreign")

	count, providerFailure, err := service.RevokeAllUserSessionsByAdmin(context.Background(), "user_target")
	if err != nil || providerFailure != "" || count != 2 {
		t.Fatalf("count=%d provider=%q err=%v, want 2/empty/nil", count, providerFailure, err)
	}
	if _, ok := store.sessions[targetOne.TokenHash]; ok {
		t.Fatal("first target session survived")
	}
	if _, ok := store.sessions[targetTwo.TokenHash]; ok {
		t.Fatal("second target session survived")
	}
	if _, ok := store.sessions[foreign.TokenHash]; !ok {
		t.Fatal("foreign user's session was revoked")
	}
}

func TestAdminTargetedRevokeIsOwnerBoundAndNonEnumerating(t *testing.T) {
	store := newFakeStore()
	service := NewService(store, SystemClock{}, time.Hour, 30*time.Hour,
		15*time.Minute, 5*time.Minute, nil)
	target := createAdminRevokeSession(t, service, "user_target")

	_, err := service.RevokeUserSessionByAdmin(context.Background(), "user_foreign", string(target.Record.SessionID))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("foreign owner revoke error = %v, want ErrSessionNotFound", err)
	}
	if _, ok := store.sessions[target.TokenHash]; !ok {
		t.Fatal("owner mismatch removed target session")
	}
	_, err = service.RevokeUserSessionByAdmin(context.Background(), "user_target", string(target.Record.SessionID))
	if err != nil {
		t.Fatalf("owner-bound revoke: %v", err)
	}
	if _, ok := store.sessions[target.TokenHash]; ok {
		t.Fatal("target session survived owner-bound revoke")
	}
}
