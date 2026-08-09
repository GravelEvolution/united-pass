//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-06
// Description: Unit tests for session rotation (ADR-0006 §6 step 4)
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

// rotateTestClock fixes time so rotation TTL assertions are exact.
func rotateTestClock() *mutableClock {
	return &mutableClock{now: time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)}
}

// rotateTestService builds a Service over the given store with remember
// sessions living 30h and an idle TTL of 30min. The test encryptor covers
// the at-rest provider session reference.
func rotateTestService(store Store, clock Clock) *Service {
	return NewService(store, clock, time.Hour, 30*time.Hour, 30*time.Minute, 5*time.Minute, testEncryptor())
}

// createRotateTestSession creates a remembered session and returns its raw
// tokens plus the stored record.
func createRotateTestSession(t *testing.T, svc *Service, userID identity.UserID) (CreateSessionResult, SessionRecord) {
	t.Helper()
	res, err := svc.CreateSession(t.Context(), CreateSessionInput{
		UserID:                   userID,
		Provider:                 "fake",
		ProviderSessionReference: "enc-ref-" + string(userID),
		AuthenticationMethods:    []auth.AuthenticationMethod{auth.MethodPassword},
		Remember:                 true,
		UserAgent:                "rotate-test-agent",
		ClientIP:                 "203.0.113.9",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return res, res.Record
}

// TestRotateSession_PreservesIdentityAndRetiresOldToken pins the frozen
// rotation semantics (ADR-0006 §6 step 4): the SessionID stays stable, the
// old token dies, a new session token + a new CSRF token are issued, the
// record's identity fields survive, and the absolute deadline is never
// extended.
func TestRotateSession_PreservesIdentityAndRetiresOldToken(t *testing.T) {
	clock := rotateTestClock()
	store := newFakeStore()
	svc := rotateTestService(store, clock)
	user := identity.UserID("user_rotate")

	created, oldRecord := createRotateTestSession(t, svc, user)

	rotated, err := svc.RotateSession(t.Context(), created.SessionToken, 1)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Fresh tokens: new session token, new CSRF token, never the old ones.
	if rotated.SessionToken == created.SessionToken || rotated.SessionToken == "" {
		t.Error("rotation must issue a fresh session token")
	}
	if rotated.CSRFToken == created.CSRFToken || rotated.CSRFToken == "" {
		t.Error("rotation must issue a fresh CSRF token")
	}

	// SessionID stable; identity and lifetime fields preserved.
	r := rotated.Record
	if r.SessionID != oldRecord.SessionID {
		t.Errorf("SessionID = %q, want stable %q", r.SessionID, oldRecord.SessionID)
	}
	if r.UserID != oldRecord.UserID || r.Provider != oldRecord.Provider {
		t.Error("rotation must preserve user and provider")
	}
	if !r.CreatedAt.Equal(oldRecord.CreatedAt) || !r.ExpiresAt.Equal(oldRecord.ExpiresAt) {
		t.Error("rotation must preserve CreatedAt and ExpiresAt (no lifetime extension)")
	}
	if r.Remember != oldRecord.Remember {
		t.Error("rotation must preserve the Remember flag")
	}
	if r.ProviderSessionReference != oldRecord.ProviderSessionReference {
		t.Error("rotation must preserve the sealed provider reference (credential survives)")
	}
	if r.CSRFTokenHash != HashToken(rotated.CSRFToken) {
		t.Error("record must bind the new CSRF token hash")
	}
	if r.CSRFTokenHash == oldRecord.CSRFTokenHash {
		t.Error("the old CSRF token hash must not survive rotation")
	}

	// Old token dead, new token live.
	if _, err := store.Get(t.Context(), HashToken(created.SessionToken)); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("old token lookup = %v, want ErrSessionNotFound", err)
	}
	if _, err := store.Get(t.Context(), HashToken(rotated.SessionToken)); err != nil {
		t.Errorf("new token lookup = %v, want the rotated record", err)
	}

	// ValidateSession accepts the rotated token and reports the stable
	// SessionID.
	principal, _, err := svc.ValidateSession(t.Context(), rotated.SessionToken)
	if err != nil {
		t.Fatalf("validate rotated token: %v", err)
	}
	if principal.SessionID != oldRecord.SessionID || principal.UserID != user {
		t.Errorf("principal = (%q, %q), want (%q, %q)", principal.UserID, principal.SessionID, user, oldRecord.SessionID)
	}

	// RemainingTTL is the remaining absolute lifetime (remember TTL here).
	if want := oldRecord.ExpiresAt.Sub(clock.Now()); rotated.RemainingTTL != want {
		t.Errorf("RemainingTTL = %v, want %v", rotated.RemainingTTL, want)
	}
}

// vanishOnRotateStore simulates the production race a concurrent logout or
// revocation wins: the record vanishes before the atomic rotation, and the
// frozen Redis guard refuses to resurrect it.
type vanishOnRotateStore struct {
	*fakeStore
}

func (s *vanishOnRotateStore) Rotate(_ context.Context, oldHash, _ string, _ SessionRecord, _, _ time.Duration) error {
	s.mu.Lock()
	delete(s.sessions, oldHash)
	s.mu.Unlock()
	return ErrSessionNotFound
}

// TestRotateSession_VanishedRaceFailsClosed pins the vanished-session guard
// as a production invariant: rotating a session a concurrent logout/revoke
// already removed must fail closed and never resurrect it.
func TestRotateSession_VanishedRaceFailsClosed(t *testing.T) {
	store := &vanishOnRotateStore{fakeStore: newFakeStore()}
	svc := rotateTestService(store, rotateTestClock())
	created, _ := createRotateTestSession(t, svc, identity.UserID("user_race"))

	if _, err := svc.RotateSession(t.Context(), created.SessionToken, 1); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
	// The vanished session must stay gone — no resurrection under any hash.
	if records, _ := store.ListUserSessions(t.Context(), "user_race", time.Now(), 0); len(records) != 0 {
		t.Errorf("store holds %d sessions after a vanished rotation, want 0", len(records))
	}
}

// TestRotateSession_ExpiredFailsClosedAndCleansUp covers both expiry classes:
// a record past its absolute deadline and one past its idle deadline are
// refused and cleaned up.
func TestRotateSession_ExpiredFailsClosedAndCleansUp(t *testing.T) {
	// Absolute expiry: remember TTL is 30h, jump 31h.
	clock := rotateTestClock()
	store := newFakeStore()
	svc := rotateTestService(store, clock)
	created, _ := createRotateTestSession(t, svc, identity.UserID("user_abs"))
	clock.now = clock.now.Add(31 * time.Hour)

	if _, err := svc.RotateSession(t.Context(), created.SessionToken, 1); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("absolute: err = %v, want ErrSessionExpired", err)
	}
	if _, err := store.Get(t.Context(), HashToken(created.SessionToken)); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expired record cleanup: %v, want ErrSessionNotFound", err)
	}

	// Idle expiry: idle TTL is 30min, jump 45min.
	clock2 := rotateTestClock()
	store2 := newFakeStore()
	svc2 := rotateTestService(store2, clock2)
	created2, _ := createRotateTestSession(t, svc2, identity.UserID("user_idle"))
	clock2.now = clock2.now.Add(45 * time.Minute)

	if _, err := svc2.RotateSession(t.Context(), created2.SessionToken, 1); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("idle: err = %v, want ErrSessionExpired", err)
	}
}

// TestRotateSession_UnknownToken covers absent tokens: an empty token and a
// token with no record both fail closed with ErrSessionNotFound.
func TestRotateSession_UnknownToken(t *testing.T) {
	svc := rotateTestService(newFakeStore(), rotateTestClock())

	if _, err := svc.RotateSession(t.Context(), "", 1); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("empty token: err = %v, want ErrSessionNotFound", err)
	}
	if _, err := svc.RotateSession(t.Context(), "no-such-token", 1); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("foreign token: err = %v, want ErrSessionNotFound", err)
	}
}

// TestRotateSession_NeverExtendsAbsoluteDeadline proves the rotated key TTL
// is the remaining lifetime, never a fresh full TTL.
func TestRotateSession_NeverExtendsAbsoluteDeadline(t *testing.T) {
	clock := rotateTestClock()
	store := newFakeStore()
	svc := rotateTestService(store, clock)
	created, oldRecord := createRotateTestSession(t, svc, identity.UserID("user_ttl"))

	// Burn 10h of the 30h remember lifetime, then rotate. The touch keeps
	// the session inside its idle window exactly like a live request would.
	clock.now = clock.now.Add(10 * time.Hour)
	if err := svc.TouchSession(t.Context(), created.SessionToken); err != nil {
		t.Fatalf("touch: %v", err)
	}
	rotated, err := svc.RotateSession(t.Context(), created.SessionToken, 1)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if want := oldRecord.ExpiresAt.Sub(clock.Now()); rotated.RemainingTTL != want {
		t.Fatalf("RemainingTTL = %v, want %v (rotation must never extend)", rotated.RemainingTTL, want)
	}
	if rotated.RemainingTTL >= 30*time.Hour {
		t.Fatal("rotation granted a fresh full TTL — the absolute deadline must be fixed at creation")
	}
}
