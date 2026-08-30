package qrauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type memoryStore struct {
	receiver string
	user     identity.UserID
	consumed bool
}

func (s *memoryStore) Create(_ context.Context, _ string, receiver string, _ time.Duration) error {
	s.receiver = receiver
	return nil
}
func (s *memoryStore) Approve(_ context.Context, _ string, user identity.UserID) error {
	if s.consumed {
		return ErrConsumed
	}
	s.user = user
	return nil
}
func (s *memoryStore) Consume(_ context.Context, _ string, receiver string) (identity.UserID, error) {
	if receiver != s.receiver {
		return "", ErrDenied
	}
	if s.consumed {
		return "", ErrConsumed
	}
	if s.user == "" {
		return "", ErrPending
	}
	s.consumed = true
	return s.user, nil
}

func TestQRChallengeNeedsSeparateBrowserReceiverProof(t *testing.T) {
	store := &memoryStore{}
	values := []string{"qr-visible-id", "browser-only-receiver"}
	svc := NewService(store, time.Minute, func() (string, error) { value := values[0]; values = values[1:]; return value, nil })
	id, receiver, err := svc.Begin(t.Context())
	if err != nil || id == receiver {
		t.Fatalf("begin id=%q receiver=%q err=%v", id, receiver, err)
	}
	if _, err := svc.Consume(t.Context(), id, "wrong"); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong receiver error=%v", err)
	}
	if err := svc.Approve(t.Context(), id, identity.UserID("user_01TEST001")); err != nil {
		t.Fatal(err)
	}
	user, err := svc.Consume(t.Context(), id, receiver)
	if err != nil || user != "user_01TEST001" {
		t.Fatalf("consume user=%q err=%v", user, err)
	}
	if _, err := svc.Consume(t.Context(), id, receiver); !errors.Is(err, ErrConsumed) {
		t.Fatalf("replay error=%v", err)
	}
}

func TestAuditChallengeReferenceNeverContainsTheVisibleChallenge(t *testing.T) {
	challengeID := "qr-visible-id"
	got := AuditChallengeReference(challengeID)
	if got == "" || got == challengeID {
		t.Fatalf("audit reference = %q, must be a non-empty one-way value", got)
	}
	if want := hash(challengeID); got != want {
		t.Fatalf("audit reference = %q, want canonical hash %q", got, want)
	}
	if got := AuditChallengeReference(""); got != "" {
		t.Fatalf("empty challenge audit reference = %q, want empty", got)
	}
}
