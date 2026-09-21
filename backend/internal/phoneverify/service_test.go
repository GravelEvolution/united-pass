package phoneverify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func TestVerifyPreservesStablePhoneConflict(t *testing.T) {
	store := &phoneVerifyStoreStub{phone: "+8613800000099", code: "123456", ok: true}
	repo := &phoneVerifyRepositoryStub{err: ErrPhoneConflict}
	service, err := NewService(store, phoneVerifySenderStub{}, repo, Config{})
	if err != nil {
		t.Fatal(err)
	}

	phone, err := service.Verify(context.Background(), VerifyInput{
		UserID: "user_target", RequestID: "phone_verify_request", Code: "123456",
	})
	if !errors.Is(err, ErrPhoneConflict) || phone != "" {
		t.Fatalf("Verify phone=%q err=%v, want stable ErrPhoneConflict", phone, err)
	}
	if repo.userID != identity.UserID("user_target") || repo.phone != "+8613800000099" {
		t.Fatalf("repository input user=%q phone=%q", repo.userID, repo.phone)
	}
}

type phoneVerifyStoreStub struct {
	phone string
	code  string
	ok    bool
	err   error
}

func (s *phoneVerifyStoreStub) Create(context.Context, string, string, string, time.Duration) error {
	return nil
}

func (s *phoneVerifyStoreStub) Consume(context.Context, string) (string, string, bool, error) {
	return s.phone, s.code, s.ok, s.err
}

type phoneVerifySenderStub struct{}

func (phoneVerifySenderStub) SendCode(context.Context, string, string) error { return nil }

type phoneVerifyRepositoryStub struct {
	userID identity.UserID
	phone  string
	err    error
}

func (r *phoneVerifyRepositoryStub) UpdatePhone(_ context.Context, userID identity.UserID, phone string) error {
	r.userID, r.phone = userID, phone
	return r.err
}
