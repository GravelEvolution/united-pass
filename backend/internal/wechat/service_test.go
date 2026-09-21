package wechat

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type fakeVerifier struct{ login, registration IdentityProof }

func (f fakeVerifier) VerifyLogin(context.Context, string) (IdentityProof, error) {
	return f.login, nil
}
func (f fakeVerifier) VerifyRegistration(context.Context, string, string) (IdentityProof, error) {
	return f.registration, nil
}

type fakeBindingReader struct {
	link    identity.IdentityLink
	user    identity.User
	linkErr error
}

func (f fakeBindingReader) GetIdentityLink(context.Context, string, string, string) (identity.IdentityLink, error) {
	return f.link, f.linkErr
}
func (f fakeBindingReader) GetByID(context.Context, identity.UserID) (identity.User, error) {
	return f.user, nil
}

type fakePhoneWriter struct {
	userID  identity.UserID
	tenant  string
	subject string
	phone   string
	err     error
}

func (f *fakePhoneWriter) CompleteLinkedWithVerifiedPhone(_ context.Context, userID identity.UserID, tenant, subject, phone string) error {
	f.userID, f.tenant, f.subject, f.phone = userID, tenant, subject, phone
	return f.err
}

func TestResolveLoginRequiresExistingActiveExplicitLink(t *testing.T) {
	userID := identity.UserID("user_abc")
	service := NewService(fakeVerifier{login: IdentityProof{TenantID: "app", Subject: "subject"}}, fakeBindingReader{link: identity.IdentityLink{UserID: userID}, user: identity.User{ID: userID, Status: identity.UserStatusActive}}, nil)
	user, err := service.ResolveLogin(context.Background(), "code")
	if err != nil || user.ID != userID {
		t.Fatalf("ResolveLogin = %#v, %v", user, err)
	}

	missing := NewService(fakeVerifier{login: IdentityProof{TenantID: "app", Subject: "subject"}}, fakeBindingReader{linkErr: identity.ErrUserNotFound}, nil)
	if _, err := missing.ResolveLogin(context.Background(), "code"); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("missing link error = %v", err)
	}
}

func TestBindVerifiedPhoneRejectsCrossAccountLink(t *testing.T) {
	writer := &fakePhoneWriter{}
	service := NewService(fakeVerifier{registration: IdentityProof{TenantID: "app", Subject: "subject", Phone: "+8613800138000"}}, fakeBindingReader{link: identity.IdentityLink{UserID: "user_other"}}, writer)
	if err := service.BindVerifiedPhone(context.Background(), "user_current", "login", "phone"); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("BindVerifiedPhone error = %v", err)
	}
	if writer.phone != "" {
		t.Fatalf("phone was written after cross-account link: %q", writer.phone)
	}
}

func TestBindVerifiedPhoneWritesOnlyProvenPhone(t *testing.T) {
	writer := &fakePhoneWriter{}
	service := NewService(fakeVerifier{registration: IdentityProof{TenantID: "app", Subject: "subject", Phone: "+8613800138000"}}, fakeBindingReader{link: identity.IdentityLink{UserID: "user_current"}}, writer)
	if err := service.BindVerifiedPhone(context.Background(), "user_current", "login", "phone"); err != nil {
		t.Fatalf("BindVerifiedPhone: %v", err)
	}
	if writer.userID != "user_current" || writer.tenant != "app" || writer.subject != "subject" || writer.phone != "+8613800138000" {
		t.Fatalf("phone write = %q %q %q %q", writer.userID, writer.tenant, writer.subject, writer.phone)
	}
}

func TestBindVerifiedPhoneReturnsExplicitConflictWithoutFallback(t *testing.T) {
	writer := &fakePhoneWriter{err: ErrPhoneConflict}
	service := NewService(fakeVerifier{registration: IdentityProof{TenantID: "app", Subject: "subject", Phone: "+8613800138000"}}, fakeBindingReader{link: identity.IdentityLink{UserID: "user_current"}}, writer)
	if err := service.BindVerifiedPhone(context.Background(), "user_current", "login", "phone"); !errors.Is(err, ErrPhoneConflict) {
		t.Fatalf("BindVerifiedPhone error = %v, want ErrPhoneConflict", err)
	}
}
