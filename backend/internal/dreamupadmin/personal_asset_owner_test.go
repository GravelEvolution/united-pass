package dreamupadmin

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type personalAssetIdentityReaderStub struct {
	user         identity.User
	userErr      error
	link         identity.IdentityLink
	linkErr      error
	userCalls    int
	linkCalls    int
	provider     string
	tenantID     string
	linkedUserID identity.UserID
}

func (s *personalAssetIdentityReaderStub) GetByID(_ context.Context, userID identity.UserID) (identity.User, error) {
	s.userCalls++
	if s.user.ID == "" {
		s.user.ID = userID
	}
	return s.user, s.userErr
}

func (s *personalAssetIdentityReaderStub) GetIdentityLinkByUserID(_ context.Context, provider, tenantID string, userID identity.UserID) (identity.IdentityLink, error) {
	s.linkCalls++
	s.provider, s.tenantID, s.linkedUserID = provider, tenantID, userID
	return s.link, s.linkErr
}

func TestPersonalAssetOwnerResolverReturnsOnlyVerifiedCanonicalBinding(t *testing.T) {
	reader := &personalAssetIdentityReaderStub{
		user: identity.User{ID: "user_owner", Status: identity.UserStatusActive},
		link: identity.IdentityLink{
			ID: "link_1", UserID: "user_owner", Provider: "zitadel",
			ProviderTenantID: "project_1", ProviderSubject: "provider_subject_1",
		},
	}
	resolver, err := NewPersonalAssetOwnerResolver(reader, "zitadel", "project_1")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolvePersonalAssetOwner(context.Background(), "user_owner")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.UserID != "user_owner" || resolved.ProviderSubject != "provider_subject_1" {
		t.Fatalf("resolved=%+v", resolved)
	}
	if reader.userCalls != 1 || reader.linkCalls != 1 || reader.provider != "zitadel" || reader.tenantID != "project_1" || reader.linkedUserID != "user_owner" {
		t.Fatalf("reader=%+v", reader)
	}
}

func TestPersonalAssetOwnerResolverFailsClosedForInvalidAuthorityState(t *testing.T) {
	tests := []struct {
		name   string
		userID string
		reader *personalAssetIdentityReaderStub
	}{
		{name: "invalid stable user id", userID: "provider_subject", reader: &personalAssetIdentityReaderStub{}},
		{name: "missing user", userID: "user_missing", reader: &personalAssetIdentityReaderStub{userErr: identity.ErrUserNotFound}},
		{name: "disabled user", userID: "user_disabled", reader: &personalAssetIdentityReaderStub{user: identity.User{ID: "user_disabled", Status: identity.UserStatusDisabled}}},
		{name: "pending user", userID: "user_pending", reader: &personalAssetIdentityReaderStub{user: identity.User{ID: "user_pending", Status: identity.UserStatusPending}}},
		{name: "missing link", userID: "user_owner", reader: &personalAssetIdentityReaderStub{user: identity.User{ID: "user_owner", Status: identity.UserStatusActive}, linkErr: identity.ErrUserNotFound}},
		{name: "ambiguous link", userID: "user_owner", reader: &personalAssetIdentityReaderStub{user: identity.User{ID: "user_owner", Status: identity.UserStatusActive}, linkErr: identity.ErrIdentityLinkConflict}},
		{name: "wrong provider", userID: "user_owner", reader: &personalAssetIdentityReaderStub{user: identity.User{ID: "user_owner", Status: identity.UserStatusActive}, link: identity.IdentityLink{ID: "link_1", UserID: "user_owner", Provider: "other", ProviderTenantID: "project_1", ProviderSubject: "subject"}}},
		{name: "wrong tenant", userID: "user_owner", reader: &personalAssetIdentityReaderStub{user: identity.User{ID: "user_owner", Status: identity.UserStatusActive}, link: identity.IdentityLink{ID: "link_1", UserID: "user_owner", Provider: "zitadel", ProviderTenantID: "other", ProviderSubject: "subject"}}},
		{name: "wrong linked user", userID: "user_owner", reader: &personalAssetIdentityReaderStub{user: identity.User{ID: "user_owner", Status: identity.UserStatusActive}, link: identity.IdentityLink{ID: "link_1", UserID: "user_other", Provider: "zitadel", ProviderTenantID: "project_1", ProviderSubject: "subject"}}},
		{name: "empty subject", userID: "user_owner", reader: &personalAssetIdentityReaderStub{user: identity.User{ID: "user_owner", Status: identity.UserStatusActive}, link: identity.IdentityLink{ID: "link_1", UserID: "user_owner", Provider: "zitadel", ProviderTenantID: "project_1"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, err := NewPersonalAssetOwnerResolver(test.reader, "zitadel", "project_1")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolvePersonalAssetOwner(context.Background(), test.userID); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("err=%v", err)
			}
			if test.name == "invalid stable user id" && (test.reader.userCalls != 0 || test.reader.linkCalls != 0) {
				t.Fatalf("invalid id reached repository: %+v", test.reader)
			}
			if test.name == "disabled user" && test.reader.linkCalls != 0 {
				t.Fatal("disabled user reached identity-link lookup")
			}
		})
	}
}

func TestPersonalAssetOwnerResolverPreservesRepositoryFailureClass(t *testing.T) {
	storageErr := errors.New("database unavailable")
	resolver, err := NewPersonalAssetOwnerResolver(&personalAssetIdentityReaderStub{userErr: storageErr}, "zitadel", "project_1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.ResolvePersonalAssetOwner(context.Background(), "user_owner")
	if !errors.Is(err, storageErr) || errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewPersonalAssetOwnerResolverRejectsIncompleteConfiguration(t *testing.T) {
	reader := &personalAssetIdentityReaderStub{}
	for _, test := range []struct {
		name, provider, tenant string
		reader                 PersonalAssetIdentityReader
	}{
		{name: "nil reader", provider: "zitadel", tenant: "project_1"},
		{name: "empty provider", reader: reader, tenant: "project_1"},
		{name: "empty tenant", reader: reader, provider: "zitadel"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewPersonalAssetOwnerResolver(test.reader, test.provider, test.tenant); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
