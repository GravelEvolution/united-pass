package dreamupadmin

import (
	"context"
	"errors"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type reviewIdentityReaderStub struct {
	user           identity.User
	userErr        error
	forward        identity.IdentityLink
	forwardErr     error
	reverse        identity.IdentityLink
	reverseErr     error
	forwardCalls   int
	reverseCalls   int
	userCalls      int
	forwardSubject string
}

func (s *reviewIdentityReaderStub) GetByID(_ context.Context, userID identity.UserID) (identity.User, error) {
	s.userCalls++
	if s.user.ID == "" {
		s.user.ID = userID
	}
	return s.user, s.userErr
}

func (s *reviewIdentityReaderStub) GetIdentityLink(_ context.Context, _, _, subject string) (identity.IdentityLink, error) {
	s.forwardCalls++
	s.forwardSubject = subject
	return s.forward, s.forwardErr
}

func (s *reviewIdentityReaderStub) GetIdentityLinkByUserID(_ context.Context, _, _ string, _ identity.UserID) (identity.IdentityLink, error) {
	s.reverseCalls++
	return s.reverse, s.reverseErr
}

func verifiedReviewIdentityReader() *reviewIdentityReaderStub {
	link := identity.IdentityLink{
		ID: "link_1", UserID: "user_applicant", Provider: "zitadel",
		ProviderTenantID: "project_1", ProviderSubject: "provider_subject_1",
	}
	return &reviewIdentityReaderStub{
		user:    identity.User{ID: "user_applicant", Status: identity.UserStatusActive},
		forward: link,
		reverse: link,
	}
}

func TestReviewIdentityResolverReturnsStableIDOnlyAfterBidirectionalVerification(t *testing.T) {
	reader := verifiedReviewIdentityReader()
	resolver, err := NewReviewIdentityResolver(reader, "zitadel", "project_1")
	if err != nil {
		t.Fatal(err)
	}
	userID, err := resolver.ResolveReviewIdentityUser(context.Background(), "provider_subject_1")
	if err != nil {
		t.Fatal(err)
	}
	if userID != "user_applicant" || reader.forwardSubject != "provider_subject_1" || reader.forwardCalls != 1 || reader.userCalls != 1 || reader.reverseCalls != 1 {
		t.Fatalf("userID=%q reader=%+v", userID, reader)
	}
}

func TestReviewIdentityResolverPreservesStableIDForSubmittedApplicantAccountStatuses(t *testing.T) {
	for _, status := range []identity.UserStatus{identity.UserStatusPending, identity.UserStatusActive, identity.UserStatusDisabled} {
		t.Run(string(status), func(t *testing.T) {
			reader := verifiedReviewIdentityReader()
			reader.user.Status = status
			resolver, err := NewReviewIdentityResolver(reader, "zitadel", "project_1")
			if err != nil {
				t.Fatal(err)
			}
			userID, err := resolver.ResolveReviewIdentityUser(context.Background(), "provider_subject_1")
			if err != nil || userID != "user_applicant" || reader.reverseCalls != 1 {
				t.Fatalf("status=%q userID=%q reverseCalls=%d err=%v", status, userID, reader.reverseCalls, err)
			}
		})
	}
}

func TestReviewIdentityResolverFailsClosedForInvalidOrAmbiguousAuthorityState(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		mutate  func(*reviewIdentityReaderStub)
	}{
		{name: "invalid subject", subject: " subject"},
		{name: "missing forward link", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.forwardErr = identity.ErrUserNotFound }},
		{name: "ambiguous forward link", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.forwardErr = identity.ErrIdentityLinkConflict }},
		{name: "wrong forward subject", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.forward.ProviderSubject = "provider_subject_2" }},
		{name: "wrong forward provider", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.forward.Provider = "other" }},
		{name: "invalid stable user id", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.forward.UserID = "provider_subject_1" }},
		{name: "missing user", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.userErr = identity.ErrUserNotFound }},
		{name: "invalid user status", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.user.Status = identity.UserStatus("corrupt") }},
		{name: "missing reverse link", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.reverseErr = identity.ErrUserNotFound }},
		{name: "ambiguous reverse link", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.reverseErr = identity.ErrIdentityLinkConflict }},
		{name: "different reverse link", subject: "provider_subject_1", mutate: func(r *reviewIdentityReaderStub) { r.reverse.ID = "link_2" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := verifiedReviewIdentityReader()
			if test.mutate != nil {
				test.mutate(reader)
			}
			resolver, err := NewReviewIdentityResolver(reader, "zitadel", "project_1")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolveReviewIdentityUser(context.Background(), test.subject); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("err=%v", err)
			}
			if test.name == "invalid subject" && reader.forwardCalls != 0 {
				t.Fatal("invalid subject reached authority repository")
			}
			if test.name == "invalid user status" && reader.reverseCalls != 0 {
				t.Fatal("inactive user reached reverse identity lookup")
			}
		})
	}
}

func TestReviewIdentityResolverPreservesInfrastructureFailure(t *testing.T) {
	storageErr := errors.New("database unavailable")
	reader := verifiedReviewIdentityReader()
	reader.forwardErr = storageErr
	resolver, err := NewReviewIdentityResolver(reader, "zitadel", "project_1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.ResolveReviewIdentityUser(context.Background(), "provider_subject_1")
	if !errors.Is(err, storageErr) || errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewReviewIdentityResolverRejectsIncompleteConfiguration(t *testing.T) {
	reader := verifiedReviewIdentityReader()
	for _, test := range []struct {
		name, provider, tenant string
		reader                 ReviewIdentityReader
	}{
		{name: "nil reader", provider: "zitadel", tenant: "project_1"},
		{name: "empty provider", reader: reader, tenant: "project_1"},
		{name: "empty tenant", reader: reader, provider: "zitadel"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewReviewIdentityResolver(test.reader, test.provider, test.tenant); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
