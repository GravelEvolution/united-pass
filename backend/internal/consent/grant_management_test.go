package consent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// fakeGrantMgmtStore is an in-memory AuthorizedGrantStore mirroring the
// owner binding and idempotency the PostgreSQL repository enforces.
type fakeGrantMgmtStore struct {
	grants map[GrantID]Grant

	listErr   error
	revokeErr error
	revokeIDs []GrantID
}

func newFakeGrantMgmtStore() *fakeGrantMgmtStore {
	return &fakeGrantMgmtStore{grants: map[GrantID]Grant{}}
}

func (s *fakeGrantMgmtStore) ListActiveGrantsByUser(_ context.Context, userID identity.UserID) ([]Grant, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	var out []Grant
	for _, g := range s.grants {
		if g.UserID == userID && g.Status == GrantActive {
			out = append(out, g)
		}
	}
	return out, nil
}

func (s *fakeGrantMgmtStore) RevokeGrant(_ context.Context, userID identity.UserID, grantID GrantID) error {
	s.revokeIDs = append(s.revokeIDs, grantID)
	if s.revokeErr != nil {
		return s.revokeErr
	}
	g, ok := s.grants[grantID]
	if !ok || g.UserID != userID {
		return ErrGrantNotFound
	}
	if g.Status == GrantRevoked {
		return nil // idempotent
	}
	g.Status = GrantRevoked
	s.grants[grantID] = g
	return nil
}

// fakeClientFacts maps local client IDs to display facts (or errors).
type fakeClientFacts struct {
	facts map[applications.OAuthClientID]ConsentClientFacts
	err   error
}

func (f *fakeClientFacts) GetAuthorizedClientFacts(_ context.Context, clientID applications.OAuthClientID) (ConsentClientFacts, error) {
	if f.err != nil {
		return ConsentClientFacts{}, f.err
	}
	facts, ok := f.facts[clientID]
	if !ok {
		return ConsentClientFacts{}, ErrClientUnknown
	}
	return facts, nil
}

func activeFacts(appName, owner string) ConsentClientFacts {
	return ConsentClientFacts{
		Client: applications.OAuthClient{
			ClientType: applications.ClientType("confidential"),
			Status:     applications.StatusActive,
		},
		Application: applications.Application{
			Name:      appName,
			OwnerName: owner,
			Status:    applications.StatusActive,
		},
	}
}

func TestNewGrantManagementServiceRequiresAllSeams(t *testing.T) {
	store := newFakeGrantMgmtStore()
	facts := &fakeClientFacts{facts: map[applications.OAuthClientID]ConsentClientFacts{}}

	if _, err := NewGrantManagementService(nil, facts); err == nil {
		t.Fatal("nil grant store accepted")
	}
	if _, err := NewGrantManagementService(store, nil); err == nil {
		t.Fatal("nil client facts reader accepted")
	}
	if _, err := NewGrantManagementService(store, facts); err != nil {
		t.Fatalf("NewGrantManagementService: %v", err)
	}
}

func TestListAuthorizedApplicationsJoinsGrantsWithDisplayFacts(t *testing.T) {
	store := newFakeGrantMgmtStore()
	older := Grant{
		ID: NewGrantID(), UserID: "user_01TEST", ClientID: "cli_older",
		Status: GrantActive, Scopes: []string{"openid", "profile"},
		GrantedAt: time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
	}
	newer := Grant{
		ID: NewGrantID(), UserID: "user_01TEST", ClientID: "cli_newer",
		Status: GrantActive, Scopes: []string{"openid", "offline_access"},
		GrantedAt: time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC),
	}
	foreign := Grant{
		ID: NewGrantID(), UserID: "user_other", ClientID: "cli_foreign",
		Status: GrantActive, Scopes: []string{"openid"},
		GrantedAt: time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC),
	}
	revoked := Grant{
		ID: NewGrantID(), UserID: "user_01TEST", ClientID: "cli_revoked",
		Status: GrantRevoked, Scopes: []string{"openid"},
		GrantedAt: time.Date(2026, 8, 6, 11, 0, 0, 0, time.UTC),
	}
	store.grants[older.ID] = older
	store.grants[newer.ID] = newer
	store.grants[foreign.ID] = foreign
	store.grants[revoked.ID] = revoked

	newerFacts := activeFacts("Newer App", "Owner N")
	newerFacts.Application.ID = "app_newer"
	olderFacts := activeFacts("Older App", "Owner O")
	olderFacts.Application.ID = "app_older"
	facts := &fakeClientFacts{facts: map[applications.OAuthClientID]ConsentClientFacts{
		"cli_newer": newerFacts,
		"cli_older": olderFacts,
	}}

	svc, err := NewGrantManagementService(store, facts)
	if err != nil {
		t.Fatalf("NewGrantManagementService: %v", err)
	}
	apps, err := svc.ListAuthorizedApplications(context.Background(), "user_01TEST")
	if err != nil {
		t.Fatalf("ListAuthorizedApplications: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("len = %d, want 2 (foreign + revoked grants excluded)", len(apps))
	}
	// Newest grant first.
	if apps[0].GrantID != newer.ID || apps[1].GrantID != older.ID {
		t.Fatalf("ordering broken: %v then %v", apps[0].GrantID, apps[1].GrantID)
	}
	row := apps[0]
	if row.ApplicationID != "app_newer" || row.ApplicationName != "Newer App" ||
		row.ApplicationOwner != "Owner N" || row.ClientType != applications.ClientType("confidential") {
		t.Fatalf("display facts = %+v", row)
	}
	if !row.HasOfflineAccess {
		t.Fatal("offline_access grant must report hasOfflineAccess")
	}
	if apps[1].HasOfflineAccess {
		t.Fatal("grant without offline_access must not report it")
	}
	if !row.GrantedAt.Equal(newer.GrantedAt) {
		t.Fatalf("grantedAt = %v", row.GrantedAt)
	}
	// The returned scope slice is a copy, not the store's backing array.
	row.Scopes[0] = "mutated"
	if newer.Scopes[0] == "mutated" || store.grants[newer.ID].Scopes[0] == "mutated" {
		t.Fatal("listing must hand out defensive scope copies")
	}
}

func TestListAuthorizedApplicationsFiltersDeadAndDisabledClients(t *testing.T) {
	grantFor := func(client applications.OAuthClientID) Grant {
		return Grant{
			ID: NewGrantID(), UserID: "user_01TEST", ClientID: client,
			Status: GrantActive, Scopes: []string{"openid"},
			GrantedAt: time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC),
		}
	}
	store := newFakeGrantMgmtStore()
	live := grantFor("cli_live")
	deleted := grantFor("cli_deleted")        // facts reader reports ErrClientUnknown
	disabledClient := grantFor("cli_dis_cli") // client kill switch down
	disabledApp := grantFor("cli_dis_app")    // application kill switch down
	store.grants[live.ID] = live
	store.grants[deleted.ID] = deleted
	store.grants[disabledClient.ID] = disabledClient
	store.grants[disabledApp.ID] = disabledApp

	liveFacts := activeFacts("Live App", "Owner")
	disClientFacts := activeFacts("Disabled Client App", "Owner")
	disClientFacts.Client.Status = applications.StatusDisabled
	disAppFacts := activeFacts("Disabled App", "Owner")
	disAppFacts.Application.Status = applications.StatusDisabled

	facts := &fakeClientFacts{facts: map[applications.OAuthClientID]ConsentClientFacts{
		"cli_live":    liveFacts,
		"cli_dis_cli": disClientFacts,
		"cli_dis_app": disAppFacts,
		// cli_deleted absent → ErrClientUnknown (soft-deleted record)
	}}

	svc, err := NewGrantManagementService(store, facts)
	if err != nil {
		t.Fatalf("NewGrantManagementService: %v", err)
	}
	apps, err := svc.ListAuthorizedApplications(context.Background(), "user_01TEST")
	if err != nil {
		t.Fatalf("ListAuthorizedApplications: %v", err)
	}
	if len(apps) != 1 || apps[0].GrantID != live.ID {
		t.Fatalf("soft-deleted or disabled clients must never display as active apps: got %d rows", len(apps))
	}
}

func TestListAuthorizedApplicationsPropagatesErrors(t *testing.T) {
	t.Run("grant store failure", func(t *testing.T) {
		store := newFakeGrantMgmtStore()
		store.listErr = errors.New("db exploded")
		svc, err := NewGrantManagementService(store, &fakeClientFacts{facts: map[applications.OAuthClientID]ConsentClientFacts{}})
		if err != nil {
			t.Fatalf("NewGrantManagementService: %v", err)
		}
		if _, err := svc.ListAuthorizedApplications(context.Background(), "user_01TEST"); err == nil {
			t.Fatal("store failure must surface")
		}
	})

	t.Run("client facts failure is not swallowed", func(t *testing.T) {
		store := newFakeGrantMgmtStore()
		store.grants["grt_x"] = Grant{
			ID: "grt_x", UserID: "user_01TEST", ClientID: "cli_1",
			Status: GrantActive, Scopes: []string{"openid"},
		}
		facts := &fakeClientFacts{err: errors.New("lookup exploded")}
		svc, err := NewGrantManagementService(store, facts)
		if err != nil {
			t.Fatalf("NewGrantManagementService: %v", err)
		}
		if _, err := svc.ListAuthorizedApplications(context.Background(), "user_01TEST"); err == nil {
			t.Fatal("non-ErrClientUnknown reader failure must surface")
		}
	})

	t.Run("empty user", func(t *testing.T) {
		svc, err := NewGrantManagementService(newFakeGrantMgmtStore(), &fakeClientFacts{facts: map[applications.OAuthClientID]ConsentClientFacts{}})
		if err != nil {
			t.Fatalf("NewGrantManagementService: %v", err)
		}
		if _, err := svc.ListAuthorizedApplications(context.Background(), ""); err == nil {
			t.Fatal("empty user must fail")
		}
	})
}

func TestRevokeGrantOwnerBindingAndValidation(t *testing.T) {
	store := newFakeGrantMgmtStore()
	own := Grant{ID: NewGrantID(), UserID: "user_01TEST", ClientID: "cli_1", Status: GrantActive}
	foreign := Grant{ID: NewGrantID(), UserID: "user_other", ClientID: "cli_2", Status: GrantActive}
	store.grants[own.ID] = own
	store.grants[foreign.ID] = foreign

	svc, err := NewGrantManagementService(store, &fakeClientFacts{facts: map[applications.OAuthClientID]ConsentClientFacts{}})
	if err != nil {
		t.Fatalf("NewGrantManagementService: %v", err)
	}
	ctx := context.Background()

	// Happy path: the store receives the caller's identity, enforcing the
	// owner binding.
	if err := svc.RevokeGrant(ctx, "user_01TEST", own.ID); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if store.grants[own.ID].Status != GrantRevoked {
		t.Fatal("own grant must be revoked")
	}

	// Idempotent repeat: same stable success.
	if err := svc.RevokeGrant(ctx, "user_01TEST", own.ID); err != nil {
		t.Fatalf("repeat revocation must stay stable: %v", err)
	}

	// Foreign grant: indistinguishable from an unknown one.
	if err := svc.RevokeGrant(ctx, "user_01TEST", foreign.ID); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("foreign grant err = %v, want ErrGrantNotFound", err)
	}
	if store.grants[foreign.ID].Status != GrantActive {
		t.Fatal("foreign grant must stay untouched")
	}

	// Unknown grant.
	if err := svc.RevokeGrant(ctx, "user_01TEST", GrantID("grt_missing")); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("unknown grant err = %v, want ErrGrantNotFound", err)
	}

	// Malformed ID fails closed before touching the store.
	before := len(store.revokeIDs)
	if err := svc.RevokeGrant(ctx, "user_01TEST", GrantID("evil-injection")); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("malformed grant id err = %v, want ErrGrantNotFound", err)
	}
	if len(store.revokeIDs) != before {
		t.Fatal("malformed grant id must not reach the store")
	}

	// Empty user fails closed.
	if err := svc.RevokeGrant(ctx, "", own.ID); err == nil {
		t.Fatal("empty user must fail")
	}
}

func TestRevokeGrantPropagatesStoreFailure(t *testing.T) {
	store := newFakeGrantMgmtStore()
	store.revokeErr = errors.New("commit exploded")
	svc, err := NewGrantManagementService(store, &fakeClientFacts{facts: map[applications.OAuthClientID]ConsentClientFacts{}})
	if err != nil {
		t.Fatalf("NewGrantManagementService: %v", err)
	}
	if err := svc.RevokeGrant(context.Background(), "user_01TEST", NewGrantID()); err == nil {
		t.Fatal("store failure must surface")
	}
}
