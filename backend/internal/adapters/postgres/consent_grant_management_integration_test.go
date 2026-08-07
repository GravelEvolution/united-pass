//go:build integration

package postgres

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/consent"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// seedActiveGrant commits a real Allow completion (§5 flow) and returns
// the resulting active grant row.
func seedActiveGrant(t *testing.T, repo *GrantRepository, authRequestID string, user identity.UserID, clientID applications.OAuthClientID, scopes []string) consent.Grant {
	t.Helper()
	op := claimAndProve(t, repo, allowOperationFor(authRequestID, consent.CompletionAllow, user, clientID, scopes))
	if err := repo.CommitAllowDecision(context.Background(), consent.AllowCommit{OperationID: op.ID}); err != nil {
		t.Fatalf("commit allow: %v", err)
	}
	grant, err := repo.GetGrant(context.Background(), user, clientID)
	if err != nil {
		t.Fatalf("get seeded grant: %v", err)
	}
	return grant
}

// readRevokeAuditRecords returns the audit events correlated with a grant
// revocation (the canonical audit stores the grant ID in request_id).
func readRevokeAuditRecords(t *testing.T, repo *GrantRepository, grantID consent.GrantID) []auditRecord {
	t.Helper()
	return readAuditRecords(t, repo, consent.DecisionOperationID(grantID))
}

func TestIntegration_GrantManagementListsActiveGrants(t *testing.T) {
	grants, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "grantmgmt-owner")
	user := createConsentUser(t, users, "grantmgmt-user", "grantmgmt-user@example.com")
	other := createConsentUser(t, users, "grantmgmt-other", "grantmgmt-other@example.com")
	ctx := context.Background()

	appA, clientA := provisionTestApp(t, appRepo, "grantmgmt-app-a", ownerID)
	appB, clientB := provisionTestApp(t, appRepo, "grantmgmt-app-b", ownerID)
	_, clientForeign := provisionTestApp(t, appRepo, "grantmgmt-app-c", ownerID)

	grantA := seedActiveGrant(t, grants, "V2-gm-a", user, clientA,
		[]string{"openid", "offline_access", "profile"})
	grantB := seedActiveGrant(t, grants, "V2-gm-b", user, clientB, []string{"openid"})
	seedActiveGrant(t, grants, "V2-gm-c", other, clientForeign, []string{"openid"})

	svc, err := consent.NewGrantManagementService(grants, appRepo)
	if err != nil {
		t.Fatalf("NewGrantManagementService: %v", err)
	}
	apps, err := svc.ListAuthorizedApplications(ctx, user)
	if err != nil {
		t.Fatalf("ListAuthorizedApplications: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("rows = %d, want 2 (foreign grants excluded)", len(apps))
	}

	byGrant := map[consent.GrantID]consent.AuthorizedApplication{}
	for _, row := range apps {
		byGrant[row.GrantID] = row
	}
	rowA, ok := byGrant[grantA.ID]
	if !ok {
		t.Fatalf("grant %s missing from listing: %+v", grantA.ID, apps)
	}
	if rowA.ApplicationID != appA || rowA.ApplicationName != "grantmgmt-app-a" ||
		rowA.ApplicationOwner != "Owner grantmgmt-owner" ||
		rowA.ClientType != applications.ClientTypeConfidential {
		t.Fatalf("display facts A: %+v", rowA)
	}
	if !rowA.HasOfflineAccess {
		t.Fatal("offline_access grant must report hasOfflineAccess")
	}
	if len(rowA.Scopes) != 3 || rowA.Scopes[0] != "offline_access" ||
		rowA.Scopes[1] != "openid" || rowA.Scopes[2] != "profile" {
		t.Fatalf("scopes A = %+v, want the canonical snapshot", rowA.Scopes)
	}
	if !rowA.GrantedAt.Equal(grantA.GrantedAt) {
		t.Fatalf("grantedAt A = %v, want %v", rowA.GrantedAt, grantA.GrantedAt)
	}
	rowB, ok := byGrant[grantB.ID]
	if !ok {
		t.Fatalf("grant %s missing from listing: %+v", grantB.ID, apps)
	}
	if rowB.ApplicationID != appB || rowB.HasOfflineAccess {
		t.Fatalf("row B: %+v", rowB)
	}

	// Newest grant first (granted_at DESC), stable under equal timestamps.
	if !sort.SliceIsSorted(apps, func(i, j int) bool {
		if apps[i].GrantedAt.Equal(apps[j].GrantedAt) {
			return apps[i].GrantID < apps[j].GrantID
		}
		return apps[i].GrantedAt.After(apps[j].GrantedAt)
	}) {
		t.Fatalf("listing order must be granted_at DESC: %+v", apps)
	}
}

func TestIntegration_GrantManagementFiltersDeadAndDisabled(t *testing.T) {
	grants, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "grantmgmt-filter-owner")
	user := createConsentUser(t, users, "grantmgmt-filter-user", "grantmgmt-filter@example.com")
	ctx := context.Background()

	liveApp, liveClient := provisionTestApp(t, appRepo, "grantmgmt-live", ownerID)
	disAppID, disAppClient := provisionTestApp(t, appRepo, "grantmgmt-disapp", ownerID)
	disClientAppID, disClientID := provisionTestApp(t, appRepo, "grantmgmt-disclient", ownerID)
	delAppID, delClient := provisionTestApp(t, appRepo, "grantmgmt-deleted", ownerID)

	seedActiveGrant(t, grants, "V2-gmf-live", user, liveClient, []string{"openid"})
	seedActiveGrant(t, grants, "V2-gmf-disapp", user, disAppClient, []string{"openid"})
	seedActiveGrant(t, grants, "V2-gmf-disclient", user, disClientID, []string{"openid"})
	seedActiveGrant(t, grants, "V2-gmf-deleted", user, delClient, []string{"openid"})

	// Kill switch 1: disable the application.
	app, err := appRepo.GetApplication(ctx, disAppID)
	if err != nil {
		t.Fatalf("GetApplication: %v", err)
	}
	if err := appRepo.SetApplicationStatus(ctx, disAppID, applications.StatusDisabled, app.Version); err != nil {
		t.Fatalf("SetApplicationStatus: %v", err)
	}

	// Kill switch 2: disable the client.
	disClient, err := appRepo.GetClient(ctx, disClientAppID, disClientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if err := appRepo.SetClientStatus(ctx, disClientID, applications.StatusDisabled, disClient.Version); err != nil {
		t.Fatalf("SetClientStatus: %v", err)
	}

	// Kill switch 3: soft-delete an application. Deleting an application
	// requires no live clients, so retire its client through the two-step
	// deletion flow first.
	delOp := newTestOperation(delAppID, delClient, applications.ProviderOperationDelete)
	if err := appRepo.MarkClientDeleting(ctx, delClient, delOp); err != nil {
		t.Fatalf("MarkClientDeleting: %v", err)
	}
	if err := appRepo.CompleteClientDeletion(ctx, delClient, delOp.ID); err != nil {
		t.Fatalf("CompleteClientDeletion: %v", err)
	}
	delApp, err := appRepo.GetApplication(ctx, delAppID)
	if err != nil {
		t.Fatalf("GetApplication(deleted): %v", err)
	}
	if err := appRepo.DeleteApplication(ctx, delAppID, delApp.Version); err != nil {
		t.Fatalf("DeleteApplication: %v", err)
	}

	svc, err := consent.NewGrantManagementService(grants, appRepo)
	if err != nil {
		t.Fatalf("NewGrantManagementService: %v", err)
	}
	apps, err := svc.ListAuthorizedApplications(ctx, user)
	if err != nil {
		t.Fatalf("ListAuthorizedApplications: %v", err)
	}
	if len(apps) != 1 || apps[0].GrantID == "" || apps[0].ApplicationID != liveApp {
		t.Fatalf("soft-deleted or disabled records must never display: %+v", apps)
	}
}

func TestIntegration_RevokeGrantOwnerBindingAuditAndIdempotency(t *testing.T) {
	grants, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "grantmgmt-revoke-owner")
	userA := createConsentUser(t, users, "grantmgmt-revoke-a", "grantmgmt-revoke-a@example.com")
	userB := createConsentUser(t, users, "grantmgmt-revoke-b", "grantmgmt-revoke-b@example.com")
	ctx := context.Background()

	_, clientA := provisionTestApp(t, appRepo, "grantmgmt-revoke-a-app", ownerID)
	_, clientB := provisionTestApp(t, appRepo, "grantmgmt-revoke-b-app", ownerID)
	grantA := seedActiveGrant(t, grants, "V2-gmr-a", userA, clientA, []string{"openid"})
	grantB := seedActiveGrant(t, grants, "V2-gmr-b", userB, clientB, []string{"openid"})

	svc, err := consent.NewGrantManagementService(grants, appRepo)
	if err != nil {
		t.Fatalf("NewGrantManagementService: %v", err)
	}

	// Foreign grants are indistinguishable from unknown ones and stay
	// untouched (ADR-0005 §6).
	if err := svc.RevokeGrant(ctx, userA, grantB.ID); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("foreign revoke err = %v, want ErrGrantNotFound", err)
	}
	if g, err := grants.GetGrant(ctx, userB, clientB); err != nil || g.Status != consent.GrantActive {
		t.Fatalf("foreign grant must stay active: %+v err=%v", g, err)
	}
	if err := svc.RevokeGrant(ctx, userA, consent.GrantID("grt_missing")); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("unknown revoke err = %v, want ErrGrantNotFound", err)
	}
	if err := svc.RevokeGrant(ctx, userA, consent.GrantID("evil-injection")); !errors.Is(err, consent.ErrGrantNotFound) {
		t.Fatalf("malformed revoke err = %v, want ErrGrantNotFound", err)
	}
	if records := readRevokeAuditRecords(t, grants, grantB.ID); len(records) != 0 {
		t.Fatalf("failed revocations must write no audit, got %+v", records)
	}

	// Owner revocation: local consent revocation, canonical audit, 204-ish
	// stable outcome. No provider call happens here.
	if err := svc.RevokeGrant(ctx, userA, grantA.ID); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	got, err := grants.GetGrant(ctx, userA, clientA)
	if err != nil {
		t.Fatalf("GetGrant after revoke: %v", err)
	}
	if got.Status != consent.GrantRevoked || got.RevokedAt.IsZero() {
		t.Fatalf("grant not revoked durably: %+v", got)
	}
	if apps, err := svc.ListAuthorizedApplications(ctx, userA); err != nil || len(apps) != 0 {
		t.Fatalf("revoked grant must leave the listing: %+v err=%v", apps, err)
	}

	records := readRevokeAuditRecords(t, grants, grantA.ID)
	if len(records) != 1 {
		t.Fatalf("expected exactly one revoke audit event, got %d: %+v", len(records), records)
	}
	r := records[0]
	if r.EventType != string(applications.EventConsentGrantRevoked) ||
		r.ActorUserID != string(userA) || r.ClientID != string(clientA) ||
		r.Result != string(applications.SecurityEventSuccess) ||
		r.Operation != "consent_revoke" {
		t.Fatalf("canonical revoke audit mismatch: %+v", r)
	}

	// Idempotent repeat: same stable outcome, no second audit event.
	if err := svc.RevokeGrant(ctx, userA, grantA.ID); err != nil {
		t.Fatalf("repeat revocation must stay stable: %v", err)
	}
	if records := readRevokeAuditRecords(t, grants, grantA.ID); len(records) != 1 {
		t.Fatalf("repeat revocation must not add audit, got %d", len(records))
	}
}

// TestIntegration_RevokedGrantNeverSilentlyReused pins the §7 invariant:
// after a local revocation the resolution pipeline must demand fresh
// consent again; only a new Allow commit may reactivate the grant row.
func TestIntegration_RevokedGrantNeverSilentlyReused(t *testing.T) {
	grants, appRepo, users := setupConsentRepo(t)
	ownerID := createTestOwner(t, users, "grantmgmt-reuse-owner")
	user := createConsentUser(t, users, "grantmgmt-reuse-user", "grantmgmt-reuse@example.com")
	appID, clientID := provisionTestApp(t, appRepo, "grantmgmt-reuse-app", ownerID)
	ctx := context.Background()

	// first_authorization mode: an active grant is the only reuse signal.
	client, err := appRepo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if err := appRepo.UpdateClientConfig(ctx, clientID, applications.ClientConfigUpdate{
		Name:         client.Name,
		LogoutURI:    client.LogoutURI,
		ConsentMode:  applications.ConsentModeFirstAuthorization,
		RedirectURIs: client.RedirectURIs,
		Scopes:       client.Scopes,
	}, client.Version); err != nil {
		t.Fatalf("UpdateClientConfig: %v", err)
	}

	providerClientID := "prov-client-" + string(clientID)
	provider := consent.NewFakeAuthRequestProvider()
	provider.AddRequest(&consent.AuthRequestView{
		ID: "V2-reuse-1", ClientID: providerClientID,
		Scopes: []string{"openid", "profile"}, RedirectURI: "https://app.example.com/callback",
		CreatedAt: time.Now().UTC(),
	})
	svc, err := consent.NewResolutionService(provider, appRepo, grants, "zitadel",
		func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatalf("NewResolutionService: %v", err)
	}
	resolve := func() consent.Resolution {
		t.Helper()
		res, err := svc.Resolve(ctx, consent.ResolutionInput{
			AuthRequestID: "V2-reuse-1",
			Session: &consent.ResolutionSession{
				UserID:             user,
				AuthenticationTime: time.Now().UTC().Add(-time.Minute),
			},
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		return res
	}

	grant := seedActiveGrant(t, grants, "V2-reuse-seed", user, clientID,
		[]string{"openid", "profile"})
	if res := resolve(); res.Status != consent.ResolutionAlreadyAuthorized {
		t.Fatalf("active grant must resolve reuse, got %q", res.Status)
	}

	// Local revocation: the grant row survives but never enables reuse.
	mgmt, err := consent.NewGrantManagementService(grants, appRepo)
	if err != nil {
		t.Fatalf("NewGrantManagementService: %v", err)
	}
	if err := mgmt.RevokeGrant(ctx, user, grant.ID); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if res := resolve(); res.Status == consent.ResolutionAlreadyAuthorized {
		t.Fatal("revoked grant must never enable silent reuse")
	} else if res.Status != consent.ResolutionValid {
		t.Fatalf("revoked grant must fall back to fresh consent, got %q", res.Status)
	}

	// The only sanctioned path back is a new Allow commit: same row,
	// refreshed consent time, cleared revocation.
	reconsent := seedActiveGrant(t, grants, "V2-reuse-reconsent", user, clientID,
		[]string{"openid", "profile"})
	if reconsent.ID != grant.ID {
		t.Fatalf("re-consent must reuse the grant row: %v vs %v", grant.ID, reconsent.ID)
	}
	if reconsent.Status != consent.GrantActive || !reconsent.RevokedAt.IsZero() {
		t.Fatalf("re-consent must clear the revocation: %+v", reconsent)
	}
	if res := resolve(); res.Status != consent.ResolutionAlreadyAuthorized {
		t.Fatalf("fresh consent must restore reuse, got %q", res.Status)
	}
}
