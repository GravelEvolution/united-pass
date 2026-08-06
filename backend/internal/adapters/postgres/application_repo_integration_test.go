//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

// testCursorKey returns a valid base64 32-byte session key for cursor
// signing in tests.
func testCursorKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 7)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// setupAppRepo builds an ApplicationRepository, a UserRepository (for owner
// rows) and the shared pool against the migrated test schema.
func setupAppRepo(t *testing.T) (*ApplicationRepository, *UserRepository) {
	t.Helper()
	pool := setupTestPool(t, 5)
	appRepo, err := NewApplicationRepository(pool.PgxPool(), testCursorKey(t))
	if err != nil {
		t.Fatalf("create application repository: %v", err)
	}
	return appRepo, NewUserRepository(pool.PgxPool())
}

func createTestOwner(t *testing.T, users *UserRepository, id string) identity.UserID {
	t.Helper()
	user := identity.User{
		ID:          identity.UserID(id),
		Status:      identity.UserStatusActive,
		DisplayName: "Owner " + id,
		Email:       id + "@example.com",
		Version:     1,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatalf("create owner user: %v", err)
	}
	return user.ID
}

func newTestApp(name string, ownerID identity.UserID) applications.Application {
	now := time.Now().UTC()
	return applications.Application{
		ID:           applications.NewApplicationID(),
		Name:         name,
		Description:  "integration test application " + name,
		Audience:     applications.AudienceExternal,
		OwnerID:      ownerID,
		Status:       applications.StatusActive,
		Provisioning: applications.ProvisioningStatusProvisioning,
		Version:      1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func newTestClient(appID applications.ApplicationID, name string) applications.OAuthClient {
	now := time.Now().UTC()
	return applications.OAuthClient{
		ID:                applications.NewOAuthClientID(),
		ApplicationID:     appID,
		Name:              name,
		Profile:           applications.ClientProfileWebServer,
		ClientType:        applications.ClientTypeConfidential,
		TokenEndpointAuth: applications.TokenAuthClientSecretBasic,
		ConsentMode:       applications.ConsentModeAlways,
		LogoutURI:         "https://app.example.com/logout",
		Status:            applications.StatusActive,
		RedirectURIs: []applications.RedirectURI{
			{URI: "https://app.example.com/callback", IsLoopback: false, AddedAt: now},
			{URI: "http://127.0.0.1:3000/callback", IsLoopback: true, AddedAt: now},
		},
		Scopes:       []string{"openid", "profile"},
		Provisioning: applications.ProvisioningStatusProvisioning,
		Version:      1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func newTestOperation(appID applications.ApplicationID, clientID applications.OAuthClientID, opType applications.ProviderOperationType) applications.ProviderOperation {
	return applications.ProviderOperation{
		ID:             applications.NewProviderOperationID(),
		Type:           opType,
		ApplicationID:  appID,
		ClientID:       clientID,
		IdempotencyKey: "idem-" + string(applications.NewProviderOperationID()),
		Status:         applications.ProviderOperationPending,
	}
}

// provisionTestApp creates an application with its initial client and flips
// both to provisioned, returning the IDs.
func provisionTestApp(t *testing.T, repo *ApplicationRepository, name string, ownerID identity.UserID) (applications.ApplicationID, applications.OAuthClientID) {
	t.Helper()
	ctx := context.Background()
	app := newTestApp(name, ownerID)
	client := newTestClient(app.ID, name+"-client")
	op := newTestOperation(app.ID, client.ID, applications.ProviderOperationProvision)
	if err := repo.CreateApplicationWithInitialClient(ctx, app, client, op); err != nil {
		t.Fatalf("create application with initial client: %v", err)
	}
	secret := applications.ClientSecretRecord{
		ID:        applications.NewClientSecretID(),
		ClientID:  client.ID,
		Label:     "initial",
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.CompleteInitialProvisioning(ctx, app.ID, client.ID,
		"zitadel", "proj-1", "prov-app-"+string(app.ID), "prov-client-"+string(client.ID), op.ID, &secret); err != nil {
		t.Fatalf("complete initial provisioning: %v", err)
	}
	return app.ID, client.ID
}

// TestIntegration_ApplicationLifecycle covers creation, provisioning
// visibility, owner join, optimistic concurrency, status flips and guarded
// soft deletion.
func TestIntegration_ApplicationLifecycle(t *testing.T) {
	repo, users := setupAppRepo(t)
	ctx := context.Background()
	ownerID := createTestOwner(t, users, "user_app_owner_001")

	app := newTestApp("Lifecycle App", ownerID)
	client := newTestClient(app.ID, "Lifecycle Client")
	op := newTestOperation(app.ID, client.ID, applications.ProviderOperationProvision)

	if err := repo.CreateApplicationWithInitialClient(ctx, app, client, op); err != nil {
		t.Fatalf("create application: %v", err)
	}

	// Not yet provisioned: invisible everywhere (fail closed).
	if _, err := repo.GetApplication(ctx, app.ID); !errors.Is(err, applications.ErrNotFound) {
		t.Fatalf("unprovisioned application: got %v, want ErrNotFound", err)
	}

	if err := repo.CompleteInitialProvisioning(ctx, app.ID, client.ID,
		"zitadel", "proj-lc", "prov-app-lc", "prov-client-lc", op.ID, nil); err != nil {
		t.Fatalf("complete provisioning: %v", err)
	}

	loaded, err := repo.GetApplication(ctx, app.ID)
	if err != nil {
		t.Fatalf("get application: %v", err)
	}
	if loaded.OwnerName != "Owner user_app_owner_001" {
		t.Errorf("OwnerName: got %q, want joined display name", loaded.OwnerName)
	}
	if loaded.Provisioning != applications.ProvisioningStatusProvisioned {
		t.Errorf("Provisioning: got %q, want provisioned", loaded.Provisioning)
	}
	if loaded.Version != 2 {
		t.Errorf("Version: got %d, want 2", loaded.Version)
	}

	// Duplicate live name is rejected.
	dup := newTestApp("Lifecycle App", ownerID)
	dupClient := newTestClient(dup.ID, "Dup Client")
	dupOp := newTestOperation(dup.ID, dupClient.ID, applications.ProviderOperationProvision)
	if err := repo.CreateApplicationWithInitialClient(ctx, dup, dupClient, dupOp); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate name: got %v, want ErrDuplicateName", err)
	}

	// Optimistic concurrency: stale version conflicts.
	upd := ApplicationUpdate{Name: "Lifecycle App 2", Description: "updated", Audience: applications.AudienceHybrid, OwnerID: ownerID}
	if err := repo.UpdateApplication(ctx, app.ID, upd, 1); !errors.Is(err, applications.ErrConflict) {
		t.Fatalf("stale update: got %v, want ErrConflict", err)
	}
	if err := repo.UpdateApplication(ctx, app.ID, upd, 2); err != nil {
		t.Fatalf("update application: %v", err)
	}
	loaded, err = repo.GetApplication(ctx, app.ID)
	if err != nil {
		t.Fatalf("reload application: %v", err)
	}
	if loaded.Name != "Lifecycle App 2" || loaded.Audience != applications.AudienceHybrid || loaded.Version != 3 {
		t.Errorf("after update: name=%q audience=%q version=%d", loaded.Name, loaded.Audience, loaded.Version)
	}

	if err := repo.SetApplicationStatus(ctx, app.ID, applications.StatusDisabled, 3); err != nil {
		t.Fatalf("disable application: %v", err)
	}

	// Deleting with a live client is a conflict.
	if err := repo.DeleteApplication(ctx, app.ID, 4); !errors.Is(err, applications.ErrConflict) {
		t.Fatalf("delete with live client: got %v, want ErrConflict", err)
	}

	// Remove the client first, then the application.
	delOp := newTestOperation(app.ID, client.ID, applications.ProviderOperationDelete)
	if err := repo.MarkClientDeleting(ctx, client.ID, delOp); err != nil {
		t.Fatalf("mark client deleting: %v", err)
	}
	if err := repo.CompleteClientDeletion(ctx, client.ID, delOp.ID); err != nil {
		t.Fatalf("complete client deletion: %v", err)
	}
	if err := repo.DeleteApplication(ctx, app.ID, 4); err != nil {
		t.Fatalf("delete application: %v", err)
	}
	if _, err := repo.GetApplication(ctx, app.ID); !errors.Is(err, applications.ErrNotFound) {
		t.Fatalf("deleted application: got %v, want ErrNotFound", err)
	}
}

// TestIntegration_ProvisioningFailureHidesApplication verifies failed
// provisioning keeps the rows invisible.
func TestIntegration_ProvisioningFailureHidesApplication(t *testing.T) {
	repo, users := setupAppRepo(t)
	ctx := context.Background()
	ownerID := createTestOwner(t, users, "user_app_owner_fail")

	app := newTestApp("Failed App", ownerID)
	client := newTestClient(app.ID, "Failed Client")
	op := newTestOperation(app.ID, client.ID, applications.ProviderOperationProvision)
	if err := repo.CreateApplicationWithInitialClient(ctx, app, client, op); err != nil {
		t.Fatalf("create application: %v", err)
	}
	if err := repo.MarkInitialProvisioningFailed(ctx, app.ID, client.ID, op.ID, "provider"); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	if _, err := repo.GetApplication(ctx, app.ID); !errors.Is(err, applications.ErrNotFound) {
		t.Fatalf("failed application: got %v, want ErrNotFound", err)
	}
	res, err := repo.ListApplications(ctx, ApplicationListQuery{})
	if err != nil {
		t.Fatalf("list applications: %v", err)
	}
	if len(res.Items) != 0 {
		t.Errorf("list should hide failed rows, got %d items", len(res.Items))
	}
}

// TestIntegration_ClientLifecycle covers hydration, anti-enumeration,
// config updates and the delete state machine.
func TestIntegration_ClientLifecycle(t *testing.T) {
	repo, users := setupAppRepo(t)
	ctx := context.Background()
	ownerID := createTestOwner(t, users, "user_client_owner_001")

	appID, _ := provisionTestApp(t, repo, "Client Host App", ownerID)

	// A second client under the same application.
	client := newTestClient(appID, "Second Client")
	client.Profile = applications.ClientProfileSPAMobile
	client.ClientType = applications.ClientTypePublic
	client.TokenEndpointAuth = applications.TokenAuthNone
	client.LogoutURI = ""
	op := newTestOperation(appID, client.ID, applications.ProviderOperationProvision)
	if err := repo.CreateClientWithOperation(ctx, client, op); err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := repo.CompleteClientProvisioning(ctx, client.ID,
		"zitadel", "proj-cl", "prov-app-cl", "prov-client-cl", op.ID, nil); err != nil {
		t.Fatalf("complete client provisioning: %v", err)
	}

	loaded, err := repo.GetClient(ctx, appID, client.ID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if len(loaded.RedirectURIs) != 2 {
		t.Errorf("redirect uris: got %d, want 2", len(loaded.RedirectURIs))
	}
	if len(loaded.Scopes) != 2 {
		t.Errorf("scopes: got %d, want 2", len(loaded.Scopes))
	}
	if loaded.ProviderClientID != "prov-client-cl" {
		t.Errorf("ProviderClientID: got %q", loaded.ProviderClientID)
	}

	// Anti-enumeration: wrong application binding yields ErrNotFound.
	otherAppID, _ := provisionTestApp(t, repo, "Other App", ownerID)
	if _, err := repo.GetClient(ctx, otherAppID, client.ID); !errors.Is(err, applications.ErrNotFound) {
		t.Fatalf("cross-app get: got %v, want ErrNotFound", err)
	}

	// Duplicate client name within the application is rejected.
	dupClient := newTestClient(appID, "Second Client")
	dupOp := newTestOperation(appID, dupClient.ID, applications.ProviderOperationProvision)
	if err := repo.CreateClientWithOperation(ctx, dupClient, dupOp); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate client name: got %v, want ErrDuplicateName", err)
	}

	// Config update replaces redirect URIs and scopes wholesale.
	upd := ClientConfigUpdate{
		Name:         "Second Client v2",
		LogoutURI:    "https://v2.example.com/logout",
		ConsentMode:  applications.ConsentModeFirstAuthorization,
		RedirectURIs: []applications.RedirectURI{{URI: "https://v2.example.com/cb", AddedAt: time.Now().UTC()}},
		Scopes:       []string{"openid"},
	}
	if err := repo.UpdateClientConfig(ctx, client.ID, upd, 2); err != nil {
		t.Fatalf("update client config: %v", err)
	}
	loaded, err = repo.GetClient(ctx, appID, client.ID)
	if err != nil {
		t.Fatalf("reload client: %v", err)
	}
	if loaded.Name != "Second Client v2" || len(loaded.RedirectURIs) != 1 || len(loaded.Scopes) != 1 {
		t.Errorf("after update: name=%q uris=%d scopes=%d", loaded.Name, len(loaded.RedirectURIs), len(loaded.Scopes))
	}
	if loaded.RedirectURIs[0].URI != "https://v2.example.com/cb" {
		t.Errorf("redirect uri not replaced: %q", loaded.RedirectURIs[0].URI)
	}

	if err := repo.SetClientStatus(ctx, client.ID, applications.StatusDisabled, 3); err != nil {
		t.Fatalf("disable client: %v", err)
	}

	// Delete state machine: deleting -> delete_failed -> deleting -> done.
	delOp := newTestOperation(appID, client.ID, applications.ProviderOperationDelete)
	if err := repo.MarkClientDeleting(ctx, client.ID, delOp); err != nil {
		t.Fatalf("mark deleting: %v", err)
	}
	// Retrying directly from deleting is allowed: provider removal is
	// idempotent, so a request that crashed after the provider removal but
	// before the local commit can safely re-drive the deletion.
	crashRetryOp := newTestOperation(appID, client.ID, applications.ProviderOperationDelete)
	if err := repo.MarkClientDeletingRetry(ctx, client.ID, crashRetryOp); err != nil {
		t.Fatalf("retry from deleting: %v", err)
	}
	if err := repo.MarkClientDeleteFailed(ctx, client.ID, crashRetryOp.ID, "provider"); err != nil {
		t.Fatalf("mark delete failed: %v", err)
	}
	if _, err := repo.GetClient(ctx, appID, client.ID); !errors.Is(err, applications.ErrNotFound) {
		t.Fatalf("delete_failed client should be hidden: got %v", err)
	}
	// Reconciliation flag + job.
	if err := repo.SetClientReconciliationRequired(ctx, client.ID); err != nil {
		t.Fatalf("flag reconciliation: %v", err)
	}
	job := applications.ReconciliationJob{
		ID:                    applications.NewProviderOperationID(),
		ApplicationID:         appID,
		ClientID:              client.ID,
		ProviderApplicationID: "prov-app-cl",
		Reason:                "delete_failed",
	}
	if err := repo.CreateReconciliationJob(ctx, job); err != nil {
		t.Fatalf("create reconciliation job: %v", err)
	}
	// Retry the delete from delete_failed: MarkClientDeleting requires
	// provisioned, so drive the final deletion directly for the retry path.
	retryOp := newTestOperation(appID, client.ID, applications.ProviderOperationDelete)
	if err := repo.MarkClientDeletingRetry(ctx, client.ID, retryOp); err != nil {
		t.Fatalf("mark client deleting retry: %v", err)
	}
	if err := repo.CompleteClientDeletion(ctx, client.ID, retryOp.ID); err != nil {
		t.Fatalf("complete deletion after retry: %v", err)
	}
	if _, err := repo.GetClient(ctx, appID, client.ID); !errors.Is(err, applications.ErrNotFound) {
		t.Fatalf("deleted client: got %v, want ErrNotFound", err)
	}

	clients, err := repo.ListClientsByApplication(ctx, appID)
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}
	if len(clients) != 1 {
		t.Errorf("remaining clients: got %d, want 1 (initial client)", len(clients))
	}
}

// TestIntegration_SecretRecordsAndRotation verifies secret metadata only —
// never values — is persisted and rotation stamps the record.
func TestIntegration_SecretRecordsAndRotation(t *testing.T) {
	repo, users := setupAppRepo(t)
	ctx := context.Background()
	ownerID := createTestOwner(t, users, "user_secret_owner")

	appID, clientID := provisionTestApp(t, repo, "Secret App", ownerID)

	rec := applications.ClientSecretRecord{
		ID:        applications.NewClientSecretID(),
		ClientID:  clientID,
		Label:     "rotated",
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSecretRecord(ctx, rec); err != nil {
		t.Fatalf("create secret record: %v", err)
	}

	rotatedAt := time.Now().UTC()
	if err := repo.MarkSecretRotated(ctx, rec.ID, rotatedAt); err != nil {
		t.Fatalf("mark rotated: %v", err)
	}
	if err := repo.MarkSecretRotated(ctx, applications.ClientSecretID("sec_missing"), rotatedAt); !errors.Is(err, applications.ErrNotFound) {
		t.Fatalf("rotate missing record: got %v, want ErrNotFound", err)
	}

	client, err := repo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	// provisionTestApp records one initial secret; this test added a second.
	if len(client.SecretRecords) != 2 {
		t.Fatalf("secret records: got %d, want 2", len(client.SecretRecords))
	}
	latest := client.SecretRecords[0] // ordered by created_at DESC
	if latest.ID != rec.ID || latest.LastRotatedAt == nil {
		t.Errorf("latest record: id=%q rotated=%v", latest.ID, latest.LastRotatedAt)
	}
}

// TestIntegration_BeginSecretRotationSingleWinner verifies the optimistic
// gate: exactly one rotation proceeds for a given client version, stale
// versions are rejected with a conflict, and missing clients stay hidden
// behind the same error surface.
func TestIntegration_BeginSecretRotationSingleWinner(t *testing.T) {
	repo, users := setupAppRepo(t)
	ctx := context.Background()
	ownerID := createTestOwner(t, users, "user_rotate_owner")
	appID, clientID := provisionTestApp(t, repo, "Rotation Gate App", ownerID)

	client, err := repo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}

	// The first rotation wins and bumps the version.
	if err := repo.BeginSecretRotation(ctx, clientID, client.Version, newRotateOp(appID, clientID)); err != nil {
		t.Fatalf("begin rotation: %v", err)
	}
	updated, err := repo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("get client after begin: %v", err)
	}
	if updated.Version != client.Version+1 {
		t.Fatalf("version = %d, want %d", updated.Version, client.Version+1)
	}

	// A concurrent rotation holding the stale version loses the gate.
	if err := repo.BeginSecretRotation(ctx, clientID, client.Version, newRotateOp(appID, clientID)); !errors.Is(err, applications.ErrConflict) {
		t.Fatalf("stale begin err = %v, want ErrConflict", err)
	}

	// Unknown clients yield the same conflict/not-found surface without
	// revealing existence differences.
	if err := repo.BeginSecretRotation(ctx, applications.OAuthClientID("clt_missing"), 1, newRotateOp(appID, "clt_missing")); !errors.Is(err, applications.ErrNotFound) {
		t.Fatalf("missing client err = %v, want ErrNotFound", err)
	}
}

// TestIntegration_RotationLifecycle verifies the durable rotation state
// machine: only an idle client can acquire the gate, outcome_unknown parks
// the client until reconciliation, and abort releases the gate for retries.
func TestIntegration_RotationLifecycle(t *testing.T) {
	repo, users := setupAppRepo(t)
	ctx := context.Background()
	ownerID := createTestOwner(t, users, "user_rotate_lifecycle")
	appID, clientID := provisionTestApp(t, repo, "Rotation Lifecycle App", ownerID)

	client, err := repo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}

	// An ambiguous provider outcome parks the client in outcome_unknown.
	op1 := newRotateOp(appID, clientID)
	if err := repo.BeginSecretRotation(ctx, clientID, client.Version, op1); err != nil {
		t.Fatalf("begin rotation: %v", err)
	}
	if err := repo.FailSecretRotationUnknown(ctx, clientID, op1.ID, "provider_outcome_unknown"); err != nil {
		t.Fatalf("fail unknown: %v", err)
	}

	// The parked client refuses further rotations even with a fresh version.
	client, err = repo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("get client after unknown: %v", err)
	}
	if err := repo.BeginSecretRotation(ctx, clientID, client.Version, newRotateOp(appID, clientID)); !errors.Is(err, applications.ErrConflict) {
		t.Fatalf("begin while outcome_unknown err = %v, want ErrConflict", err)
	}
}

// TestIntegration_RotationAbortAndComplete verifies a confirmed failure
// releases the gate for retries and a successful commit atomically stamps
// the old record, inserts the new one and returns the gate to idle.
func TestIntegration_RotationAbortAndComplete(t *testing.T) {
	repo, users := setupAppRepo(t)
	ctx := context.Background()
	ownerID := createTestOwner(t, users, "user_rotate_abort")
	appID, clientID := provisionTestApp(t, repo, "Rotation Abort App", ownerID)

	client, err := repo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}

	// Confirmed provider failure: abort returns the gate to idle.
	failed := newRotateOp(appID, clientID)
	if err := repo.BeginSecretRotation(ctx, clientID, client.Version, failed); err != nil {
		t.Fatalf("begin rotation: %v", err)
	}
	if err := repo.AbortSecretRotation(ctx, clientID, failed.ID, "provider_unavailable"); err != nil {
		t.Fatalf("abort: %v", err)
	}

	// Retry wins the gate again and commits successfully.
	client, err = repo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("get client after abort: %v", err)
	}
	op := newRotateOp(appID, clientID)
	if err := repo.BeginSecretRotation(ctx, clientID, client.Version, op); err != nil {
		t.Fatalf("retry begin: %v", err)
	}
	records, err := repo.GetClientSecretRecords(ctx, clientID)
	if err != nil || len(records) == 0 {
		t.Fatalf("secret records: %d, err=%v", len(records), err)
	}
	newRec := applications.ClientSecretRecord{
		ID:        applications.NewClientSecretID(),
		ClientID:  clientID,
		Label:     "rotated",
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.CompleteSecretRotation(ctx, clientID, op.ID, records[0].ID, newRec, time.Now().UTC()); err != nil {
		t.Fatalf("complete rotation: %v", err)
	}

	// The gate is idle again: another rotation can immediately begin.
	client, err = repo.GetClient(ctx, appID, clientID)
	if err != nil {
		t.Fatalf("get client after complete: %v", err)
	}
	if err := repo.BeginSecretRotation(ctx, clientID, client.Version, newRotateOp(appID, clientID)); err != nil {
		t.Fatalf("begin after complete: %v", err)
	}

	// The recorded operation is retrievable and succeeded.
	stored, err := repo.GetOperationByIdempotencyKey(ctx, op.IdempotencyKey)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if stored.Status != applications.ProviderOperationSucceeded {
		t.Errorf("operation status = %s, want succeeded", stored.Status)
	}
}

// newRotateOp builds a pending rotate_client_secret operation record.
func newRotateOp(appID applications.ApplicationID, clientID applications.OAuthClientID) applications.ProviderOperation {
	opID := applications.NewProviderOperationID()
	return applications.ProviderOperation{
		ID:             opID,
		Type:           applications.ProviderOperationRotateSecret,
		ApplicationID:  appID,
		ClientID:       clientID,
		IdempotencyKey: "rotate:" + string(opID),
		Status:         applications.ProviderOperationPending,
	}
}

// TestIntegration_OperationIdempotency verifies recorded operations are
// retrievable by idempotency key for retry reuse.
func TestIntegration_OperationIdempotency(t *testing.T) {
	repo, users := setupAppRepo(t)
	ctx := context.Background()
	ownerID := createTestOwner(t, users, "user_op_owner")

	app := newTestApp("Op App", ownerID)
	client := newTestClient(app.ID, "Op Client")
	op := newTestOperation(app.ID, client.ID, applications.ProviderOperationProvision)
	if err := repo.CreateApplicationWithInitialClient(ctx, app, client, op); err != nil {
		t.Fatalf("create application: %v", err)
	}

	if _, err := repo.GetOperationByIdempotencyKey(ctx, "idem-missing"); !errors.Is(err, applications.ErrNotFound) {
		t.Fatalf("missing operation: got %v, want ErrNotFound", err)
	}

	loaded, err := repo.GetOperationByIdempotencyKey(ctx, op.IdempotencyKey)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if loaded.ID != op.ID || loaded.ApplicationID != app.ID || loaded.ClientID != client.ID {
		t.Errorf("operation mismatch: %+v", loaded)
	}
	if loaded.Status != applications.ProviderOperationPending {
		t.Errorf("status: got %q, want pending", loaded.Status)
	}

	if err := repo.CompleteInitialProvisioning(ctx, app.ID, client.ID,
		"zitadel", "proj-op", "prov-app-op", "prov-client-op", op.ID, nil); err != nil {
		t.Fatalf("complete provisioning: %v", err)
	}
	loaded, err = repo.GetOperationByIdempotencyKey(ctx, op.IdempotencyKey)
	if err != nil {
		t.Fatalf("reload operation: %v", err)
	}
	if loaded.Status != applications.ProviderOperationSucceeded {
		t.Errorf("status after completion: got %q, want succeeded", loaded.Status)
	}
}

// TestIntegration_ListApplicationsPagination exercises keyset pagination,
// filters, ordering and cursor security.
func TestIntegration_ListApplicationsPagination(t *testing.T) {
	repo, users := setupAppRepo(t)
	ctx := context.Background()
	ownerID := createTestOwner(t, users, "user_list_owner")

	names := []string{"Alpha App", "Beta App", "Gamma App", "Delta App"}
	ids := map[applications.ApplicationID]bool{}
	for _, name := range names {
		appID, _ := provisionTestApp(t, repo, name, ownerID)
		ids[appID] = true
	}
	// A disabled application must still be listable when no status filter is
	// set, and filterable by status.
	disabledApp := newTestApp("Disabled App", ownerID)
	disabledClient := newTestClient(disabledApp.ID, "Disabled Client")
	disabledOp := newTestOperation(disabledApp.ID, disabledClient.ID, applications.ProviderOperationProvision)
	if err := repo.CreateApplicationWithInitialClient(ctx, disabledApp, disabledClient, disabledOp); err != nil {
		t.Fatalf("create disabled app: %v", err)
	}
	if err := repo.CompleteInitialProvisioning(ctx, disabledApp.ID, disabledClient.ID,
		"zitadel", "proj-d", "prov-app-"+string(disabledApp.ID), "prov-client-"+string(disabledClient.ID), disabledOp.ID, nil); err != nil {
		t.Fatalf("complete disabled app provisioning: %v", err)
	}
	if err := repo.SetApplicationStatus(ctx, disabledApp.ID, applications.StatusDisabled, 2); err != nil {
		t.Fatalf("disable app: %v", err)
	}

	// Page through everything by name with limit 2.
	var seen []applications.ApplicationID
	cursor := ""
	for page := 0; page < 10; page++ {
		res, err := repo.ListApplications(ctx, ApplicationListQuery{Cursor: cursor, Limit: 2, Sort: "name"})
		if err != nil {
			t.Fatalf("list page %d: %v", page, err)
		}
		for _, item := range res.Items {
			seen = append(seen, item.ID)
			if item.ClientCount != 1 {
				t.Errorf("item %q ClientCount: got %d, want 1", item.Name, item.ClientCount)
			}
		}
		if !res.HasMore {
			break
		}
		if res.NextCursor == "" {
			t.Fatal("HasMore without NextCursor")
		}
		cursor = res.NextCursor
	}
	if len(seen) != 5 {
		t.Fatalf("paginated rows: got %d, want 5", len(seen))
	}
	for _, id := range seen[:4] {
		if !ids[id] && id != disabledApp.ID {
			t.Errorf("unexpected application id %q", id)
		}
	}
	// Name ascending: first row must be "Alpha App".
	first, err := repo.ListApplications(ctx, ApplicationListQuery{Limit: 1, Sort: "name"})
	if err != nil || len(first.Items) != 1 || first.Items[0].Name != "Alpha App" {
		t.Fatalf("name sort first row: items=%v err=%v", first.Items, err)
	}

	// Query filter matches server-side.
	res, err := repo.ListApplications(ctx, ApplicationListQuery{Query: "gamma"})
	if err != nil || len(res.Items) != 1 || res.Items[0].Name != "Gamma App" {
		t.Fatalf("query filter: items=%v err=%v", res.Items, err)
	}

	// Status filter.
	res, err = repo.ListApplications(ctx, ApplicationListQuery{Status: "disabled"})
	if err != nil || len(res.Items) != 1 || res.Items[0].ID != disabledApp.ID {
		t.Fatalf("status filter: items=%v err=%v", res.Items, err)
	}

	// Owner filter.
	res, err = repo.ListApplications(ctx, ApplicationListQuery{OwnerID: string(ownerID), Limit: 100})
	if err != nil || len(res.Items) != 5 {
		t.Fatalf("owner filter: got %d items, err=%v", len(res.Items), err)
	}

	// Tampered cursor is rejected.
	page, err := repo.ListApplications(ctx, ApplicationListQuery{Limit: 2, Sort: "name"})
	if err != nil || !page.HasMore {
		t.Fatalf("setup page: err=%v hasMore=%v", err, page.HasMore)
	}
	tampered := page.NextCursor + "x"
	if _, err := repo.ListApplications(ctx, ApplicationListQuery{Cursor: tampered, Limit: 2, Sort: "name"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("tampered cursor: got %v, want ErrInvalidCursor", err)
	}
	if _, err := repo.ListApplications(ctx, ApplicationListQuery{Cursor: "!!!not-base64!!!"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("malformed cursor: got %v, want ErrInvalidCursor", err)
	}

	// A cursor is bound to its filter state: replay it with a different query.
	if _, err := repo.ListApplications(ctx, ApplicationListQuery{Cursor: page.NextCursor, Limit: 2, Sort: "name", Query: "alpha"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("state-mismatched cursor: got %v, want ErrInvalidCursor", err)
	}

	// Unknown sort key fails closed.
	if _, err := repo.ListApplications(ctx, ApplicationListQuery{Sort: "evil; DROP TABLE"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("unknown sort: got %v, want ErrInvalidCursor", err)
	}
}

// TestIntegration_SecurityEvents verifies audit rows persist with safe
// payloads.
func TestIntegration_SecurityEvents(t *testing.T) {
	pool := setupTestPool(t, 5)
	store := NewSecurityEventStore(pool.PgxPool())
	ctx := context.Background()

	ev := applications.SecurityEvent{
		EventID:       applications.NewSecurityEventID(),
		EventType:     applications.EventApplicationCreated,
		ActorUserID:   identity.UserID("user_audit_001"),
		ApplicationID: applications.ApplicationID("app_audit_001"),
		RequestID:     "req-1",
		Operation:     "create_application",
		Result:        applications.SecurityEventSuccess,
		OccurredAt:    time.Now().UTC(),
	}
	if err := store.Record(ctx, ev); err != nil {
		t.Fatalf("record event: %v", err)
	}

	denied := ev
	denied.EventID = applications.NewSecurityEventID()
	denied.EventType = applications.EventSecretRotationFailed
	denied.Result = applications.SecurityEventDenied
	denied.FailureClass = "authorization"
	if err := store.Record(ctx, denied); err != nil {
		t.Fatalf("record denied event: %v", err)
	}

	var count int
	if err := pool.PgxPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 2 {
		t.Errorf("security_events rows: got %d, want 2", count)
	}

	var payload string
	if err := pool.PgxPool().QueryRow(ctx,
		`SELECT payload->>'failure_class' FROM security_events WHERE event_id = $1`,
		string(denied.EventID)).Scan(&payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if payload != "authorization" {
		t.Errorf("failure_class payload: got %q, want authorization", payload)
	}
}

// TestIntegration_CursorSignerFailsClosed guards key derivation.
func TestIntegration_CursorSignerFailsClosed(t *testing.T) {
	if _, err := newCursorSigner(""); err == nil {
		t.Fatal("empty key must fail closed")
	}
	if _, err := newCursorSigner("not-base64"); err == nil {
		t.Fatal("invalid key must fail closed")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := newCursorSigner(short); err == nil {
		t.Fatal("short key must fail closed")
	}
	signer, err := newCursorSigner(testCursorKey(t))
	if err != nil {
		t.Fatalf("valid key: %v", err)
	}
	encoded, err := signer.encode(applicationCursor{Sort: "name", ID: "app_x"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := signer.decode(encoded)
	if err != nil || decoded.ID != "app_x" {
		t.Fatalf("roundtrip: %+v err=%v", decoded, err)
	}
	// A different key must not accept the cursor.
	otherKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	other, err := newCursorSigner(otherKey)
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	if _, err := other.decode(encoded); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("foreign-key decode: got %v, want ErrInvalidCursor", err)
	}
}
