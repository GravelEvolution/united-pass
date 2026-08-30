//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Authoritative OAuth provisioning-state read-back integration tests
//

//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
)

func TestIntegration_FindProvisioningCandidatesIncludesHiddenAndRecoveryState(t *testing.T) {
	repo, users := setupAppRepo(t)
	owner := createTestOwner(t, users, "dreamup_bootstrap_owner")
	ctx := context.Background()

	app := newTestApp("MoonStone DreamUP", owner)
	app.Description = "MoonStone DreamUP 2026 上海站"
	client := newTestClient(app.ID, "DreamUP Web")
	client.ConsentMode = applications.ConsentModeFirstAuthorization
	client.LogoutURI = "https://dreamup.moonstone.org.cn/"
	client.RedirectURIs = []applications.RedirectURI{{
		URI:     "https://dreamup.moonstone.org.cn/auth/callback",
		AddedAt: time.Now().UTC(),
	}}
	client.Scopes = []string{"openid", "profile", "email"}
	op := newTestOperation(app.ID, client.ID, applications.ProviderOperationProvision)
	if err := repo.CreateApplicationWithInitialClient(ctx, app, client, op); err != nil {
		t.Fatal(err)
	}
	secret := applications.ClientSecretRecord{
		ID: applications.NewClientSecretID(), ClientID: client.ID, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CompleteInitialProvisioning(ctx, app.ID, client.ID,
		"zitadel", "provider-project", "provider-app", "provider-client", op.ID, &secret,
		applications.SecurityEvent{
			EventID:       applications.NewSecurityEventID(),
			EventType:     applications.EventApplicationCreated,
			ActorUserID:   owner,
			ApplicationID: app.ID,
			RequestID:     "dreamup.bootstrap/integration-fixture",
			Operation:     "application.create",
			Result:        applications.SecurityEventSuccess,
			OccurredAt:    time.Now().UTC(),
		}); err != nil {
		t.Fatal(err)
	}

	// Simulate every mutable discovery marker drifting together. The immutable
	// bootstrap audit anchor must still identify the original aggregate.
	if _, err := repo.pool.Exec(ctx,
		`UPDATE oauth_applications SET name = 'Renamed', description = 'Changed' WHERE application_id = $1`,
		string(app.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(ctx,
		`UPDATE oauth_clients
		    SET name = 'Renamed client', logout_uri = 'https://changed.example/logout',
		        provider_reconciliation_required = TRUE,
		        secret_rotation_status = 'outcome_unknown'
		  WHERE client_id = $1`, string(client.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(ctx,
		`UPDATE oauth_client_redirect_uris
		    SET uri = 'https://changed.example/callback'
		  WHERE client_id = $1`, string(client.ID)); err != nil {
		t.Fatal(err)
	}

	extra := newTestClient(app.ID, "Failed extra client")
	extraOp := newTestOperation(app.ID, extra.ID, applications.ProviderOperationProvision)
	if err := repo.CreateClientWithOperation(ctx, extra, extraOp); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkClientProvisioningFailed(ctx, extra.ID, extraOp.ID, "provider_unavailable"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(ctx,
		`UPDATE oauth_applications SET deleted_at = NOW() WHERE application_id = $1`, string(app.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(ctx,
		`UPDATE oauth_clients SET deleted_at = NOW() WHERE client_id = $1`, string(client.ID)); err != nil {
		t.Fatal(err)
	}

	// A separate (even deleted) application may coincidentally reuse one
	// mutable marker. Once a durable bootstrap anchor exists, that collision
	// must not turn the authoritative result into an application-count drift.
	collisionApp := newTestApp("Unrelated application", owner)
	collisionClient := newTestClient(collisionApp.ID, "DreamUP Web")
	collisionOp := newTestOperation(collisionApp.ID, collisionClient.ID, applications.ProviderOperationProvision)
	if err := repo.CreateApplicationWithInitialClient(ctx, collisionApp, collisionClient, collisionOp); err != nil {
		t.Fatal(err)
	}
	collisionSecret := applications.ClientSecretRecord{
		ID: applications.NewClientSecretID(), ClientID: collisionClient.ID, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CompleteInitialProvisioning(ctx, collisionApp.ID, collisionClient.ID,
		"zitadel", "provider-project", "unrelated-provider-app", "unrelated-provider-client",
		collisionOp.ID, &collisionSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(ctx,
		`UPDATE oauth_applications SET deleted_at = NOW() WHERE application_id = $1`, string(collisionApp.ID)); err != nil {
		t.Fatal(err)
	}

	states, err := repo.FindProvisioningCandidates(ctx, applications.ProvisioningFingerprint{
		ApplicationName:        "MoonStone DreamUP",
		ApplicationDescription: "MoonStone DreamUP 2026 上海站",
		ClientName:             "DreamUP Web",
		RedirectURI:            "https://dreamup.moonstone.org.cn/auth/callback",
		LogoutURI:              "https://dreamup.moonstone.org.cn/",
		BootstrapRequestPrefix: "dreamup.bootstrap/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Application.ID != app.ID {
		t.Fatalf("states = %#v", states)
	}
	if !states[0].BootstrapAnchored {
		t.Fatal("durable bootstrap anchor was not surfaced")
	}
	if states[0].Application.DeletedAt == nil {
		t.Fatal("soft-deleted anchored application was not surfaced")
	}
	if len(states[0].Clients) != 2 {
		t.Fatalf("client count = %d, want hidden client included", len(states[0].Clients))
	}
	var gotPrimary, gotFailed bool
	for _, got := range states[0].Clients {
		switch got.ID {
		case client.ID:
			gotPrimary = got.DeletedAt != nil && got.ProviderReconciliationRequired &&
				got.SecretRotationStatus == applications.SecretRotationOutcomeUnknown
		case extra.ID:
			gotFailed = got.Provisioning == applications.ProvisioningStatusProvisioningFailed
		}
	}
	if !gotPrimary || !gotFailed {
		t.Fatalf("authoritative client state missing: primary=%t failed=%t", gotPrimary, gotFailed)
	}
}
