//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/audit"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

func TestIntegration_PolicyVersionPublicationAndAuditExport(t *testing.T) {
	pool := setupTestPool(t, 5)
	users := NewUserRepository(pool.PgxPool())
	actor := createTestOwner(t, users, "user_policy_admin")
	repo := NewPolicyRepository(pool.PgxPool())
	ctx := context.Background()
	input := policies.DraftInput{Name: "Application administrators", Description: "integration", Resource: "application:*", Action: "application.manage", Effect: policies.EffectAllow, Principals: []policies.Clause{{Attribute: "department", Operator: policies.OperatorEqual, Value: "Identity"}}}
	id, version, err := repo.Create(ctx, actor, input)
	if err != nil || version != 1 {
		t.Fatalf("create policy id=%q version=%d err=%v", id, version, err)
	}
	if _, err := repo.Update(ctx, actor, id, 99, input); !errors.Is(err, policies.ErrConflict) {
		t.Fatalf("stale update err=%v", err)
	}
	firstJob, err := repo.BeginPublication(ctx, actor, id, version, "req_publish_v1")
	if err != nil {
		t.Fatal(err)
	}
	version, err = repo.Update(ctx, actor, id, 1, input)
	if err != nil || version != 2 {
		t.Fatalf("update version=%d err=%v", version, err)
	}
	claimedPublications, err := repo.ClaimPublicationJobs(ctx, 5)
	if err != nil || len(claimedPublications) != 1 || claimedPublications[0].JobID != firstJob.JobID || claimedPublications[0].Policy.Version != 1 {
		t.Fatalf("claimed publications=%#v err=%v", claimedPublications, err)
	}
	if err := repo.CompletePublication(ctx, firstJob.JobID); err != nil {
		t.Fatal(err)
	}
	published, err := repo.ListPublished(ctx, "application.manage", "application:*")
	if err != nil || len(published) != 1 || published[0].Version != 1 {
		t.Fatalf("recovered published=%#v err=%v", published, err)
	}
	job, err := repo.BeginPublication(ctx, actor, id, version, "req_publish")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CompletePublication(ctx, job.JobID); err != nil {
		t.Fatal(err)
	}
	published, err = repo.ListPublished(ctx, "application.manage", "application:*")
	if err != nil || len(published) != 1 || published[0].Version != 2 {
		t.Fatalf("published=%#v err=%v", published, err)
	}
	detail, err := repo.Get(ctx, id)
	if err != nil || detail.Status != policies.StatusPublished || len(detail.VersionHistory) != 2 {
		t.Fatalf("detail=%#v err=%v", detail, err)
	}

	auditRepo := NewAuditRepository(pool.PgxPool())
	page, err := auditRepo.List(ctx, audit.Query{EventType: "policy.published", Limit: 10})
	if err != nil || len(page.Items) != 2 || page.Items[0].TargetID != string(id) {
		t.Fatalf("audit page=%#v err=%v", page, err)
	}
	export, err := auditRepo.CreateExport(ctx, actor, "req_export", audit.Query{EventType: "policy.published"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := auditRepo.ClaimExports(ctx, 5)
	if err != nil || len(claimed) != 1 || claimed[0].ExportID != export.ExportID {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	if err := auditRepo.CompleteExport(ctx, export.ExportID, []byte("csv"), 1, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err := auditRepo.GetExport(ctx, export.ExportID)
	if err != nil || loaded.Status != "completed" || string(loaded.Content) != "csv" {
		t.Fatalf("export=%#v err=%v", loaded, err)
	}
	if _, err := pool.PgxPool().Exec(ctx, `UPDATE audit_export_jobs SET expires_at=NOW()-INTERVAL '1 second' WHERE export_id=$1`, string(export.ExportID)); err != nil {
		t.Fatal(err)
	}
	if _, err := auditRepo.ClaimExports(ctx, 5); err != nil {
		t.Fatal(err)
	}
	loaded, err = auditRepo.GetExport(ctx, export.ExportID)
	if err != nil || len(loaded.Content) != 0 {
		t.Fatalf("expired export content was retained: bytes=%d err=%v", len(loaded.Content), err)
	}
}
