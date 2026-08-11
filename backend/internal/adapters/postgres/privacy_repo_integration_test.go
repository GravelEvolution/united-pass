//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/privacy"
)

func TestIntegration_PrivacyRightsAndLegalPublicationLifecycle(t *testing.T) {
	pool := setupTestPool(t, 5)
	users := NewUserRepository(pool.PgxPool())
	userID := createTestOwner(t, users, "user_privacy_launch")
	ctx := context.Background()
	if _, err := pool.PgxPool().Exec(ctx,
		`UPDATE users SET display_name='Privacy User',nickname='private',phone='+8613800000000' WHERE id=$1`,
		string(userID)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.PgxPool().Exec(ctx,
		`INSERT INTO user_personas(user_id,persona) VALUES($1,'consumer')`, string(userID)); err != nil {
		t.Fatal(err)
	}
	if err := users.CreateIdentityLink(ctx, identity.IdentityLink{
		ID: "link_privacy_launch", UserID: userID, Provider: "zitadel", ProviderTenantID: "tenant",
		ProviderSubject: "zitadel_privacy_user", CreatedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := users.CreateIdentityLink(ctx, identity.IdentityLink{
		ID: "link_privacy_feishu", UserID: userID, Provider: "provider_feishu", ProviderTenantID: "tenant_feishu",
		ProviderSubject: "ou_privacy_user", CreatedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.PgxPool().Exec(ctx,
		`INSERT INTO provider_sync_jobs(sync_id,provider_id,actor_user_id,status)
		 VALUES('sync_privacy','provider_feishu',$1,'success')`, string(userID)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.PgxPool().Exec(ctx, `INSERT INTO provider_directory_users
		(provider_id,provider_tenant_id,external_subject,display_name,email,employee_number,title,
		 department_ids,checksum,last_seen_sync_id)
		VALUES('provider_feishu','tenant_feishu','ou_privacy_user','Privacy Directory User',
		 'directory@example.com','E-100','Engineer','["dep_external"]','checksum','sync_privacy')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.PgxPool().Exec(ctx, `INSERT INTO provider_sync_conflicts
		(conflict_id,provider_id,provider_tenant_id,external_subject,external_name,external_email,
		 matched_user_id,match_reason,status,resolved_by_user_id)
		VALUES('conflict_privacy','provider_feishu','tenant_feishu','ou_privacy_user',
		 'Privacy Directory User','directory@example.com',$1,'manual','resolved',$1)`, string(userID)); err != nil {
		t.Fatal(err)
	}

	repo := NewPrivacyRepository(pool.PgxPool(), "zitadel")
	service := privacy.NewService(repo, nil, nil, nil)
	supported, _ := privacy.SupportedDocument("privacy")
	publication, err := service.PublishLegalDocument(ctx, privacy.LegalPublicationInput{
		DocumentKind: "privacy", Version: supported.Version, ContentSHA256: supported.ContentSHA256,
		EffectiveAt: time.Now().UTC().Add(time.Hour), ApprovalReference: "LEGAL-INTEGRATION-1",
		ApprovedBy: "Integration Legal", PublishedBy: userID, RequestID: "req_legal",
	})
	if err != nil || publication.ApprovalReference != "LEGAL-INTEGRATION-1" {
		t.Fatalf("publish legal document=%+v err=%v", publication, err)
	}
	publications, err := service.ListLegalPublications(ctx)
	if err != nil || len(publications) != 1 || publications[0].ContentSHA256 != supported.ContentSHA256 {
		t.Fatalf("legal publications=%+v err=%v", publications, err)
	}

	export, err := service.BeginExport(ctx, userID, "req_export")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := repo.ClaimExports(ctx, 5)
	if err != nil || len(claimed) != 1 || claimed[0].ExportID != export.ExportID {
		t.Fatalf("claimed exports=%+v err=%v", claimed, err)
	}
	document, err := repo.BuildExportDocument(ctx, userID, time.Now().UTC())
	if err != nil || document.Profile.Email == "" || len(document.IdentityLinks) != 2 ||
		len(document.ProviderDirectoryProfiles) != 1 || document.ProviderDirectoryProfiles[0].Email != "directory@example.com" {
		t.Fatalf("export document=%+v err=%v", document, err)
	}
	if err := repo.CompleteExport(ctx, export.ExportID, []byte("{\"schemaVersion\":\"1.0\"}\n"), 5, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	loadedExport, err := service.GetExport(ctx, userID, export.ExportID)
	if err != nil || loadedExport.DownloadURL == nil || loadedExport.TotalSections != 5 {
		t.Fatalf("completed export=%+v err=%v", loadedExport, err)
	}
	if _, err := pool.PgxPool().Exec(ctx, `
		UPDATE personal_data_export_jobs
		   SET updated_at=NOW()-INTERVAL '31 days',expires_at=NOW()-INTERVAL '1 day'
		 WHERE export_id=$1`, string(export.ExportID)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ClaimExports(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetExport(ctx, export.ExportID); !errors.Is(err, privacy.ErrNotFound) {
		t.Fatalf("old terminal export metadata retained: %v", err)
	}
	export, err = service.BeginExport(ctx, userID, "req_export_before_delete")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = repo.ClaimExports(ctx, 5)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim second export=%+v err=%v", claimed, err)
	}
	if err := repo.CompleteExport(ctx, export.ExportID, []byte("{}\n"), 6, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	deletion, err := service.RequestDeletion(ctx, userID, "req_delete_1")
	if err != nil || deletion.Status != "pending" {
		t.Fatalf("request deletion=%+v err=%v", deletion, err)
	}
	cancelled, err := service.CancelDeletion(ctx, userID, "req_cancel")
	if err != nil || cancelled.Status != "cancelled" || cancelled.ProviderSubject != "" {
		t.Fatalf("cancel deletion=%+v err=%v", cancelled, err)
	}
	deletion, err = service.RequestDeletion(ctx, userID, "req_delete_2")
	if err != nil || deletion.DeletionID == cancelled.DeletionID {
		t.Fatalf("re-request deletion=%+v err=%v", deletion, err)
	}
	if _, err := pool.PgxPool().Exec(ctx,
		`UPDATE account_deletion_requests
		    SET requested_at=NOW()-INTERVAL '31 days',execute_after=NOW()-INTERVAL '1 day'
		  WHERE deletion_id=$1`,
		string(deletion.DeletionID)); err != nil {
		t.Fatal(err)
	}
	due, err := repo.ClaimDeletions(ctx, 5)
	if err != nil || len(due) != 1 || due[0].Status != "processing" {
		t.Fatalf("claimed deletions=%+v err=%v", due, err)
	}
	if err := repo.MarkProviderDeleted(ctx, deletion.DeletionID); err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteDeletion(ctx, deletion.DeletionID); err != nil {
		t.Fatal(err)
	}

	var status, displayName, email, phone string
	if err := pool.PgxPool().QueryRow(ctx,
		`SELECT status,display_name,email,phone FROM users WHERE id=$1`, string(userID)).Scan(
		&status, &displayName, &email, &phone); err != nil {
		t.Fatal(err)
	}
	if status != "disabled" || displayName != "已注销用户" || email != "" || phone != "" {
		t.Fatalf("anonymized user status=%q name=%q email=%q phone=%q", status, displayName, email, phone)
	}
	var links, exports, completed, auditEvents, directoryRows, conflictRows int
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM identity_links WHERE user_id=$1`, string(userID)).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM personal_data_export_jobs WHERE user_id=$1`, string(userID)).Scan(&exports); err != nil {
		t.Fatal(err)
	}
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM account_deletion_requests WHERE user_id=$1 AND status='completed' AND provider_subject=''`, string(userID)).Scan(&completed); err != nil {
		t.Fatal(err)
	}
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM security_events WHERE actor_user_id=$1 AND event_type LIKE 'privacy.%'`, string(userID)).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM provider_directory_users WHERE external_subject='ou_privacy_user'`).Scan(&directoryRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.PgxPool().QueryRow(ctx, `SELECT COUNT(*) FROM provider_sync_conflicts WHERE external_subject='ou_privacy_user'`).Scan(&conflictRows); err != nil {
		t.Fatal(err)
	}
	if links != 0 || exports != 0 || completed != 1 || auditEvents < 4 || directoryRows != 0 || conflictRows != 0 {
		t.Fatalf("cleanup links=%d exports=%d completed=%d audit=%d directory=%d conflicts=%d",
			links, exports, completed, auditEvents, directoryRows, conflictRows)
	}
}
