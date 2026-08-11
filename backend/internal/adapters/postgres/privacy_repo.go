//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: PostgreSQL privacy-rights and legal-publication repository
//

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/privacy"
)

type PrivacyRepository struct {
	pool         *pgxpool.Pool
	authProvider string
}

func NewPrivacyRepository(pool *pgxpool.Pool, authProvider string) *PrivacyRepository {
	return &PrivacyRepository{pool: pool, authProvider: authProvider}
}

func (r *PrivacyRepository) BeginExport(ctx context.Context, user identity.UserID, requestID string) (privacy.Export, error) {
	id := privacy.ExportID(newPolicyStoreID("pexp_"))
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return privacy.Export{}, err
	}
	defer tx.Rollback(ctx)
	var requested time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO personal_data_export_jobs(export_id,user_id,request_id)
		VALUES($1,$2,$3) RETURNING requested_at`, string(id), string(user), requestID).Scan(&requested)
	if isUniqueViolation(err) {
		return privacy.Export{}, privacy.ErrConflict
	}
	if err != nil {
		return privacy.Export{}, fmt.Errorf("postgres: begin personal data export: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "privacy.data_export_requested",
		ActorUserID: user, RequestID: requestID, Operation: "account.data_export",
		Result: applications.SecurityEventSuccess, TargetKey: "personal_data_export_id",
		TargetID: string(id), OccurredAt: requested,
	}); err != nil {
		return privacy.Export{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return privacy.Export{}, err
	}
	return privacy.Export{ExportID: id, UserID: user, Status: "pending", RequestedAt: requested}, nil
}

func (r *PrivacyRepository) GetExport(ctx context.Context, id privacy.ExportID) (privacy.Export, error) {
	var result privacy.Export
	err := r.pool.QueryRow(ctx, `
		SELECT export_id,user_id,status,content,total_sections,requested_at,completed_at,expires_at
		  FROM personal_data_export_jobs WHERE export_id=$1`, string(id)).Scan(
		&result.ExportID, &result.UserID, &result.Status, &result.Content, &result.TotalSections,
		&result.RequestedAt, &result.CompletedAt, &result.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return privacy.Export{}, privacy.ErrNotFound
	}
	if err != nil {
		return privacy.Export{}, fmt.Errorf("postgres: get personal data export: %w", err)
	}
	return result, nil
}

func (r *PrivacyRepository) ClaimExports(ctx context.Context, limit int) ([]privacy.Export, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		DELETE FROM personal_data_export_jobs
		 WHERE status IN ('completed','failed') AND updated_at<NOW()-INTERVAL '30 days'`); err != nil {
		return nil, fmt.Errorf("postgres: purge personal data export metadata: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE personal_data_export_jobs SET content=NULL,updated_at=NOW()
		 WHERE status='completed' AND expires_at<=NOW() AND content IS NOT NULL`); err != nil {
		return nil, fmt.Errorf("postgres: purge personal data exports: %w", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT export_id,user_id,requested_at
		  FROM personal_data_export_jobs
		 WHERE status='pending'
		    OR (status='processing' AND updated_at < NOW()-INTERVAL '5 minutes')
		 ORDER BY requested_at,export_id FOR UPDATE SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	jobs := make([]privacy.Export, 0)
	for rows.Next() {
		var job privacy.Export
		if err := rows.Scan(&job.ExportID, &job.UserID, &job.RequestedAt); err != nil {
			rows.Close()
			return nil, err
		}
		job.Status = "processing"
		jobs = append(jobs, job)
	}
	rows.Close()
	for _, job := range jobs {
		if _, err := tx.Exec(ctx, `UPDATE personal_data_export_jobs SET status='processing',updated_at=NOW() WHERE export_id=$1`, string(job.ExportID)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return jobs, nil
}

func (r *PrivacyRepository) CompleteExport(ctx context.Context, id privacy.ExportID, content []byte, sections int, expires time.Time) error {
	result, err := r.pool.Exec(ctx, `
		UPDATE personal_data_export_jobs
		   SET status='completed',content=$2,total_sections=$3,completed_at=NOW(),expires_at=$4,updated_at=NOW()
		 WHERE export_id=$1 AND status='processing'`, string(id), content, sections, expires)
	if err != nil {
		return fmt.Errorf("postgres: complete personal data export: %w", err)
	}
	if result.RowsAffected() != 1 {
		return privacy.ErrNotFound
	}
	return nil
}

func (r *PrivacyRepository) FailExport(ctx context.Context, id privacy.ExportID, failure string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE personal_data_export_jobs
		   SET status='failed',failure_class=$2,completed_at=NOW(),updated_at=NOW()
		 WHERE export_id=$1`, string(id), failure)
	return err
}

func (r *PrivacyRepository) BuildExportDocument(ctx context.Context, user identity.UserID, generated time.Time) (privacy.ExportDocument, error) {
	document := privacy.ExportDocument{SchemaVersion: "1.0", GeneratedAt: generated,
		Personas: []string{}, IdentityLinks: []privacy.ExportLink{},
		ProviderDirectoryProfiles: []privacy.ExportDirectoryProfile{}, Authorizations: []privacy.ExportGrant{}}
	err := r.pool.QueryRow(ctx, `
		SELECT id,status,display_name,nickname,avatar_url,email,email_verified,phone,phone_verified,created_at,updated_at
		  FROM users WHERE id=$1`, string(user)).Scan(
		&document.Profile.UserID, &document.Profile.Status, &document.Profile.DisplayName,
		&document.Profile.Nickname, &document.Profile.AvatarURL, &document.Profile.Email,
		&document.Profile.EmailVerified, &document.Profile.Phone, &document.Profile.PhoneVerified,
		&document.Profile.CreatedAt, &document.Profile.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return privacy.ExportDocument{}, privacy.ErrNotFound
	}
	if err != nil {
		return privacy.ExportDocument{}, fmt.Errorf("postgres: export profile: %w", err)
	}

	rows, err := r.pool.Query(ctx, `SELECT persona FROM user_personas WHERE user_id=$1 ORDER BY persona`, string(user))
	if err != nil {
		return privacy.ExportDocument{}, err
	}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			rows.Close()
			return privacy.ExportDocument{}, err
		}
		document.Personas = append(document.Personas, value)
	}
	rows.Close()

	rows, err = r.pool.Query(ctx, `
		SELECT d.provider_id,d.provider_tenant_id,d.external_subject,d.union_id,d.tenant_user_id,
		       d.display_name,d.email,d.employee_number,d.title,d.department_ids::text,d.active,d.updated_at
		  FROM provider_directory_users d
		  JOIN identity_links l
		    ON l.user_id=$1 AND l.provider=d.provider_id
		   AND l.provider_tenant_id=d.provider_tenant_id AND l.provider_subject=d.external_subject
		 ORDER BY d.provider_id,d.provider_tenant_id,d.external_subject`, string(user))
	if err != nil {
		return privacy.ExportDocument{}, err
	}
	for rows.Next() {
		var item privacy.ExportDirectoryProfile
		var departmentIDs string
		if err := rows.Scan(&item.ProviderID, &item.ProviderTenantID, &item.ExternalSubject,
			&item.UnionID, &item.TenantUserID, &item.DisplayName, &item.Email,
			&item.EmployeeNumber, &item.Title, &departmentIDs, &item.Active, &item.UpdatedAt); err != nil {
			rows.Close()
			return privacy.ExportDocument{}, err
		}
		if err := json.Unmarshal([]byte(departmentIDs), &item.DepartmentIDs); err != nil {
			rows.Close()
			return privacy.ExportDocument{}, fmt.Errorf("postgres: decode provider directory departments: %w", err)
		}
		document.ProviderDirectoryProfiles = append(document.ProviderDirectoryProfiles, item)
	}
	rows.Close()

	rows, err = r.pool.Query(ctx, `
		SELECT provider,provider_tenant_id,provider_subject,created_at,last_seen_at
		  FROM identity_links WHERE user_id=$1 ORDER BY provider,provider_tenant_id,provider_subject`, string(user))
	if err != nil {
		return privacy.ExportDocument{}, err
	}
	for rows.Next() {
		var item privacy.ExportLink
		if err := rows.Scan(&item.Provider, &item.ProviderTenantID, &item.ProviderSubject, &item.CreatedAt, &item.LastSeenAt); err != nil {
			rows.Close()
			return privacy.ExportDocument{}, err
		}
		document.IdentityLinks = append(document.IdentityLinks, item)
	}
	rows.Close()

	var employee privacy.ExportEmployee
	err = r.pool.QueryRow(ctx, `
		SELECT e.employee_number,e.department_id,d.name,e.title,e.supervisor_user_id,e.status,e.onboarded_at,e.offboarded_at
		  FROM employee_profiles e JOIN departments d ON d.department_id=e.department_id
		 WHERE e.user_id=$1`, string(user)).Scan(&employee.EmployeeNumber, &employee.DepartmentID,
		&employee.DepartmentName, &employee.Title, &employee.SupervisorID, &employee.Status,
		&employee.OnboardedAt, &employee.OffboardedAt)
	if err == nil {
		document.Employee = &employee
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return privacy.ExportDocument{}, err
	}

	rows, err = r.pool.Query(ctx, `
		SELECT g.grant_id,a.application_id,a.name,c.client_id,c.name,g.status,
		       COALESCE(array_agg(s.scope ORDER BY s.scope) FILTER (WHERE s.scope IS NOT NULL),ARRAY[]::text[]),
		       g.granted_at,g.revoked_at
		  FROM oauth_authorization_grants g
		  JOIN oauth_clients c ON c.client_id=g.client_id
		  JOIN oauth_applications a ON a.application_id=c.application_id
		  LEFT JOIN oauth_authorization_grant_scopes s ON s.grant_id=g.grant_id
		 WHERE g.user_id=$1
		 GROUP BY g.grant_id,a.application_id,a.name,c.client_id,c.name,g.status,g.granted_at,g.revoked_at
		 ORDER BY g.granted_at,g.grant_id`, string(user))
	if err != nil {
		return privacy.ExportDocument{}, err
	}
	for rows.Next() {
		var item privacy.ExportGrant
		if err := rows.Scan(&item.GrantID, &item.ApplicationID, &item.ApplicationName, &item.ClientID,
			&item.ClientName, &item.Status, &item.Scopes, &item.GrantedAt, &item.RevokedAt); err != nil {
			rows.Close()
			return privacy.ExportDocument{}, err
		}
		document.Authorizations = append(document.Authorizations, item)
	}
	rows.Close()

	deletion, err := r.GetDeletion(ctx, user)
	if err != nil {
		return privacy.ExportDocument{}, err
	}
	document.Deletion = deletion
	return document, nil
}

func (r *PrivacyRepository) GetDeletion(ctx context.Context, user identity.UserID) (*privacy.Deletion, error) {
	var result privacy.Deletion
	err := r.pool.QueryRow(ctx, `
		SELECT deletion_id,user_id,provider_subject,status,requested_at,execute_after,cancelled_at,completed_at
		  FROM account_deletion_requests WHERE user_id=$1`, string(user)).Scan(
		&result.DeletionID, &result.UserID, &result.ProviderSubject, &result.Status,
		&result.RequestedAt, &result.ExecuteAfter, &result.CancelledAt, &result.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get account deletion: %w", err)
	}
	return &result, nil
}

func (r *PrivacyRepository) RequestDeletion(ctx context.Context, user identity.UserID, requestID string, executeAfter time.Time) (privacy.Deletion, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return privacy.Deletion{}, err
	}
	defer tx.Rollback(ctx)
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`, string(user)).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return privacy.Deletion{}, privacy.ErrNotFound
	} else if err != nil {
		return privacy.Deletion{}, err
	}
	if status != string(identity.UserStatusActive) {
		return privacy.Deletion{}, privacy.ErrConflict
	}
	var providerSubject string
	err = tx.QueryRow(ctx, `
		SELECT provider_subject FROM identity_links
		 WHERE user_id=$1 AND provider=$2 ORDER BY created_at LIMIT 1`, string(user), r.authProvider).Scan(&providerSubject)
	if errors.Is(err, pgx.ErrNoRows) || providerSubject == "" {
		return privacy.Deletion{}, privacy.ErrConflict
	}
	if err != nil {
		return privacy.Deletion{}, err
	}

	var existing string
	err = tx.QueryRow(ctx, `SELECT status FROM account_deletion_requests WHERE user_id=$1 FOR UPDATE`, string(user)).Scan(&existing)
	if err == nil && existing != "cancelled" && existing != "failed" {
		return privacy.Deletion{}, privacy.ErrConflict
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return privacy.Deletion{}, err
	}
	id := privacy.DeletionID(newPolicyStoreID("del_"))
	var result privacy.Deletion
	if existing == "cancelled" || existing == "failed" {
		err = tx.QueryRow(ctx, `
			UPDATE account_deletion_requests
			   SET deletion_id=$2,provider_subject=$3,request_id=$4,status='pending',attempts=0,
			       failure_class='',requested_at=NOW(),execute_after=$5,updated_at=NOW(),
			       cancelled_at=NULL,provider_deleted_at=NULL,completed_at=NULL
			 WHERE user_id=$1
			 RETURNING deletion_id,user_id,provider_subject,status,requested_at,execute_after,cancelled_at,completed_at`,
			string(user), string(id), providerSubject, requestID, executeAfter).Scan(
			&result.DeletionID, &result.UserID, &result.ProviderSubject, &result.Status,
			&result.RequestedAt, &result.ExecuteAfter, &result.CancelledAt, &result.CompletedAt)
	} else {
		err = tx.QueryRow(ctx, `
			INSERT INTO account_deletion_requests(deletion_id,user_id,provider_subject,request_id,execute_after)
			VALUES($1,$2,$3,$4,$5)
			RETURNING deletion_id,user_id,provider_subject,status,requested_at,execute_after,cancelled_at,completed_at`,
			string(id), string(user), providerSubject, requestID, executeAfter).Scan(
			&result.DeletionID, &result.UserID, &result.ProviderSubject, &result.Status,
			&result.RequestedAt, &result.ExecuteAfter, &result.CancelledAt, &result.CompletedAt)
	}
	if err != nil {
		return privacy.Deletion{}, fmt.Errorf("postgres: request account deletion: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "privacy.account_deletion_requested",
		ActorUserID: user, RequestID: requestID, Operation: "account.delete",
		Result: applications.SecurityEventSuccess, TargetKey: "account_deletion_id",
		TargetID: string(result.DeletionID), OccurredAt: result.RequestedAt,
	}); err != nil {
		return privacy.Deletion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return privacy.Deletion{}, err
	}
	return result, nil
}

func (r *PrivacyRepository) CancelDeletion(ctx context.Context, user identity.UserID, requestID string) (privacy.Deletion, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return privacy.Deletion{}, err
	}
	defer tx.Rollback(ctx)
	var result privacy.Deletion
	err = tx.QueryRow(ctx, `
		UPDATE account_deletion_requests
		   SET status='cancelled',provider_subject='',cancelled_at=NOW(),updated_at=NOW(),request_id=$2
		 WHERE user_id=$1 AND status='pending' AND execute_after>NOW()
		 RETURNING deletion_id,user_id,provider_subject,status,requested_at,execute_after,cancelled_at,completed_at`,
		string(user), requestID).Scan(&result.DeletionID, &result.UserID, &result.ProviderSubject,
		&result.Status, &result.RequestedAt, &result.ExecuteAfter, &result.CancelledAt, &result.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return privacy.Deletion{}, privacy.ErrConflict
	}
	if err != nil {
		return privacy.Deletion{}, err
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "privacy.account_deletion_cancelled",
		ActorUserID: user, RequestID: requestID, Operation: "account.delete.cancel",
		Result: applications.SecurityEventSuccess, TargetKey: "account_deletion_id",
		TargetID: string(result.DeletionID), OccurredAt: *result.CancelledAt,
	}); err != nil {
		return privacy.Deletion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return privacy.Deletion{}, err
	}
	return result, nil
}

func (r *PrivacyRepository) ClaimDeletions(ctx context.Context, limit int) ([]privacy.Deletion, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT deletion_id,user_id,provider_subject,status,requested_at,execute_after,cancelled_at,completed_at
		  FROM account_deletion_requests
		 WHERE (status='pending' AND execute_after<=NOW()
		        AND (attempts=0 OR updated_at<=NOW()-INTERVAL '1 minute'))
		    OR (status='processing' AND updated_at<NOW()-INTERVAL '5 minutes')
		    OR (status='provider_deleted' AND updated_at<=NOW()-INTERVAL '1 minute')
		 ORDER BY execute_after,deletion_id FOR UPDATE SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	items := make([]privacy.Deletion, 0)
	for rows.Next() {
		var item privacy.Deletion
		if err := rows.Scan(&item.DeletionID, &item.UserID, &item.ProviderSubject, &item.Status,
			&item.RequestedAt, &item.ExecuteAfter, &item.CancelledAt, &item.CompletedAt); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, item)
	}
	rows.Close()
	for i := range items {
		if items[i].Status != "provider_deleted" {
			items[i].Status = "processing"
			if _, err := tx.Exec(ctx, `
				UPDATE account_deletion_requests SET status='processing',attempts=attempts+1,updated_at=NOW()
				 WHERE deletion_id=$1`, string(items[i].DeletionID)); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return items, nil
}

func (r *PrivacyRepository) MarkProviderDeleted(ctx context.Context, id privacy.DeletionID) error {
	result, err := r.pool.Exec(ctx, `
		UPDATE account_deletion_requests
		   SET status='provider_deleted',provider_deleted_at=COALESCE(provider_deleted_at,NOW()),updated_at=NOW(),failure_class=''
		 WHERE deletion_id=$1 AND status IN ('processing','provider_deleted')`, string(id))
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return privacy.ErrNotFound
	}
	return nil
}

func (r *PrivacyRepository) CompleteDeletion(ctx context.Context, id privacy.DeletionID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var user identity.UserID
	var requestID string
	err = tx.QueryRow(ctx, `
		SELECT user_id,request_id FROM account_deletion_requests
		 WHERE deletion_id=$1 AND status='provider_deleted' FOR UPDATE`, string(id)).Scan(&user, &requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return privacy.ErrNotFound
	}
	if err != nil {
		return err
	}
	statements := []string{
		`UPDATE departments SET owner_user_id=NULL,updated_at=NOW(),version=version+1 WHERE owner_user_id=$1`,
		`UPDATE employee_profiles SET supervisor_user_id=NULL,updated_at=NOW(),version=version+1 WHERE supervisor_user_id=$1`,
		`UPDATE provider_sync_conflicts SET matched_user_id=NULL WHERE matched_user_id=$1`,
		`DELETE FROM provider_sync_conflicts c USING identity_links l
		  WHERE l.user_id=$1 AND c.provider_id=l.provider AND c.provider_tenant_id=l.provider_tenant_id
		    AND c.external_subject=l.provider_subject`,
		`DELETE FROM provider_directory_users d USING identity_links l
		  WHERE l.user_id=$1 AND d.provider_id=l.provider AND d.provider_tenant_id=l.provider_tenant_id
		    AND d.external_subject=l.provider_subject`,
		`DELETE FROM oauth_authorization_grant_scopes WHERE grant_id IN (SELECT grant_id FROM oauth_authorization_grants WHERE user_id=$1)`,
		`DELETE FROM oauth_authorization_grants WHERE user_id=$1`,
		`DELETE FROM password_mutation_intents WHERE user_id=$1`,
		`DELETE FROM employee_profiles WHERE user_id=$1`,
		`DELETE FROM user_personas WHERE user_id=$1`,
		`DELETE FROM identity_links WHERE user_id=$1`,
		`DELETE FROM personal_data_export_jobs WHERE user_id=$1`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement, string(user)); err != nil {
			return fmt.Errorf("postgres: anonymize account: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET status='disabled',display_name='已注销用户',nickname='',avatar_url='',email='',
		       email_verified=FALSE,phone='',phone_verified=FALSE,security_epoch=security_epoch+1,
		       updated_at=NOW(),version=version+1 WHERE id=$1`, string(user)); err != nil {
		return err
	}
	var completed time.Time
	if err := tx.QueryRow(ctx, `
		UPDATE account_deletion_requests
		   SET status='completed',provider_subject='',completed_at=NOW(),updated_at=NOW(),failure_class=''
		 WHERE deletion_id=$1 RETURNING completed_at`, string(id)).Scan(&completed); err != nil {
		return err
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "privacy.account_deletion_completed",
		ActorUserID: user, RequestID: requestID, Operation: "account.delete.complete",
		Result: applications.SecurityEventSuccess, TargetKey: "account_deletion_id",
		TargetID: string(id), OccurredAt: completed,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PrivacyRepository) FailDeletionAttempt(ctx context.Context, id privacy.DeletionID, failure string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE account_deletion_requests
		   SET status=CASE
		         WHEN status='processing' AND attempts>=10 THEN 'failed'
		         WHEN status='processing' THEN 'pending'
		         ELSE 'provider_deleted'
		       END,
		       provider_subject=CASE
		         WHEN status='processing' AND attempts>=10 THEN ''
		         ELSE provider_subject
		       END,
		       failure_class=$2,updated_at=NOW()
		 WHERE deletion_id=$1 AND status IN ('processing','provider_deleted')`, string(id), failure)
	return err
}

func (r *PrivacyRepository) ListLegalPublications(ctx context.Context) ([]privacy.LegalPublication, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT document_kind,version,content_sha256,effective_at,approval_reference,approved_by,
		       published_by_user_id,published_at
		  FROM legal_document_publications WHERE superseded_at IS NULL ORDER BY document_kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]privacy.LegalPublication, 0, 2)
	for rows.Next() {
		var item privacy.LegalPublication
		if err := rows.Scan(&item.DocumentKind, &item.Version, &item.ContentSHA256, &item.EffectiveAt,
			&item.ApprovalReference, &item.ApprovedBy, &item.PublishedBy, &item.PublishedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *PrivacyRepository) PublishLegalDocument(ctx context.Context, input privacy.LegalPublicationInput) (privacy.LegalPublication, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return privacy.LegalPublication{}, err
	}
	defer tx.Rollback(ctx)
	var existing privacy.LegalPublication
	err = tx.QueryRow(ctx, `
		SELECT document_kind,version,content_sha256,effective_at,approval_reference,approved_by,
		       published_by_user_id,published_at
		  FROM legal_document_publications WHERE document_kind=$1 AND version=$2`,
		input.DocumentKind, input.Version).Scan(&existing.DocumentKind, &existing.Version,
		&existing.ContentSHA256, &existing.EffectiveAt, &existing.ApprovalReference,
		&existing.ApprovedBy, &existing.PublishedBy, &existing.PublishedAt)
	if err == nil {
		if existing.ContentSHA256 == input.ContentSHA256 && existing.EffectiveAt.Equal(input.EffectiveAt) &&
			existing.ApprovalReference == input.ApprovalReference && existing.ApprovedBy == input.ApprovedBy {
			return existing, nil
		}
		return privacy.LegalPublication{}, privacy.ErrConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return privacy.LegalPublication{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE legal_document_publications SET superseded_at=NOW()
		 WHERE document_kind=$1 AND superseded_at IS NULL`, input.DocumentKind); err != nil {
		return privacy.LegalPublication{}, err
	}
	var result privacy.LegalPublication
	err = tx.QueryRow(ctx, `
		INSERT INTO legal_document_publications
		(document_kind,version,content_sha256,effective_at,approval_reference,approved_by,published_by_user_id)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		RETURNING document_kind,version,content_sha256,effective_at,approval_reference,approved_by,published_by_user_id,published_at`,
		input.DocumentKind, input.Version, input.ContentSHA256, input.EffectiveAt,
		input.ApprovalReference, input.ApprovedBy, string(input.PublishedBy)).Scan(
		&result.DocumentKind, &result.Version, &result.ContentSHA256, &result.EffectiveAt,
		&result.ApprovalReference, &result.ApprovedBy, &result.PublishedBy, &result.PublishedAt)
	if isUniqueViolation(err) {
		return privacy.LegalPublication{}, privacy.ErrConflict
	}
	if err != nil {
		return privacy.LegalPublication{}, err
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "legal.document_published",
		ActorUserID: input.PublishedBy, RequestID: input.RequestID, Operation: "legal.publish",
		Result: applications.SecurityEventSuccess, TargetKey: "legal_document",
		TargetID: input.DocumentKind + ":" + input.Version, OccurredAt: result.PublishedAt,
	}); err != nil {
		return privacy.LegalPublication{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return privacy.LegalPublication{}, err
	}
	return result, nil
}
