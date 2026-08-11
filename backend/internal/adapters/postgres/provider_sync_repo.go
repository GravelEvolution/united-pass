//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: PostgreSQL durable Provider directory synchronization jobs
//

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/providers"
)

func (r *ProviderRepository) EnqueueSync(ctx context.Context, actor identity.UserID, providerID providers.ProviderID, requestID string) (providers.SyncJob, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return providers.SyncJob{}, fmt.Errorf("postgres: begin provider sync enqueue: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var existing providers.SyncJob
	err = scanSyncJob(tx.QueryRow(ctx,
		`SELECT sync_id, provider_id, actor_user_id, request_id, status, started_at,
		        completed_at, departments_added, departments_updated, employees_added,
		        employees_updated, employees_offboarded, conflicts_detected, attempts, failure_class
		   FROM provider_sync_jobs
		  WHERE provider_id = $1 AND status IN ('pending', 'running')
		  FOR UPDATE`, string(providerID)), &existing)
	if err == nil {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return providers.SyncJob{}, fmt.Errorf("postgres: commit existing provider sync: %w", commitErr)
		}
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return providers.SyncJob{}, err
	}
	job := providers.SyncJob{SyncID: providers.NewSyncID(), ProviderID: providerID, ActorUserID: actor, RequestID: requestID, Status: providers.SyncStatusPending, StartedAt: time.Now().UTC()}
	_, err = tx.Exec(ctx,
		`INSERT INTO provider_sync_jobs
		    (sync_id, provider_id, actor_user_id, request_id, status, started_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'pending', $5, $5, $5)`, string(job.SyncID), string(providerID), string(actor), requestID, job.StartedAt)
	if err != nil {
		if isUniqueViolation(err) {
			if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
				return providers.SyncJob{}, fmt.Errorf("postgres: rollback duplicate provider sync: %w", rollbackErr)
			}
			var winner providers.SyncJob
			if winnerErr := scanSyncJob(r.pool.QueryRow(ctx,
				`SELECT sync_id, provider_id, actor_user_id, request_id, status, started_at,
				        completed_at, departments_added, departments_updated, employees_added,
				        employees_updated, employees_offboarded, conflicts_detected, attempts, failure_class
				   FROM provider_sync_jobs
				  WHERE provider_id = $1 AND status IN ('pending', 'running')`, string(providerID)), &winner); winnerErr != nil {
				return providers.SyncJob{}, fmt.Errorf("postgres: read concurrent provider sync: %w", winnerErr)
			}
			return winner, nil
		}
		return providers.SyncJob{}, fmt.Errorf("postgres: enqueue provider sync: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: providers.EventDirectorySyncRequested,
		ActorUserID: actor, RequestID: requestID, Operation: "provider.directory.sync",
		Result: applications.SecurityEventSuccess, TargetKey: "sync_id", TargetID: string(job.SyncID),
		Extra: map[string]string{"provider_id": string(providerID)}, OccurredAt: job.StartedAt,
	}); err != nil {
		return providers.SyncJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return providers.SyncJob{}, fmt.Errorf("postgres: commit provider sync enqueue: %w", err)
	}
	return job, nil
}

func (r *ProviderRepository) ClaimSync(ctx context.Context, staleBefore time.Time) (*providers.SyncJob, error) {
	row := r.pool.QueryRow(ctx,
		`WITH candidate AS (
		     SELECT sync_id FROM provider_sync_jobs
		      WHERE status = 'pending' OR (status = 'running' AND updated_at < $1)
		      ORDER BY created_at, sync_id
		      FOR UPDATE SKIP LOCKED LIMIT 1
		 )
		 UPDATE provider_sync_jobs j
		    SET status = 'running', attempts = attempts + 1, updated_at = NOW()
		   FROM candidate c WHERE j.sync_id = c.sync_id
		 RETURNING j.sync_id, j.provider_id, j.actor_user_id, j.request_id, j.status,
		           j.started_at, j.completed_at, j.departments_added,
		           j.departments_updated, j.employees_added, j.employees_updated,
		           j.employees_offboarded, j.conflicts_detected, j.attempts, j.failure_class`, staleBefore)
	var job providers.SyncJob
	if err := scanSyncJob(row, &job); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &job, nil
}

type syncJobScanner interface{ Scan(dest ...any) error }

func scanSyncJob(row syncJobScanner, job *providers.SyncJob) error {
	var syncID, providerID, actorID, status string
	if err := row.Scan(&syncID, &providerID, &actorID, &job.RequestID, &status,
		&job.StartedAt, &job.CompletedAt, &job.DepartmentsAdded,
		&job.DepartmentsUpdated, &job.EmployeesAdded, &job.EmployeesUpdated,
		&job.EmployeesOffboarded, &job.ConflictsDetected, &job.Attempts,
		&job.FailureClass); err != nil {
		return err
	}
	job.SyncID, job.ProviderID, job.ActorUserID, job.Status = providers.SyncID(syncID), providers.ProviderID(providerID), identity.UserID(actorID), providers.SyncStatus(status)
	return nil
}

func (r *ProviderRepository) ApplySnapshot(ctx context.Context, job providers.SyncJob, snapshot providers.DirectorySnapshot) (providers.SyncJob, error) {
	if err := providers.ValidateSnapshot(snapshot); err != nil {
		return providers.SyncJob{}, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return providers.SyncJob{}, fmt.Errorf("postgres: begin provider snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var lockedStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM provider_sync_jobs WHERE sync_id = $1 FOR UPDATE`, string(job.SyncID)).Scan(&lockedStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return providers.SyncJob{}, providers.ErrNotFound
		}
		return providers.SyncJob{}, fmt.Errorf("postgres: lock provider sync: %w", err)
	}
	if lockedStatus != string(providers.SyncStatusRunning) {
		return providers.SyncJob{}, providers.ErrConflict
	}

	for _, item := range snapshot.Departments {
		checksum := checksumValues(item.ExternalID, item.ParentExternalID, item.Name, item.LeaderSubject)
		var previous string
		err := tx.QueryRow(ctx,
			`SELECT checksum FROM provider_directory_departments
			  WHERE provider_id = $1 AND provider_tenant_id = $2 AND external_department_id = $3`,
			string(job.ProviderID), snapshot.TenantID, item.ExternalID).Scan(&previous)
		if errors.Is(err, pgx.ErrNoRows) {
			job.DepartmentsAdded++
		} else if err != nil {
			return providers.SyncJob{}, fmt.Errorf("postgres: inspect staged department: %w", err)
		} else if previous != checksum {
			job.DepartmentsUpdated++
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO provider_directory_departments
			    (provider_id, provider_tenant_id, external_department_id,
			     parent_external_id, name, leader_subject, checksum, active,
			     last_seen_sync_id, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE,$8,NOW(),NOW())
			 ON CONFLICT (provider_id, provider_tenant_id, external_department_id)
			 DO UPDATE SET parent_external_id = EXCLUDED.parent_external_id,
			     name = EXCLUDED.name, leader_subject = EXCLUDED.leader_subject,
			     checksum = EXCLUDED.checksum, active = TRUE,
			     last_seen_sync_id = EXCLUDED.last_seen_sync_id, updated_at = NOW()`,
			string(job.ProviderID), snapshot.TenantID, item.ExternalID, item.ParentExternalID,
			item.Name, item.LeaderSubject, checksum, string(job.SyncID))
		if err != nil {
			return providers.SyncJob{}, fmt.Errorf("postgres: stage provider department: %w", err)
		}
	}
	if !snapshot.Partial {
		if _, err := tx.Exec(ctx,
			`UPDATE provider_directory_departments SET active = FALSE, updated_at = NOW()
			  WHERE provider_id = $1 AND provider_tenant_id = $2
			    AND last_seen_sync_id <> $3 AND active = TRUE`, string(job.ProviderID), snapshot.TenantID, string(job.SyncID)); err != nil {
			return providers.SyncJob{}, fmt.Errorf("postgres: retire staged departments: %w", err)
		}
	}

	for _, item := range snapshot.Users {
		departmentsJSON, err := json.Marshal(item.DepartmentIDs)
		if err != nil {
			return providers.SyncJob{}, fmt.Errorf("postgres: encode provider departments: %w", err)
		}
		checksum := checksumValues(item.Subject, item.UnionID, item.TenantUserID, item.Name, item.Email, item.EmployeeNumber, item.Title, string(departmentsJSON), fmt.Sprint(item.Active))
		var previous string
		err = tx.QueryRow(ctx,
			`SELECT checksum FROM provider_directory_users
			  WHERE provider_id = $1 AND provider_tenant_id = $2 AND external_subject = $3`,
			string(job.ProviderID), snapshot.TenantID, item.Subject).Scan(&previous)
		if errors.Is(err, pgx.ErrNoRows) {
			job.EmployeesAdded++
		} else if err != nil {
			return providers.SyncJob{}, fmt.Errorf("postgres: inspect staged user: %w", err)
		} else if previous != checksum {
			job.EmployeesUpdated++
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO provider_directory_users
			    (provider_id, provider_tenant_id, external_subject, union_id,
			     tenant_user_id, display_name, email, employee_number, title,
			     department_ids, checksum, active, last_seen_sync_id, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
			 ON CONFLICT (provider_id, provider_tenant_id, external_subject)
			 DO UPDATE SET union_id = EXCLUDED.union_id, tenant_user_id = EXCLUDED.tenant_user_id,
			     display_name = EXCLUDED.display_name, email = EXCLUDED.email,
			     employee_number = EXCLUDED.employee_number, title = EXCLUDED.title,
			     department_ids = EXCLUDED.department_ids, checksum = EXCLUDED.checksum,
			     active = EXCLUDED.active, last_seen_sync_id = EXCLUDED.last_seen_sync_id,
			     updated_at = NOW()`, string(job.ProviderID), snapshot.TenantID, item.Subject,
			item.UnionID, item.TenantUserID, item.Name, item.Email, item.EmployeeNumber,
			item.Title, departmentsJSON, checksum, item.Active, string(job.SyncID))
		if err != nil {
			return providers.SyncJob{}, fmt.Errorf("postgres: stage provider user: %w", err)
		}
		linked, err := hasIdentityLinkTx(ctx, tx, job.ProviderID, snapshot.TenantID, item.Subject)
		if err != nil {
			return providers.SyncJob{}, err
		}
		if !linked {
			candidateID, reason, err := suggestedUserTx(ctx, tx, item.Email, item.Name)
			if err != nil {
				return providers.SyncJob{}, err
			}
			conflictID := providers.NewConflictID()
			var status string
			err = tx.QueryRow(ctx,
				`INSERT INTO provider_sync_conflicts
				    (conflict_id, provider_id, provider_tenant_id, external_subject,
				     external_name, external_email, matched_user_id, match_reason,
				     status, detected_at, created_at, updated_at)
				 VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,'pending',NOW(),NOW(),NOW())
				 ON CONFLICT (provider_id, provider_tenant_id, external_subject)
				 DO UPDATE SET external_name = EXCLUDED.external_name,
				     external_email = EXCLUDED.external_email,
				     matched_user_id = CASE WHEN provider_sync_conflicts.status = 'pending' THEN EXCLUDED.matched_user_id ELSE provider_sync_conflicts.matched_user_id END,
				     match_reason = CASE WHEN provider_sync_conflicts.status = 'pending' THEN EXCLUDED.match_reason ELSE provider_sync_conflicts.match_reason END,
				     updated_at = NOW()
				 RETURNING status`, string(conflictID), string(job.ProviderID), snapshot.TenantID,
				item.Subject, item.Name, item.Email, string(candidateID), string(reason)).Scan(&status)
			if err != nil {
				return providers.SyncJob{}, fmt.Errorf("postgres: stage provider conflict: %w", err)
			}
			if status == string(providers.ConflictStatusPending) {
				job.ConflictsDetected++
			}
		}
	}
	if !snapshot.Partial {
		command, err := tx.Exec(ctx,
			`UPDATE provider_directory_users SET active = FALSE, updated_at = NOW()
			  WHERE provider_id = $1 AND provider_tenant_id = $2
			    AND last_seen_sync_id <> $3 AND active = TRUE`, string(job.ProviderID), snapshot.TenantID, string(job.SyncID))
		if err != nil {
			return providers.SyncJob{}, fmt.Errorf("postgres: retire staged users: %w", err)
		}
		job.EmployeesOffboarded += int(command.RowsAffected())
	}
	job.Status = providers.SyncStatusSuccess
	if snapshot.Partial || job.ConflictsDetected > 0 {
		job.Status = providers.SyncStatusPartial
	}
	completedAt := time.Now().UTC()
	job.CompletedAt = &completedAt
	job.FailureClass = snapshot.FailureClass
	_, err = tx.Exec(ctx,
		`UPDATE provider_sync_jobs SET status = $2, departments_added = $3,
		        departments_updated = $4, employees_added = $5, employees_updated = $6,
		        employees_offboarded = $7, conflicts_detected = $8,
		        failure_class = $9, completed_at = $10, updated_at = $10
		  WHERE sync_id = $1`, string(job.SyncID), string(job.Status), job.DepartmentsAdded,
		job.DepartmentsUpdated, job.EmployeesAdded, job.EmployeesUpdated,
		job.EmployeesOffboarded, job.ConflictsDetected, job.FailureClass, completedAt)
	if err != nil {
		return providers.SyncJob{}, fmt.Errorf("postgres: complete provider sync: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE identity_providers SET updated_at = $2 WHERE provider_id = $1`, string(job.ProviderID), completedAt); err != nil {
		return providers.SyncJob{}, fmt.Errorf("postgres: touch provider: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: providers.EventDirectorySyncCompleted,
		ActorUserID: job.ActorUserID, RequestID: job.RequestID, Operation: "provider.directory.sync",
		Result: applications.SecurityEventSuccess, TargetKey: "sync_id", TargetID: string(job.SyncID),
		Extra: map[string]string{"provider_id": string(job.ProviderID), "sync_status": string(job.Status)}, OccurredAt: completedAt,
	}); err != nil {
		return providers.SyncJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return providers.SyncJob{}, fmt.Errorf("postgres: commit provider snapshot: %w", err)
	}
	return job, nil
}

func (r *ProviderRepository) FailSync(ctx context.Context, job providers.SyncJob, failureClass string) error {
	if failureClass == "" {
		failureClass = "provider"
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin provider sync failure: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	status := providers.SyncStatusPending
	var completedAt *time.Time
	if job.Attempts >= 3 {
		status = providers.SyncStatusFailed
		now := time.Now().UTC()
		completedAt = &now
	}
	command, err := tx.Exec(ctx,
		`UPDATE provider_sync_jobs SET status = $2, failure_class = $3,
		        completed_at = $4, updated_at = NOW()
		  WHERE sync_id = $1 AND status = 'running'`, string(job.SyncID), string(status), failureClass, completedAt)
	if err != nil {
		return fmt.Errorf("postgres: record provider sync failure: %w", err)
	}
	if command.RowsAffected() != 1 {
		return providers.ErrConflict
	}
	if status == providers.SyncStatusFailed {
		if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
			EventID: applications.NewSecurityEventID(), EventType: providers.EventDirectorySyncFailed,
			ActorUserID: job.ActorUserID, RequestID: job.RequestID, Operation: "provider.directory.sync",
			Result: applications.SecurityEventDenied, FailureClass: failureClass,
			TargetKey: "sync_id", TargetID: string(job.SyncID),
			Extra: map[string]string{"provider_id": string(job.ProviderID)}, OccurredAt: *completedAt,
		}); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit provider sync failure: %w", err)
	}
	return nil
}

func (r *ProviderRepository) ListSyncHistory(ctx context.Context, providerID providers.ProviderID, limit int) ([]providers.SyncHistoryEntry, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT sync_id, provider_id, actor_user_id, request_id, status, started_at,
		        completed_at, departments_added, departments_updated, employees_added,
		        employees_updated, employees_offboarded, conflicts_detected, attempts, failure_class
		   FROM provider_sync_jobs WHERE provider_id = $1
		  ORDER BY started_at DESC, sync_id DESC LIMIT $2`, string(providerID), limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list provider sync history: %w", err)
	}
	defer rows.Close()
	items := make([]providers.SyncHistoryEntry, 0)
	for rows.Next() {
		var job providers.SyncJob
		if err := scanSyncJob(rows, &job); err != nil {
			return nil, fmt.Errorf("postgres: scan provider sync history: %w", err)
		}
		items = append(items, providers.SyncHistoryEntry{SyncJob: job, Summary: syncSummary(job)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate provider sync history: %w", err)
	}
	return items, nil
}

func (r *ProviderRepository) ListConflicts(ctx context.Context, providerID providers.ProviderID, limit int) ([]providers.SyncConflict, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT c.conflict_id, c.provider_id, c.provider_tenant_id,
		        c.external_subject, c.external_name, c.external_email,
		        c.matched_user_id, COALESCE(u.display_name, ''), c.match_reason,
		        c.status, c.detected_at
		   FROM provider_sync_conflicts c
		   LEFT JOIN users u ON u.id = c.matched_user_id
		  WHERE c.provider_id = $1
		  ORDER BY CASE c.status WHEN 'pending' THEN 0 ELSE 1 END,
		           c.detected_at DESC, c.conflict_id DESC LIMIT $2`, string(providerID), limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list provider conflicts: %w", err)
	}
	defer rows.Close()
	items := make([]providers.SyncConflict, 0)
	for rows.Next() {
		var item providers.SyncConflict
		var conflictID, rawProviderID, reason, status string
		var matchedUserID *string
		if err := rows.Scan(&conflictID, &rawProviderID, &item.TenantID,
			&item.ExternalSubject, &item.ExternalName, &item.ExternalEmail,
			&matchedUserID, &item.MatchedUserName, &reason, &status, &item.DetectedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan provider conflict: %w", err)
		}
		item.ConflictID, item.ProviderID = providers.ConflictID(conflictID), providers.ProviderID(rawProviderID)
		if matchedUserID != nil {
			item.MatchedUserID = identity.UserID(*matchedUserID)
		}
		item.MatchReason, item.Status = providers.MatchReason(reason), providers.ConflictStatus(status)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate provider conflicts: %w", err)
	}
	return items, nil
}

func hasIdentityLinkTx(ctx context.Context, tx pgx.Tx, providerID providers.ProviderID, tenantID, subject string) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM identity_links WHERE provider = $1 AND provider_tenant_id = $2 AND provider_subject = $3)`,
		string(providerID), tenantID, subject).Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: inspect explicit provider link: %w", err)
	}
	return exists, nil
}

func suggestedUserTx(ctx context.Context, tx pgx.Tx, email, name string) (identity.UserID, providers.MatchReason, error) {
	for _, candidate := range []struct {
		value, column string
		reason        providers.MatchReason
	}{
		{strings.TrimSpace(email), "email", providers.MatchReasonEmail},
		{strings.TrimSpace(name), "display_name", providers.MatchReasonName},
	} {
		if candidate.value == "" {
			continue
		}
		query := `SELECT id FROM users WHERE status = 'active' AND lower(` + candidate.column + `) = lower($1) ORDER BY id LIMIT 2`
		rows, err := tx.Query(ctx, query, candidate.value)
		if err != nil {
			return "", providers.MatchReasonManual, fmt.Errorf("postgres: search provider link suggestion: %w", err)
		}
		ids := make([]identity.UserID, 0, 2)
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return "", providers.MatchReasonManual, err
			}
			ids = append(ids, identity.UserID(id))
		}
		rows.Close()
		if len(ids) == 1 {
			return ids[0], candidate.reason, nil
		}
	}
	return "", providers.MatchReasonManual, nil
}

func checksumValues(values ...string) string {
	h := sha256.New()
	for _, value := range values {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func syncSummary(job providers.SyncJob) string {
	switch job.Status {
	case providers.SyncStatusPending:
		return "同步已排队"
	case providers.SyncStatusRunning:
		return "同步处理中"
	case providers.SyncStatusFailed:
		return "同步失败"
	default:
		return fmt.Sprintf("部门 +%d/~%d；成员 +%d/~%d；冲突 %d", job.DepartmentsAdded, job.DepartmentsUpdated, job.EmployeesAdded, job.EmployeesUpdated, job.ConflictsDetected)
	}
}
