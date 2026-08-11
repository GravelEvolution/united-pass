//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: PostgreSQL Provider administration and explicit identity linking
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/providers"
)

type ProviderRepository struct {
	pool  *pgxpool.Pool
	users *UserRepository
}

func NewProviderRepository(pool *pgxpool.Pool) *ProviderRepository {
	return &ProviderRepository{pool: pool, users: NewUserRepository(pool)}
}

func (r *ProviderRepository) ListProviders(ctx context.Context, query providers.ListQuery) (providers.CursorPage[providers.ProviderSummary], error) {
	limit := query.Limit
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	if query.Cursor != "" && !providers.HasProviderIDPrefix(query.Cursor) {
		return providers.CursorPage[providers.ProviderSummary]{}, providers.ErrInvalidInput
	}
	if query.Status != "" && query.Status != string(providers.ProviderStatusPlanned) && query.Status != string(providers.ProviderStatusActive) && query.Status != string(providers.ProviderStatusDisabled) {
		return providers.CursorPage[providers.ProviderSummary]{}, providers.ErrInvalidInput
	}
	rows, err := r.pool.Query(ctx,
		`SELECT p.provider_id, p.display_name, p.vendor, p.integration_label,
		        p.status, p.login_enabled, COUNT(l.id), p.updated_at
		   FROM identity_providers p
		   LEFT JOIN identity_links l ON l.provider = p.provider_id
		  WHERE ($1 = '' OR p.provider_id > $1)
		    AND ($2 = '' OR p.status = $2)
		    AND ($3 = '' OR p.display_name ILIKE '%' || $3 || '%'
		         OR p.vendor ILIKE '%' || $3 || '%'
		         OR p.integration_label ILIKE '%' || $3 || '%')
		  GROUP BY p.provider_id
		  ORDER BY p.provider_id
		  LIMIT $4`, query.Cursor, query.Status, strings.TrimSpace(query.Query), limit+1)
	if err != nil {
		return providers.CursorPage[providers.ProviderSummary]{}, fmt.Errorf("postgres: list providers: %w", err)
	}
	defer rows.Close()
	items := make([]providers.ProviderSummary, 0, limit+1)
	for rows.Next() {
		item, err := scanProviderSummary(rows)
		if err != nil {
			return providers.CursorPage[providers.ProviderSummary]{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return providers.CursorPage[providers.ProviderSummary]{}, fmt.Errorf("postgres: iterate providers: %w", err)
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	next := ""
	if hasMore && len(items) > 0 {
		next = string(items[len(items)-1].ProviderID)
	}
	return providers.CursorPage[providers.ProviderSummary]{Items: items, NextCursor: next, HasMore: hasMore}, nil
}

type providerSummaryScanner interface{ Scan(dest ...any) error }

func scanProviderSummary(row providerSummaryScanner) (providers.ProviderSummary, error) {
	var item providers.ProviderSummary
	var providerID, status string
	if err := row.Scan(&providerID, &item.DisplayName, &item.Vendor, &item.IntegrationLabel,
		&status, &item.LoginEnabled, &item.LinkedUserCount, &item.UpdatedAt); err != nil {
		return providers.ProviderSummary{}, fmt.Errorf("postgres: scan provider: %w", err)
	}
	item.ProviderID = providers.ProviderID(providerID)
	item.Status = providers.ProviderStatus(status)
	return item, nil
}

func (r *ProviderRepository) GetProvider(ctx context.Context, providerID providers.ProviderID) (providers.ProviderDetail, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT p.provider_id, p.display_name, p.vendor, p.integration_label,
		        p.status, p.login_enabled, COUNT(DISTINCT l.id), p.updated_at,
		        p.last_validated_at,
		        latest.sync_id, latest.status, latest.started_at, latest.completed_at,
		        latest.departments_added, latest.departments_updated,
		        latest.employees_added, latest.employees_updated,
		        latest.employees_offboarded, latest.conflicts_detected,
		        latest.attempts, latest.failure_class
		   FROM identity_providers p
		   LEFT JOIN identity_links l ON l.provider = p.provider_id
		   LEFT JOIN LATERAL (
		       SELECT * FROM provider_sync_jobs j
		        WHERE j.provider_id = p.provider_id
		        ORDER BY j.started_at DESC, j.sync_id DESC LIMIT 1
		   ) latest ON TRUE
		  WHERE p.provider_id = $1
		  GROUP BY p.provider_id, latest.sync_id, latest.status, latest.started_at,
		           latest.completed_at, latest.departments_added,
		           latest.departments_updated, latest.employees_added,
		           latest.employees_updated, latest.employees_offboarded,
		           latest.conflicts_detected, latest.attempts, latest.failure_class`, string(providerID))
	var detail providers.ProviderDetail
	var rawProviderID, status string
	var validatedAt *time.Time
	var syncID, syncStatus, failureClass *string
	var startedAt, completedAt *time.Time
	var depAdded, depUpdated, empAdded, empUpdated, empOffboarded, conflicts, attempts *int
	if err := row.Scan(&rawProviderID, &detail.DisplayName, &detail.Vendor, &detail.IntegrationLabel,
		&status, &detail.LoginEnabled, &detail.LinkedUserCount, &detail.UpdatedAt,
		&validatedAt, &syncID, &syncStatus, &startedAt, &completedAt,
		&depAdded, &depUpdated, &empAdded, &empUpdated, &empOffboarded, &conflicts,
		&attempts, &failureClass); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return providers.ProviderDetail{}, providers.ErrNotFound
		}
		return providers.ProviderDetail{}, fmt.Errorf("postgres: get provider: %w", err)
	}
	detail.ProviderID = providers.ProviderID(rawProviderID)
	detail.Status = providers.ProviderStatus(status)
	detail.LastValidatedAt = validatedAt
	if syncID != nil {
		job := providers.SyncJob{
			SyncID: providers.SyncID(*syncID), ProviderID: detail.ProviderID,
			Status: providers.SyncStatus(*syncStatus), StartedAt: *startedAt,
			CompletedAt: completedAt, DepartmentsAdded: *depAdded,
			DepartmentsUpdated: *depUpdated, EmployeesAdded: *empAdded,
			EmployeesUpdated: *empUpdated, EmployeesOffboarded: *empOffboarded,
			ConflictsDetected: *conflicts, Attempts: *attempts, FailureClass: *failureClass,
		}
		detail.LastSyncResult = &job
		detail.LastSyncAt = startedAt
	}
	return detail, nil
}

func (r *ProviderRepository) SetProviderEnabled(ctx context.Context, actor identity.UserID, providerID providers.ProviderID, enabled bool, requestID string) (providers.ProviderDetail, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return providers.ProviderDetail{}, fmt.Errorf("postgres: begin provider state: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var current bool
	if err := tx.QueryRow(ctx, `SELECT login_enabled FROM identity_providers WHERE provider_id = $1 FOR UPDATE`, string(providerID)).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return providers.ProviderDetail{}, providers.ErrNotFound
		}
		return providers.ProviderDetail{}, fmt.Errorf("postgres: lock provider: %w", err)
	}
	if current != enabled {
		_, err = tx.Exec(ctx,
			`UPDATE identity_providers
			    SET status = $2, login_enabled = $3,
			        last_validated_at = CASE WHEN $3 THEN NOW() ELSE last_validated_at END,
			        updated_at = NOW()
			  WHERE provider_id = $1`, string(providerID), map[bool]string{true: string(providers.ProviderStatusActive), false: string(providers.ProviderStatusDisabled)}[enabled], enabled)
		if err != nil {
			return providers.ProviderDetail{}, fmt.Errorf("postgres: update provider state: %w", err)
		}
		eventType, operation := providers.EventProviderDisabled, "provider.disable"
		if enabled {
			eventType, operation = providers.EventProviderEnabled, "provider.enable"
		}
		if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
			EventID: applications.NewSecurityEventID(), EventType: eventType,
			ActorUserID: actor, RequestID: requestID, Operation: operation,
			Result: applications.SecurityEventSuccess, TargetKey: "provider_id",
			TargetID: string(providerID), OccurredAt: time.Now().UTC(),
		}); err != nil {
			return providers.ProviderDetail{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return providers.ProviderDetail{}, fmt.Errorf("postgres: commit provider state: %w", err)
	}
	return r.GetProvider(ctx, providerID)
}

func (r *ProviderRepository) ResolveConflict(ctx context.Context, actor identity.UserID, conflictID providers.ConflictID, userID identity.UserID, requestID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin conflict resolution: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var providerID, tenantID, subject, status string
	var matchedUserID *string
	if err := tx.QueryRow(ctx,
		`SELECT provider_id, provider_tenant_id, external_subject, status, matched_user_id
		   FROM provider_sync_conflicts WHERE conflict_id = $1 FOR UPDATE`, string(conflictID)).Scan(&providerID, &tenantID, &subject, &status, &matchedUserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return providers.ErrNotFound
		}
		return fmt.Errorf("postgres: lock provider conflict: %w", err)
	}
	if status == string(providers.ConflictStatusResolved) && matchedUserID != nil && *matchedUserID == string(userID) {
		return nil
	}
	if status != string(providers.ConflictStatusPending) {
		return providers.ErrConflict
	}
	var userStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 FOR SHARE`, string(userID)).Scan(&userStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return providers.ErrNotFound
		}
		return fmt.Errorf("postgres: validate conflict target user: %w", err)
	}
	if userStatus != string(identity.UserStatusActive) {
		return providers.ErrConflict
	}
	var existingUserID string
	err = tx.QueryRow(ctx,
		`SELECT user_id FROM identity_links
		  WHERE provider = $1 AND provider_tenant_id = $2 AND provider_subject = $3
		  FOR UPDATE`, providerID, tenantID, subject).Scan(&existingUserID)
	if err == nil && existingUserID != string(userID) {
		return providers.ErrConflict
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: inspect provider identity link: %w", err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = tx.Exec(ctx,
			`INSERT INTO identity_links
			    (id, user_id, provider, provider_tenant_id, provider_subject, created_at, last_seen_at)
			 VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`, generateLinkID(), string(userID), providerID, tenantID, subject)
		if err != nil {
			if isUniqueViolation(err) {
				return providers.ErrConflict
			}
			return fmt.Errorf("postgres: create explicit provider identity link: %w", err)
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE provider_sync_conflicts
		    SET matched_user_id = $2, match_reason = 'manual', status = 'resolved',
		        resolved_at = NOW(), resolved_by_user_id = $3, updated_at = NOW()
		  WHERE conflict_id = $1`, string(conflictID), string(userID), string(actor)); err != nil {
		return fmt.Errorf("postgres: resolve provider conflict: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: providers.EventIdentityConflictResolved,
		ActorUserID: actor, RequestID: requestID, Operation: "provider.identity.link",
		Result: applications.SecurityEventSuccess, TargetKey: "conflict_id", TargetID: string(conflictID),
		Extra: map[string]string{"provider_id": providerID, "user_id": string(userID)}, OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit conflict resolution: %w", err)
	}
	return nil
}

func (r *ProviderRepository) IgnoreConflict(ctx context.Context, actor identity.UserID, conflictID providers.ConflictID, requestID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin ignore conflict: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status, providerID string
	if err := tx.QueryRow(ctx, `SELECT status, provider_id FROM provider_sync_conflicts WHERE conflict_id = $1 FOR UPDATE`, string(conflictID)).Scan(&status, &providerID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return providers.ErrNotFound
		}
		return fmt.Errorf("postgres: lock ignored conflict: %w", err)
	}
	if status == string(providers.ConflictStatusIgnored) {
		return nil
	}
	if status != string(providers.ConflictStatusPending) {
		return providers.ErrConflict
	}
	if _, err := tx.Exec(ctx,
		`UPDATE provider_sync_conflicts SET status = 'ignored', resolved_at = NOW(),
		        resolved_by_user_id = $2, updated_at = NOW() WHERE conflict_id = $1`, string(conflictID), string(actor)); err != nil {
		return fmt.Errorf("postgres: ignore provider conflict: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: providers.EventIdentityConflictIgnored,
		ActorUserID: actor, RequestID: requestID, Operation: "provider.identity.ignore",
		Result: applications.SecurityEventSuccess, TargetKey: "conflict_id", TargetID: string(conflictID),
		Extra: map[string]string{"provider_id": providerID}, OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit ignore conflict: %w", err)
	}
	return nil
}

func (r *ProviderRepository) RecordUnlinkedIdentity(ctx context.Context, providerID providers.ProviderID, tenantID string, info providers.OAuthUserInfo) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin unlinked provider identity: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	candidateID, reason, err := suggestedUserTx(ctx, tx, info.Email, info.Name)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
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
		     updated_at = NOW()`, providers.NewConflictID(), string(providerID), tenantID,
		info.Subject, info.Name, info.Email, string(candidateID), string(reason))
	if err != nil {
		return fmt.Errorf("postgres: record unlinked provider identity: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit unlinked provider identity: %w", err)
	}
	return nil
}

func (r *ProviderRepository) LinkedUser(ctx context.Context, providerID providers.ProviderID, tenantID, subject string) (identity.User, error) {
	link, err := r.users.GetIdentityLink(ctx, string(providerID), tenantID, subject)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return identity.User{}, providers.ErrNotFound
		}
		return identity.User{}, err
	}
	if _, err := r.pool.Exec(ctx, `UPDATE identity_links SET last_seen_at = NOW() WHERE id = $1`, link.ID); err != nil {
		return identity.User{}, fmt.Errorf("postgres: touch provider identity link: %w", err)
	}
	user, err := r.users.GetByID(ctx, link.UserID)
	if errors.Is(err, identity.ErrUserNotFound) {
		return identity.User{}, providers.ErrNotFound
	}
	return user, err
}

func (r *ProviderRepository) RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, targetKey, targetID, eventType, operation, requestID string) error {
	return insertSecurityEvent(ctx, r.pool, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: eventType,
		ActorUserID: actor, RequestID: requestID, Operation: operation,
		Result: applications.SecurityEventDenied, FailureClass: "authorization",
		TargetKey: targetKey, TargetID: targetID, OccurredAt: time.Now().UTC(),
	})
}
