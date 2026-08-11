//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: PostgreSQL audit query and durable export repository
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
	"github.com/GravelEvolution/united-pass/backend/internal/audit"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type AuditRepository struct{ pool *pgxpool.Pool }

func NewAuditRepository(pool *pgxpool.Pool) *AuditRepository { return &AuditRepository{pool: pool} }

func (r *AuditRepository) List(ctx context.Context, query audit.Query) (audit.Page, error) {
	if query.Limit == 0 {
		query.Limit = 50
	}
	items, err := r.list(ctx, query, query.Limit+1)
	if err != nil {
		return audit.Page{}, err
	}
	page := audit.Page{Items: items}
	if len(items) > query.Limit {
		page.HasMore = true
		page.Items = items[:query.Limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodePolicyCursor(last.OccurredAt, last.EventID)
	}
	return page, nil
}

func (r *AuditRepository) ListForExport(ctx context.Context, query audit.Query, limit int) ([]audit.Event, error) {
	query.Cursor = ""
	query.Limit = limit
	return r.list(ctx, query, limit)
}

func (r *AuditRepository) list(ctx context.Context, query audit.Query, limit int) ([]audit.Event, error) {
	cursorTime, cursorID, err := decodePolicyCursor(query.Cursor)
	if err != nil {
		return nil, audit.ErrValidation
	}
	rows, err := r.pool.Query(ctx, `
		SELECT e.event_id,e.event_type,COALESCE(NULLIF(u.display_name,''),e.actor_user_id),e.actor_user_id,
		       CASE WHEN e.target_kind<>'' THEN e.target_kind WHEN e.application_id<>'' THEN 'application' WHEN e.client_id<>'' THEN 'oauth_client' ELSE e.operation END,
		       CASE WHEN e.target_id<>'' THEN e.target_id WHEN e.application_id<>'' THEN e.application_id ELSE e.client_id END,
		       e.occurred_at,e.result,e.request_id,e.operation
		  FROM security_events e LEFT JOIN users u ON u.id=e.actor_user_id
		 WHERE ($1='' OR e.event_type=$1)
		   AND ($2='' OR e.result=$2)
		   AND ($3='' OR COALESCE(NULLIF(u.display_name,''),e.actor_user_id) ILIKE '%'||$3||'%')
		   AND ($4='' OR e.request_id=$4)
		   AND ($5='' OR e.event_type ILIKE '%'||$5||'%' OR COALESCE(NULLIF(u.display_name,''),e.actor_user_id) ILIKE '%'||$5||'%' OR e.target_id ILIKE '%'||$5||'%' OR e.application_id ILIKE '%'||$5||'%' OR e.client_id ILIKE '%'||$5||'%' OR e.operation ILIKE '%'||$5||'%')
		   AND ($6::timestamptz IS NULL OR e.occurred_at >= $6)
		   AND ($7::timestamptz IS NULL OR e.occurred_at <= $7)
		   AND ($8::timestamptz IS NULL OR (e.occurred_at,e.event_id)<($8,$9))
		 ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT $10`, query.EventType, query.Result, query.ActorName, query.RequestID, query.Query, query.From, query.To, cursorTime, cursorID, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list audit events: %w", err)
	}
	defer rows.Close()
	items := make([]audit.Event, 0)
	for rows.Next() {
		var item audit.Event
		if err := rows.Scan(&item.EventID, &item.EventType, &item.ActorName, &item.ActorID, &item.TargetLabel, &item.TargetID, &item.OccurredAt, &item.Result, &item.RequestID, &item.Details); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *AuditRepository) CreateExport(ctx context.Context, actor identity.UserID, requestID string, query audit.Query) (audit.Export, error) {
	id := audit.ExportID(newPolicyStoreID("exp_"))
	encoded, err := json.Marshal(query)
	if err != nil {
		return audit.Export{}, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return audit.Export{}, err
	}
	defer tx.Rollback(ctx)
	var requested time.Time
	err = tx.QueryRow(ctx, `INSERT INTO audit_export_jobs(export_id,actor_user_id,request_id,filters) VALUES($1,$2,$3,$4) RETURNING requested_at`, string(id), string(actor), requestID, encoded).Scan(&requested)
	if err != nil {
		return audit.Export{}, fmt.Errorf("postgres: create audit export: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{EventID: applications.NewSecurityEventID(), EventType: "audit.export_requested", ActorUserID: actor, RequestID: requestID, Operation: "audit.export", Result: applications.SecurityEventSuccess, TargetKey: "audit_export_id", TargetID: string(id), OccurredAt: requested}); err != nil {
		return audit.Export{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return audit.Export{}, err
	}
	return audit.Export{ExportID: id, Status: "pending", RequestedAt: requested, ActorID: actor, Query: query}, nil
}

func (r *AuditRepository) GetExport(ctx context.Context, id audit.ExportID) (audit.Export, error) {
	var result audit.Export
	var filters []byte
	err := r.pool.QueryRow(ctx, `SELECT export_id,actor_user_id,status,filters,content,total_events,requested_at,completed_at,expires_at FROM audit_export_jobs WHERE export_id=$1`, string(id)).Scan(&result.ExportID, &result.ActorID, &result.Status, &filters, &result.Content, &result.TotalEvents, &result.RequestedAt, &result.CompletedAt, &result.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return audit.Export{}, audit.ErrNotFound
	}
	if err != nil {
		return audit.Export{}, fmt.Errorf("postgres: get audit export: %w", err)
	}
	if err := json.Unmarshal(filters, &result.Query); err != nil {
		return audit.Export{}, fmt.Errorf("postgres: decode audit export filters: %w", err)
	}
	return result, nil
}

func (r *AuditRepository) ClaimExports(ctx context.Context, limit int) ([]audit.Export, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE audit_export_jobs SET content=NULL,updated_at=NOW() WHERE status='completed' AND expires_at<=NOW() AND content IS NOT NULL`); err != nil {
		return nil, fmt.Errorf("postgres: purge expired audit exports: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT export_id,actor_user_id,filters,requested_at FROM audit_export_jobs WHERE status='pending' OR (status='processing' AND updated_at < NOW()-INTERVAL '5 minutes') ORDER BY requested_at,export_id FOR UPDATE SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	jobs := make([]audit.Export, 0)
	for rows.Next() {
		var job audit.Export
		var filters []byte
		if err := rows.Scan(&job.ExportID, &job.ActorID, &filters, &job.RequestedAt); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(filters, &job.Query); err != nil {
			rows.Close()
			return nil, err
		}
		job.Status = "processing"
		jobs = append(jobs, job)
	}
	rows.Close()
	for _, job := range jobs {
		if _, err := tx.Exec(ctx, `UPDATE audit_export_jobs SET status='processing',updated_at=NOW() WHERE export_id=$1`, string(job.ExportID)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return jobs, nil
}

func (r *AuditRepository) CompleteExport(ctx context.Context, id audit.ExportID, content []byte, total int, expires time.Time) error {
	result, err := r.pool.Exec(ctx, `UPDATE audit_export_jobs SET status='completed',content=$2,total_events=$3,completed_at=NOW(),expires_at=$4,updated_at=NOW() WHERE export_id=$1 AND status='processing'`, string(id), content, total, expires)
	if err != nil {
		return fmt.Errorf("postgres: complete audit export: %w", err)
	}
	if result.RowsAffected() != 1 {
		return audit.ErrNotFound
	}
	return nil
}

func (r *AuditRepository) FailExport(ctx context.Context, id audit.ExportID, failure string) error {
	_, err := r.pool.Exec(ctx, `UPDATE audit_export_jobs SET status='failed',failure_class=$2,updated_at=NOW(),completed_at=NOW() WHERE export_id=$1`, string(id), failure)
	return err
}

func (r *AuditRepository) RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, action, requestID string) error {
	return insertSecurityEvent(ctx, r.pool, applications.SecurityEvent{EventID: applications.NewSecurityEventID(), EventType: "authorization.denied", ActorUserID: actor, RequestID: requestID, Operation: action, Result: applications.SecurityEventDenied, TargetKey: "action", TargetID: action, OccurredAt: time.Now().UTC()})
}
