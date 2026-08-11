//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Durable Phase 5 cross-store access revocation ledger
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

func (r *WorkforceRepository) EnqueueSessionRevocation(ctx context.Context, actor, userID identity.UserID, reason workforce.AccessRevocationReason, requestID string) (workforce.AccessRevocationJob, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return workforce.AccessRevocationJob{}, fmt.Errorf("postgres: begin session revocation job: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireUserExistsTx(ctx, tx, userID); err != nil {
		return workforce.AccessRevocationJob{}, err
	}
	job, err := enqueueAccessRevocationTx(ctx, tx, actor, userID, reason, requestID)
	if err != nil {
		return workforce.AccessRevocationJob{}, err
	}
	if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(
		workforce.EventUserSessionsRevokeRequested, actor, "user_id", string(userID),
		requestID, "user.sessions.revoke", applications.SecurityEventSuccess, "", map[string]string{
			"revocation_job_id": string(job.JobID),
		})); err != nil {
		return workforce.AccessRevocationJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return workforce.AccessRevocationJob{}, fmt.Errorf("postgres: commit session revocation job: %w", err)
	}
	return job, nil
}

func enqueueAccessRevocationTx(ctx context.Context, tx pgx.Tx, actor, userID identity.UserID, reason workforce.AccessRevocationReason, requestID string) (workforce.AccessRevocationJob, error) {
	jobID := workforce.NewAccessRevocationJobID()
	row := tx.QueryRow(ctx,
		`INSERT INTO access_revocation_jobs
		     (job_id, actor_user_id, user_id, request_id, reason, status,
		      attempts, failure_class, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, 'pending', 0, '', NOW(), NOW())
		 ON CONFLICT (user_id, reason) WHERE status = 'pending'
		 DO UPDATE SET updated_at = access_revocation_jobs.updated_at
		 RETURNING job_id, actor_user_id, user_id, reason, request_id,
		           attempts, created_at`,
		string(jobID), string(actor), string(userID), requestID, string(reason))
	return scanAccessRevocationJob(row)
}

func scanAccessRevocationJob(row pgx.Row) (workforce.AccessRevocationJob, error) {
	var job workforce.AccessRevocationJob
	var jobID, actorID, userID, reason string
	if err := row.Scan(&jobID, &actorID, &userID, &reason, &job.RequestID,
		&job.Attempts, &job.CreatedAt); err != nil {
		return workforce.AccessRevocationJob{}, mapWorkforceMutationError(err, "scan access revocation job")
	}
	job.JobID = workforce.AccessRevocationJobID(jobID)
	job.ActorUserID = identity.UserID(actorID)
	job.UserID = identity.UserID(userID)
	job.Reason = workforce.AccessRevocationReason(reason)
	return job, nil
}

func (r *WorkforceRepository) ResolveAccessRevocation(ctx context.Context, job workforce.AccessRevocationJob, affectedCount int, providerFailureClass string) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("postgres: begin resolve access revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status string
	if err := tx.QueryRow(ctx,
		`SELECT status FROM access_revocation_jobs WHERE job_id = $1 FOR UPDATE`, string(job.JobID)).Scan(&status); err != nil {
		return mapWorkforceMutationError(err, "lock access revocation job")
	}
	if status == "resolved" {
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE access_revocation_jobs
		    SET status = 'resolved', failure_class = '', resolved_at = NOW(), updated_at = NOW()
		  WHERE job_id = $1`, string(job.JobID)); err != nil {
		return fmt.Errorf("postgres: resolve access revocation job: %w", err)
	}
	extra := map[string]string{
		"revocation_job_id": string(job.JobID),
		"reason":            string(job.Reason),
		"affected_count":    strconv.Itoa(affectedCount),
	}
	if providerFailureClass != "" {
		extra["provider_failure_class"] = providerFailureClass
	}
	if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(
		workforce.EventAccessRevocationCompleted, job.ActorUserID, "user_id", string(job.UserID),
		job.RequestID, "access_revocation.complete", applications.SecurityEventSuccess, "", extra)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *WorkforceRepository) FailAccessRevocation(ctx context.Context, job workforce.AccessRevocationJob, failureClass string) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("postgres: begin fail access revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var attempts int
	err = tx.QueryRow(ctx,
		`UPDATE access_revocation_jobs
		    SET attempts = attempts + 1, failure_class = $2, updated_at = NOW()
		  WHERE job_id = $1 AND status = 'pending'
		 RETURNING attempts`, string(job.JobID), failureClass).Scan(&attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return tx.Commit(ctx)
	}
	if err != nil {
		return fmt.Errorf("postgres: update failed access revocation: %w", err)
	}
	if attempts == 1 {
		if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(
			workforce.EventAccessRevocationDegraded, job.ActorUserID, "user_id", string(job.UserID),
			job.RequestID, "access_revocation.complete", applications.SecurityEventDenied,
			failureClass, map[string]string{
				"revocation_job_id": string(job.JobID),
				"reason":            string(job.Reason),
			})); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *WorkforceRepository) ListPendingAccessRevocations(ctx context.Context, limit int) ([]workforce.AccessRevocationJob, error) {
	if limit < 1 || limit > 100 {
		return nil, workforce.ErrInvalidInput
	}
	rows, err := r.pool.Query(ctx,
		`SELECT job_id, actor_user_id, user_id, reason, request_id, attempts, created_at
		   FROM access_revocation_jobs
		  WHERE status = 'pending'
		  ORDER BY created_at, job_id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list pending access revocations: %w", err)
	}
	defer rows.Close()
	result := make([]workforce.AccessRevocationJob, 0)
	for rows.Next() {
		job, err := scanAccessRevocationJob(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, job)
	}
	return result, rows.Err()
}

func (r *WorkforceRepository) RecordTargetSessionRevocation(ctx context.Context, actor, userID identity.UserID, sessionID, requestID, result, failureClass, providerFailureClass string) error {
	extra := map[string]string{"session_id": sessionID}
	if providerFailureClass != "" {
		extra["provider_failure_class"] = providerFailureClass
	}
	auditResult := applications.SecurityEventSuccess
	if result != "success" {
		auditResult = applications.SecurityEventDenied
	}
	return insertSecurityEvent(ctx, r.pool, workforceSecurityEvent(
		workforce.EventUserSessionRevoked, actor, "user_id", string(userID), requestID,
		"user.session.revoke", auditResult, failureClass, extra))
}

func (r *WorkforceRepository) RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, targetKey, targetID, eventType, operation, requestID string) error {
	return insertSecurityEvent(ctx, r.pool, workforceSecurityEvent(
		eventType, actor, targetKey, targetID, requestID, operation,
		applications.SecurityEventDenied, "authorization", nil))
}

func requireUserExistsTx(ctx context.Context, tx pgx.Tx, userID identity.UserID) error {
	var value string
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, string(userID)).Scan(&value); err != nil {
		return mapWorkforceMutationError(err, "lock user for session revocation")
	}
	return nil
}
