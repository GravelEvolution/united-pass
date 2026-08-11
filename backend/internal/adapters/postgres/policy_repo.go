//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: PostgreSQL policy version and publication job repository
//

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/policies"
)

type PolicyRepository struct {
	pool *pgxpool.Pool
}

func NewPolicyRepository(pool *pgxpool.Pool) *PolicyRepository {
	return &PolicyRepository{pool: pool}
}

func (r *PolicyRepository) List(ctx context.Context, query policies.ListQuery) (policies.Page, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	cursorTime, cursorID, err := decodePolicyCursor(query.Cursor)
	if err != nil {
		return policies.Page{}, policies.ErrValidation
	}
	rows, err := r.pool.Query(ctx, `
		SELECT p.policy_id, p.name, p.resource, p.current_version, p.status,
		       COALESCE(u.display_name, p.updated_by_user_id), p.updated_at
		  FROM authorization_policies p
		  LEFT JOIN users u ON u.id = p.updated_by_user_id
		 WHERE ($1 = '' OR p.name ILIKE '%' || $1 || '%' OR p.resource ILIKE '%' || $1 || '%' OR p.action ILIKE '%' || $1 || '%')
		   AND ($2 = '' OR p.status = $2)
		   AND ($3::timestamptz IS NULL OR (p.updated_at, p.policy_id) < ($3, $4))
		 ORDER BY p.updated_at DESC, p.policy_id DESC
		 LIMIT $5`, query.Query, string(query.Status), cursorTime, cursorID, limit+1)
	if err != nil {
		return policies.Page{}, fmt.Errorf("postgres: list policies: %w", err)
	}
	defer rows.Close()
	items := make([]policies.Summary, 0, limit+1)
	for rows.Next() {
		var item policies.Summary
		if err := rows.Scan(&item.PolicyID, &item.Name, &item.Resource, &item.Version, &item.Status, &item.UpdatedBy, &item.UpdatedAt); err != nil {
			return policies.Page{}, fmt.Errorf("postgres: scan policy: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return policies.Page{}, fmt.Errorf("postgres: iterate policies: %w", err)
	}
	page := policies.Page{Items: items}
	if len(items) > limit {
		page.HasMore = true
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodePolicyCursor(last.UpdatedAt, string(last.PolicyID))
	}
	return page, nil
}

func (r *PolicyRepository) Get(ctx context.Context, id policies.PolicyID) (policies.Detail, error) {
	var detail policies.Detail
	var principalJSON, conditionJSON []byte
	err := r.pool.QueryRow(ctx, `
		SELECT p.policy_id, v.name, v.description, v.resource, v.action, v.effect,
		       v.version, p.status, v.principals, v.conditions,
		       COALESCE(u.display_name, v.updated_by_user_id), p.updated_at
		  FROM authorization_policies p
		  JOIN authorization_policy_versions v
		    ON v.policy_id = p.policy_id AND v.version = p.current_version
		  LEFT JOIN users u ON u.id = v.updated_by_user_id
		 WHERE p.policy_id = $1`, string(id)).Scan(
		&detail.PolicyID, &detail.Name, &detail.Description, &detail.Resource, &detail.Action,
		&detail.Effect, &detail.Version, &detail.Status, &principalJSON, &conditionJSON,
		&detail.UpdatedBy, &detail.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return policies.Detail{}, policies.ErrNotFound
	}
	if err != nil {
		return policies.Detail{}, fmt.Errorf("postgres: get policy: %w", err)
	}
	if err := json.Unmarshal(principalJSON, &detail.Principals); err != nil {
		return policies.Detail{}, fmt.Errorf("postgres: decode policy principals: %w", err)
	}
	if err := json.Unmarshal(conditionJSON, &detail.Conditions); err != nil {
		return policies.Detail{}, fmt.Errorf("postgres: decode policy conditions: %w", err)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT v.version, v.status, COALESCE(u.display_name, v.updated_by_user_id),
		       COALESCE(v.published_at, v.created_at), v.change_summary
		  FROM authorization_policy_versions v
		  LEFT JOIN users u ON u.id = v.updated_by_user_id
		 WHERE v.policy_id = $1
		 ORDER BY v.version DESC, v.created_at DESC`, string(id))
	if err != nil {
		return policies.Detail{}, fmt.Errorf("postgres: list policy versions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var version policies.VersionSummary
		if err := rows.Scan(&version.Version, &version.Status, &version.UpdatedBy, &version.UpdatedAt, &version.ChangeSummary); err != nil {
			return policies.Detail{}, fmt.Errorf("postgres: scan policy version: %w", err)
		}
		detail.VersionHistory = append(detail.VersionHistory, version)
	}
	if detail.Principals == nil {
		detail.Principals = []policies.Clause{}
	}
	if detail.Conditions == nil {
		detail.Conditions = []policies.Clause{}
	}
	return detail, rows.Err()
}

func (r *PolicyRepository) Create(ctx context.Context, actor identity.UserID, input policies.DraftInput) (policies.PolicyID, int, error) {
	id := policies.PolicyID(newPolicyStoreID("pol_"))
	principals, conditions, err := encodeClauses(input)
	if err != nil {
		return "", 0, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("postgres: begin policy create: %w", err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		INSERT INTO authorization_policies
		(policy_id, name, description, resource, action, effect, current_version, status, updated_by_user_id)
		VALUES ($1,$2,$3,$4,$5,$6,1,'draft',$7)`, string(id), input.Name, input.Description, input.Resource, input.Action, string(input.Effect), string(actor))
	if err != nil {
		return "", 0, mapPolicyWriteError("create policy", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO authorization_policy_versions
		(policy_id, version, name, description, resource, action, effect, principals, conditions, status, change_summary, updated_by_user_id)
		VALUES ($1,1,$2,$3,$4,$5,$6,$7,$8,'draft','草稿创建',$9)`, string(id), input.Name, input.Description, input.Resource, input.Action, string(input.Effect), principals, conditions, string(actor))
	if err != nil {
		return "", 0, fmt.Errorf("postgres: create policy version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", 0, fmt.Errorf("postgres: commit policy create: %w", err)
	}
	return id, 1, nil
}

func (r *PolicyRepository) Update(ctx context.Context, actor identity.UserID, id policies.PolicyID, expectedVersion int, input policies.DraftInput) (int, error) {
	principals, conditions, err := encodeClauses(input)
	if err != nil {
		return 0, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("postgres: begin policy update: %w", err)
	}
	defer tx.Rollback(ctx)
	var current int
	if err := tx.QueryRow(ctx, `SELECT current_version FROM authorization_policies WHERE policy_id=$1 FOR UPDATE`, string(id)).Scan(&current); errors.Is(err, pgx.ErrNoRows) {
		return 0, policies.ErrNotFound
	} else if err != nil {
		return 0, fmt.Errorf("postgres: lock policy: %w", err)
	}
	if current != expectedVersion {
		return 0, policies.ErrConflict
	}
	next := current + 1
	_, err = tx.Exec(ctx, `
		UPDATE authorization_policies
		   SET name=$2, description=$3, resource=$4, action=$5, effect=$6,
		       current_version=$7, status='draft', updated_by_user_id=$8, updated_at=NOW()
		 WHERE policy_id=$1`, string(id), input.Name, input.Description, input.Resource, input.Action, string(input.Effect), next, string(actor))
	if err != nil {
		return 0, mapPolicyWriteError("update policy", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO authorization_policy_versions
		(policy_id, version, name, description, resource, action, effect, principals, conditions, status, change_summary, updated_by_user_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'draft','编辑草稿',$10)`, string(id), next, input.Name, input.Description, input.Resource, input.Action, string(input.Effect), principals, conditions, string(actor))
	if err != nil {
		return 0, fmt.Errorf("postgres: create policy draft version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("postgres: commit policy update: %w", err)
	}
	return next, nil
}

func (r *PolicyRepository) BeginPublication(ctx context.Context, actor identity.UserID, id policies.PolicyID, expectedVersion int, requestID string) (policies.PublicationJob, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return policies.PublicationJob{}, fmt.Errorf("postgres: begin policy publication: %w", err)
	}
	defer tx.Rollback(ctx)
	policy, err := scanPublicationPolicy(ctx, tx, id, expectedVersion, true)
	if err != nil {
		return policies.PublicationJob{}, err
	}
	job := policies.PublicationJob{JobID: policies.PublicationJobID(newPolicyStoreID("pub_")), Policy: policy, ActorID: actor, RequestID: requestID}
	_, err = tx.Exec(ctx, `
		INSERT INTO policy_publication_jobs(job_id, policy_id, version, actor_user_id, request_id)
		VALUES($1,$2,$3,$4,$5)`, string(job.JobID), string(id), expectedVersion, string(actor), requestID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return policies.PublicationJob{}, policies.ErrConflict
		}
		return policies.PublicationJob{}, fmt.Errorf("postgres: create policy publication job: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return policies.PublicationJob{}, fmt.Errorf("postgres: commit policy publication job: %w", err)
	}
	return job, nil
}

func (r *PolicyRepository) CompletePublication(ctx context.Context, jobID policies.PublicationJobID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin complete publication: %w", err)
	}
	defer tx.Rollback(ctx)
	var id policies.PolicyID
	var version int
	var actor identity.UserID
	var requestID, status string
	err = tx.QueryRow(ctx, `SELECT policy_id, version, actor_user_id, request_id, status FROM policy_publication_jobs WHERE job_id=$1 FOR UPDATE`, string(jobID)).Scan(&id, &version, &actor, &requestID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return policies.ErrPublicationJob
	}
	if err != nil {
		return fmt.Errorf("postgres: lock publication job: %w", err)
	}
	if status == "completed" {
		return tx.Commit(ctx)
	}
	if status == "failed" {
		return policies.ErrPublicationJob
	}
	result, err := tx.Exec(ctx, `
		UPDATE authorization_policies SET published_version=$2,
		       status=CASE WHEN current_version=$2 THEN 'published' ELSE status END,
		       updated_by_user_id=$3, updated_at=NOW()
		 WHERE policy_id=$1 AND current_version >= $2`, string(id), version, string(actor))
	if err != nil || result.RowsAffected() != 1 {
		return policies.ErrConflict
	}
	_, err = tx.Exec(ctx, `UPDATE authorization_policy_versions SET status='published', change_summary='发布版本 v' || version, published_at=NOW() WHERE policy_id=$1 AND version=$2`, string(id), version)
	if err != nil {
		return fmt.Errorf("postgres: publish policy version: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE policy_publication_jobs SET status='completed', completed_at=NOW(), updated_at=NOW() WHERE job_id=$1`, string(jobID))
	if err != nil {
		return fmt.Errorf("postgres: complete publication job: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "policy.published", ActorUserID: actor,
		RequestID: requestID, Operation: "policy.publish", Result: applications.SecurityEventSuccess,
		TargetKey: "policy_id", TargetID: string(id), Extra: map[string]string{"version": fmt.Sprint(version)}, OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PolicyRepository) FailPublication(ctx context.Context, jobID policies.PublicationJobID, failureClass string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var policyID policies.PolicyID
	var actor identity.UserID
	var requestID, status string
	var version int
	err = tx.QueryRow(ctx, `SELECT policy_id,version,actor_user_id,request_id,status FROM policy_publication_jobs WHERE job_id=$1 FOR UPDATE`, string(jobID)).Scan(&policyID, &version, &actor, &requestID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return policies.ErrPublicationJob
	}
	if err != nil {
		return fmt.Errorf("postgres: lock failed policy publication: %w", err)
	}
	if status == "completed" || status == "failed" {
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `UPDATE policy_publication_jobs SET status='failed', failure_class=$2, attempts=attempts+1, updated_at=NOW(), completed_at=NOW() WHERE job_id=$1`, string(jobID), failureClass); err != nil {
		return fmt.Errorf("postgres: fail policy publication: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, applications.SecurityEvent{
		EventID: applications.NewSecurityEventID(), EventType: "policy.publication_failed", ActorUserID: actor,
		RequestID: requestID, Operation: "policy.publish", Result: applications.SecurityEventDenied,
		FailureClass: failureClass, TargetKey: "policy_id", TargetID: string(policyID),
		Extra: map[string]string{"version": fmt.Sprint(version)}, OccurredAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PolicyRepository) ClaimPublicationJobs(ctx context.Context, limit int) ([]policies.PublicationJob, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT j.job_id, j.policy_id, j.version, j.actor_user_id, j.request_id
		  FROM policy_publication_jobs j
		 WHERE j.status='pending' OR (j.status='running' AND j.updated_at < NOW()-INTERVAL '5 minutes')
		 ORDER BY j.created_at, j.job_id
		 FOR UPDATE SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: claim policy publications: %w", err)
	}
	type claimed struct {
		jobID     policies.PublicationJobID
		id        policies.PolicyID
		version   int
		actor     identity.UserID
		requestID string
	}
	claimedJobs := make([]claimed, 0)
	for rows.Next() {
		var item claimed
		if err := rows.Scan(&item.jobID, &item.id, &item.version, &item.actor, &item.requestID); err != nil {
			rows.Close()
			return nil, err
		}
		claimedJobs = append(claimedJobs, item)
	}
	rows.Close()
	jobs := make([]policies.PublicationJob, 0, len(claimedJobs))
	for _, item := range claimedJobs {
		policy, err := scanPublicationPolicy(ctx, tx, item.id, item.version, false)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `UPDATE policy_publication_jobs SET status='running', attempts=attempts+1, updated_at=NOW() WHERE job_id=$1`, string(item.jobID))
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, policies.PublicationJob{JobID: item.jobID, Policy: policy, ActorID: item.actor, RequestID: item.requestID})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return jobs, nil
}

func (r *PolicyRepository) ListPublished(ctx context.Context, action, resource string) ([]policies.PublishedPolicy, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT p.policy_id, v.name, v.resource, v.action, v.effect, v.version, v.principals, v.conditions
		  FROM authorization_policies p
		  JOIN authorization_policy_versions v ON v.policy_id=p.policy_id AND v.version=p.published_version
		 WHERE v.action=$1 AND (v.resource=$2 OR v.resource='*') AND v.status='published'
		 ORDER BY p.policy_id`, action, resource)
	if err != nil {
		return nil, fmt.Errorf("postgres: list published policies: %w", err)
	}
	defer rows.Close()
	items := make([]policies.PublishedPolicy, 0)
	for rows.Next() {
		var item policies.PublishedPolicy
		var principalsJSON, conditionsJSON []byte
		if err := rows.Scan(&item.PolicyID, &item.Name, &item.Resource, &item.Action, &item.Effect, &item.Version, &principalsJSON, &conditionsJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(principalsJSON, &item.Principals); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(conditionsJSON, &item.Conditions); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *PolicyRepository) RecordAuthorizationDenied(ctx context.Context, actor identity.UserID, action, requestID string) error {
	return insertSecurityEvent(ctx, r.pool, applications.SecurityEvent{EventID: applications.NewSecurityEventID(), EventType: "authorization.denied", ActorUserID: actor, RequestID: requestID, Operation: action, Result: applications.SecurityEventDenied, TargetKey: "action", TargetID: action, OccurredAt: time.Now().UTC()})
}

func scanPublicationPolicy(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id policies.PolicyID, version int, lock bool) (policies.PublishedPolicy, error) {
	query := `SELECT p.policy_id,v.name,v.resource,v.action,v.effect,v.version,v.principals,v.conditions,p.current_version FROM authorization_policies p JOIN authorization_policy_versions v ON v.policy_id=p.policy_id AND v.version=$2 WHERE p.policy_id=$1`
	if lock {
		query += ` FOR UPDATE OF p`
	}
	var item policies.PublishedPolicy
	var principalJSON, conditionJSON []byte
	var current int
	err := q.QueryRow(ctx, query, string(id), version).Scan(&item.PolicyID, &item.Name, &item.Resource, &item.Action, &item.Effect, &item.Version, &principalJSON, &conditionJSON, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return item, policies.ErrNotFound
	}
	if err != nil {
		return item, fmt.Errorf("postgres: load publication policy: %w", err)
	}
	// A newly requested publication must target the exact working version.
	// Recovery jobs, however, already captured an immutable version before a
	// later draft could be saved and must remain replayable idempotently.
	if lock && current != version {
		return item, policies.ErrConflict
	}
	if err := json.Unmarshal(principalJSON, &item.Principals); err != nil {
		return item, err
	}
	if err := json.Unmarshal(conditionJSON, &item.Conditions); err != nil {
		return item, err
	}
	return item, nil
}

func encodeClauses(input policies.DraftInput) ([]byte, []byte, error) {
	principals, err := json.Marshal(input.Principals)
	if err != nil {
		return nil, nil, err
	}
	conditions, err := json.Marshal(input.Conditions)
	return principals, conditions, err
}

func mapPolicyWriteError(operation string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return policies.ErrDuplicateName
	}
	return fmt.Errorf("postgres: %s: %w", operation, err)
}

func newPolicyStoreID(prefix string) string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic(fmt.Sprintf("postgres: generate policy id: %v", err))
	}
	return prefix + hex.EncodeToString(value)
}

func encodePolicyCursor(timestamp time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(timestamp.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodePolicyCursor(cursor string) (*time.Time, string, error) {
	if cursor == "" {
		return nil, "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, "", err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return nil, "", errors.New("invalid cursor")
	}
	parsed, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return nil, "", err
	}
	return &parsed, parts[1], nil
}
