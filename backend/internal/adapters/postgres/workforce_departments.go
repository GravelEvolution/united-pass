//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Transactional Phase 5 department hierarchy mutations
//

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

func (r *WorkforceRepository) CreateDepartment(ctx context.Context, actor identity.UserID, input workforce.DepartmentInput, requestID string) (workforce.DepartmentDetail, error) {
	tx, err := r.beginDepartmentMutation(ctx)
	if err != nil {
		return workforce.DepartmentDetail{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if input.ParentDepartmentID != "" {
		if err := requireDepartmentTx(ctx, tx, input.ParentDepartmentID); err != nil {
			return workforce.DepartmentDetail{}, err
		}
	}
	if err := requireDepartmentOwnerTx(ctx, tx, input.OwnerUserID); err != nil {
		return workforce.DepartmentDetail{}, err
	}
	id := workforce.NewDepartmentID()
	if _, err := tx.Exec(ctx,
		`INSERT INTO departments
		     (department_id, name, parent_department_id, owner_user_id,
		      version, created_at, updated_at)
		 VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), 1, NOW(), NOW())`,
		string(id), input.Name, string(input.ParentDepartmentID), string(input.OwnerUserID)); err != nil {
		if isUniqueViolation(err) {
			return workforce.DepartmentDetail{}, workforce.ErrConflict
		}
		return workforce.DepartmentDetail{}, fmt.Errorf("postgres: create department: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(
		workforce.EventDepartmentCreated, actor, "department_id", string(id),
		requestID, "department.create", applications.SecurityEventSuccess, "", map[string]string{
			"parent_department_id": string(input.ParentDepartmentID),
		})); err != nil {
		return workforce.DepartmentDetail{}, err
	}
	detail, err := getDepartment(ctx, tx, id)
	if err != nil {
		return workforce.DepartmentDetail{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return workforce.DepartmentDetail{}, fmt.Errorf("postgres: commit department create: %w", err)
	}
	return detail, nil
}

func (r *WorkforceRepository) UpdateDepartment(ctx context.Context, actor identity.UserID, departmentID workforce.DepartmentID, patch workforce.DepartmentPatch, requestID string) (workforce.DepartmentDetail, error) {
	tx, err := r.beginDepartmentMutation(ctx)
	if err != nil {
		return workforce.DepartmentDetail{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var name, parentID, ownerID string
	if err := tx.QueryRow(ctx,
		`SELECT name, COALESCE(parent_department_id, ''), COALESCE(owner_user_id, '')
		   FROM departments WHERE department_id = $1 FOR UPDATE`, string(departmentID)).Scan(&name, &parentID, &ownerID); err != nil {
		return workforce.DepartmentDetail{}, mapWorkforceMutationError(err, "lock department for update")
	}
	if patch.Name != nil {
		name = *patch.Name
	}
	if patch.ParentDepartmentID != nil {
		parentID = string(*patch.ParentDepartmentID)
	}
	if patch.OwnerUserID != nil {
		ownerID = string(*patch.OwnerUserID)
	}
	if parentID == string(departmentID) {
		return workforce.DepartmentDetail{}, workforce.ErrDepartmentCycle
	}
	if parentID != "" {
		if err := requireDepartmentTx(ctx, tx, workforce.DepartmentID(parentID)); err != nil {
			return workforce.DepartmentDetail{}, err
		}
		cycle, err := departmentAncestorContains(ctx, tx, workforce.DepartmentID(parentID), departmentID)
		if err != nil {
			return workforce.DepartmentDetail{}, err
		}
		if cycle {
			return workforce.DepartmentDetail{}, workforce.ErrDepartmentCycle
		}
	}
	if err := requireDepartmentOwnerTx(ctx, tx, identity.UserID(ownerID)); err != nil {
		return workforce.DepartmentDetail{}, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE departments
		    SET name = $2, parent_department_id = NULLIF($3, ''),
		        owner_user_id = NULLIF($4, ''), updated_at = NOW(),
		        version = version + 1
		  WHERE department_id = $1`, string(departmentID), name, parentID, ownerID); err != nil {
		if isUniqueViolation(err) {
			return workforce.DepartmentDetail{}, workforce.ErrConflict
		}
		return workforce.DepartmentDetail{}, fmt.Errorf("postgres: update department: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(
		workforce.EventDepartmentUpdated, actor, "department_id", string(departmentID),
		requestID, "department.update", applications.SecurityEventSuccess, "", map[string]string{
			"parent_department_id": parentID,
		})); err != nil {
		return workforce.DepartmentDetail{}, err
	}
	detail, err := getDepartment(ctx, tx, departmentID)
	if err != nil {
		return workforce.DepartmentDetail{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return workforce.DepartmentDetail{}, fmt.Errorf("postgres: commit department update: %w", err)
	}
	return detail, nil
}

func (r *WorkforceRepository) DeleteDepartment(ctx context.Context, actor identity.UserID, departmentID workforce.DepartmentID, requestID string) error {
	tx, err := r.beginDepartmentMutation(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var name string
	if err := tx.QueryRow(ctx,
		`SELECT name FROM departments WHERE department_id = $1 FOR UPDATE`, string(departmentID)).Scan(&name); err != nil {
		return mapWorkforceMutationError(err, "lock department for delete")
	}
	var childCount, memberCount int
	if err := tx.QueryRow(ctx,
		`SELECT
		   (SELECT COUNT(*) FROM departments WHERE parent_department_id = $1),
		   (SELECT COUNT(*) FROM employee_profiles WHERE department_id = $1)`,
		string(departmentID)).Scan(&childCount, &memberCount); err != nil {
		return fmt.Errorf("postgres: inspect department emptiness: %w", err)
	}
	if childCount != 0 || memberCount != 0 {
		return workforce.ErrDepartmentNotEmpty
	}
	if _, err := tx.Exec(ctx, `DELETE FROM departments WHERE department_id = $1`, string(departmentID)); err != nil {
		return fmt.Errorf("postgres: delete department: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(
		workforce.EventDepartmentDeleted, actor, "department_id", string(departmentID),
		requestID, "department.delete", applications.SecurityEventSuccess, "", map[string]string{
			"department_name": name,
		})); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit department delete: %w", err)
	}
	return nil
}

func (r *WorkforceRepository) beginDepartmentMutation(ctx context.Context) (pgx.Tx, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("postgres: begin department transaction: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, departmentHierarchyLock); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("postgres: lock department hierarchy: %w", err)
	}
	return tx, nil
}

func departmentAncestorContains(ctx context.Context, tx pgx.Tx, parent, target workforce.DepartmentID) (bool, error) {
	var found bool
	err := tx.QueryRow(ctx,
		`WITH RECURSIVE ancestors AS (
		   SELECT department_id, parent_department_id
		     FROM departments WHERE department_id = $1
		   UNION ALL
		   SELECT d.department_id, d.parent_department_id
		     FROM departments d JOIN ancestors a ON d.department_id = a.parent_department_id
		 )
		 SELECT EXISTS (SELECT 1 FROM ancestors WHERE department_id = $2)`,
		string(parent), string(target)).Scan(&found)
	if err != nil {
		return false, fmt.Errorf("postgres: inspect department ancestors: %w", err)
	}
	return found, nil
}

func requireDepartmentOwnerTx(ctx context.Context, tx pgx.Tx, ownerID identity.UserID) error {
	if ownerID == "" {
		return nil
	}
	var status string
	err := tx.QueryRow(ctx,
		`SELECT ep.status
		   FROM employee_profiles ep JOIN users u ON u.id = ep.user_id
		  WHERE ep.user_id = $1 AND u.status = 'active'
		  FOR UPDATE`, string(ownerID)).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || status != string(workforce.EmployeeStatusActive) {
		return workforce.ErrSupervisorNotActive
	}
	if err != nil {
		return fmt.Errorf("postgres: validate department owner: %w", err)
	}
	return nil
}
