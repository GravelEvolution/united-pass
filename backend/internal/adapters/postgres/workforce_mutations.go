//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Transactional Phase 5 identity and workforce mutations
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

func (r *WorkforceRepository) ChangeUserStatus(ctx context.Context, mutation workforce.UserStatusMutation) (*workforce.AccessRevocationJob, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("postgres: begin user status transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var current string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 FOR UPDATE`, string(mutation.TargetUserID)).Scan(&current); err != nil {
		return nil, mapWorkforceMutationError(err, "lock user for status change")
	}
	if mutation.Status == identity.UserStatusActive {
		var pending bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM access_revocation_jobs
			  WHERE user_id = $1 AND reason = 'user_disabled' AND status = 'pending')`,
			string(mutation.TargetUserID)).Scan(&pending); err != nil {
			return nil, fmt.Errorf("postgres: check pending user cleanup: %w", err)
		}
		if pending {
			return nil, workforce.ErrConflict
		}
	}
	if current != string(mutation.Status) {
		if _, err := tx.Exec(ctx,
			`UPDATE users SET status = $2, updated_at = NOW(), version = version + 1 WHERE id = $1`,
			string(mutation.TargetUserID), string(mutation.Status)); err != nil {
			return nil, fmt.Errorf("postgres: update user status: %w", err)
		}
	}
	clearedOwners, clearedSupervisors := 0, 0
	if mutation.Status == identity.UserStatusDisabled {
		clearedOwners, clearedSupervisors, err = clearWorkforceAssignmentsTx(ctx, tx, mutation.TargetUserID)
		if err != nil {
			return nil, err
		}
	}

	eventType := workforce.EventUserEnabled
	operation := "user.enable"
	if mutation.Status == identity.UserStatusDisabled {
		eventType = workforce.EventUserDisabled
		operation = "user.disable"
	}
	if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(eventType,
		mutation.ActorUserID, "user_id", string(mutation.TargetUserID),
		mutation.RequestID, operation, applications.SecurityEventSuccess, "", map[string]string{
			"from_status":               current,
			"to_status":                 string(mutation.Status),
			"cleared_department_owners": strconv.Itoa(clearedOwners),
			"cleared_supervisors":       strconv.Itoa(clearedSupervisors),
		})); err != nil {
		return nil, err
	}

	var job *workforce.AccessRevocationJob
	if mutation.Status == identity.UserStatusDisabled && mutation.RevokeSessions {
		created, err := enqueueAccessRevocationTx(ctx, tx, mutation.ActorUserID,
			mutation.TargetUserID, workforce.RevocationUserDisabled, mutation.RequestID)
		if err != nil {
			return nil, err
		}
		job = &created
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("postgres: commit user status transaction: %w", err)
	}
	return job, nil
}

func (r *WorkforceRepository) LinkEmployee(ctx context.Context, actor identity.UserID, input workforce.EmployeeProfileInput, requestID string) (workforce.EmployeeProfile, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return workforce.EmployeeProfile{}, fmt.Errorf("postgres: begin employee link transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireActiveUserTx(ctx, tx, input.UserID); err != nil {
		return workforce.EmployeeProfile{}, err
	}
	if err := requireDepartmentTx(ctx, tx, input.DepartmentID); err != nil {
		return workforce.EmployeeProfile{}, err
	}
	if err := requireActiveSupervisorTx(ctx, tx, input.SupervisorUserID); err != nil {
		return workforce.EmployeeProfile{}, err
	}

	var employeeNumber string
	err = tx.QueryRow(ctx,
		`INSERT INTO employee_profiles
		     (user_id, employee_number, department_id, title, supervisor_user_id,
		      status, onboarded_at, created_at, updated_at)
		 VALUES ($1, 'UP-' || lpad(nextval('employee_number_seq')::text, 6, '0'),
		         $2, $3, NULLIF($4, ''), 'active', NOW(), NOW(), NOW())
		 RETURNING employee_number`,
		string(input.UserID), string(input.DepartmentID), input.Title,
		string(input.SupervisorUserID)).Scan(&employeeNumber)
	if err != nil {
		if isUniqueViolation(err) {
			return workforce.EmployeeProfile{}, workforce.ErrConflict
		}
		return workforce.EmployeeProfile{}, fmt.Errorf("postgres: link employee profile: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO user_personas (user_id, persona, created_at)
		 VALUES ($1, 'employee', NOW()) ON CONFLICT DO NOTHING`, string(input.UserID)); err != nil {
		return workforce.EmployeeProfile{}, fmt.Errorf("postgres: add employee persona: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(
		workforce.EventEmployeeLinked, actor, "employee_user_id", string(input.UserID),
		requestID, "employee.link", applications.SecurityEventSuccess, "", map[string]string{
			"department_id":   string(input.DepartmentID),
			"employee_number": employeeNumber,
		})); err != nil {
		return workforce.EmployeeProfile{}, err
	}
	profile, err := getEmployeeProfile(ctx, tx, input.UserID)
	if err != nil {
		return workforce.EmployeeProfile{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return workforce.EmployeeProfile{}, fmt.Errorf("postgres: commit employee link: %w", err)
	}
	return profile, nil
}

func (r *WorkforceRepository) UpdateEmployee(ctx context.Context, actor identity.UserID, input workforce.EmployeeProfileInput, requestID string) (workforce.EmployeeProfile, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return workforce.EmployeeProfile{}, fmt.Errorf("postgres: begin employee update transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status string
	if err := tx.QueryRow(ctx,
		`SELECT status FROM employee_profiles WHERE user_id = $1 FOR UPDATE`, string(input.UserID)).Scan(&status); err != nil {
		return workforce.EmployeeProfile{}, mapWorkforceMutationError(err, "lock employee profile")
	}
	if status != string(workforce.EmployeeStatusActive) {
		return workforce.EmployeeProfile{}, workforce.ErrEmployeeNotActive
	}
	if err := requireDepartmentTx(ctx, tx, input.DepartmentID); err != nil {
		return workforce.EmployeeProfile{}, err
	}
	if err := requireActiveSupervisorTx(ctx, tx, input.SupervisorUserID); err != nil {
		return workforce.EmployeeProfile{}, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE employee_profiles
		    SET department_id = $2, title = $3, supervisor_user_id = NULLIF($4, ''),
		        updated_at = NOW(), version = version + 1
		  WHERE user_id = $1`, string(input.UserID), string(input.DepartmentID),
		input.Title, string(input.SupervisorUserID)); err != nil {
		return workforce.EmployeeProfile{}, fmt.Errorf("postgres: update employee profile: %w", err)
	}
	if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(
		workforce.EventEmployeeUpdated, actor, "employee_user_id", string(input.UserID),
		requestID, "employee.update", applications.SecurityEventSuccess, "", map[string]string{
			"department_id": string(input.DepartmentID),
		})); err != nil {
		return workforce.EmployeeProfile{}, err
	}
	profile, err := getEmployeeProfile(ctx, tx, input.UserID)
	if err != nil {
		return workforce.EmployeeProfile{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return workforce.EmployeeProfile{}, fmt.Errorf("postgres: commit employee update: %w", err)
	}
	return profile, nil
}

func (r *WorkforceRepository) OffboardEmployee(ctx context.Context, actor, userID identity.UserID, requestID string) (workforce.EmployeeProfile, workforce.AccessRevocationJob, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return workforce.EmployeeProfile{}, workforce.AccessRevocationJob{}, fmt.Errorf("postgres: begin offboarding transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status string
	if err := tx.QueryRow(ctx,
		`SELECT status FROM employee_profiles WHERE user_id = $1 FOR UPDATE`, string(userID)).Scan(&status); err != nil {
		return workforce.EmployeeProfile{}, workforce.AccessRevocationJob{}, mapWorkforceMutationError(err, "lock employee for offboarding")
	}
	if status == string(workforce.EmployeeStatusActive) {
		if _, err := tx.Exec(ctx,
			`UPDATE employee_profiles
			    SET status = 'offboarding', offboarded_at = NOW(),
			        updated_at = NOW(), version = version + 1
			  WHERE user_id = $1`, string(userID)); err != nil {
			return workforce.EmployeeProfile{}, workforce.AccessRevocationJob{}, fmt.Errorf("postgres: offboard employee: %w", err)
		}
		clearedOwners, clearedSupervisors, err := clearWorkforceAssignmentsTx(ctx, tx, userID)
		if err != nil {
			return workforce.EmployeeProfile{}, workforce.AccessRevocationJob{}, err
		}
		if err := insertSecurityEvent(ctx, tx, workforceSecurityEvent(
			workforce.EventEmployeeOffboarded, actor, "employee_user_id", string(userID),
			requestID, "employee.offboard", applications.SecurityEventSuccess, "", map[string]string{
				"from_status":               string(workforce.EmployeeStatusActive),
				"to_status":                 string(workforce.EmployeeStatusOffboarding),
				"cleared_department_owners": strconv.Itoa(clearedOwners),
				"cleared_supervisors":       strconv.Itoa(clearedSupervisors),
			})); err != nil {
			return workforce.EmployeeProfile{}, workforce.AccessRevocationJob{}, err
		}
	} else if status != string(workforce.EmployeeStatusOffboarding) {
		return workforce.EmployeeProfile{}, workforce.AccessRevocationJob{}, workforce.ErrEmployeeNotActive
	}
	job, err := enqueueAccessRevocationTx(ctx, tx, actor, userID,
		workforce.RevocationEmployeeOffboarded, requestID)
	if err != nil {
		return workforce.EmployeeProfile{}, workforce.AccessRevocationJob{}, err
	}
	profile, err := getEmployeeProfile(ctx, tx, userID)
	if err != nil {
		return workforce.EmployeeProfile{}, workforce.AccessRevocationJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return workforce.EmployeeProfile{}, workforce.AccessRevocationJob{}, fmt.Errorf("postgres: commit offboarding: %w", err)
	}
	return profile, job, nil
}

// clearWorkforceAssignmentsTx preserves the invariant that every department
// owner and supervisor reference resolves to an active employee. User disable
// and employee offboarding call it in the same transaction as their durable
// state transition; no transient invalid assignment can be committed.
func clearWorkforceAssignmentsTx(ctx context.Context, tx pgx.Tx, userID identity.UserID) (int, int, error) {
	ownerResult, err := tx.Exec(ctx,
		`UPDATE departments
		    SET owner_user_id = NULL, updated_at = NOW(), version = version + 1
		  WHERE owner_user_id = $1`, string(userID))
	if err != nil {
		return 0, 0, fmt.Errorf("postgres: clear disabled workforce owner assignments: %w", err)
	}
	supervisorResult, err := tx.Exec(ctx,
		`UPDATE employee_profiles
		    SET supervisor_user_id = NULL, updated_at = NOW(), version = version + 1
		  WHERE supervisor_user_id = $1`, string(userID))
	if err != nil {
		return 0, 0, fmt.Errorf("postgres: clear disabled workforce supervisor assignments: %w", err)
	}
	return int(ownerResult.RowsAffected()), int(supervisorResult.RowsAffected()), nil
}

func requireActiveUserTx(ctx context.Context, tx pgx.Tx, userID identity.UserID) error {
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 FOR UPDATE`, string(userID)).Scan(&status); err != nil {
		return mapWorkforceMutationError(err, "lock active user")
	}
	if status != string(identity.UserStatusActive) {
		return workforce.ErrUserNotActive
	}
	return nil
}

func requireDepartmentTx(ctx context.Context, tx pgx.Tx, departmentID workforce.DepartmentID) error {
	var value string
	if err := tx.QueryRow(ctx,
		`SELECT department_id FROM departments WHERE department_id = $1 FOR UPDATE`,
		string(departmentID)).Scan(&value); err != nil {
		return mapWorkforceMutationError(err, "lock department")
	}
	return nil
}

func requireActiveSupervisorTx(ctx context.Context, tx pgx.Tx, userID identity.UserID) error {
	if userID == "" {
		return nil
	}
	var status string
	err := tx.QueryRow(ctx,
		`SELECT ep.status FROM employee_profiles ep
		   JOIN users u ON u.id = ep.user_id
		  WHERE ep.user_id = $1 AND u.status = 'active'
		  FOR UPDATE`, string(userID)).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || status != string(workforce.EmployeeStatusActive) {
		return workforce.ErrSupervisorNotActive
	}
	if err != nil {
		return fmt.Errorf("postgres: check active supervisor: %w", err)
	}
	return nil
}

func mapWorkforceMutationError(err error, operation string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return workforce.ErrNotFound
	}
	return fmt.Errorf("postgres: %s: %w", operation, err)
}

func workforceSecurityEvent(eventType string, actor identity.UserID, targetKey, targetID,
	requestID, operation string, result applications.SecurityEventResult,
	failureClass string, extra map[string]string,
) applications.SecurityEvent {
	return applications.SecurityEvent{
		EventID:      applications.NewSecurityEventID(),
		EventType:    eventType,
		ActorUserID:  actor,
		RequestID:    requestID,
		Operation:    operation,
		Result:       result,
		FailureClass: failureClass,
		TargetKey:    targetKey,
		TargetID:     targetID,
		Extra:        extra,
		OccurredAt:   time.Now().UTC(),
	}
}
