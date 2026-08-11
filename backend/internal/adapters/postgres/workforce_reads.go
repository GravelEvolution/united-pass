//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: PostgreSQL read models for Phase 5 identity and workforce management
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

func (r *WorkforceRepository) GetUserDetail(ctx context.Context, userID identity.UserID) (workforce.UserDetail, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT u.id, u.status, u.display_name, u.nickname, u.avatar_url,
		        u.email, u.email_verified, u.phone, u.phone_verified,
		        u.created_at, u.updated_at, u.version,
		        COALESCE((SELECT MAX(i.last_seen_at) FROM identity_links i WHERE i.user_id = u.id), u.created_at)
		   FROM users u WHERE u.id = $1`, string(userID))
	var detail workforce.UserDetail
	var id, status string
	if err := row.Scan(&id, &status, &detail.User.DisplayName, &detail.User.Nickname,
		&detail.User.AvatarURL, &detail.User.Email, &detail.User.EmailVerified,
		&detail.User.Phone, &detail.User.PhoneVerified, &detail.User.CreatedAt,
		&detail.User.UpdatedAt, &detail.User.Version, &detail.LastActiveAt); err != nil {
		return workforce.UserDetail{}, mapWorkforceReadError(err, "get user detail")
	}
	detail.User.ID = identity.UserID(id)
	detail.User.Status = identity.UserStatus(status)

	personas, err := r.listPersonas(ctx, userID)
	if err != nil {
		return workforce.UserDetail{}, err
	}
	detail.User.Personas = personas

	profile, err := r.GetEmployeeProfile(ctx, userID)
	if err == nil {
		detail.EmployeeProfile = &profile
	} else if !errors.Is(err, workforce.ErrNotFound) {
		return workforce.UserDetail{}, err
	}

	detail.LinkedIdentities, err = r.listLinkedIdentities(ctx, userID)
	if err != nil {
		return workforce.UserDetail{}, err
	}
	detail.AuthorizedApplications, err = r.listUserAuthorizedApplications(ctx, userID)
	if err != nil {
		return workforce.UserDetail{}, err
	}
	detail.RecentAuditEvents, err = r.listUserAuditEvents(ctx, userID, 20)
	if err != nil {
		return workforce.UserDetail{}, err
	}
	return detail, nil
}

func (r *WorkforceRepository) listPersonas(ctx context.Context, userID identity.UserID) ([]identity.Persona, error) {
	rows, err := r.pool.Query(ctx, `SELECT persona FROM user_personas WHERE user_id = $1 ORDER BY persona`, string(userID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list user personas: %w", err)
	}
	defer rows.Close()
	result := make([]identity.Persona, 0, 2)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("postgres: scan user persona: %w", err)
		}
		result = append(result, identity.Persona(value))
	}
	return result, rows.Err()
}

func (r *WorkforceRepository) GetEmployeeProfile(ctx context.Context, userID identity.UserID) (workforce.EmployeeProfile, error) {
	return getEmployeeProfile(ctx, r.pool, userID)
}

type employeeProfileQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func getEmployeeProfile(ctx context.Context, querier employeeProfileQuerier, userID identity.UserID) (workforce.EmployeeProfile, error) {
	row := querier.QueryRow(ctx,
		`SELECT ep.user_id, ep.employee_number, ep.department_id, d.name,
		        ep.title, ep.status, COALESCE(ep.supervisor_user_id, ''),
		        COALESCE(s.display_name, ''), ep.onboarded_at, ep.offboarded_at,
		        ep.version
		   FROM employee_profiles ep
		   JOIN departments d ON d.department_id = ep.department_id
		   LEFT JOIN users s ON s.id = ep.supervisor_user_id
		  WHERE ep.user_id = $1`, string(userID))
	return scanEmployeeProfile(row)
}

func scanEmployeeProfile(row pgx.Row) (workforce.EmployeeProfile, error) {
	var profile workforce.EmployeeProfile
	var userID, departmentID, status, supervisorID string
	if err := row.Scan(&userID, &profile.EmployeeNumber, &departmentID,
		&profile.DepartmentName, &profile.Title, &status, &supervisorID,
		&profile.SupervisorName, &profile.OnboardedAt, &profile.OffboardedAt,
		&profile.Version); err != nil {
		return workforce.EmployeeProfile{}, mapWorkforceReadError(err, "get employee profile")
	}
	profile.UserID = identity.UserID(userID)
	profile.DepartmentID = workforce.DepartmentID(departmentID)
	profile.Status = workforce.EmployeeStatus(status)
	profile.SupervisorUserID = identity.UserID(supervisorID)
	return profile, nil
}

func (r *WorkforceRepository) listLinkedIdentities(ctx context.Context, userID identity.UserID) ([]workforce.LinkedIdentity, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, provider, provider_subject, created_at
		   FROM identity_links WHERE user_id = $1 ORDER BY created_at, id`, string(userID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list linked identities: %w", err)
	}
	defer rows.Close()
	result := make([]workforce.LinkedIdentity, 0)
	for rows.Next() {
		var item workforce.LinkedIdentity
		if err := rows.Scan(&item.ProviderID, &item.Provider, &item.ExternalSubject, &item.LinkedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan linked identity: %w", err)
		}
		item.ProviderName = strings.ToUpper(item.Provider)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *WorkforceRepository) listUserAuthorizedApplications(ctx context.Context, userID identity.UserID) ([]workforce.AuthorizedApplication, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT a.name, g.granted_at, g.status,
		        COALESCE(array_agg(gs.scope ORDER BY gs.scope) FILTER (WHERE gs.scope IS NOT NULL), '{}')
		   FROM oauth_authorization_grants g
		   JOIN oauth_clients c ON c.client_id = g.client_id
		   JOIN oauth_applications a ON a.application_id = c.application_id
		   LEFT JOIN oauth_authorization_grant_scopes gs ON gs.grant_id = g.grant_id
		  WHERE g.user_id = $1
		  GROUP BY g.grant_id, a.name, g.granted_at, g.status
		  ORDER BY g.granted_at DESC, g.grant_id DESC`, string(userID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list user authorized applications: %w", err)
	}
	defer rows.Close()
	result := make([]workforce.AuthorizedApplication, 0)
	for rows.Next() {
		var item workforce.AuthorizedApplication
		if err := rows.Scan(&item.ApplicationName, &item.GrantedAt, &item.Status, &item.Scopes); err != nil {
			return nil, fmt.Errorf("postgres: scan user authorized application: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *WorkforceRepository) listUserAuditEvents(ctx context.Context, userID identity.UserID, limit int) ([]workforce.AuditEvent, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT e.event_id, e.event_type, e.actor_user_id,
		        COALESCE(a.display_name, ''), e.occurred_at, e.result,
		        e.request_id,
		        COALESCE(e.payload->>'user_id', e.payload->>'employee_user_id', e.payload->>'target_user_id', '')
		   FROM security_events e
		   LEFT JOIN users a ON a.id = e.actor_user_id
		  WHERE e.actor_user_id = $1
		     OR e.payload->>'user_id' = $1
		     OR e.payload->>'employee_user_id' = $1
		     OR e.payload->>'target_user_id' = $1
		  ORDER BY e.occurred_at DESC, e.event_id DESC
		  LIMIT $2`, string(userID), limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list user audit events: %w", err)
	}
	defer rows.Close()
	result := make([]workforce.AuditEvent, 0)
	for rows.Next() {
		var item workforce.AuditEvent
		var actorID string
		if err := rows.Scan(&item.EventID, &item.EventType, &actorID, &item.ActorName,
			&item.OccurredAt, &item.Result, &item.RequestID, &item.TargetID); err != nil {
			return nil, fmt.Errorf("postgres: scan user audit event: %w", err)
		}
		item.ActorID = identity.UserID(actorID)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *WorkforceRepository) ListDepartments(ctx context.Context, query string, limit int) ([]workforce.DepartmentSummary, error) {
	query = strings.TrimSpace(query)
	if utf8.RuneCountInString(query) > workforceSearchMaxRunes {
		return nil, workforce.ErrInvalidInput
	}
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 100 {
		return nil, workforce.ErrInvalidInput
	}
	rows, err := r.pool.Query(ctx,
		`SELECT d.department_id, d.name, COALESCE(p.name, ''),
		        COUNT(ep.user_id), COALESCE(o.display_name, ''), d.updated_at
		   FROM departments d
		   LEFT JOIN departments p ON p.department_id = d.parent_department_id
		   LEFT JOIN users o ON o.id = d.owner_user_id
		   LEFT JOIN employee_profiles ep ON ep.department_id = d.department_id
		  WHERE $1 = '' OR d.name ILIKE '%' || $1 || '%'
		     OR COALESCE(o.display_name, '') ILIKE '%' || $1 || '%'
		  GROUP BY d.department_id, d.name, p.name, o.display_name, d.updated_at
		  ORDER BY lower(d.name), d.department_id
		  LIMIT $2`, query, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list departments: %w", err)
	}
	defer rows.Close()
	result := make([]workforce.DepartmentSummary, 0)
	for rows.Next() {
		var item workforce.DepartmentSummary
		var departmentID string
		if err := rows.Scan(&departmentID, &item.Name, &item.ParentName,
			&item.MemberCount, &item.OwnerName, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan department summary: %w", err)
		}
		item.DepartmentID = workforce.DepartmentID(departmentID)
		result = append(result, item)
	}
	return result, rows.Err()
}

type departmentDetailQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (r *WorkforceRepository) GetDepartment(ctx context.Context, departmentID workforce.DepartmentID) (workforce.DepartmentDetail, error) {
	return getDepartment(ctx, r.pool, departmentID)
}

func getDepartment(ctx context.Context, querier departmentDetailQuerier, departmentID workforce.DepartmentID) (workforce.DepartmentDetail, error) {
	row := querier.QueryRow(ctx,
		`SELECT d.department_id, d.name, COALESCE(d.parent_department_id, ''),
		        COALESCE(p.name, ''), COALESCE(d.owner_user_id, ''),
		        COALESCE(o.display_name, ''),
		        (SELECT COUNT(*) FROM employee_profiles ep WHERE ep.department_id = d.department_id),
		        d.version, d.created_at, d.updated_at
		   FROM departments d
		   LEFT JOIN departments p ON p.department_id = d.parent_department_id
		   LEFT JOIN users o ON o.id = d.owner_user_id
		  WHERE d.department_id = $1`, string(departmentID))
	var detail workforce.DepartmentDetail
	var id, parentID, ownerID string
	if err := row.Scan(&id, &detail.Name, &parentID, &detail.ParentName,
		&ownerID, &detail.OwnerName, &detail.MemberCount, &detail.Version,
		&detail.CreatedAt, &detail.UpdatedAt); err != nil {
		return workforce.DepartmentDetail{}, mapWorkforceReadError(err, "get department")
	}
	detail.DepartmentID = workforce.DepartmentID(id)
	detail.ParentDepartmentID = workforce.DepartmentID(parentID)
	detail.OwnerUserID = identity.UserID(ownerID)

	children, err := querier.Query(ctx,
		`SELECT c.department_id, c.name,
		        (SELECT COUNT(*) FROM employee_profiles ep WHERE ep.department_id = c.department_id)
		   FROM departments c WHERE c.parent_department_id = $1
		  ORDER BY lower(c.name), c.department_id`, string(departmentID))
	if err != nil {
		return workforce.DepartmentDetail{}, fmt.Errorf("postgres: list child departments: %w", err)
	}
	detail.ChildDepartments = make([]workforce.DepartmentChild, 0)
	for children.Next() {
		var item workforce.DepartmentChild
		var childID string
		if err := children.Scan(&childID, &item.Name, &item.MemberCount); err != nil {
			children.Close()
			return workforce.DepartmentDetail{}, fmt.Errorf("postgres: scan child department: %w", err)
		}
		item.DepartmentID = workforce.DepartmentID(childID)
		detail.ChildDepartments = append(detail.ChildDepartments, item)
	}
	if err := children.Err(); err != nil {
		children.Close()
		return workforce.DepartmentDetail{}, fmt.Errorf("postgres: iterate child departments: %w", err)
	}
	children.Close()

	members, err := querier.Query(ctx,
		`SELECT u.id, u.display_name, ep.title, ep.employee_number
		   FROM employee_profiles ep JOIN users u ON u.id = ep.user_id
		  WHERE ep.department_id = $1
		  ORDER BY lower(u.display_name), u.id`, string(departmentID))
	if err != nil {
		return workforce.DepartmentDetail{}, fmt.Errorf("postgres: list department members: %w", err)
	}
	defer members.Close()
	detail.Members = make([]workforce.DepartmentMember, 0)
	for members.Next() {
		var item workforce.DepartmentMember
		var userID string
		if err := members.Scan(&userID, &item.DisplayName, &item.Title, &item.EmployeeNumber); err != nil {
			return workforce.DepartmentDetail{}, fmt.Errorf("postgres: scan department member: %w", err)
		}
		item.UserID = identity.UserID(userID)
		detail.Members = append(detail.Members, item)
	}
	if err := members.Err(); err != nil {
		return workforce.DepartmentDetail{}, fmt.Errorf("postgres: iterate department members: %w", err)
	}
	return detail, nil
}

func mapWorkforceReadError(err error, operation string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return workforce.ErrNotFound
	}
	return fmt.Errorf("postgres: %s: %w", operation, err)
}
