//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: PostgreSQL-authoritative principal attributes for Cerbos
//

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/permissions"
)

type PermissionContextRepository struct {
	pool *pgxpool.Pool
}

func NewPermissionContextRepository(pool *pgxpool.Pool) *PermissionContextRepository {
	return &PermissionContextRepository{pool: pool}
}

func (r *PermissionContextRepository) GetPermissionPrincipal(ctx context.Context, userID identity.UserID) (permissions.PrincipalContext, error) {
	var status, departmentID, departmentName, employeeStatus string
	var personas []string
	var challengeVersion int64
	var activeSystemSuper bool
	err := r.pool.QueryRow(ctx, `
		SELECT u.status,
		       COALESCE(ARRAY(SELECT DISTINCT up.persona FROM user_personas up WHERE up.user_id=u.id ORDER BY up.persona), '{}'),
		       COALESCE(ep.department_id, ''), COALESCE(d.name, ''), COALESCE(ep.status, ''),
		       COALESCE(ac.credential_version, 0),
		       EXISTS (
		           SELECT 1 FROM admin_role_bindings arb
		            WHERE arb.user_id=u.id AND arb.role IN ('super_admin','top_admin')
		              AND arb.scope_kind='system' AND arb.scope_key='system'
		              AND arb.enabled=TRUE AND arb.disabled_at IS NULL
		       )
		  FROM users u
		  LEFT JOIN employee_profiles ep ON ep.user_id=u.id
		  LEFT JOIN departments d ON d.department_id=ep.department_id
		  LEFT JOIN admin_challenges ac ON ac.user_id=u.id AND ac.status='active'
		 WHERE u.id=$1
		`, string(userID)).Scan(&status, &personas, &departmentID, &departmentName, &employeeStatus, &challengeVersion, &activeSystemSuper)
	if errors.Is(err, pgx.ErrNoRows) {
		return permissions.PrincipalContext{}, identity.ErrUserNotFound
	}
	if err != nil {
		return permissions.PrincipalContext{}, fmt.Errorf("postgres: load permission principal: %w", err)
	}
	roles := permissionContextRoles(personas, status, employeeStatus, activeSystemSuper)
	attributes := map[string]any{
		"userId":         string(userID),
		"accountStatus":  status,
		"personas":       strings.Join(personas, ","),
		"departmentId":   departmentID,
		"department":     departmentName,
		"employeeStatus": employeeStatus,
		"eventRole":      permissionContextSystemRole(status, employeeStatus, activeSystemSuper),
	}
	return permissions.PrincipalContext{Roles: roles, Attributes: attributes, ChallengeVersion: challengeVersion}, nil
}

func permissionContextSystemRole(accountStatus, employeeStatus string, activeSystemSuper bool) string {
	if activeSystemSuper && accountStatus == string(identity.UserStatusActive) && employeeStatus != "offboarding" {
		return "super_admin"
	}
	return ""
}

func permissionContextRoles(personas []string, accountStatus, employeeStatus string, activeSystemSuper bool) []string {
	roles := append([]string{"authenticated"}, personas...)
	activePrincipal := accountStatus == string(identity.UserStatusActive) && employeeStatus != "offboarding"
	return permissions.GlobalPrincipalRoles(roles, activeSystemSuper && activePrincipal)
}
