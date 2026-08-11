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
	err := r.pool.QueryRow(ctx, `
		SELECT u.status,
		       COALESCE(array_agg(DISTINCT up.persona) FILTER (WHERE up.persona IS NOT NULL), '{}'),
		       COALESCE(ep.department_id, ''), COALESCE(d.name, ''), COALESCE(ep.status, '')
		  FROM users u
		  LEFT JOIN user_personas up ON up.user_id=u.id
		  LEFT JOIN employee_profiles ep ON ep.user_id=u.id
		  LEFT JOIN departments d ON d.department_id=ep.department_id
		 WHERE u.id=$1
		 GROUP BY u.id, ep.department_id, d.name, ep.status`, string(userID)).Scan(&status, &personas, &departmentID, &departmentName, &employeeStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return permissions.PrincipalContext{}, identity.ErrUserNotFound
	}
	if err != nil {
		return permissions.PrincipalContext{}, fmt.Errorf("postgres: load permission principal: %w", err)
	}
	roles := []string{"authenticated"}
	for _, persona := range personas {
		roles = append(roles, persona)
	}
	attributes := map[string]any{
		"userId":         string(userID),
		"accountStatus":  status,
		"personas":       strings.Join(personas, ","),
		"departmentId":   departmentID,
		"department":     departmentName,
		"employeeStatus": employeeStatus,
	}
	return permissions.PrincipalContext{Roles: roles, Attributes: attributes}, nil
}
