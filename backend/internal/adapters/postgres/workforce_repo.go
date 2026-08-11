//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: PostgreSQL persistence for Phase 5 identity and workforce management
//

package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/identity"
	"github.com/GravelEvolution/united-pass/backend/internal/workforce"
)

const departmentHierarchyLock = "united-pass/department-hierarchy/v1"
const workforceSearchMaxRunes = 200

type WorkforceRepository struct {
	pool   *pgxpool.Pool
	signer *workforceCursorSigner
}

func NewWorkforceRepository(pool *pgxpool.Pool, sessionKeyB64 string) (*WorkforceRepository, error) {
	signer, err := newWorkforceCursorSigner(sessionKeyB64)
	if err != nil {
		return nil, err
	}
	return &WorkforceRepository{pool: pool, signer: signer}, nil
}

func normalizePage(limit int, sort string, allowed map[string]struct{}) (int, string, error) {
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 100 {
		return 0, "", workforce.ErrInvalidInput
	}
	if sort == "" {
		sort = "-updatedAt"
	}
	if _, ok := allowed[sort]; !ok {
		return 0, "", workforce.ErrInvalidInput
	}
	return limit, sort, nil
}

var workforceDirectorySorts = map[string]struct{}{
	"updatedAt": {}, "-updatedAt": {}, "displayName": {}, "-displayName": {},
}

func (r *WorkforceRepository) ListUsers(ctx context.Context, query workforce.UserListQuery) (workforce.CursorPage[workforce.UserSummary], error) {
	limit, sortKey, err := normalizePage(query.Limit, query.Sort, workforceDirectorySorts)
	if err != nil {
		return workforce.CursorPage[workforce.UserSummary]{}, err
	}
	query.Query = strings.TrimSpace(query.Query)
	if utf8.RuneCountInString(query.Query) > workforceSearchMaxRunes {
		return workforce.CursorPage[workforce.UserSummary]{}, workforce.ErrInvalidInput
	}
	if query.Status != "" && query.Status != "active" && query.Status != "pending" && query.Status != "disabled" {
		return workforce.CursorPage[workforce.UserSummary]{}, workforce.ErrInvalidInput
	}

	args := []any{query.Query, query.Status}
	where := []string{
		`($1 = '' OR u.display_name ILIKE '%' || $1 || '%' OR u.email ILIKE '%' || $1 || '%' OR u.id ILIKE '%' || $1 || '%')`,
		`($2 = '' OR u.status = $2)`,
	}
	state := workforceCursor{Kind: "users", Sort: sortKey, Query: query.Query, Status: query.Status}
	if query.Cursor != "" {
		state, err = r.signer.decode(query.Cursor)
		if err != nil || state.Kind != "users" || state.Sort != sortKey || state.Query != query.Query || state.Status != query.Status || state.ID == "" {
			return workforce.CursorPage[workforce.UserSummary]{}, workforce.ErrInvalidCursor
		}
		args = append(args, state.Value, state.ID)
		where = append(where, directoryBoundary(sortKey, "u.updated_at", "u.display_name", len(args)-1))
	}
	args = append(args, limit+1)
	order := directoryOrder(sortKey, "u.updated_at", "u.display_name", "u.id")

	sql := `SELECT u.id, u.status, u.display_name, u.email,
	       CASE
	         WHEN EXISTS (SELECT 1 FROM user_personas p WHERE p.user_id = u.id AND p.persona = 'consumer')
	          AND EXISTS (SELECT 1 FROM user_personas p WHERE p.user_id = u.id AND p.persona = 'employee') THEN '外部用户 · 员工'
	         WHEN EXISTS (SELECT 1 FROM user_personas p WHERE p.user_id = u.id AND p.persona = 'employee') THEN '员工'
	         ELSE '外部用户'
	       END,
	       COALESCE((SELECT MAX(i.last_seen_at) FROM identity_links i WHERE i.user_id = u.id), u.created_at),
	       u.updated_at
	  FROM users u
	 WHERE ` + strings.Join(where, " AND ") + `
	 ORDER BY ` + order + ` LIMIT $` + strconv.Itoa(len(args))

	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return workforce.CursorPage[workforce.UserSummary]{}, fmt.Errorf("postgres: list users: %w", err)
	}
	defer rows.Close()

	items := make([]workforce.UserSummary, 0, limit+1)
	updated := make([]time.Time, 0, limit+1)
	for rows.Next() {
		var item workforce.UserSummary
		var id, status string
		var updatedAt time.Time
		if err := rows.Scan(&id, &status, &item.DisplayName, &item.Email, &item.PersonaLabel, &item.LastActiveAt, &updatedAt); err != nil {
			return workforce.CursorPage[workforce.UserSummary]{}, fmt.Errorf("postgres: scan user list: %w", err)
		}
		item.UserID = identity.UserID(id)
		item.Status = identity.UserStatus(status)
		items = append(items, item)
		updated = append(updated, updatedAt)
	}
	if err := rows.Err(); err != nil {
		return workforce.CursorPage[workforce.UserSummary]{}, fmt.Errorf("postgres: iterate users: %w", err)
	}

	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
		updated = updated[:limit]
	}
	next := ""
	if hasMore && len(items) > 0 {
		last := items[len(items)-1]
		value := updated[len(updated)-1].UTC().Format(time.RFC3339Nano)
		if sortKey == "displayName" || sortKey == "-displayName" {
			value = last.DisplayName
		}
		next, err = r.signer.encode(workforceCursor{Kind: "users", Sort: sortKey, Query: query.Query, Status: query.Status, Value: value, ID: string(last.UserID)})
		if err != nil {
			return workforce.CursorPage[workforce.UserSummary]{}, err
		}
	}
	return workforce.CursorPage[workforce.UserSummary]{Items: items, NextCursor: next, HasMore: hasMore}, nil
}

func (r *WorkforceRepository) ListEmployees(ctx context.Context, query workforce.EmployeeListQuery) (workforce.CursorPage[workforce.EmployeeSummary], error) {
	limit, sortKey, err := normalizePage(query.Limit, query.Sort, workforceDirectorySorts)
	if err != nil {
		return workforce.CursorPage[workforce.EmployeeSummary]{}, err
	}
	query.Query = strings.TrimSpace(query.Query)
	if utf8.RuneCountInString(query.Query) > workforceSearchMaxRunes {
		return workforce.CursorPage[workforce.EmployeeSummary]{}, workforce.ErrInvalidInput
	}
	if query.Status != "" && query.Status != "active" && query.Status != "offboarding" {
		return workforce.CursorPage[workforce.EmployeeSummary]{}, workforce.ErrInvalidInput
	}
	args := []any{query.Query, query.Status}
	where := []string{
		`($1 = '' OR u.display_name ILIKE '%' || $1 || '%' OR u.email ILIKE '%' || $1 || '%' OR ep.employee_number ILIKE '%' || $1 || '%' OR d.name ILIKE '%' || $1 || '%' OR ep.title ILIKE '%' || $1 || '%')`,
		`($2 = '' OR ep.status = $2)`,
	}
	state := workforceCursor{Kind: "employees", Sort: sortKey, Query: query.Query, Status: query.Status}
	if query.Cursor != "" {
		state, err = r.signer.decode(query.Cursor)
		if err != nil || state.Kind != "employees" || state.Sort != sortKey || state.Query != query.Query || state.Status != query.Status || state.ID == "" {
			return workforce.CursorPage[workforce.EmployeeSummary]{}, workforce.ErrInvalidCursor
		}
		args = append(args, state.Value, state.ID)
		where = append(where, directoryBoundary(sortKey, "ep.updated_at", "u.display_name", len(args)-1))
	}
	args = append(args, limit+1)
	order := directoryOrder(sortKey, "ep.updated_at", "u.display_name", "u.id")
	sql := `SELECT u.id, u.display_name, ep.employee_number, d.name, ep.title,
	               ep.status, ep.updated_at
	          FROM employee_profiles ep
	          JOIN users u ON u.id = ep.user_id
	          JOIN departments d ON d.department_id = ep.department_id
	         WHERE ` + strings.Join(where, " AND ") + `
	         ORDER BY ` + order + ` LIMIT $` + strconv.Itoa(len(args))
	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return workforce.CursorPage[workforce.EmployeeSummary]{}, fmt.Errorf("postgres: list employees: %w", err)
	}
	defer rows.Close()
	items := make([]workforce.EmployeeSummary, 0, limit+1)
	for rows.Next() {
		var item workforce.EmployeeSummary
		var userID, status string
		if err := rows.Scan(&userID, &item.DisplayName, &item.EmployeeNumber, &item.DepartmentName, &item.Title, &status, &item.UpdatedAt); err != nil {
			return workforce.CursorPage[workforce.EmployeeSummary]{}, fmt.Errorf("postgres: scan employee list: %w", err)
		}
		item.UserID = identity.UserID(userID)
		item.Status = workforce.EmployeeStatus(status)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return workforce.CursorPage[workforce.EmployeeSummary]{}, fmt.Errorf("postgres: iterate employees: %w", err)
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	next := ""
	if hasMore && len(items) > 0 {
		last := items[len(items)-1]
		value := last.UpdatedAt.UTC().Format(time.RFC3339Nano)
		if sortKey == "displayName" || sortKey == "-displayName" {
			value = last.DisplayName
		}
		next, err = r.signer.encode(workforceCursor{Kind: "employees", Sort: sortKey, Query: query.Query, Status: query.Status, Value: value, ID: string(last.UserID)})
		if err != nil {
			return workforce.CursorPage[workforce.EmployeeSummary]{}, err
		}
	}
	return workforce.CursorPage[workforce.EmployeeSummary]{Items: items, NextCursor: next, HasMore: hasMore}, nil
}

func directoryOrder(sortKey, timeColumn, nameColumn, idColumn string) string {
	switch sortKey {
	case "updatedAt":
		return timeColumn + " ASC, " + idColumn + " ASC"
	case "displayName":
		return "lower(" + nameColumn + ") ASC, " + idColumn + " ASC"
	case "-displayName":
		return "lower(" + nameColumn + ") DESC, " + idColumn + " DESC"
	default:
		return timeColumn + " DESC, " + idColumn + " DESC"
	}
}

// directoryBoundary returns a fixed-vocabulary keyset predicate. valueArg is
// the 1-based placeholder number of the cursor value; the ID follows it.
func directoryBoundary(sortKey, timeColumn, nameColumn string, valueArg int) string {
	value := "$" + strconv.Itoa(valueArg)
	id := "$" + strconv.Itoa(valueArg+1)
	switch sortKey {
	case "updatedAt":
		return "(" + timeColumn + ", u.id) > (" + value + "::timestamptz, " + id + ")"
	case "displayName":
		return "(lower(" + nameColumn + "), u.id) > (lower(" + value + "), " + id + ")"
	case "-displayName":
		return "(lower(" + nameColumn + "), u.id) < (lower(" + value + "), " + id + ")"
	default:
		return "(" + timeColumn + ", u.id) < (" + value + "::timestamptz, " + id + ")"
	}
}
