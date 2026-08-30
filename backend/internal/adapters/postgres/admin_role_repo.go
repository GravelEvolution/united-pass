package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
	"github.com/GravelEvolution/united-pass/backend/internal/applications"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

type adminDBTX interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type AdminRoleRepository struct {
	exec  adminDBTX
	tx    pgx.Tx
	codec *adminpagination.CursorCodec
}

const (
	adminRoleActorUserLockSQL     = `SELECT status FROM users WHERE id=$1 FOR UPDATE`
	adminRoleActorEmployeeLockSQL = `SELECT status FROM employee_profiles WHERE user_id=$1 FOR UPDATE`
	adminRoleActorBindingLockSQL  = `SELECT binding_id FROM admin_role_bindings
		WHERE binding_id=$1 AND user_id=$2 AND version=$3 AND role=$4
		  AND scope_kind=$5 AND scope_key=$6 AND event_id IS NOT DISTINCT FROM $7
		  AND enabled=TRUE AND disabled_at IS NULL FOR UPDATE`
)

var _ adminroles.ActorAuthorizationRepository = (*AdminRoleRepository)(nil)

func NewAdminRoleRepository(pool *pgxpool.Pool, codec *adminpagination.CursorCodec) *AdminRoleRepository {
	return &AdminRoleRepository{exec: pool, codec: codec}
}

func newAdminRoleRepository(tx pgx.Tx, codec *adminpagination.CursorCodec) *AdminRoleRepository {
	return &AdminRoleRepository{exec: tx, tx: tx, codec: codec}
}

func (r *AdminRoleRepository) Revalidate(ctx context.Context, actorID identity.UserID, eventID string, decision adminroles.RoleManagementDecision) error {
	if r.tx == nil || actorID == "" || !decision.Allowed || decision.BindingID == "" || decision.BindingVersion <= 0 || adminroles.ValidateRoleScope(decision.Role, decision.Scope) != nil {
		return adminroles.ErrRoleMutationForbidden
	}
	if decision.Scope.Kind == adminroles.ScopeEvent && decision.Scope.EventID != eventID {
		return adminroles.ErrRoleMutationForbidden
	}
	var accountStatus string
	if err := r.tx.QueryRow(ctx, adminRoleActorUserLockSQL, string(actorID)).Scan(&accountStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return adminroles.ErrRoleMutationForbidden
		}
		return fmt.Errorf("postgres: lock role mutation actor: %w", err)
	}
	if accountStatus != string(identity.UserStatusActive) {
		return adminroles.ErrRoleMutationForbidden
	}
	var employeeStatus string
	err := r.tx.QueryRow(ctx, adminRoleActorEmployeeLockSQL, string(actorID)).Scan(&employeeStatus)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: lock role mutation employee: %w", err)
	}
	if err == nil && employeeStatus != "active" {
		return adminroles.ErrRoleMutationForbidden
	}
	scopeKey, err := decision.Scope.Key()
	if err != nil {
		return adminroles.ErrRoleMutationForbidden
	}
	var bindingID string
	err = r.tx.QueryRow(ctx, adminRoleActorBindingLockSQL,
		decision.BindingID, string(actorID), decision.BindingVersion, string(decision.Role),
		string(decision.Scope.Kind), scopeKey, nullableEvent(decision.Scope)).Scan(&bindingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return adminroles.ErrRoleMutationForbidden
	}
	if err != nil {
		return fmt.Errorf("postgres: lock role mutation authorization: %w", err)
	}
	if bindingID != decision.BindingID {
		return adminroles.ErrRoleMutationForbidden
	}
	return nil
}

func (r *AdminRoleRepository) GetForScope(ctx context.Context, userID identity.UserID, scope adminroles.Scope) (adminroles.Binding, error) {
	key, err := scope.Key()
	if err != nil {
		return adminroles.Binding{}, err
	}
	binding, err := scanAdminBinding(r.exec.QueryRow(ctx, `SELECT binding_id,user_id,role,scope_kind,event_id,enabled,version,granted_by,reason_id,disabled_at,created_at,updated_at FROM admin_role_bindings WHERE user_id=$1 AND scope_kind=$2 AND scope_key=$3 AND disabled_at IS NULL`, string(userID), string(scope.Kind), key))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminroles.Binding{}, adminroles.ErrBindingNotFound
	}
	if err != nil {
		return adminroles.Binding{}, fmt.Errorf("postgres: get admin binding: %w", err)
	}
	return binding, nil
}

func (r *AdminRoleRepository) ListForUser(ctx context.Context, userID identity.UserID, query adminpagination.Query) (adminpagination.Page[adminroles.Binding], error) {
	if err := adminroles.ValidateUserListQuery(query); err != nil {
		return adminpagination.Page[adminroles.Binding]{}, err
	}
	return r.list(ctx, "user_id", string(userID), query)
}

func (r *AdminRoleRepository) ListForEvent(ctx context.Context, eventID string, query adminpagination.Query) (adminpagination.Page[adminroles.Binding], error) {
	if err := adminroles.ValidateEventListQuery(eventID, query); err != nil {
		return adminpagination.Page[adminroles.Binding]{}, err
	}
	return r.list(ctx, "event_id", eventID, query)
}

func (r *AdminRoleRepository) list(ctx context.Context, column, value string, query adminpagination.Query) (adminpagination.Page[adminroles.Binding], error) {
	limit := normalizeAdminLimit(query.Limit)
	sort := query.Sort
	if sort == "" {
		sort = "id:asc"
	}
	if sort != "id:asc" || r.codec == nil {
		return adminpagination.Page[adminroles.Binding]{}, adminpagination.ErrInvalidCursor
	}
	lastID := ""
	if query.Cursor != "" {
		state, err := r.codec.Decode(query.Cursor, adminExpectation(query, sort, limit))
		if err != nil {
			return adminpagination.Page[adminroles.Binding]{}, err
		}
		lastID = state.LastPosition["id"]
	}
	sql := `SELECT binding_id,user_id,role,scope_kind,event_id,enabled,version,granted_by,reason_id,disabled_at,created_at,updated_at FROM admin_role_bindings WHERE ` + column + `=$1 AND binding_id>$2 ORDER BY binding_id ASC LIMIT $3`
	rows, err := r.exec.Query(ctx, sql, value, lastID, limit+1)
	if err != nil {
		return adminpagination.Page[adminroles.Binding]{}, fmt.Errorf("postgres: list admin bindings: %w", err)
	}
	defer rows.Close()
	items := make([]adminroles.Binding, 0, limit)
	for rows.Next() {
		item, err := scanAdminBinding(rows)
		if err != nil {
			return adminpagination.Page[adminroles.Binding]{}, fmt.Errorf("postgres: scan admin binding: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return adminpagination.Page[adminroles.Binding]{}, fmt.Errorf("postgres: iterate admin bindings: %w", err)
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	page := adminpagination.Page[adminroles.Binding]{Items: items, HasMore: hasMore}
	if hasMore {
		now := time.Now().UTC()
		state := adminpagination.State{ActorID: query.ActorID, ScopeKind: query.ScopeKind, EventID: query.EventID, ListKind: query.ListKind, Filters: query.Filters, Sort: sort, LastPosition: map[string]string{"id": items[len(items)-1].ID}, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Limit: limit, DownstreamCursor: query.DownstreamCursor}
		page.NextCursor, err = r.codec.Encode(state)
		if err != nil {
			return adminpagination.Page[adminroles.Binding]{}, err
		}
	}
	return page, nil
}

func (r *AdminRoleRepository) Create(ctx context.Context, binding adminroles.Binding, audit adminroles.MutationAudit) (adminroles.Binding, error) {
	if r.tx == nil {
		return adminroles.Binding{}, errors.New("postgres: admin role write requires unit of work")
	}
	if err := adminroles.ValidateRoleScope(binding.Role, binding.Scope); err != nil {
		return adminroles.Binding{}, err
	}
	key, _ := binding.Scope.Key()
	if binding.Version == 0 {
		binding.Version = 1
	}
	if binding.CreatedAt.IsZero() {
		binding.CreatedAt = time.Now().UTC()
	}
	if binding.UpdatedAt.IsZero() {
		binding.UpdatedAt = binding.CreatedAt
	}
	binding.Enabled = true
	_, err := r.tx.Exec(ctx, `INSERT INTO admin_role_bindings (binding_id,user_id,role,scope_kind,scope_key,event_id,enabled,version,granted_by,reason_id,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7,$8,$9,$10,$11)`, binding.ID, string(binding.UserID), string(binding.Role), string(binding.Scope.Kind), key, nullableEvent(binding.Scope), binding.Version, string(binding.GrantedBy), binding.ReasonID, binding.CreatedAt, binding.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return adminroles.Binding{}, adminroles.ErrBindingConflict
		}
		return adminroles.Binding{}, fmt.Errorf("postgres: create admin binding: %w", err)
	}
	if err := recordAdminMutation(ctx, r.tx, audit, "admin.role.created", "role_binding", binding.ID); err != nil {
		return adminroles.Binding{}, err
	}
	return binding, nil
}

func (r *AdminRoleRepository) Update(ctx context.Context, binding adminroles.Binding, expectedVersion int64, audit adminroles.MutationAudit) (adminroles.Binding, error) {
	if r.tx == nil {
		return adminroles.Binding{}, errors.New("postgres: admin role write requires unit of work")
	}
	if err := adminroles.ValidateRoleScope(binding.Role, binding.Scope); err != nil {
		return adminroles.Binding{}, err
	}
	current, err := scanAdminBinding(r.tx.QueryRow(ctx, `SELECT binding_id,user_id,role,scope_kind,event_id,enabled,version,granted_by,reason_id,disabled_at,created_at,updated_at FROM admin_role_bindings WHERE binding_id=$1 FOR UPDATE`, binding.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminroles.Binding{}, adminroles.ErrBindingNotFound
	}
	if err != nil {
		return adminroles.Binding{}, fmt.Errorf("postgres: lock admin binding: %w", err)
	}
	if current.Version != expectedVersion || adminroles.ValidateBindingReplacement(current, binding) != nil {
		return adminroles.Binding{}, adminroles.ErrBindingConflict
	}
	tag, err := r.tx.Exec(ctx, `UPDATE admin_role_bindings SET role=$2,version=version+1,updated_at=NOW(),granted_by=$3,reason_id=$4 WHERE binding_id=$1 AND version=$5 AND disabled_at IS NULL`, binding.ID, string(binding.Role), string(audit.ActorID), audit.ReasonID, expectedVersion)
	if err != nil {
		return adminroles.Binding{}, fmt.Errorf("postgres: update admin binding: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return adminroles.Binding{}, adminroles.ErrBindingConflict
	}
	if err := recordAdminMutation(ctx, r.tx, audit, "admin.role.updated", "role_binding", binding.ID); err != nil {
		return adminroles.Binding{}, err
	}
	return scanAdminBinding(r.tx.QueryRow(ctx, `SELECT binding_id,user_id,role,scope_kind,event_id,enabled,version,granted_by,reason_id,disabled_at,created_at,updated_at FROM admin_role_bindings WHERE binding_id=$1`, binding.ID))
}

func (r *AdminRoleRepository) Disable(ctx context.Context, bindingID string, expectedVersion int64, audit adminroles.MutationAudit) (adminroles.Binding, error) {
	if r.tx == nil {
		return adminroles.Binding{}, errors.New("postgres: admin role write requires unit of work")
	}
	tag, err := r.tx.Exec(ctx, `UPDATE admin_role_bindings SET enabled=FALSE,disabled_at=NOW(),version=version+1,updated_at=NOW(),reason_id=$2 WHERE binding_id=$1 AND version=$3 AND disabled_at IS NULL`, bindingID, audit.ReasonID, expectedVersion)
	if err != nil {
		return adminroles.Binding{}, fmt.Errorf("postgres: disable admin binding: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return adminroles.Binding{}, adminroles.ErrBindingConflict
	}
	if err := recordAdminMutation(ctx, r.tx, audit, "admin.role.disabled", "role_binding", bindingID); err != nil {
		return adminroles.Binding{}, err
	}
	return scanAdminBinding(r.tx.QueryRow(ctx, `SELECT binding_id,user_id,role,scope_kind,event_id,enabled,version,granted_by,reason_id,disabled_at,created_at,updated_at FROM admin_role_bindings WHERE binding_id=$1`, bindingID))
}

func scanAdminBinding(row pgx.Row) (adminroles.Binding, error) {
	var binding adminroles.Binding
	var role, kind, userID string
	var eventID *string
	err := row.Scan(&binding.ID, &userID, &role, &kind, &eventID, &binding.Enabled, &binding.Version, &binding.GrantedBy, &binding.ReasonID, &binding.DisabledAt, &binding.CreatedAt, &binding.UpdatedAt)
	if err != nil {
		return adminroles.Binding{}, err
	}
	binding.UserID = identity.UserID(userID)
	binding.Role = adminroles.Role(role)
	binding.Scope.Kind = adminroles.ScopeKind(kind)
	if eventID != nil {
		binding.Scope.EventID = *eventID
	}
	return binding, nil
}

func nullableEvent(scope adminroles.Scope) any {
	if scope.Kind == adminroles.ScopeEvent {
		return scope.EventID
	}
	return nil
}
func normalizeAdminLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > adminpagination.MaxPageSize {
		return adminpagination.MaxPageSize
	}
	return limit
}
func adminExpectation(query adminpagination.Query, sort string, limit int) adminpagination.Expectation {
	return adminpagination.Expectation{ActorID: query.ActorID, ScopeKind: query.ScopeKind, EventID: query.EventID, ListKind: query.ListKind, Filters: query.Filters, Sort: sort, Limit: limit}
}

func recordAdminMutation(ctx context.Context, tx pgx.Tx, audit adminroles.MutationAudit, eventType, targetKind, targetID string) error {
	if audit.ActorID == "" || audit.RequestID == "" || audit.Action == "" || audit.ReasonID == "" {
		return errors.New("postgres: incomplete admin mutation audit")
	}
	return insertSecurityEvent(ctx, tx, applications.SecurityEvent{EventID: applications.NewSecurityEventID(), EventType: eventType, ActorUserID: audit.ActorID, RequestID: audit.RequestID, Operation: audit.Action, Result: applications.SecurityEventSuccess, TargetKey: targetKind + "_id", TargetID: targetID, Extra: map[string]string{"reason_id": audit.ReasonID}, OccurredAt: time.Now().UTC()})
}
