package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/adminpagination"
	"github.com/GravelEvolution/united-pass/backend/internal/adminroles"
)

type DreamUPEventRegistryRepository struct {
	exec  adminDBTX
	tx    pgx.Tx
	codec *adminpagination.CursorCodec
}

func NewDreamUPEventRegistryRepository(pool *pgxpool.Pool, codec *adminpagination.CursorCodec) *DreamUPEventRegistryRepository {
	return &DreamUPEventRegistryRepository{exec: pool, codec: codec}
}
func newDreamUPEventRegistryRepository(tx pgx.Tx, codec *adminpagination.CursorCodec) *DreamUPEventRegistryRepository {
	return &DreamUPEventRegistryRepository{exec: tx, tx: tx, codec: codec}
}

func (r *DreamUPEventRegistryRepository) GetExact(ctx context.Context, eventID string) (adminroles.RegisteredEvent, error) {
	event, err := scanRegisteredEvent(r.exec.QueryRow(ctx, `SELECT event_id,series,slug,display_name,source_version,authoritative_read_at,enabled,version,created_at,updated_at FROM dreamup_event_registry WHERE event_id=$1`, eventID))
	if errors.Is(err, pgx.ErrNoRows) {
		return adminroles.RegisteredEvent{}, adminroles.ErrEventRegistryNotFound
	}
	if err != nil {
		return adminroles.RegisteredEvent{}, fmt.Errorf("postgres: get DreamUP registry event: %w", err)
	}
	if !event.Enabled {
		return adminroles.RegisteredEvent{}, adminroles.ErrEventRegistryDisabled
	}
	if err := validateRegisteredEvent(event); err != nil {
		return adminroles.RegisteredEvent{}, err
	}
	return event, nil
}

func (r *DreamUPEventRegistryRepository) ListEnabled(ctx context.Context, query adminpagination.Query) (adminpagination.Page[adminroles.RegisteredEvent], error) {
	if err := adminroles.ValidateRegistryListQuery(query); err != nil {
		return adminpagination.Page[adminroles.RegisteredEvent]{}, err
	}
	limit := normalizeAdminLimit(query.Limit)
	sort := query.Sort
	if sort == "" {
		sort = "id:asc"
	}
	if sort != "id:asc" || r.codec == nil {
		return adminpagination.Page[adminroles.RegisteredEvent]{}, adminpagination.ErrInvalidCursor
	}
	lastID := ""
	if query.Cursor != "" {
		state, err := r.codec.Decode(query.Cursor, adminExpectation(query, sort, limit))
		if err != nil {
			return adminpagination.Page[adminroles.RegisteredEvent]{}, err
		}
		lastID = state.LastPosition["id"]
	}
	rows, err := r.exec.Query(ctx, `SELECT event_id,series,slug,display_name,source_version,authoritative_read_at,enabled,version,created_at,updated_at FROM dreamup_event_registry WHERE enabled=TRUE AND event_id>$1 ORDER BY event_id ASC LIMIT $2`, lastID, limit+1)
	if err != nil {
		return adminpagination.Page[adminroles.RegisteredEvent]{}, fmt.Errorf("postgres: list DreamUP registry: %w", err)
	}
	defer rows.Close()
	items := make([]adminroles.RegisteredEvent, 0, limit)
	for rows.Next() {
		item, err := scanRegisteredEvent(rows)
		if err != nil {
			return adminpagination.Page[adminroles.RegisteredEvent]{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return adminpagination.Page[adminroles.RegisteredEvent]{}, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	page := adminpagination.Page[adminroles.RegisteredEvent]{Items: items, HasMore: hasMore}
	if hasMore {
		now := time.Now().UTC()
		page.NextCursor, err = r.codec.Encode(adminpagination.State{ActorID: query.ActorID, ScopeKind: query.ScopeKind, EventID: query.EventID, ListKind: query.ListKind, Filters: query.Filters, Sort: sort, LastPosition: map[string]string{"id": items[len(items)-1].EventID}, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Limit: limit})
		if err != nil {
			return adminpagination.Page[adminroles.RegisteredEvent]{}, err
		}
	}
	return page, nil
}

func (r *DreamUPEventRegistryRepository) PutExact(ctx context.Context, event adminroles.RegisteredEvent, audit adminroles.MutationAudit) (adminroles.RegisteredEvent, error) {
	if r.tx == nil {
		return adminroles.RegisteredEvent{}, errors.New("postgres: event registry write requires unit of work")
	}
	event = prepareNewRegisteredEvent(event)
	if err := validateRegisteredEvent(event); err != nil {
		return adminroles.RegisteredEvent{}, err
	}
	current, err := scanRegisteredEvent(r.tx.QueryRow(ctx, `SELECT event_id,series,slug,display_name,source_version,authoritative_read_at,enabled,version,created_at,updated_at FROM dreamup_event_registry WHERE event_id=$1 FOR UPDATE`, event.EventID))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if event.CreatedAt.IsZero() {
			event.CreatedAt = time.Now().UTC()
		}
		if event.UpdatedAt.IsZero() {
			event.UpdatedAt = event.CreatedAt
		}
		_, err = r.tx.Exec(ctx, `INSERT INTO dreamup_event_registry (event_id,series,slug,display_name,source_version,authoritative_read_at,enabled,version,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, event.EventID, event.Series, event.Slug, event.DisplayName, event.SourceVersion, event.AuthoritativeReadAt, event.Enabled, event.Version, event.CreatedAt, event.UpdatedAt)
	case err != nil:
		return adminroles.RegisteredEvent{}, fmt.Errorf("postgres: lock event registry: %w", err)
	default:
		if event.Version != current.Version {
			return adminroles.RegisteredEvent{}, adminroles.ErrEventRegistryConflict
		}
		if err := validateRegisteredEventReplacement(current, event); err != nil {
			return adminroles.RegisteredEvent{}, err
		}
		tag, updateErr := r.tx.Exec(ctx, `UPDATE dreamup_event_registry SET display_name=$2,source_version=$3,authoritative_read_at=$4,enabled=$5,version=version+1,updated_at=NOW() WHERE event_id=$1 AND version=$6`, event.EventID, event.DisplayName, event.SourceVersion, event.AuthoritativeReadAt, event.Enabled, current.Version)
		err = updateErr
		if err == nil && tag.RowsAffected() != 1 {
			return adminroles.RegisteredEvent{}, adminroles.ErrEventRegistryConflict
		}
	}
	if err != nil {
		if isUniqueViolation(err) {
			return adminroles.RegisteredEvent{}, adminroles.ErrEventRegistryConflict
		}
		return adminroles.RegisteredEvent{}, fmt.Errorf("postgres: put event registry: %w", err)
	}
	if err := recordAdminMutation(ctx, r.tx, audit, "admin.registry.updated", "event_registry", event.EventID); err != nil {
		return adminroles.RegisteredEvent{}, err
	}
	return scanRegisteredEvent(r.tx.QueryRow(ctx, `SELECT event_id,series,slug,display_name,source_version,authoritative_read_at,enabled,version,created_at,updated_at FROM dreamup_event_registry WHERE event_id=$1`, event.EventID))
}

func (r *DreamUPEventRegistryRepository) SetEnabled(ctx context.Context, eventID string, enabled bool, expectedVersion int64, audit adminroles.MutationAudit) (adminroles.RegisteredEvent, error) {
	if r.tx == nil {
		return adminroles.RegisteredEvent{}, errors.New("postgres: event registry write requires unit of work")
	}
	tag, err := r.tx.Exec(ctx, `UPDATE dreamup_event_registry SET enabled=$2,version=version+1,updated_at=NOW() WHERE event_id=$1 AND version=$3`, eventID, enabled, expectedVersion)
	if err != nil {
		return adminroles.RegisteredEvent{}, fmt.Errorf("postgres: set registry enabled: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return adminroles.RegisteredEvent{}, adminroles.ErrEventRegistryConflict
	}
	if err := recordAdminMutation(ctx, r.tx, audit, "admin.registry.updated", "event_registry", eventID); err != nil {
		return adminroles.RegisteredEvent{}, err
	}
	return scanRegisteredEvent(r.tx.QueryRow(ctx, `SELECT event_id,series,slug,display_name,source_version,authoritative_read_at,enabled,version,created_at,updated_at FROM dreamup_event_registry WHERE event_id=$1`, eventID))
}

func prepareNewRegisteredEvent(event adminroles.RegisteredEvent) adminroles.RegisteredEvent {
	if event.Version == 0 {
		event.Version = 1
	}
	return event
}

func validateRegisteredEvent(event adminroles.RegisteredEvent) error {
	if event.EventID == "" || event.Series != "dreamup" || event.Slug == "" || event.SourceVersion == "" || event.AuthoritativeReadAt.IsZero() || event.Version < 1 {
		return adminroles.ErrInvalidRegisteredEvent
	}
	return nil
}

func validateRegisteredEventReplacement(current, next adminroles.RegisteredEvent) error {
	if err := validateRegisteredEvent(next); err != nil {
		return adminroles.ErrEventRegistryConflict
	}
	if current.EventID != next.EventID || current.Series != next.Series || current.Slug != next.Slug || !next.AuthoritativeReadAt.After(current.AuthoritativeReadAt) || next.SourceVersion == current.SourceVersion {
		return adminroles.ErrEventRegistryConflict
	}
	return nil
}

func scanRegisteredEvent(row pgx.Row) (adminroles.RegisteredEvent, error) {
	var event adminroles.RegisteredEvent
	err := row.Scan(&event.EventID, &event.Series, &event.Slug, &event.DisplayName, &event.SourceVersion, &event.AuthoritativeReadAt, &event.Enabled, &event.Version, &event.CreatedAt, &event.UpdatedAt)
	return event, err
}
