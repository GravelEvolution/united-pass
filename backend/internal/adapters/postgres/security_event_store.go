package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/applications"
)

// SecurityEventStore persists durable audit events (ADR-0004 §8). Payloads
// are restricted to safe, stable fields — never secrets, tokens, cookies,
// passwords or raw provider errors.
type SecurityEventStore struct {
	pool *pgxpool.Pool
}

// NewSecurityEventStore builds the audit store.
func NewSecurityEventStore(pool *pgxpool.Pool) *SecurityEventStore {
	return &SecurityEventStore{pool: pool}
}

// Record persists one audit event outside any surrounding transaction.
func (s *SecurityEventStore) Record(ctx context.Context, ev applications.SecurityEvent) error {
	return s.exec(ctx, s.pool, ev)
}

// RecordTx persists one audit event inside the caller's transaction so the
// audit row commits or rolls back with the audited change.
func (s *SecurityEventStore) RecordTx(ctx context.Context, tx pgx.Tx, ev applications.SecurityEvent) error {
	return s.exec(ctx, tx, ev)
}

type eventExecer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

func (s *SecurityEventStore) exec(ctx context.Context, q eventExecer, ev applications.SecurityEvent) error {
	payload, err := eventPayload(ev)
	if err != nil {
		return fmt.Errorf("postgres: encode security event payload: %w", err)
	}
	if _, err := q.Exec(ctx,
		`INSERT INTO security_events
		     (event_id, event_type, actor_user_id, application_id, client_id,
		      request_id, operation, result, payload, occurred_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		string(ev.EventID), ev.EventType, string(ev.ActorUserID),
		string(ev.ApplicationID), string(ev.ClientID), ev.RequestID,
		ev.Operation, string(ev.Result), payload, ev.OccurredAt); err != nil {
		return fmt.Errorf("postgres: record security event: %w", err)
	}
	return nil
}

// ListByApplication returns the audit trail actually recorded for one
// application, newest first. ActorName is the joined users.display_name
// (empty when the actor row is gone); it is derived display text only.
func (s *SecurityEventStore) ListByApplication(ctx context.Context, appID applications.ApplicationID) ([]applications.AuditEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT e.event_id, e.event_type, COALESCE(u.display_name, ''),
		        e.occurred_at, e.result
		   FROM security_events e
		   LEFT JOIN users u ON u.id = e.actor_user_id
		  WHERE e.application_id = $1
		  ORDER BY e.occurred_at DESC, e.event_id DESC`,
		string(appID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list security events: %w", err)
	}
	defer rows.Close()

	entries := make([]applications.AuditEntry, 0)
	for rows.Next() {
		var (
			entry           applications.AuditEntry
			eventID, result string
		)
		if err := rows.Scan(&eventID, &entry.EventType, &entry.ActorName, &entry.OccurredAt, &result); err != nil {
			return nil, fmt.Errorf("postgres: scan security event row: %w", err)
		}
		entry.EventID = applications.SecurityEventID(eventID)
		entry.Result = applications.SecurityEventResult(result)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate security event rows: %w", err)
	}
	return entries, nil
}

// eventPayload builds the JSONB payload. Only safe, stable fields are
// included.
func eventPayload(ev applications.SecurityEvent) ([]byte, error) {
	payload := map[string]string{}
	if ev.FailureClass != "" {
		payload["failure_class"] = ev.FailureClass
	}
	return json.Marshal(payload)
}
