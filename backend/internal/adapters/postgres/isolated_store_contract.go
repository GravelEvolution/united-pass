package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type isolatedColumnSpec struct {
	udtName  string
	nullable bool
}

var isolatedOperationalColumnContract = map[string]map[string]isolatedColumnSpec{
	"wechat_registration_provider_intents": {
		"subject_hash": {udtName: "bytea"}, "user_id": {udtName: "text"},
		"request_verifier": {udtName: "text"}, "created_at": {udtName: "timestamptz"},
		"cleanup_checked_at": {udtName: "timestamptz", nullable: true},
	},
	"admin_operation_outbox": {
		"operation_id": {udtName: "text"}, "operation_kind": {udtName: "text"},
		"idempotency_key": {udtName: "text"}, "request_fingerprint_version": {udtName: "text"},
		"request_fingerprint_key_id": {udtName: "text"}, "request_fingerprint_hmac": {udtName: "text"},
		"payload_key_id": {udtName: "text", nullable: true}, "payload_nonce": {udtName: "bytea", nullable: true},
		"payload_ciphertext": {udtName: "bytea", nullable: true}, "result_code": {udtName: "text"},
		"result_digest": {udtName: "text"}, "result_payload": {udtName: "jsonb"},
		"delivery_state": {udtName: "text"}, "delivery_phase": {udtName: "text"},
		"claim_token_hash": {udtName: "text", nullable: true}, "claim_lease_until": {udtName: "timestamptz", nullable: true},
		"attempts": {udtName: "int4"}, "next_attempt_at": {udtName: "timestamptz"},
		"version": {udtName: "int8"}, "terminal_at": {udtName: "timestamptz", nullable: true},
		"audit_reconciled_at": {udtName: "timestamptz", nullable: true}, "payload_expires_at": {udtName: "timestamptz", nullable: true},
		"payload_purged_at": {udtName: "timestamptz", nullable: true}, "created_at": {udtName: "timestamptz"},
		"updated_at": {udtName: "timestamptz"},
	},
}

// ValidateIsolatedOperationalStore proves that the selected search path holds
// only the forward-migrated DreamUP/Mini Program operational tables. Startup
// fails closed if an authority table or any unrelated business table shares
// this schema.
func ValidateIsolatedOperationalStore(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("postgres: isolated operational store is unavailable")
	}
	rows, err := pool.Query(ctx, `
SELECT c.relname,c.relkind::text
  FROM pg_catalog.pg_class AS c
  JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
 WHERE n.nspname=current_schema()
   AND c.relkind IN('r','p','v','m','f','S')
 ORDER BY c.relname`)
	if err != nil {
		return fmt.Errorf("postgres: inspect isolated operational schema: %w", err)
	}
	defer rows.Close()
	allowed := map[string]string{
		"admin_operation_outbox":               "r",
		"goose_db_version":                     "r",
		"goose_db_version_id_seq":              "S",
		"wechat_registration_provider_intents": "r",
	}
	seen := make(map[string]bool, len(allowed))
	for rows.Next() {
		var table, relationKind string
		if err := rows.Scan(&table, &relationKind); err != nil {
			return fmt.Errorf("postgres: scan isolated operational schema: %w", err)
		}
		expectedKind, ok := allowed[table]
		if !ok || relationKind != expectedKind {
			return errors.New("postgres: isolated operational schema contains an unrelated table")
		}
		seen[table] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: inspect isolated operational schema: %w", err)
	}
	for table := range allowed {
		if !seen[table] {
			return errors.New("postgres: isolated operational schema is not fully migrated")
		}
	}
	if err := validateIsolatedOperationalColumns(ctx, pool); err != nil {
		return err
	}
	var version int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version_id) FILTER (WHERE is_applied),0) FROM goose_db_version`).Scan(&version); err != nil {
		return fmt.Errorf("postgres: read isolated operational migration version: %w", err)
	}
	if version != 1 {
		return errors.New("postgres: isolated operational migration version is unsupported")
	}
	return nil
}

func validateIsolatedOperationalColumns(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
SELECT table_name,column_name,udt_name,is_nullable
  FROM information_schema.columns
 WHERE table_schema=current_schema()
   AND table_name IN('wechat_registration_provider_intents','admin_operation_outbox')
 ORDER BY table_name,ordinal_position`)
	if err != nil {
		return fmt.Errorf("postgres: inspect isolated operational columns: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]map[string]bool, len(isolatedOperationalColumnContract))
	for rows.Next() {
		var table, column, udtName, nullable string
		if err := rows.Scan(&table, &column, &udtName, &nullable); err != nil {
			return fmt.Errorf("postgres: scan isolated operational column: %w", err)
		}
		tableContract, ok := isolatedOperationalColumnContract[table]
		if !ok {
			return errors.New("postgres: isolated operational column belongs to an unrelated table")
		}
		spec, ok := tableContract[column]
		if !ok || spec.udtName != udtName || spec.nullable != (nullable == "YES") {
			return errors.New("postgres: isolated operational column contract drifted")
		}
		if seen[table] == nil {
			seen[table] = make(map[string]bool, len(tableContract))
		}
		seen[table][column] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: inspect isolated operational columns: %w", err)
	}
	for table, columns := range isolatedOperationalColumnContract {
		for column := range columns {
			if !seen[table][column] {
				return errors.New("postgres: isolated operational column contract is incomplete")
			}
		}
	}
	return nil
}
