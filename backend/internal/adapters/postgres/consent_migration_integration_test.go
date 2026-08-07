//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: PostgreSQL migration-path integration tests for the consent schema
//

//go:build integration

package postgres

// Migration path tests for the consent completion-plan schema. The
// committed history matters here, not just the head shape: 00005 created
// the original decision-column schema and 00006 evolves it into the
// durable completion plan. Both the fresh-install path (00001 → head) and
// the upgrade path (original 00005 → 00006) must land on the same final
// schema, and 00006 must fail closed against legacy or unreleased shapes.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// originalGrantsMigrationVersion is the committed 00005 file that created
// the decision-column schema.
const originalGrantsMigrationVersion = 5

// openMigrationTestDB prepares a database/sql handle bound to the test
// schema with goose configured, and registers a cleanup that drops every
// migrated table plus the version bookkeeping.
func openMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	url, schema := mustLoadTestDBConfig(t)

	connConfig, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	if connConfig.RuntimeParams == nil {
		connConfig.RuntimeParams = make(map[string]string)
	}
	connConfig.RuntimeParams["search_path"] = schema

	db := stdlib.OpenDB(*connConfig)
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quotedSchema)); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	goose.SetTableName(pgx.Identifier{schema, "goose_db_version"}.Sanitize())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set dialect: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TABLE IF EXISTS
			security_events, provider_reconciliation_jobs, oauth_provider_operations,
			oauth_authorization_grant_scopes, oauth_authorization_grants,
			oauth_authorization_decision_operation_scopes,
			oauth_authorization_decision_operations,
			oauth_client_secret_records, oauth_client_scopes, oauth_client_redirect_uris,
			oauth_clients, oauth_applications,
			user_personas, identity_links, users CASCADE`)
		_, _ = db.Exec(`DROP TABLE IF EXISTS goose_db_version`)
		_ = db.Close()
	})
	return db
}

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (
	        SELECT 1 FROM information_schema.columns
	         WHERE table_schema = current_schema()
	           AND table_name = $1 AND column_name = $2)`,
		table, column).Scan(&exists); err != nil {
		t.Fatalf("probe column %s.%s: %v", table, column, err)
	}
	return exists
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (
	        SELECT 1 FROM information_schema.tables
	         WHERE table_schema = current_schema() AND table_name = $1)`,
		table).Scan(&exists); err != nil {
		t.Fatalf("probe table %s: %v", table, err)
	}
	return exists
}

// assertCompletionPlanSchema verifies the final head shape both migration
// paths must reach: completion_kind (never decision), the operation scope
// snapshot table, and the CHECK constraints actually rejecting bad rows.
func assertCompletionPlanSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	if !columnExists(t, db, "oauth_authorization_decision_operations", "completion_kind") {
		t.Fatal("completion_kind column missing at head")
	}
	if columnExists(t, db, "oauth_authorization_decision_operations", "decision") {
		t.Fatal("decision column must be renamed away at head")
	}
	if !tableExists(t, db, "oauth_authorization_decision_operation_scopes") {
		t.Fatal("operation scope snapshot table missing at head")
	}

	// The completion-kind CHECK rejects the legacy ambiguous value.
	if _, err := db.Exec(`INSERT INTO oauth_authorization_decision_operations
	        (operation_id, provider, auth_request_id, completion_kind, status)
	     VALUES ('dop_migkind', 'zitadel', 'V2-mig-kind', 'deny', 'pending')`); err == nil {
		t.Fatal("legacy completion kind 'deny' must violate the head CHECK")
	}
	// A valid kind passes.
	if _, err := db.Exec(`INSERT INTO oauth_authorization_decision_operations
	        (operation_id, provider, auth_request_id, completion_kind, status)
	     VALUES ('dop_migok', 'zitadel', 'V2-mig-ok', 'access_denied', 'pending')`); err != nil {
		t.Fatalf("valid completion kind rejected: %v", err)
	}
	// The provider length CHECK rejects oversized providers.
	if _, err := db.Exec(`INSERT INTO oauth_authorization_decision_operations
	        (operation_id, provider, auth_request_id, completion_kind, status)
	     VALUES ('dop_migprov', $1, 'V2-mig-prov', 'allow', 'pending')`,
		strings.Repeat("p", 65)); err == nil {
		t.Fatal("oversized provider must violate the head CHECK")
	}
}

// TestMigrationFreshInstallReachesCompletionPlanSchema migrates an empty
// schema from 00001 to head and verifies the final completion-plan shape.
func TestMigrationFreshInstallReachesCompletionPlanSchema(t *testing.T) {
	db := openMigrationTestDB(t)
	if err := goose.UpContext(context.Background(), db, findMigrationsDir(t)); err != nil {
		t.Fatalf("fresh install migration: %v", err)
	}
	assertCompletionPlanSchema(t, db)
}

// TestMigrationUpgradeFromOriginalGrantsSchema applies the committed
// original 00005 (decision column), verifies that intermediate shape, and
// then applies 00006 on top — the path any database that already ran the
// original 00005 will take.
func TestMigrationUpgradeFromOriginalGrantsSchema(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()
	migrationsDir := findMigrationsDir(t)

	if err := goose.UpToContext(ctx, db, migrationsDir, originalGrantsMigrationVersion); err != nil {
		t.Fatalf("migrate to original 00005: %v", err)
	}
	// The intermediate shape: decision column, no completion plan.
	if !columnExists(t, db, "oauth_authorization_decision_operations", "decision") {
		t.Fatal("original 00005 must create the decision column")
	}
	if columnExists(t, db, "oauth_authorization_decision_operations", "completion_kind") {
		t.Fatal("original 00005 must not have completion_kind")
	}
	if tableExists(t, db, "oauth_authorization_decision_operation_scopes") {
		t.Fatal("original 00005 must not create the scope snapshot table")
	}

	if err := goose.UpContext(ctx, db, migrationsDir); err != nil {
		t.Fatalf("upgrade 00005 -> head: %v", err)
	}
	assertCompletionPlanSchema(t, db)
}

// TestMigrationCompletionPlanFailsClosedOnLegacyRows verifies that 00006
// refuses to run when the original schema already holds operation rows:
// their completion kind is ambiguous and no scope snapshot can be
// recovered, so the migration fails loudly instead of pretending.
func TestMigrationCompletionPlanFailsClosedOnLegacyRows(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()
	migrationsDir := findMigrationsDir(t)

	if err := goose.UpToContext(ctx, db, migrationsDir, originalGrantsMigrationVersion); err != nil {
		t.Fatalf("migrate to original 00005: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO oauth_authorization_decision_operations
	        (operation_id, provider, auth_request_id, decision, status)
	     VALUES ('dop_legacy1', 'zitadel', 'V2-legacy', 'allow', 'pending')`); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	err := goose.UpContext(ctx, db, migrationsDir)
	if err == nil {
		t.Fatal("migration over legacy rows must fail closed")
	}
	if !strings.Contains(err.Error(), "legacy rows") {
		t.Fatalf("failure must explain the legacy-row problem, got: %v", err)
	}
}

// TestMigrationCompletionPlanFailsOnUnreleasedShape verifies that 00006
// also refuses databases which applied the unreleased rewritten 00005
// (completion_kind already present): goose recorded that version as
// applied and would silently skip the lost evolution otherwise.
func TestMigrationCompletionPlanFailsOnUnreleasedShape(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()
	migrationsDir := findMigrationsDir(t)

	if err := goose.UpToContext(ctx, db, migrationsDir, originalGrantsMigrationVersion); err != nil {
		t.Fatalf("migrate to original 00005: %v", err)
	}
	// Simulate the unreleased rewritten shape.
	if _, err := db.Exec(`ALTER TABLE oauth_authorization_decision_operations
	        RENAME COLUMN decision TO completion_kind`); err != nil {
		t.Fatalf("simulate unreleased shape: %v", err)
	}

	err := goose.UpContext(ctx, db, migrationsDir)
	if err == nil {
		t.Fatal("migration over the unreleased shape must fail closed")
	}
	if !strings.Contains(err.Error(), "unreleased") {
		t.Fatalf("failure must explain the unreleased-shape problem, got: %v", err)
	}
}
