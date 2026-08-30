package postgres

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/integrationboundary"
)

// TestIntegration_RebuildIsolatedOperationalStore is an explicit local-only
// migration rehearsal. It is destructive only to the token-bound disposable
// isolated schema and cannot target a production host, database or schema.
func TestIntegration_RebuildIsolatedOperationalStore(t *testing.T) {
	if os.Getenv("UP_TEST_REBUILD_ISOLATED") != "true" {
		t.Skip("explicit isolated migration rebuild was not requested")
	}
	rawURL := os.Getenv("UP_TEST_ISOLATED_DATABASE_URL")
	schema := os.Getenv("UP_TEST_ISOLATED_DATABASE_SCHEMA")
	runToken := os.Getenv(integrationboundary.RunTokenEnvironment)
	if err := integrationboundary.ValidateIsolatedPostgres(rawURL, schema, runToken); err != nil {
		t.Fatal(err)
	}
	connection, err := pgx.ParseConfig(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if connection.RuntimeParams == nil {
		connection.RuntimeParams = make(map[string]string)
	}
	connection.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*connection)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	// A prior interrupted rehearsal from this same disposable database may
	// have placed these two isolated tables in public before search_path was
	// set. Remove only those exact test artifacts; authority tables are never
	// accepted by the integration boundary or named here.
	if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS public.admin_operation_outbox,public.wechat_registration_provider_intents CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	goose.SetTableName(pgx.Identifier{schema, "goose_db_version"}.Sanitize())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpContext(ctx, db, filepath.Join(findBackendRoot(t), "isolated-migrations")); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPoolFromConfig(ctx, config.DatabaseConfig{
		URL: rawURL, Schema: schema, MaxConns: 2, MinConns: 0, ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := ValidateIsolatedOperationalStore(ctx, pool.PgxPool()); err != nil {
		t.Fatal(err)
	}
	var publicArtifacts int
	if err := pool.PgxPool().QueryRow(ctx, `
SELECT COUNT(*)
  FROM pg_catalog.pg_class AS c
  JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
 WHERE n.nspname='public'
   AND c.relname IN('admin_operation_outbox','wechat_registration_provider_intents')`).Scan(&publicArtifacts); err != nil {
		t.Fatal(err)
	}
	if publicArtifacts != 0 {
		t.Fatalf("isolated business artifacts leaked into public schema: %d", publicArtifacts)
	}
}
