//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Database migration CLI entry point (goose up/down/status)
//

// Package main implements the migration command for United Pass.
//
// Usage:
//
//	go run ./cmd/migrate up          # Apply authority migrations through v13
//	go run ./cmd/migrate status       # Show migration status
//	go run ./cmd/migrate version      # Show current migration version
//	go run ./cmd/migrate reset        # Roll back to the first forward-only barrier (requires --confirm)
//
// Migrations are NOT executed automatically at API server startup.
// This command must be run explicitly.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// authorityMigrationCeiling is the last migration owned by the production
// United Pass authority database. Migrations 14 and 15 are retained only as
// historical compatibility material for legacy shared-store installations;
// current DreamUP and Mini Program operational state belongs in the distinct
// isolated database managed by cmd/migrate-isolated.
const authorityMigrationCeiling int64 = 13

func main() {
	confirmReset := flag.Bool("confirm", false, "Required for destructive operations (reset)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <command>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  up       Apply authority migrations through v%d\n", authorityMigrationCeiling)
		fmt.Fprintf(os.Stderr, "  status   Show migration status\n")
		fmt.Fprintf(os.Stderr, "  version  Show current migration version\n")
		fmt.Fprintf(os.Stderr, "  reset    Roll back until a forward-only migration refuses (requires --confirm)\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	command := flag.Arg(0)

	// Load .env for local development (does not override existing env vars).
	envPath := filepath.Join(".", ".env")
	if _, err := os.Stat(envPath); err == nil {
		if _, err := config.LoadDotEnv(envPath); err != nil {
			fmt.Fprintf(os.Stderr, "error loading .env: %v\n", err)
			os.Exit(1)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	if !cfg.HasDatabase() {
		fmt.Fprintf(os.Stderr, "error: UP_DATABASE_URL is not set\n")
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	migrationsDir := filepath.Join(".", "migrations")
	if _, err := os.Stat(migrationsDir); err != nil {
		fmt.Fprintf(os.Stderr, "error: migrations directory not found: %v\n", err)
		os.Exit(1)
	}

	db, err := openDB(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// The schema name comes from an environment variable and is interpolated
	// into SQL below, so it must pass strict identifier validation before it
	// is used in any statement.
	if !config.ValidSchemaIdentifier(cfg.Database.Schema) {
		fmt.Fprintf(os.Stderr, "error: schema %q is not a valid PostgreSQL identifier\n", cfg.Database.Schema)
		os.Exit(1)
	}

	// Create the configured schema if it doesn't exist. The migration files
	// no longer create the schema; the runner is responsible for creating it.
	// pgx.Identifier quoting prevents injection even though the name has
	// already passed identifier validation.
	quotedSchema := pgx.Identifier{cfg.Database.Schema}.Sanitize()
	if _, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quotedSchema)); err != nil {
		fmt.Fprintf(os.Stderr, "error creating schema: %v\n", err)
		os.Exit(1)
	}

	// Configure goose to use the configured schema for its version table.
	goose.SetTableName(pgx.Identifier{cfg.Database.Schema, "goose_db_version"}.Sanitize())

	if err := goose.SetDialect("postgres"); err != nil {
		fmt.Fprintf(os.Stderr, "error setting dialect: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	switch command {
	case "up":
		if err := migrateAuthorityUp(ctx, db, migrationsDir); err != nil {
			fmt.Fprintf(os.Stderr, "error applying migrations: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Authority migrations applied successfully through v%d.\n", authorityMigrationCeiling)

	case "status":
		if err := goose.StatusContext(ctx, db, migrationsDir); err != nil {
			fmt.Fprintf(os.Stderr, "error getting status: %v\n", err)
			os.Exit(1)
		}

	case "version":
		v, err := goose.GetDBVersionContext(ctx, db)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting version: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Current migration version: %d\n", v)

	case "reset":
		if !*confirmReset {
			fmt.Fprintf(os.Stderr, "error: reset requires --confirm flag\n")
			os.Exit(1)
		}
		if err := goose.ResetContext(ctx, db, migrationsDir); err != nil {
			fmt.Fprintf(os.Stderr, "error resetting migrations: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("All migrations rolled back.")

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		flag.Usage()
		os.Exit(1)
	}
}

func authorityMigrationTarget(current int64) (int64, error) {
	if current < 0 {
		return 0, fmt.Errorf("authority migration version %d is invalid", current)
	}
	if current > authorityMigrationCeiling {
		return 0, fmt.Errorf("authority migration version %d exceeds the supported production ceiling v%d; do not downgrade or apply retired shared-store migrations", current, authorityMigrationCeiling)
	}
	return authorityMigrationCeiling, nil
}

func migrateAuthorityUp(ctx context.Context, db *sql.DB, migrationsDir string) error {
	current, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return fmt.Errorf("read current authority migration version: %w", err)
	}
	target, err := authorityMigrationTarget(current)
	if err != nil {
		return err
	}
	if err := goose.UpToContext(ctx, db, migrationsDir, target); err != nil {
		return err
	}
	applied, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return fmt.Errorf("verify authority migration version: %w", err)
	}
	if applied != target {
		return fmt.Errorf("authority migration stopped at v%d, want v%d", applied, target)
	}
	return nil
}

// openDB opens a *sql.DB using pgx's stdlib adapter so goose can use it.
func openDB(cfg config.Config) (*sql.DB, error) {
	connConfig, err := pgx.ParseConfig(cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	// Set the search_path to the configured schema so all migrations
	// operate in the correct schema.
	if connConfig.RuntimeParams == nil {
		connConfig.RuntimeParams = make(map[string]string)
	}
	connConfig.RuntimeParams["search_path"] = cfg.Database.Schema
	return stdlib.OpenDB(*connConfig), nil
}
