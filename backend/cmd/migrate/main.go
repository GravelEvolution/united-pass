// Package main implements the migration command for United Pass.
//
// Usage:
//
//	go run ./cmd/migrate up          # Apply all pending migrations
//	go run ./cmd/migrate status       # Show migration status
//	go run ./cmd/migrate version      # Show current migration version
//	go run ./cmd/migrate reset        # Roll back all migrations (requires --confirm)
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

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func main() {
	confirmReset := flag.Bool("confirm", false, "Required for destructive operations (reset)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <command>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  up       Apply all pending migrations\n")
		fmt.Fprintf(os.Stderr, "  status   Show migration status\n")
		fmt.Fprintf(os.Stderr, "  version  Show current migration version\n")
		fmt.Fprintf(os.Stderr, "  reset    Roll back all migrations (requires --confirm)\n")
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

	// Create the configured schema if it doesn't exist. The migration files
	// no longer create the schema; the runner is responsible for creating it.
	if _, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", cfg.Database.Schema)); err != nil {
		fmt.Fprintf(os.Stderr, "error creating schema: %v\n", err)
		os.Exit(1)
	}

	// Configure goose to use the configured schema for its version table.
	goose.SetTableName(fmt.Sprintf("%s.goose_db_version", cfg.Database.Schema))

	if err := goose.SetDialect("postgres"); err != nil {
		fmt.Fprintf(os.Stderr, "error setting dialect: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	switch command {
	case "up":
		if err := goose.UpContext(ctx, db, migrationsDir); err != nil {
			fmt.Fprintf(os.Stderr, "error applying migrations: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Migrations applied successfully.")

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

// openDB opens a *sql.DB using pgx's stdlib adapter so goose can use it.
func openDB(cfg config.Config) (*sql.DB, error) {
	dbURL := cfg.Database.URL
	if cfg.Database.AllowInsecure && !cfg.IsProduction() {
		rewritten, err := postgres.RewriteURLForInsecureMode(dbURL)
		if err != nil {
			return nil, fmt.Errorf("rewrite URL for insecure mode: %w", err)
		}
		dbURL = rewritten
	}

	connConfig, err := pgx.ParseConfig(dbURL)
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
