// Package main applies only the forward-only DreamUP/Mini Program operational
// store migrations. It never reads UP_DATABASE_URL as its target.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <up|status|version>\n", os.Args[0])
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	command := flag.Arg(0)
	if command != "up" && command != "status" && command != "version" {
		fmt.Fprintln(os.Stderr, "error: isolated migrations are forward-only")
		os.Exit(1)
	}
	if _, err := os.Stat(filepath.Join(".", ".env")); err == nil {
		if _, err := config.LoadDotEnv(filepath.Join(".", ".env")); err != nil {
			fmt.Fprintln(os.Stderr, "error loading environment")
			os.Exit(1)
		}
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration is invalid")
		os.Exit(1)
	}
	if !cfg.HasIsolatedDatabase() {
		fmt.Fprintln(os.Stderr, "error: UP_ISOLATED_DATABASE_URL is not set")
		os.Exit(1)
	}
	migrationsDir := filepath.Join(".", "isolated-migrations")
	if _, err := os.Stat(migrationsDir); err != nil {
		fmt.Fprintln(os.Stderr, "error: isolated-migrations directory is unavailable")
		os.Exit(1)
	}
	db, err := openIsolatedDB(cfg.IsolatedDatabase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: isolated database is unavailable")
		os.Exit(1)
	}
	defer db.Close()
	quotedSchema := pgx.Identifier{cfg.IsolatedDatabase.Schema}.Sanitize()
	if command == "up" {
		if _, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quotedSchema)); err != nil {
			fmt.Fprintln(os.Stderr, "error: isolated schema could not be prepared")
			os.Exit(1)
		}
	}
	goose.SetTableName(pgx.Identifier{cfg.IsolatedDatabase.Schema, "goose_db_version"}.Sanitize())
	if err := goose.SetDialect("postgres"); err != nil {
		fmt.Fprintln(os.Stderr, "error: migration dialect is unavailable")
		os.Exit(1)
	}
	ctx := context.Background()
	switch command {
	case "up":
		err = goose.UpContext(ctx, db, migrationsDir)
	case "status":
		err = goose.StatusContext(ctx, db, migrationsDir)
	case "version":
		var version int64
		version, err = goose.GetDBVersionContext(ctx, db)
		if err == nil {
			fmt.Printf("Current isolated migration version: %d\n", version)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: isolated migration command failed")
		os.Exit(1)
	}
}

func openIsolatedDB(database config.DatabaseConfig) (*sql.DB, error) {
	connConfig, err := pgx.ParseConfig(database.URL)
	if err != nil {
		return nil, err
	}
	if connConfig.RuntimeParams == nil {
		connConfig.RuntimeParams = make(map[string]string)
	}
	connConfig.RuntimeParams["search_path"] = database.Schema
	return stdlib.OpenDB(*connConfig), nil
}
