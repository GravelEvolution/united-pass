// Package postgres provides PostgreSQL adapter implementations for United Pass
// domain repositories. This package owns all SQL and pgx interaction; domain
// and application packages depend on repository interfaces, never on pgx types.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
)

// Pool wraps a *pgxpool.Pool with readiness-friendly helpers. The pool does
// NOT auto-run migrations; schema migrations are applied explicitly through
// the separate cmd/migrate command (see ADR-0002 section 11).
type Pool struct {
	pool *pgxpool.Pool
}

// NewPool creates a connection pool from the database configuration stored in
// cfg. It parses the database URL, applies MaxConns, MinConns and the connect
// timeout, and sets the search_path runtime parameter to the configured schema
// so every connection defaults to the correct schema without per-query
// qualification.
//
// The pool does NOT run migrations. Callers must run migrations explicitly via
// cmd/migrate before or after pool creation.
func NewPool(ctx context.Context, cfg config.Config) (*Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse database URL: %w", err)
	}

	poolConfig.MaxConns = cfg.Database.MaxConns
	poolConfig.MinConns = cfg.Database.MinConns
	poolConfig.ConnConfig.ConnectTimeout = cfg.Database.ConnectTimeout

	// Set search_path so all queries operate in the configured schema by
	// default. This mirrors the migration tool's search_path behaviour and
	// avoids requiring schema-qualified table names in repository queries.
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = cfg.Database.Schema

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("postgres: create connection pool: %w", err)
	}

	return &Pool{pool: pool}, nil
}

// Ping verifies database connectivity within the given timeout. It is suitable
// for readiness checks (/readyz). A short timeout should be used so a slow or
// unreachable database degrades readiness quickly rather than blocking the
// health endpoint.
func (p *Pool) Ping(ctx context.Context, timeout time.Duration) error {
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := p.pool.Ping(pingCtx); err != nil {
		return fmt.Errorf("postgres: ping database: %w", err)
	}
	return nil
}

// Close releases all connections in the pool. It is idempotent and safe to
// call multiple times. This should be invoked during graceful shutdown.
func (p *Pool) Close() {
	p.pool.Close()
}

// PgxPool returns the underlying *pgxpool.Pool for use by repositories and
// transaction management. Repositories accept *pgxpool.Pool directly so they
// can be constructed independently of this wrapper.
func (p *Pool) PgxPool() *pgxpool.Pool {
	return p.pool
}
