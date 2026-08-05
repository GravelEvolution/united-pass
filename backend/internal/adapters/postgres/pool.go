// Package postgres provides PostgreSQL adapter implementations for United Pass
// domain repositories. This package owns all SQL and pgx interaction; domain
// and application packages depend on repository interfaces, never on pgx types.
package postgres

import (
	"context"
	"fmt"
	"net/url"
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
// When cfg.Database.AllowInsecure is true (and the environment is not
// production), the database URL is rewritten to set sslmode=disable so pgx
// does not attempt a TLS handshake. This is only for development against a
// remote server that does not support TLS.
//
// The pool does NOT run migrations. Callers must run migrations explicitly via
// cmd/migrate before or after pool creation.
func NewPool(ctx context.Context, cfg config.Config) (*Pool, error) {
	dbURL := cfg.Database.URL
	if cfg.Database.AllowInsecure && !cfg.IsProduction() {
		rewritten, err := RewriteURLForInsecureMode(dbURL)
		if err != nil {
			return nil, fmt.Errorf("postgres: rewrite URL for insecure mode: %w", err)
		}
		dbURL = rewritten
	}

	poolConfig, err := pgxpool.ParseConfig(dbURL)
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

// RewriteURLForInsecureMode rewrites a PostgreSQL connection URL to set
// sslmode=disable, preventing pgx from attempting a TLS handshake. This is
// exported so that integration tests (which create their own pgx connections
// for migrations outside of NewPool) can apply the same rewriting.
//
// Callers must ensure this is only used in non-production environments.
func RewriteURLForInsecureMode(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	q := u.Query()
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()
	return u.String(), nil
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
