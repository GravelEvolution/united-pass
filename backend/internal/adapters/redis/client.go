// Package redis provides Redis adapter implementations for United Pass
// ephemeral state: browser sessions, MFA challenges, and rate limit counters.
// This package owns all go-redis interaction; domain and application packages
// depend on store interfaces, never on redis.Client types.
//
// Redis is NOT a persistent store in United Pass. It holds only ephemeral,
// expiring data: sessions, MFA challenges, and rate-limit counters. No user
// identity, identity links, or personas are stored here. See ADR-0002.
package redis

import (
	"context"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/GravelEvolution/united-pass/backend/internal/config"
)

// Client wraps a *redis.Client with a key prefix used to namespace all United
// Pass keys. The wrapper isolates go-redis types from domain code and provides
// a readiness-friendly Ping helper.
type Client struct {
	rdb       *goredis.Client
	keyPrefix string
}

// NewClient creates a Redis client from the provided configuration. It parses
// the URL with redis.ParseURL and overrides pool and timeout settings from the
// config. The key prefix is stored for use by stores to construct namespaced
// keys.
//
// The key prefix (e.g. "up:development:") namespaces keys per environment so
// development, test, and production never collide. See ADR-0002 section 8.
func NewClient(cfg config.RedisConfig) (*Client, error) {
	opts, err := goredis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("redis: parse URL: %w", err)
	}

	if cfg.PoolSize > 0 {
		opts.PoolSize = cfg.PoolSize
	}
	if cfg.ConnectTimeout > 0 {
		opts.DialTimeout = cfg.ConnectTimeout
	}
	if cfg.ReadTimeout > 0 {
		opts.ReadTimeout = cfg.ReadTimeout
	}
	if cfg.WriteTimeout > 0 {
		opts.WriteTimeout = cfg.WriteTimeout
	}

	rdb := goredis.NewClient(opts)

	return &Client{
		rdb:       rdb,
		keyPrefix: cfg.KeyPrefix,
	}, nil
}

// Ping verifies Redis connectivity. It is suitable for readiness checks
// (/readyz). A short context timeout should be applied by the caller so a slow
// or unreachable Redis degrades readiness quickly rather than blocking.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis: ping: %w", err)
	}
	return nil
}

// Close releases the Redis connection pool. It should be invoked during
// graceful shutdown. The error, if any, is from the underlying client close.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// RDB returns the underlying *redis.Client. This accessor is intended for use
// by stores within this package and for advanced integration scenarios. Domain
// and application code must not call this method.
func (c *Client) RDB() *goredis.Client {
	return c.rdb
}

// KeyPrefix returns the configured key prefix used to namespace keys.
func (c *Client) KeyPrefix() string {
	return c.keyPrefix
}

// buildKey constructs a namespaced Redis key by joining the prefix and parts.
// Callers must ensure that parts contain only hashes, never raw tokens, emails,
// or identifiers. This is enforced by the store methods that call it.
func (c *Client) buildKey(parts ...string) string {
	var b strings.Builder
	b.Grow(len(c.keyPrefix))
	b.WriteString(c.keyPrefix)
	for _, p := range parts {
		b.WriteString(p)
	}
	return b.String()
}
