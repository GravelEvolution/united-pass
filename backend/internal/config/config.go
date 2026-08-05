// Package config loads and validates typed runtime configuration for the
// United Pass API service. Configuration is concentrated here so the rest of
// the codebase never reads environment variables directly.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment classifies the deployment context. Production triggers stricter
// startup validation and security defaults.
type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentProduction  Environment = "production"
)

const (
	defaultHTTPAddr            = ":8080"
	defaultReadHeaderTimeout   = 5 * time.Second
	defaultReadTimeout         = 15 * time.Second
	defaultWriteTimeout        = 30 * time.Second
	defaultIdleTimeout         = 60 * time.Second
	defaultShutdownTimeout     = 30 * time.Second
	defaultMaxRequestBodyBytes = 1 << 20 // 1 MiB
	defaultLogLevel            = "info"
)

// Config holds all process-level configuration. Values are loaded once at
// startup and treated as immutable for the lifetime of the process.
type Config struct {
	Environment         Environment
	HTTPAddr            string
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	ShutdownTimeout     time.Duration
	MaxRequestBodyBytes int64
	LogLevel            string
}

// Load reads configuration from environment variables, applying development
// defaults for any value that is not explicitly set.
func Load() (Config, error) {
	cfg := Config{
		Environment:         Environment(envOr("UP_ENVIRONMENT", string(EnvironmentDevelopment))),
		HTTPAddr:            envOr("UP_HTTP_ADDR", defaultHTTPAddr),
		ReadHeaderTimeout:   durationOr("UP_READ_HEADER_TIMEOUT", defaultReadHeaderTimeout),
		ReadTimeout:         durationOr("UP_READ_TIMEOUT", defaultReadTimeout),
		WriteTimeout:        durationOr("UP_WRITE_TIMEOUT", defaultWriteTimeout),
		IdleTimeout:         durationOr("UP_IDLE_TIMEOUT", defaultIdleTimeout),
		ShutdownTimeout:     durationOr("UP_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		MaxRequestBodyBytes: int64Or("UP_MAX_REQUEST_BODY_BYTES", defaultMaxRequestBodyBytes),
		LogLevel:            envOr("UP_LOG_LEVEL", defaultLogLevel),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate enforces invariants. Production requires explicit, safe settings and
// rejects any configuration that would weaken security or availability.
func (c Config) Validate() error {
	var errs []error

	switch c.Environment {
	case EnvironmentDevelopment, EnvironmentProduction:
	default:
		errs = append(errs, fmt.Errorf("invalid environment %q: must be %q or %q",
			c.Environment, EnvironmentDevelopment, EnvironmentProduction))
	}

	if c.HTTPAddr == "" {
		errs = append(errs, errors.New("http address must not be empty"))
	}
	if c.ReadHeaderTimeout <= 0 {
		errs = append(errs, errors.New("read header timeout must be positive"))
	}
	if c.ReadTimeout <= 0 {
		errs = append(errs, errors.New("read timeout must be positive"))
	}
	if c.WriteTimeout <= 0 {
		errs = append(errs, errors.New("write timeout must be positive"))
	}
	if c.IdleTimeout <= 0 {
		errs = append(errs, errors.New("idle timeout must be positive"))
	}
	if c.ShutdownTimeout <= 0 {
		errs = append(errs, errors.New("shutdown timeout must be positive"))
	}
	if c.MaxRequestBodyBytes <= 0 {
		errs = append(errs, errors.New("max request body bytes must be positive"))
	}

	if _, err := parseLogLevel(c.LogLevel); err != nil {
		errs = append(errs, err)
	}

	if c.IsProduction() {
		if c.ShutdownTimeout > 60*time.Second {
			errs = append(errs, errors.New("production shutdown timeout must not exceed 60s"))
		}
		if c.MaxRequestBodyBytes > 16*(1<<20) {
			errs = append(errs, errors.New("production max request body bytes must not exceed 16 MiB"))
		}
	}

	return errors.Join(errs...)
}

// IsProduction reports whether the process runs in the production environment.
func (c Config) IsProduction() bool {
	return c.Environment == EnvironmentProduction
}

// LogLevel returns the parsed slog.Level for the configured log level.
func (c Config) LogLevelValue() (slog.Level, error) {
	return parseLogLevel(c.LogLevel)
}

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q: must be debug, info, warn or error", raw)
	}
}

func envOr(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func durationOr(key string, fallback time.Duration) time.Duration {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := time.ParseDuration(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func int64Or(key string, fallback int64) int64 {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			return parsed
		}
	}
	return fallback
}
