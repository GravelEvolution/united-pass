// Package config loads and validates typed runtime configuration for the
// United Pass API service. Configuration is concentrated here so the rest of
// the codebase never reads environment variables directly.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
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

	defaultDatabaseSchema               = "united_pass"
	defaultDatabaseMaxConns       int32 = 10
	defaultDatabaseMinConns       int32 = 1
	defaultDatabaseConnectTimeout       = 10 * time.Second

	defaultRedisKeyPrefix          = "up:development:"
	defaultRedisPoolSize       int = 10
	defaultRedisConnectTimeout     = 10 * time.Second
	defaultRedisReadTimeout        = 3 * time.Second
	defaultRedisWriteTimeout       = 3 * time.Second

	defaultSessionTTL           = 12 * time.Hour
	defaultSessionRememberTTL   = 720 * time.Hour
	defaultSessionIdleTTL       = 2 * time.Hour
	defaultSessionTouchInterval = 5 * time.Minute
	defaultSessionSameSite      = "lax"

	defaultMFAChallengeTTL = 5 * time.Minute
	defaultMFAMaxAttempts  = 5
	defaultLoginRateLimit  = 10
	defaultLoginRateWindow = 15 * time.Minute
	defaultMFARateLimit    = 10
	defaultMFARateWindow   = 15 * time.Minute

	defaultReauthChallengeTTL    = 5 * time.Minute
	defaultReauthGrantTTL        = 5 * time.Minute
	defaultReauthMaxAttempts     = 5
	defaultReauthRateLimit       = 10
	defaultReauthRateWindow      = 15 * time.Minute
	defaultReauthCleanupInterval = 60 * time.Second

	defaultRotationGracePeriod = time.Duration(0)
	defaultRotationRateLimit   = 3
	defaultRotationRateWindow  = 15 * time.Minute
)

// Config holds all process-level configuration. Values are loaded once at
// startup and treated as immutable for the lifetime of the process.
type Config struct {
	// Phase 0 — HTTP server
	Environment         Environment
	HTTPAddr            string
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	ShutdownTimeout     time.Duration
	MaxRequestBodyBytes int64
	LogLevel            string

	// Phase 1 — Storage
	Database DatabaseConfig
	Redis    RedisConfig

	// Phase 1 — Session
	Session SessionConfig

	// Phase 1 — Authentication
	MFA       MFAConfig
	RateLimit RateLimitConfig
	Auth      AuthProviderConfig

	// Phase 1 — Permissions
	Permission PermissionConfig

	// Phase 2 — Reauthentication and secret rotation
	Reauth   ReauthConfig
	Rotation RotationConfig

	// Integration tests
	Test TestConfig
}

// DatabaseConfig holds PostgreSQL connection parameters.
type DatabaseConfig struct {
	URL            string
	Schema         string
	MaxConns       int32
	MinConns       int32
	ConnectTimeout time.Duration
}

// RedisConfig holds Redis connection parameters.
type RedisConfig struct {
	URL            string
	KeyPrefix      string
	PoolSize       int
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
}

// SessionConfig holds browser session parameters.
type SessionConfig struct {
	TTL             time.Duration
	RememberTTL     time.Duration
	IdleTTL         time.Duration
	TouchInterval   time.Duration
	CookieSecure    bool
	CookieSameSite  string
	EncryptionKey   string // base64-encoded 32-byte AES-GCM key
	EncryptionKeyID string
}

// MFAConfig holds MFA challenge parameters.
type MFAConfig struct {
	ChallengeTTL time.Duration
	MaxAttempts  int
}

// RateLimitConfig holds rate limiting parameters.
type RateLimitConfig struct {
	LoginLimit  int
	LoginWindow time.Duration
	MFALimit    int
	MFAWindow   time.Duration
}

// ReauthConfig holds reauthentication challenge and grant parameters
// (ADR-0004 §7). Challenges and grants are short-lived, single-use and
// bound to user + session + action + target resource.
type ReauthConfig struct {
	ChallengeTTL time.Duration
	GrantTTL     time.Duration
	MaxAttempts  int
	RateLimit    int
	RateWindow   time.Duration
	// CleanupInterval is how often the abandoned-challenge cleanup worker
	// sweeps the Redis cleanup index and revokes leaked provider sessions.
	CleanupInterval time.Duration
}

// RotationConfig holds OAuth client secret rotation parameters (ADR-0004 §6).
// GracePeriod is the overlap window reported as previousSecretExpiresAt;
// against ZITADEL v2.71 the effective grace period is zero because the
// provider invalidates the previous secret immediately.
type RotationConfig struct {
	GracePeriod time.Duration
	RateLimit   int
	RateWindow  time.Duration
}

// AuthProviderConfig holds authentication provider parameters.
type AuthProviderConfig struct {
	Provider     string
	BaseURL      string
	ProjectID    string
	ClientID     string
	ClientSecret string
	// ServiceAccountKeyFile is the path to the ZITADEL service account
	// key.json used for JWT profile authentication to the ZITADEL API. The
	// key file is read at adapter construction; it must contain the keyId
	// and the RSA private key.
	ServiceAccountKeyFile string
	// Domain is the WebAuthn relying-party domain used for passkey MFA
	// challenges (e.g. "login.example.com"). It must be the exact domain or
	// a top-level domain of the request origin. Empty disables passkey
	// challenges (TOTP remains available).
	Domain string
}

// PermissionConfig holds permission resolver parameters.
type PermissionConfig struct {
	DevOverrideEnabled bool
	DevOverrideUserID  string
}

// TestConfig holds integration test environment parameters.
type TestConfig struct {
	DatabaseURL    string
	DatabaseSchema string
	RedisURL       string
	RedisKeyPrefix string
}

// Load reads configuration from environment variables, applying development
// defaults for any value that is not explicitly set. Call LoadDotEnv first in
// local development to populate variables from an ignored .env file.
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

		Database: DatabaseConfig{
			URL:            envOr("UP_DATABASE_URL", ""),
			Schema:         envOr("UP_DATABASE_SCHEMA", defaultDatabaseSchema),
			MaxConns:       int32Or("UP_DATABASE_MAX_CONNS", defaultDatabaseMaxConns),
			MinConns:       int32Or("UP_DATABASE_MIN_CONNS", defaultDatabaseMinConns),
			ConnectTimeout: durationOr("UP_DATABASE_CONNECT_TIMEOUT", defaultDatabaseConnectTimeout),
		},

		Redis: RedisConfig{
			URL:            envOr("UP_REDIS_URL", ""),
			KeyPrefix:      envOr("UP_REDIS_KEY_PREFIX", defaultRedisKeyPrefix),
			PoolSize:       intOr("UP_REDIS_POOL_SIZE", defaultRedisPoolSize),
			ConnectTimeout: durationOr("UP_REDIS_CONNECT_TIMEOUT", defaultRedisConnectTimeout),
			ReadTimeout:    durationOr("UP_REDIS_READ_TIMEOUT", defaultRedisReadTimeout),
			WriteTimeout:   durationOr("UP_REDIS_WRITE_TIMEOUT", defaultRedisWriteTimeout),
		},

		Session: SessionConfig{
			TTL:             durationOr("UP_SESSION_TTL", defaultSessionTTL),
			RememberTTL:     durationOr("UP_SESSION_REMEMBER_TTL", defaultSessionRememberTTL),
			IdleTTL:         durationOr("UP_SESSION_IDLE_TTL", defaultSessionIdleTTL),
			TouchInterval:   durationOr("UP_SESSION_TOUCH_INTERVAL", defaultSessionTouchInterval),
			CookieSecure:    boolOr("UP_SESSION_COOKIE_SECURE", true),
			CookieSameSite:  envOr("UP_SESSION_COOKIE_SAME_SITE", defaultSessionSameSite),
			EncryptionKey:   envOr("UP_SESSION_ENCRYPTION_KEY", ""),
			EncryptionKeyID: envOr("UP_SESSION_ENCRYPTION_KEY_ID", ""),
		},

		MFA: MFAConfig{
			ChallengeTTL: durationOr("UP_MFA_CHALLENGE_TTL", defaultMFAChallengeTTL),
			MaxAttempts:  intOr("UP_MFA_MAX_ATTEMPTS", defaultMFAMaxAttempts),
		},

		RateLimit: RateLimitConfig{
			LoginLimit:  intOr("UP_LOGIN_RATE_LIMIT", defaultLoginRateLimit),
			LoginWindow: durationOr("UP_LOGIN_RATE_WINDOW", defaultLoginRateWindow),
			MFALimit:    intOr("UP_MFA_RATE_LIMIT", defaultMFARateLimit),
			MFAWindow:   durationOr("UP_MFA_RATE_WINDOW", defaultMFARateWindow),
		},

		Auth: AuthProviderConfig{
			Provider:              envOr("UP_AUTH_PROVIDER", ""),
			BaseURL:               envOr("UP_AUTH_PROVIDER_BASE_URL", ""),
			ProjectID:             envOr("UP_AUTH_PROVIDER_PROJECT_ID", ""),
			ClientID:              envOr("UP_AUTH_PROVIDER_CLIENT_ID", ""),
			ClientSecret:          envOr("UP_AUTH_PROVIDER_CLIENT_SECRET", ""),
			ServiceAccountKeyFile: envOr("UP_AUTH_PROVIDER_SERVICE_ACCOUNT_KEY_FILE", ""),
			Domain:                envOr("UP_AUTH_PROVIDER_DOMAIN", ""),
		},

		Permission: PermissionConfig{
			DevOverrideEnabled: boolOr("UP_PERMISSION_DEV_OVERRIDE", false),
			DevOverrideUserID:  envOr("UP_PERMISSION_DEV_OVERRIDE_USER_ID", ""),
		},

		Reauth: ReauthConfig{
			ChallengeTTL:    durationOr("UP_REAUTH_CHALLENGE_TTL", defaultReauthChallengeTTL),
			GrantTTL:        durationOr("UP_REAUTH_GRANT_TTL", defaultReauthGrantTTL),
			MaxAttempts:     intOr("UP_REAUTH_MAX_ATTEMPTS", defaultReauthMaxAttempts),
			RateLimit:       intOr("UP_REAUTH_RATE_LIMIT", defaultReauthRateLimit),
			RateWindow:      durationOr("UP_REAUTH_RATE_WINDOW", defaultReauthRateWindow),
			CleanupInterval: durationOr("UP_REAUTH_CLEANUP_INTERVAL", defaultReauthCleanupInterval),
		},

		Rotation: RotationConfig{
			GracePeriod: durationOr("UP_SECRET_ROTATION_GRACE_PERIOD", defaultRotationGracePeriod),
			RateLimit:   intOr("UP_SECRET_ROTATION_RATE_LIMIT", defaultRotationRateLimit),
			RateWindow:  durationOr("UP_SECRET_ROTATION_RATE_WINDOW", defaultRotationRateWindow),
		},

		Test: TestConfig{
			DatabaseURL:    envOr("UP_TEST_DATABASE_URL", ""),
			DatabaseSchema: envOr("UP_TEST_DATABASE_SCHEMA", "united_pass_test"),
			RedisURL:       envOr("UP_TEST_REDIS_URL", ""),
			RedisKeyPrefix: envOr("UP_TEST_REDIS_KEY_PREFIX", "up:test:"),
		},
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

	// Session validation.
	if c.Session.TTL <= 0 {
		errs = append(errs, errors.New("session TTL must be positive"))
	}
	if c.Session.EncryptionKey != "" {
		key, err := base64.StdEncoding.DecodeString(c.Session.EncryptionKey)
		if err != nil {
			errs = append(errs, errors.New("session encryption key must be base64-encoded"))
		} else if len(key) != 32 {
			errs = append(errs, fmt.Errorf("session encryption key must decode to 32 bytes, got %d", len(key)))
		}
		// The ciphertext format is "{keyID}:{payload}"; a ':' in the key ID
		// would break parsing and could collide with other key IDs.
		if strings.Contains(c.Session.EncryptionKeyID, ":") {
			errs = append(errs, errors.New("session encryption key id must not contain ':'"))
		}
	}
	if c.Session.RememberTTL <= 0 {
		errs = append(errs, errors.New("session remember TTL must be positive"))
	}
	if c.Session.IdleTTL <= 0 {
		errs = append(errs, errors.New("session idle TTL must be positive"))
	}
	if c.Session.TouchInterval <= 0 {
		errs = append(errs, errors.New("session touch interval must be positive"))
	}
	switch strings.ToLower(c.Session.CookieSameSite) {
	case "lax", "strict", "none":
	default:
		errs = append(errs, fmt.Errorf("invalid session cookie SameSite %q: must be lax, strict or none", c.Session.CookieSameSite))
	}

	// MFA validation.
	if c.MFA.ChallengeTTL <= 0 {
		errs = append(errs, errors.New("MFA challenge TTL must be positive"))
	}
	if c.MFA.MaxAttempts <= 0 {
		errs = append(errs, errors.New("MFA max attempts must be positive"))
	}

	// Reauthentication validation.
	if c.Reauth.ChallengeTTL <= 0 {
		errs = append(errs, errors.New("reauthentication challenge TTL must be positive"))
	}
	if c.Reauth.GrantTTL <= 0 {
		errs = append(errs, errors.New("reauthentication grant TTL must be positive"))
	}
	if c.Reauth.MaxAttempts <= 0 {
		errs = append(errs, errors.New("reauthentication max attempts must be positive"))
	}
	if c.Reauth.RateLimit <= 0 {
		errs = append(errs, errors.New("reauthentication rate limit must be positive"))
	}
	if c.Reauth.RateWindow <= 0 {
		errs = append(errs, errors.New("reauthentication rate window must be positive"))
	}
	if c.Reauth.CleanupInterval <= 0 {
		errs = append(errs, errors.New("reauthentication cleanup interval must be positive"))
	}

	// Secret rotation validation.
	if c.Rotation.GracePeriod < 0 {
		errs = append(errs, errors.New("secret rotation grace period must not be negative"))
	}
	if c.Rotation.RateLimit <= 0 {
		errs = append(errs, errors.New("secret rotation rate limit must be positive"))
	}
	if c.Rotation.RateWindow <= 0 {
		errs = append(errs, errors.New("secret rotation rate window must be positive"))
	}

	// Rate limit validation.
	if c.RateLimit.LoginLimit <= 0 {
		errs = append(errs, errors.New("login rate limit must be positive"))
	}
	if c.RateLimit.LoginWindow <= 0 {
		errs = append(errs, errors.New("login rate window must be positive"))
	}
	if c.RateLimit.MFALimit <= 0 {
		errs = append(errs, errors.New("MFA rate limit must be positive"))
	}
	if c.RateLimit.MFAWindow <= 0 {
		errs = append(errs, errors.New("MFA rate window must be positive"))
	}

	// Database validation (when configured).
	if c.Database.URL != "" {
		if c.Database.Schema == "" {
			errs = append(errs, errors.New("database schema must not be empty when database URL is set"))
		} else if !ValidSchemaIdentifier(c.Database.Schema) {
			errs = append(errs, fmt.Errorf("database schema %q is not a valid PostgreSQL identifier", c.Database.Schema))
		}
		if c.Database.MaxConns <= 0 {
			errs = append(errs, errors.New("database max connections must be positive"))
		}
		if c.Database.MinConns < 0 {
			errs = append(errs, errors.New("database min connections must not be negative"))
		}
		if c.Database.ConnectTimeout <= 0 {
			errs = append(errs, errors.New("database connect timeout must be positive"))
		}
	}

	// Redis validation (when configured).
	if c.Redis.URL != "" {
		if c.Redis.KeyPrefix == "" {
			errs = append(errs, errors.New("redis key prefix must not be empty when redis URL is set"))
		}
		if c.Redis.PoolSize <= 0 {
			errs = append(errs, errors.New("redis pool size must be positive"))
		}
		if c.Redis.ConnectTimeout <= 0 {
			errs = append(errs, errors.New("redis connect timeout must be positive"))
		}
	}

	// Integration test validation (when configured).
	if c.Test.DatabaseURL != "" {
		if c.Test.DatabaseSchema == "" {
			errs = append(errs, errors.New("test database schema must not be empty when test database URL is set"))
		} else if !ValidSchemaIdentifier(c.Test.DatabaseSchema) {
			errs = append(errs, fmt.Errorf("test database schema %q is not a valid PostgreSQL identifier", c.Test.DatabaseSchema))
		}
	}

	if c.IsProduction() {
		if c.ShutdownTimeout > 60*time.Second {
			errs = append(errs, errors.New("production shutdown timeout must not exceed 60s"))
		}
		if c.MaxRequestBodyBytes > 16*(1<<20) {
			errs = append(errs, errors.New("production max request body bytes must not exceed 16 MiB"))
		}
		// Production requires TLS-capable database and Redis.
		if c.Database.URL == "" {
			errs = append(errs, errors.New("production requires UP_DATABASE_URL"))
		}
		if c.Redis.URL == "" {
			errs = append(errs, errors.New("production requires UP_REDIS_URL"))
		}
		if !c.Session.CookieSecure {
			errs = append(errs, errors.New("production requires UP_SESSION_COOKIE_SECURE=true"))
		}
		if c.Auth.Provider == "" || c.Auth.BaseURL == "" {
			errs = append(errs, errors.New("production requires authentication provider configuration"))
		}
		if c.Auth.Provider == "zitadel" && c.Auth.ServiceAccountKeyFile == "" {
			errs = append(errs, errors.New("zitadel provider requires UP_AUTH_PROVIDER_SERVICE_ACCOUNT_KEY_FILE"))
		}
		// Production ZITADEL must be reached over HTTPS. Rejecting plaintext
		// and URL injection prevents a misconfigured deployment from
		// downgrading the provider connection or leaking credentials.
		if c.Auth.BaseURL != "" {
			u, err := url.Parse(c.Auth.BaseURL)
			if err != nil {
				errs = append(errs, fmt.Errorf("authentication provider base URL is invalid: %w", err))
			} else {
				if u.Scheme != "https" {
					errs = append(errs, errors.New("production authentication provider base URL must use https"))
				}
				if u.Host == "" {
					errs = append(errs, errors.New("authentication provider base URL must include a host"))
				}
				if u.User != nil {
					errs = append(errs, errors.New("authentication provider base URL must not contain userinfo"))
				}
				if u.RawQuery != "" || u.Fragment != "" {
					errs = append(errs, errors.New("authentication provider base URL must not contain query or fragment"))
				}
			}
		}
		// Production stores provider session references encrypted at rest
		// (ADR-0002 section 13), so the encryption key is mandatory.
		if c.Session.EncryptionKey == "" {
			errs = append(errs, errors.New("production requires UP_SESSION_ENCRYPTION_KEY"))
		}
		if c.Permission.DevOverrideEnabled {
			errs = append(errs, errors.New("production must not enable permission dev override"))
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

// HasDatabase reports whether a database URL is configured.
func (c Config) HasDatabase() bool {
	return c.Database.URL != ""
}

// HasRedis reports whether a Redis URL is configured.
func (c Config) HasRedis() bool {
	return c.Redis.URL != ""
}

// HasAuthProvider reports whether an authentication provider is configured.
func (c Config) HasAuthProvider() bool {
	return c.Auth.Provider != "" && c.Auth.BaseURL != ""
}

// schemaIdentifierPattern restricts schema names to safe PostgreSQL
// identifiers: lowercase ASCII letters, digits and underscores, at most 63
// characters (PostgreSQL's NAMEDATALEN limit). Schema names from environment
// variables must never be interpolated into SQL without this check.
var schemaIdentifierPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// ValidSchemaIdentifier reports whether s is a safe PostgreSQL schema
// identifier. Schema names are interpolated into SQL (CREATE SCHEMA, goose
// version table name, cleanup statements), so they must be validated before
// use and quoted with pgx.Identifier when concatenated into statements.
func ValidSchemaIdentifier(s string) bool {
	return schemaIdentifierPattern.MatchString(s)
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

func int32Or(key string, fallback int32) int32 {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err == nil {
			return int32(parsed)
		}
	}
	return fallback
}

func intOr(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := strconv.Atoi(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func boolOr(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}
