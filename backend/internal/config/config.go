//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Application configuration model and environment loading
//

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

	defaultSecurityProviderDeadline      = 10 * time.Second
	defaultSecurityLeaseTTL              = 60 * time.Second
	defaultSecuritySettlementTimeout     = 15 * time.Second
	defaultSecurityRecoveryTimeout       = 15 * time.Second
	defaultSecurityMaxSettlementAttempts = 3

	defaultFeishuBaseURL           = "https://open.feishu.cn"
	defaultFeishuAuthorizeURL      = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	defaultFeishuContactScope      = "应用通讯录授权范围"
	defaultFeishuOAuthStateTTL     = 5 * time.Minute
	defaultFeishuRequestTimeout    = 15 * time.Second
	defaultFeishuReconcileInterval = 15 * time.Second
	defaultFeishuSyncTimeout       = 2 * time.Minute
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

	// Phase 4 — Security generation and password mutation intents (ADR-0007)
	SecurityState SecurityStateConfig

	// Phase 3 — OAuth endpoint topology
	OAuth OAuthConfig

	// Phase 6 — Feishu login and directory Provider
	Feishu FeishuConfig

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

// SecurityStateConfig holds the ADR-0007 security generation (epoch) and
// durable password mutation intent parameters. PostgreSQL is the single
// authority for the epoch and the intent ledger; Redis may mirror hot-path
// state at most and never decides.
type SecurityStateConfig struct {
	// ProviderDeadline bounds the provider SetPassword call.
	ProviderDeadline time.Duration
	// LeaseTTL bounds the active intent lease before a takeover may
	// proceed. It must strictly outlive the provider deadline plus the
	// settlement timeout (the frozen safety margin) so a live, legitimate
	// mutation always owns its fence.
	LeaseTTL time.Duration
	// SettlementTimeout bounds the detached settlement run after the
	// provider outcome is known.
	SettlementTimeout time.Duration
	// RecoveryTimeout bounds each detached opportunistic recovery run.
	RecoveryTimeout time.Duration
	// MaxSettlementAttempts bounds takeover settlement retries before the
	// intent is force-settled degraded (bounded terminalization, F6).
	MaxSettlementAttempts int
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

// OAuthConfig describes the public OAuth endpoint topology (ADR-0005 §1).
// The protocol endpoints themselves (authorize, token, revoke, introspect,
// keys, userinfo, end_session, device_authorization, discovery) live in the
// reverse proxy in front of the provider; Go and Next.js never implement
// them. PublicOrigin is the single browser-visible origin, and every other
// topology value is derived from it so the pieces can never drift apart.
type OAuthConfig struct {
	// PublicOrigin is the origin the reverse proxy serves the public OAuth
	// endpoints on (e.g. "https://id.example.com"). It is an origin, not an
	// arbitrary base URL: scheme + host (+ optional port) only — no path
	// other than "/", no userinfo, query or fragment. It must never be
	// conflated with UP_AUTH_PROVIDER_BASE_URL, which is the internal
	// provider management/API address; this value is the browser-visible
	// issuer origin.
	PublicOrigin string
}

// FeishuConfig contains the server-only Phase 6 Provider configuration.
// AppSecret never leaves this typed configuration object and is never copied
// into API responses, database rows or logs.
type FeishuConfig struct {
	BaseURL           string
	AuthorizeURL      string
	AppID             string
	AppSecret         string
	TenantID          string
	RedirectURL       string
	ContactScope      string
	OAuthStateTTL     time.Duration
	RequestTimeout    time.Duration
	ReconcileInterval time.Duration
	SyncTimeout       time.Duration
}

// Configured reports whether the complete Feishu credential and tenant set
// is present. Partial sets are rejected by Config.Validate.
func (c FeishuConfig) Configured() bool {
	return c.AppID != "" && c.AppSecret != "" && c.TenantID != "" && c.RedirectURL != ""
}

// InteractionBaseURI derives the ZITADEL LoginV2 Interaction Base URI from
// the public origin: <origin>/_interaction. This is the only derivation in
// the system — there is deliberately no independent interaction base
// configuration. Returns "" when no public origin is configured.
func (c OAuthConfig) InteractionBaseURI() string {
	if c.PublicOrigin == "" {
		return ""
	}
	return strings.TrimRight(c.PublicOrigin, "/") + "/_interaction"
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

		SecurityState: SecurityStateConfig{
			ProviderDeadline:      durationOr("UP_SECURITY_PROVIDER_DEADLINE", defaultSecurityProviderDeadline),
			LeaseTTL:              durationOr("UP_SECURITY_LEASE_TTL", defaultSecurityLeaseTTL),
			SettlementTimeout:     durationOr("UP_SECURITY_SETTLEMENT_TIMEOUT", defaultSecuritySettlementTimeout),
			RecoveryTimeout:       durationOr("UP_SECURITY_RECOVERY_TIMEOUT", defaultSecurityRecoveryTimeout),
			MaxSettlementAttempts: intOr("UP_SECURITY_MAX_SETTLEMENT_ATTEMPTS", defaultSecurityMaxSettlementAttempts),
		},

		OAuth: OAuthConfig{
			PublicOrigin: envOr("UP_OAUTH_PUBLIC_ORIGIN", ""),
		},

		Feishu: FeishuConfig{
			BaseURL:           envOr("UP_FEISHU_BASE_URL", defaultFeishuBaseURL),
			AuthorizeURL:      envOr("UP_FEISHU_AUTHORIZE_URL", defaultFeishuAuthorizeURL),
			AppID:             envOr("UP_FEISHU_APP_ID", ""),
			AppSecret:         envOr("UP_FEISHU_APP_SECRET", ""),
			TenantID:          envOr("UP_FEISHU_TENANT_ID", ""),
			RedirectURL:       envOr("UP_FEISHU_REDIRECT_URL", ""),
			ContactScope:      envOr("UP_FEISHU_CONTACT_SCOPE", defaultFeishuContactScope),
			OAuthStateTTL:     durationOr("UP_FEISHU_OAUTH_STATE_TTL", defaultFeishuOAuthStateTTL),
			RequestTimeout:    durationOr("UP_FEISHU_REQUEST_TIMEOUT", defaultFeishuRequestTimeout),
			ReconcileInterval: durationOr("UP_FEISHU_RECONCILE_INTERVAL", defaultFeishuReconcileInterval),
			SyncTimeout:       durationOr("UP_FEISHU_SYNC_TIMEOUT", defaultFeishuSyncTimeout),
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

	// Security state validation (ADR-0007).
	if c.SecurityState.ProviderDeadline <= 0 {
		errs = append(errs, errors.New("security state provider deadline must be positive"))
	}
	if c.SecurityState.SettlementTimeout <= 0 {
		errs = append(errs, errors.New("security state settlement timeout must be positive"))
	}
	if c.SecurityState.RecoveryTimeout <= 0 {
		errs = append(errs, errors.New("security state recovery timeout must be positive"))
	}
	if c.SecurityState.MaxSettlementAttempts <= 0 {
		errs = append(errs, errors.New("security state max settlement attempts must be positive"))
	}
	// Lease expiry must strictly outlive the provider deadline plus the
	// settlement timeout (the frozen safety margin): a live, legitimate
	// mutation must always own its fence until its authoritative work is
	// done.
	if c.SecurityState.LeaseTTL <= c.SecurityState.ProviderDeadline+c.SecurityState.SettlementTimeout {
		errs = append(errs, errors.New("security state lease TTL must strictly exceed the provider deadline plus the settlement timeout"))
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

	// OAuth topology validation (when configured). The public origin is an
	// origin, not a base URL; derived URIs (InteractionBaseURI) must never be
	// poisonable by extra URL components smuggled into the configuration.
	if c.OAuth.PublicOrigin != "" {
		if err := validateOAuthPublicOrigin(c.OAuth.PublicOrigin, c.IsProduction()); err != nil {
			errs = append(errs, err)
		}
	}

	// Feishu Provider validation. The integration is optional, but partial
	// credentials are never accepted because they produce a misleading
	// secretConfigured state and fail only after an administrator enables it.
	feishuValues := []string{c.Feishu.AppID, c.Feishu.AppSecret, c.Feishu.TenantID, c.Feishu.RedirectURL}
	configuredFeishuValues := 0
	for _, value := range feishuValues {
		if value != "" {
			configuredFeishuValues++
		}
	}
	if configuredFeishuValues != 0 && configuredFeishuValues != len(feishuValues) {
		errs = append(errs, errors.New("Feishu requires UP_FEISHU_APP_ID, UP_FEISHU_APP_SECRET, UP_FEISHU_TENANT_ID and UP_FEISHU_REDIRECT_URL together"))
	}
	if configuredFeishuValues > 0 {
		if c.Feishu.OAuthStateTTL <= 0 || c.Feishu.OAuthStateTTL > 15*time.Minute {
			errs = append(errs, errors.New("Feishu OAuth state TTL must be positive and at most 15 minutes"))
		}
		if c.Feishu.RequestTimeout <= 0 || c.Feishu.ReconcileInterval <= 0 || c.Feishu.SyncTimeout <= 0 {
			errs = append(errs, errors.New("Feishu request, reconciliation and sync durations must be positive"))
		}
	}
	if c.Feishu.Configured() {
		if len(c.Feishu.AppID) > 256 || len(c.Feishu.AppSecret) > 512 || len(c.Feishu.TenantID) > 256 {
			errs = append(errs, errors.New("Feishu credential or tenant identifier exceeds the allowed length"))
		}
		if strings.TrimSpace(c.Feishu.ContactScope) == "" || len(c.Feishu.ContactScope) > 256 {
			errs = append(errs, errors.New("Feishu contact scope label must be 1 to 256 bytes"))
		}
		if err := validateProviderURL(c.Feishu.BaseURL, c.IsProduction(), false); err != nil {
			errs = append(errs, fmt.Errorf("Feishu base URL: %w", err))
		}
		if err := validateProviderURL(c.Feishu.AuthorizeURL, c.IsProduction(), true); err != nil {
			errs = append(errs, fmt.Errorf("Feishu authorization URL: %w", err))
		}
		if err := validateFeishuRedirectURL(c.Feishu.RedirectURL, c.IsProduction()); err != nil {
			errs = append(errs, err)
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
		// The public OAuth topology is mandatory in production: the issuer,
		// the LoginV2 Interaction Base URI and the provisioned app
		// configuration are all derived from it.
		if c.OAuth.PublicOrigin == "" {
			errs = append(errs, errors.New("production requires UP_OAUTH_PUBLIC_ORIGIN"))
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

// validateOAuthPublicOrigin enforces strict origin syntax: scheme://host[:port]
// with nothing else. A trailing "/" is tolerated and normalized away by
// InteractionBaseURI. Production additionally requires HTTPS.
func validateOAuthPublicOrigin(origin string, requireHTTPS bool) error {
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("oauth public origin is invalid: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if requireHTTPS {
			return errors.New("oauth public origin must use https in production")
		}
	default:
		return fmt.Errorf("oauth public origin scheme %q must be http or https", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("oauth public origin must include a host")
	}
	if u.User != nil {
		return errors.New("oauth public origin must not contain userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("oauth public origin must not contain a path, got %q", u.Path)
	}
	if u.RawQuery != "" {
		return errors.New("oauth public origin must not contain a query")
	}
	if u.Fragment != "" {
		return errors.New("oauth public origin must not contain a fragment")
	}
	return nil
}

func validateProviderURL(raw string, requireHTTPS, allowPath bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && (requireHTTPS || u.Scheme != "http") {
		return errors.New("URL must use https")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("URL must include a host and must not contain userinfo, query or fragment")
	}
	if !allowPath && u.Path != "" && u.Path != "/" {
		return errors.New("base URL must not contain a path")
	}
	return nil
}

func validateFeishuRedirectURL(raw string, requireHTTPS bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("Feishu redirect URL is invalid: %w", err)
	}
	if u.Scheme != "https" && (requireHTTPS || u.Scheme != "http") {
		return errors.New("Feishu redirect URL must use https")
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return errors.New("Feishu redirect URL must include a host and must not contain userinfo, query or fragment")
	}
	if u.Path == "" || u.Path == "/" {
		return errors.New("Feishu redirect URL must contain the exact callback path")
	}
	if u.Path != "/api/v1/auth/providers/feishu/callback" {
		return errors.New("Feishu redirect URL path must be /api/v1/auth/providers/feishu/callback")
	}
	return nil
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
