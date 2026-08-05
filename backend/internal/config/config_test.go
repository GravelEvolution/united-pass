package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("UP_ENVIRONMENT", "development")
	// Clear optional overrides so defaults apply.
	clearEnv(t,
		"UP_HTTP_ADDR", "UP_READ_HEADER_TIMEOUT", "UP_READ_TIMEOUT",
		"UP_WRITE_TIMEOUT", "UP_IDLE_TIMEOUT", "UP_SHUTDOWN_TIMEOUT",
		"UP_MAX_REQUEST_BODY_BYTES", "UP_LOG_LEVEL",
	)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s", cfg.ReadHeaderTimeout)
	}
	if cfg.MaxRequestBodyBytes != 1<<20 {
		t.Errorf("MaxRequestBodyBytes = %d, want %d", cfg.MaxRequestBodyBytes, 1<<20)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
}

func TestLoadParsesOverrides(t *testing.T) {
	t.Setenv("UP_ENVIRONMENT", "development")
	t.Setenv("UP_HTTP_ADDR", ":9090")
	t.Setenv("UP_READ_TIMEOUT", "45s")
	t.Setenv("UP_MAX_REQUEST_BODY_BYTES", "2097152")
	t.Setenv("UP_LOG_LEVEL", "debug")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":9090")
	}
	if cfg.ReadTimeout != 45*time.Second {
		t.Errorf("ReadTimeout = %v, want 45s", cfg.ReadTimeout)
	}
	if cfg.MaxRequestBodyBytes != 2097152 {
		t.Errorf("MaxRequestBodyBytes = %d, want 2097152", cfg.MaxRequestBodyBytes)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
}

func TestValidateRejectsInvalidEnvironment(t *testing.T) {
	cfg := Config{
		Environment:         "staging",
		HTTPAddr:            ":8080",
		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         15 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         60 * time.Second,
		ShutdownTimeout:     30 * time.Second,
		MaxRequestBodyBytes: 1 << 20,
		LogLevel:            "info",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject invalid environment")
	}
}

func TestValidateRejectsNonPositiveTimeouts(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.ReadTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject zero read timeout")
	}
}

func TestValidateRejectsInvalidLogLevel(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.LogLevel = "verbose"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject invalid log level")
	}
}

func TestValidateProductionConstraints(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Environment = EnvironmentProduction

	cfg.ShutdownTimeout = 120 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject production shutdown timeout > 60s")
	}

	cfg.ShutdownTimeout = 30 * time.Second
	cfg.MaxRequestBodyBytes = 32 * (1 << 20)
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject production max body > 16 MiB")
	}

	cfg.MaxRequestBodyBytes = 1 << 20
	// Production requires database, Redis, auth provider, and secure cookies.
	cfg.Database = DatabaseConfig{
		URL:            "postgres://user:pass@host:5432/db?sslmode=require",
		Schema:         "united_pass",
		MaxConns:       10,
		MinConns:       1,
		ConnectTimeout: 10 * time.Second,
	}
	cfg.Redis = RedisConfig{
		URL:            "rediss://:pass@host:6379/0",
		KeyPrefix:      "up:production:",
		PoolSize:       10,
		ConnectTimeout: 10 * time.Second,
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   3 * time.Second,
	}
	cfg.Session.CookieSecure = true
	cfg.Auth.Provider = "zitadel"
	cfg.Auth.BaseURL = "https://auth.example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate should accept valid production config: %v", err)
	}

	// Production must reject permission dev override.
	cfg.Permission.DevOverrideEnabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject production permission dev override")
	}

	// Production must reject AllowInsecure for both database and Redis.
	cfg.Permission.DevOverrideEnabled = false
	cfg.Database.AllowInsecure = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject production database AllowInsecure")
	}
	cfg.Database.AllowInsecure = false

	cfg.Redis.AllowInsecure = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject production redis AllowInsecure")
	}
	cfg.Redis.AllowInsecure = false
}

func TestLogLevelValue(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.LogLevel = "warn"
	level, err := cfg.LogLevelValue()
	if err != nil {
		t.Fatalf("LogLevelValue returned error: %v", err)
	}
	// slog.LevelWarn is a negative value; compare via string to avoid coupling.
	if level.String() != "WARN" {
		t.Errorf("LogLevelValue = %q, want WARN", level.String())
	}
}

func TestValidateDevelopmentAcceptsAllowInsecure(t *testing.T) {
	cfg := validDevelopmentConfig()
	cfg.Database.AllowInsecure = true
	cfg.Redis.AllowInsecure = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate should accept AllowInsecure in development: %v", err)
	}
}

func validDevelopmentConfig() Config {
	return Config{
		Environment:         EnvironmentDevelopment,
		HTTPAddr:            ":8080",
		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         15 * time.Second,
		WriteTimeout:        30 * time.Second,
		IdleTimeout:         60 * time.Second,
		ShutdownTimeout:     30 * time.Second,
		MaxRequestBodyBytes: 1 << 20,
		LogLevel:            "info",

		Session: SessionConfig{
			TTL:            12 * time.Hour,
			RememberTTL:    720 * time.Hour,
			IdleTTL:        2 * time.Hour,
			TouchInterval:  5 * time.Minute,
			CookieSecure:   false,
			CookieSameSite: "lax",
		},

		MFA: MFAConfig{
			ChallengeTTL: 5 * time.Minute,
			MaxAttempts:  5,
		},

		RateLimit: RateLimitConfig{
			LoginLimit:  10,
			LoginWindow: 15 * time.Minute,
			MFALimit:    10,
			MFAWindow:   15 * time.Minute,
		},
	}
}

func clearEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		t.Setenv(key, "")
	}
}
