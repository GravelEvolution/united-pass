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
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate should accept valid production config: %v", err)
	}
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
	}
}

func clearEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		t.Setenv(key, "")
	}
}
