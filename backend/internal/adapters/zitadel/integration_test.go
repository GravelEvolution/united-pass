//go:build integration

// Package zitadel integration tests exercise the adapter against a real
// ZITADEL instance (see docker-compose.zitadel.yml and
// scripts/zitadel-init.sh). They are skipped unless the following variables
// are set:
//
//	UP_TEST_ZITADEL_BASE_URL     e.g. http://localhost:8080
//	UP_TEST_ZITADEL_KEY_FILE     path to the service account key.json
//	UP_TEST_ZITADEL_USER         login name of the test human user
//	UP_TEST_ZITADEL_PASSWORD     password of the test human user
//	UP_TEST_ZITADEL_TOTP_SECRET  base32 TOTP secret (stored by zitadel-init.sh;
//	                             used to compute the current code automatically)
//
// When UP_TEST_DATABASE_URL is also set, the first-login identity mapping is
// exercised against a real PostgreSQL UserRepository (the schema must already
// be migrated with cmd/migrate). Otherwise a recording linker is used and the
// full-profile assertions are skipped.
//
// The test verifies the full login flow, first-login identity mapping, MFA,
// revocation and readiness against the running instance.
package zitadel

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/GravelEvolution/united-pass/backend/internal/adapters/postgres"
	"github.com/GravelEvolution/united-pass/backend/internal/auth"
	"github.com/GravelEvolution/united-pass/backend/internal/config"
	"github.com/GravelEvolution/united-pass/backend/internal/identity"
)

func testZitadelConfig(t *testing.T) config.AuthProviderConfig {
	t.Helper()
	baseURL := os.Getenv("UP_TEST_ZITADEL_BASE_URL")
	keyFile := os.Getenv("UP_TEST_ZITADEL_KEY_FILE")
	if baseURL == "" || keyFile == "" {
		t.Skip("UP_TEST_ZITADEL_BASE_URL / UP_TEST_ZITADEL_KEY_FILE not set; skipping ZITADEL integration tests")
	}
	return config.AuthProviderConfig{
		Provider:              ProviderName,
		BaseURL:               baseURL,
		ServiceAccountKeyFile: keyFile,
		ProjectID:             os.Getenv("UP_TEST_ZITADEL_PROJECT_ID"),
		Domain:                "localhost",
	}
}

// newIntegrationLinker builds the linker for the E2E test. When a test
// database is configured it uses the real PostgreSQL UserRepository so the
// test verifies actual user creation, identity links and profile
// synchronization; otherwise a recording linker is used.
func newIntegrationLinker(t *testing.T) (identity.UserLinker, *postgres.Pool, bool) {
	t.Helper()
	dbURL := os.Getenv("UP_TEST_DATABASE_URL")
	if dbURL == "" {
		return &recordingLinker{}, nil, false
	}
	cfg := config.Config{}
	cfg.Database.URL = dbURL
	cfg.Database.Schema = os.Getenv("UP_TEST_DATABASE_SCHEMA")
	if cfg.Database.Schema == "" {
		cfg.Database.Schema = "united_pass_test"
	}
	cfg.Database.MaxConns = 5
	cfg.Database.MinConns = 1
	cfg.Database.ConnectTimeout = 10 * time.Second

	// Re-apply migrations: the PostgreSQL integration suite drops the test
	// schema tables in its cleanup, so the tables may be missing when this
	// suite runs afterwards. Migrations are idempotent (goose tracks
	// versions), so this is safe to run every time.
	ensureSchemaMigrated(t, dbURL, cfg.Database.Schema)

	pool, err := postgres.NewPool(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	return postgres.NewUserRepository(pool.PgxPool()), pool, true
}

// ensureSchemaMigrated creates the test schema (if absent) and applies all
// migrations to it. See postgres integration tests for the same pattern.
func ensureSchemaMigrated(t *testing.T, url, schema string) {
	t.Helper()
	if !config.ValidSchemaIdentifier(schema) {
		t.Fatalf("test schema %q is not a valid PostgreSQL identifier", schema)
	}
	connConfig, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	if connConfig.RuntimeParams == nil {
		connConfig.RuntimeParams = make(map[string]string)
	}
	connConfig.RuntimeParams["search_path"] = schema

	db := stdlib.OpenDB(*connConfig)
	defer db.Close()

	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quotedSchema)); err != nil {
		t.Fatalf("create test schema: %v", err)
	}

	goose.SetTableName(pgx.Identifier{schema, "goose_db_version"}.Sanitize())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set dialect: %v", err)
	}
	migrationsDir := findMigrationsDir(t)
	if err := goose.UpContext(context.Background(), db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
}

// findMigrationsDir locates the repository migrations directory by walking up
// from the test working directory.
func findMigrationsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "migrations")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("migrations directory not found")
	return ""
}

// recordingLinker records the provider subject and profile info it resolved
// and always returns an active user. It is the fallback when no test database
// is configured.
type recordingLinker struct {
	subject string
	info    identity.ProviderUserInfo
}

func (l *recordingLinker) GetOrCreateUserByProviderSubject(_ context.Context, _, _ string, info identity.ProviderUserInfo) (identity.User, error) {
	l.subject = info.Subject
	l.info = info
	return identity.User{
		ID:     identity.UserID("user_test_local"),
		Status: identity.UserStatusActive,
	}, nil
}

// totpCode computes the current RFC 6238 TOTP code (SHA1, 30s period, 6
// digits) for the given base32 secret, so the E2E test can run unattended.
func totpCode(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("decode TOTP secret: %v", err)
	}
	counter := uint64(time.Now().Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0F
	code := (binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7FFFFFFF) % 1000000
	return fmt.Sprintf("%06d", code)
}

func TestIntegration_ZitadelAuthenticatorE2E(t *testing.T) {
	cfg := testZitadelConfig(t)
	user := os.Getenv("UP_TEST_ZITADEL_USER")
	password := os.Getenv("UP_TEST_ZITADEL_PASSWORD")
	if user == "" || password == "" {
		t.Skip("UP_TEST_ZITADEL_USER / UP_TEST_ZITADEL_PASSWORD not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sdk, err := NewSDKClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewSDKClient: %v", err)
	}
	defer sdk.Close()

	linker, pool, realDB := newIntegrationLinker(t)
	if pool != nil {
		defer pool.Close()
	}

	a := NewAuthenticator(sdk.SessionServiceV2(), sdk.UserServiceV2(), linker, cfg.ProjectID, cfg.Domain, nil)

	// Readiness: the service account must be able to reach the API.
	if err := a.Check(ctx); err != nil {
		t.Fatalf("provider readiness: %v", err)
	}

	// Step 1: password authentication.
	res, err := a.BeginPasswordAuthentication(ctx, auth.PasswordAuthenticationInput{
		Identifier: user,
		Password:   password,
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}

	switch res.Status {
	case auth.StatusAuthenticated:
		t.Log("authenticated without MFA")
		verifyAuthenticatedResult(t, linker, realDB, res)
		// Step 3: revoke the provider session.
		if err := a.RevokeProviderSession(ctx, res.ProviderSessionReference); err != nil {
			t.Fatalf("RevokeProviderSession: %v", err)
		}

	case auth.StatusMFARequired:
		t.Logf("MFA required; available methods: %v", res.AvailableMethods)
		secret := os.Getenv("UP_TEST_ZITADEL_TOTP_SECRET")
		if secret == "" {
			t.Skip("MFA required but UP_TEST_ZITADEL_TOTP_SECRET not set (saved by zitadel-init.sh)")
		}
		// The provider session ID must be server-side only; it must never be
		// exposed as a browser token.
		if res.ProviderSessionID == "" {
			t.Fatal("provider session ID must be set server-side for MFA completion")
		}
		// Step 2: complete MFA with an automatically computed TOTP code.
		completed, err := a.CompleteMFA(ctx, auth.MFAChallengeInput{
			ProviderSessionID: res.ProviderSessionID,
			Method:            auth.MFAMethodTOTP,
			Code:              totpCode(t, secret),
		})
		if err != nil {
			t.Fatalf("CompleteMFA: %v", err)
		}
		if completed.Status != auth.StatusAuthenticated {
			t.Fatalf("MFA completion status = %q, want authenticated", completed.Status)
		}
		verifyAuthenticatedResult(t, linker, realDB, completed)
		// Step 3: revoke the provider session.
		if err := a.RevokeProviderSession(ctx, completed.ProviderSessionReference); err != nil {
			t.Fatalf("RevokeProviderSession: %v", err)
		}

	case auth.StatusInvalidCredentials:
		t.Fatalf("invalid credentials for configured test user: check UP_TEST_ZITADEL_USER/PASSWORD")

	default:
		t.Fatalf("unexpected status: %q", res.Status)
	}
}

// verifyAuthenticatedResult checks the authenticated result and, when a real
// database is used, that the user was actually created with the provider
// profile synchronized.
func verifyAuthenticatedResult(t *testing.T, linker identity.UserLinker, realDB bool, res auth.AuthenticationResult) {
	t.Helper()
	if res.UserID == "" {
		t.Error("local user id must be set after authentication")
	}
	if res.ProviderSessionReference == "" {
		t.Error("provider session reference must be set after authentication")
	}
	if strings.Contains(res.ProviderSessionReference, ":") {
		t.Error("provider session reference must be the session ID only (no session token)")
	}

	if realDB {
		// Re-read the user through the repository to confirm the profile was
		// persisted and the identity link exists.
		user, err := getUserByID(t, linker, res.UserID)
		if err != nil {
			t.Fatalf("read back created user: %v", err)
		}
		if user.Email == "" {
			t.Error("created user must have the provider email synchronized")
		}
		if user.DisplayName == "" {
			t.Error("created user must have the provider display name synchronized")
		}
	}
}

// getUserByID reads a user through a UserLinker-backed repository when the
// linker is backed by a real repository.
func getUserByID(t *testing.T, linker identity.UserLinker, userID identity.UserID) (identity.User, error) {
	t.Helper()
	if repo, ok := linker.(*postgres.UserRepository); ok {
		return repo.GetByID(context.Background(), userID)
	}
	return identity.User{}, nil
}

func TestIntegration_ZitadelAuthenticatorWrongPassword(t *testing.T) {
	cfg := testZitadelConfig(t)
	user := os.Getenv("UP_TEST_ZITADEL_USER")
	password := os.Getenv("UP_TEST_ZITADEL_PASSWORD")
	if user == "" || password == "" {
		t.Skip("UP_TEST_ZITADEL_USER / UP_TEST_ZITADEL_PASSWORD not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sdk, err := NewSDKClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewSDKClient: %v", err)
	}
	defer sdk.Close()

	a := NewAuthenticator(sdk.SessionServiceV2(), sdk.UserServiceV2(), &recordingLinker{}, cfg.ProjectID, cfg.Domain, nil)

	res, err := a.BeginPasswordAuthentication(ctx, auth.PasswordAuthenticationInput{
		Identifier: user,
		Password:   "definitely-wrong-password",
	})
	if err != nil {
		t.Fatalf("BeginPasswordAuthentication: %v", err)
	}
	if res.Status != auth.StatusInvalidCredentials {
		t.Fatalf("status = %q, want %q", res.Status, auth.StatusInvalidCredentials)
	}
}
