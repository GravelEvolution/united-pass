// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Package integrationboundary rejects integration-test configuration that is
// not owned by the disposable local matrix. The checks happen before any test
// opens a database or Redis connection.
package integrationboundary

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const RunTokenEnvironment = "UP_TEST_DISPOSABLE_RUN_TOKEN"

var runTokenPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

func ValidateRunToken(token string) error {
	if !runTokenPattern.MatchString(token) {
		return errors.New("disposable integration run token is missing or invalid")
	}
	return nil
}

func ValidatePostgres(rawURL, schema, token string) error {
	return validatePostgres(rawURL, schema, token, "up_it_schema_")
}

// ValidateIsolatedPostgres binds the operational-store schema to the same
// disposable database/role while requiring a distinct schema prefix. Tests
// can therefore prove v13 authority compatibility without ever accepting a
// production target.
func ValidateIsolatedPostgres(rawURL, schema, token string) error {
	return validatePostgres(rawURL, schema, token, "up_iso_schema_")
}

func validatePostgres(rawURL, schema, token, schemaPrefix string) error {
	if err := ValidateRunToken(token); err != nil {
		return err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "postgres" || parsed.Hostname() != "127.0.0.1" || parsed.Port() != "15433" {
		return errors.New("PostgreSQL integration endpoint is outside the disposable local boundary")
	}
	expected := "up_it_" + token
	if parsed.User == nil || parsed.User.Username() != expected || parsed.Path != "/"+expected {
		return errors.New("PostgreSQL integration database and role are not owned by this run")
	}
	if password, ok := parsed.User.Password(); !ok || password == "" {
		return errors.New("PostgreSQL integration password is missing")
	}
	if parsed.RawQuery != "sslmode=disable" || parsed.Fragment != "" {
		return errors.New("PostgreSQL integration connection parameters are not exact")
	}
	if schema != schemaPrefix+token {
		return errors.New("PostgreSQL integration schema is not owned by this run")
	}
	return nil
}

func ValidateRedis(rawURL, prefix, token string) error {
	if err := ValidateRunToken(token); err != nil {
		return err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "redis" || parsed.Hostname() != "127.0.0.1" || parsed.Port() != "16379" {
		return errors.New("Redis integration endpoint is outside the disposable local boundary")
	}
	if parsed.User == nil || parsed.User.Username() != "" {
		return errors.New("Redis integration user information is invalid")
	}
	if password, ok := parsed.User.Password(); !ok || password == "" {
		return errors.New("Redis integration password is missing")
	}
	if parsed.Path != "/15" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("Redis integration database selection is not exact")
	}
	if prefix != "up:local-it:"+token+":" {
		return errors.New("Redis integration prefix is not owned by this run")
	}
	return nil
}

type zitadelSnapshot struct {
	BaseURL    string `json:"baseUrl"`
	KeyFile    string `json:"keyFile"`
	User       string `json:"user"`
	Password   string `json:"password"`
	TOTPSecret string `json:"totpSecret"`
	ProjectID  string `json:"projectId"`
}

func ValidateZitadelSnapshot(statePath, repositoryRoot, token string) error {
	if err := ValidateRunToken(token); err != nil {
		return err
	}
	expectedDirectory := filepath.Join(repositoryRoot, ".git", "local-integration-snapshots", token)
	expectedState := filepath.Join(expectedDirectory, "init-state.snapshot.json")
	actualState, err := filepath.Abs(statePath)
	if err != nil || !samePath(actualState, expectedState) {
		return errors.New("ZITADEL integration state is not the immutable snapshot owned by this run")
	}
	raw, err := os.ReadFile(actualState)
	if err != nil {
		return errors.New("ZITADEL integration state cannot be read")
	}
	var state zitadelSnapshot
	if err := json.Unmarshal(raw, &state); err != nil {
		return errors.New("ZITADEL integration state is malformed")
	}
	if state.BaseURL != "http://127.0.0.1:18185" && state.BaseURL != "http://localhost:18185" {
		return errors.New("ZITADEL integration endpoint is outside the fixed local boundary")
	}
	expectedKey := filepath.Join(expectedDirectory, "service-account-key.snapshot.json")
	if !samePath(state.KeyFile, expectedKey) {
		return errors.New("ZITADEL integration key is not the immutable snapshot owned by this run")
	}
	if strings.TrimSpace(state.User) == "" || state.Password == "" || state.TOTPSecret == "" || strings.TrimSpace(state.ProjectID) == "" {
		return errors.New("ZITADEL integration state is incomplete")
	}
	return nil
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(leftAbs), filepath.Clean(rightAbs))
}
