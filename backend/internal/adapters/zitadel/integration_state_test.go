//go:build integration

package zitadel

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

const maxIntegrationStateBytes = 1 << 20

type integrationState struct {
	BaseURL    string `json:"baseUrl"`
	KeyFile    string `json:"keyFile"`
	User       string `json:"user"`
	Password   string `json:"password"`
	TOTPSecret string `json:"totpSecret"`
	ProjectID  string `json:"projectId"`
}

// testZitadelValue reads only the immutable matrix snapshot. TestMain rejects
// direct provider-variable overrides before any integration test can run.
func testZitadelValue(t *testing.T, name string) string {
	t.Helper()
	statePath := os.Getenv("UP_TEST_ZITADEL_STATE_FILE")
	if statePath == "" {
		return ""
	}
	state, err := readIntegrationState(statePath)
	if err != nil {
		t.Fatalf("read protected ZITADEL integration state: %v", err)
	}
	switch name {
	case "UP_TEST_ZITADEL_BASE_URL":
		return state.BaseURL
	case "UP_TEST_ZITADEL_KEY_FILE":
		return state.KeyFile
	case "UP_TEST_ZITADEL_USER":
		return state.User
	case "UP_TEST_ZITADEL_PASSWORD":
		return state.Password
	case "UP_TEST_ZITADEL_TOTP_SECRET":
		return state.TOTPSecret
	case "UP_TEST_ZITADEL_PROJECT_ID":
		return state.ProjectID
	default:
		return ""
	}
}

func readIntegrationState(path string) (integrationState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return integrationState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return integrationState{}, errors.New("integration state must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxIntegrationStateBytes {
		return integrationState{}, errors.New("integration state has an invalid size")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return integrationState{}, err
	}
	var state integrationState
	if err := json.Unmarshal(raw, &state); err != nil {
		return integrationState{}, errors.New("integration state is malformed")
	}
	return state, nil
}

func TestIntegrationStateReadbackDoesNotRequireJQ(t *testing.T) {
	path := t.TempDir() + string(os.PathSeparator) + "init-state.json"
	raw := []byte(`{"baseUrl":"http://127.0.0.1:18185","keyFile":"key.json","user":"tester","password":"test-password","totpSecret":"totp-value","projectId":"project-1"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := readIntegrationState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaseURL != "http://127.0.0.1:18185" || state.ProjectID != "project-1" || state.Password == "" || state.TOTPSecret == "" {
		t.Fatalf("unexpected protected state readback metadata: base=%q project=%q", state.BaseURL, state.ProjectID)
	}
}

func TestIntegrationStateSuppliesEveryZitadelInputAndIgnoresDirectOverrides(t *testing.T) {
	path := t.TempDir() + string(os.PathSeparator) + "init-state.json"
	raw := []byte(`{"baseUrl":"http://127.0.0.1:18185","keyFile":"key.json","user":"tester","password":"test-password","totpSecret":"totp-value","projectId":"project-1"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UP_TEST_ZITADEL_STATE_FILE", path)

	want := map[string]string{
		"UP_TEST_ZITADEL_BASE_URL":    "http://127.0.0.1:18185",
		"UP_TEST_ZITADEL_KEY_FILE":    "key.json",
		"UP_TEST_ZITADEL_USER":        "tester",
		"UP_TEST_ZITADEL_PASSWORD":    "test-password",
		"UP_TEST_ZITADEL_TOTP_SECRET": "totp-value",
		"UP_TEST_ZITADEL_PROJECT_ID":  "project-1",
	}
	for name, expected := range want {
		if got := testZitadelValue(t, name); got != expected {
			t.Fatalf("%s from state = %q, want %q", name, got, expected)
		}
	}

	t.Setenv("UP_TEST_ZITADEL_BASE_URL", "http://127.0.0.1:19000")
	if got := testZitadelValue(t, "UP_TEST_ZITADEL_BASE_URL"); got != "http://127.0.0.1:18185" {
		t.Fatalf("direct environment override escaped the immutable snapshot: %q", got)
	}
}
