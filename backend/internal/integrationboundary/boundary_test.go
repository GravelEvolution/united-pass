package integrationboundary

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const boundaryToken = "0123456789ab"

func TestValidatePostgresRequiresExactDisposableResource(t *testing.T) {
	valid := "postgres://up_it_0123456789ab:secret@127.0.0.1:15433/up_it_0123456789ab?sslmode=disable"
	if err := ValidatePostgres(valid, "up_it_schema_0123456789ab", boundaryToken); err != nil {
		t.Fatalf("valid disposable PostgreSQL boundary rejected: %v", err)
	}
	for _, candidate := range []struct {
		url    string
		schema string
		token  string
	}{
		{"postgres://up_it_0123456789ab:secret@localhost:15433/up_it_0123456789ab?sslmode=disable", "up_it_schema_0123456789ab", boundaryToken},
		{"postgres://production:secret@127.0.0.1:15433/production?sslmode=disable", "public", boundaryToken},
		{valid, "up_it_schema_ffffffffffff", boundaryToken},
		{valid, "up_it_schema_0123456789ab", "ffffffffffff"},
	} {
		if err := ValidatePostgres(candidate.url, candidate.schema, candidate.token); err == nil {
			t.Fatalf("unsafe PostgreSQL boundary accepted: %#v", candidate)
		}
	}
}

func TestValidateIsolatedPostgresRequiresDistinctDisposableSchema(t *testing.T) {
	valid := "postgres://up_it_0123456789ab:secret@127.0.0.1:15433/up_it_0123456789ab?sslmode=disable"
	if err := ValidateIsolatedPostgres(valid, "up_iso_schema_0123456789ab", boundaryToken); err != nil {
		t.Fatalf("valid isolated PostgreSQL boundary rejected: %v", err)
	}
	if err := ValidateIsolatedPostgres(valid, "up_it_schema_0123456789ab", boundaryToken); err == nil {
		t.Fatal("authority schema accepted as isolated PostgreSQL target")
	}
}

func TestValidateRedisRequiresExactDisposableResource(t *testing.T) {
	valid := "redis://:secret@127.0.0.1:16379/15"
	if err := ValidateRedis(valid, "up:local-it:0123456789ab:", boundaryToken); err != nil {
		t.Fatalf("valid disposable Redis boundary rejected: %v", err)
	}
	for _, candidate := range []struct {
		url    string
		prefix string
		token  string
	}{
		{"redis://:secret@localhost:16379/15", "up:local-it:0123456789ab:", boundaryToken},
		{"redis://:secret@127.0.0.1:6379/0", "up:local-it:0123456789ab:", boundaryToken},
		{valid, "up:production:", boundaryToken},
		{valid, "up:local-it:0123456789ab:child:", boundaryToken},
	} {
		if err := ValidateRedis(candidate.url, candidate.prefix, candidate.token); err == nil {
			t.Fatalf("unsafe Redis boundary accepted: %#v", candidate)
		}
	}
}

func TestValidateZitadelSnapshotRejectsArbitraryLoopbackState(t *testing.T) {
	repositoryRoot := t.TempDir()
	snapshotDirectory := filepath.Join(repositoryRoot, ".git", "local-integration-snapshots", boundaryToken)
	if err := os.MkdirAll(snapshotDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(snapshotDirectory, "service-account-key.snapshot.json")
	if err := os.WriteFile(keyPath, []byte(`{"type":"serviceaccount"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := map[string]string{
		"baseUrl": "http://127.0.0.1:18185", "keyFile": keyPath,
		"user": "tester", "password": "secret", "totpSecret": "totp", "projectId": "project",
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(snapshotDirectory, "init-state.snapshot.json")
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateZitadelSnapshot(statePath, repositoryRoot, boundaryToken); err != nil {
		t.Fatalf("valid ZITADEL snapshot rejected: %v", err)
	}
	state["baseUrl"] = "http://localhost:18185"
	localhostRaw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, localhostRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateZitadelSnapshot(statePath, repositoryRoot, boundaryToken); err != nil {
		t.Fatalf("reserved localhost ZITADEL origin was rejected: %v", err)
	}
	state["baseUrl"] = "http://127.0.0.1:18185"
	raw, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	arbitrary := filepath.Join(repositoryRoot, "arbitrary-state.json")
	if err := os.WriteFile(arbitrary, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateZitadelSnapshot(arbitrary, repositoryRoot, boundaryToken); err == nil {
		t.Fatal("arbitrary loopback ZITADEL state was accepted")
	}
}
