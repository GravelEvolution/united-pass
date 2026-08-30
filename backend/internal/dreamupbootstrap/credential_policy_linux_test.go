//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Linux root-owned credential policy tests
//

//go:build linux

package dreamupbootstrap

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestProductionCredentialPolicyRequiresRootAndOwnerOnlyParent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "dreamup-secret")

	credential, err := reserveCredentialFile(path, newCredentialSecurityPolicy())
	if os.Geteuid() != 0 {
		if credential != nil {
			credential.abort()
		}
		if err == nil {
			t.Fatal("non-root process reserved a production credential file")
		}
		return
	}
	if err != nil {
		t.Fatalf("root-owned secure destination rejected: %v", err)
	}
	defer credential.abort()
	info, err := credential.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("credential ownership/mode = %#v %o", stat, info.Mode().Perm())
	}
}

func TestProductionCredentialPolicyRejectsAccessibleParent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("non-root is already rejected by the production policy")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	credential, err := reserveCredentialFile(filepath.Join(parent, "dreamup-secret"), newCredentialSecurityPolicy())
	if credential != nil {
		credential.abort()
	}
	if err == nil {
		t.Fatal("group/world-accessible parent was accepted")
	}
}
