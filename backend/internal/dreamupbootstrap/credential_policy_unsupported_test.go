//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Non-Linux credential policy fail-closed test
//

//go:build !linux

package dreamupbootstrap

import (
	"path/filepath"
	"testing"
)

func TestProductionCredentialPolicyFailsClosedOutsideLinux(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dreamup-secret")
	credential, err := reserveCredentialFile(path, newCredentialSecurityPolicy())
	if credential != nil {
		credential.abort()
	}
	if err == nil {
		t.Fatal("non-Linux production credential policy accepted first-run secret output")
	}
}
