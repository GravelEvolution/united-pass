//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: DreamUP bootstrap configuration loading tests
//

package config

import "testing"

func TestLoadReadsDreamUPBootstrapOwnerUserID(t *testing.T) {
	t.Setenv("UP_ENVIRONMENT", "development")
	t.Setenv("UP_DREAMUP_OWNER_USER_ID", "0198f112-4cb8-7a72-b613-4da34fe51b3d")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got := cfg.DreamUPBootstrap.OwnerUserID; got != "0198f112-4cb8-7a72-b613-4da34fe51b3d" {
		t.Fatalf("DreamUPBootstrap.OwnerUserID = %q", got)
	}
}
