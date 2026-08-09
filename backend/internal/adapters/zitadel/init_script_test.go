//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-09
// Description: Static security regressions for the local ZITADEL initializer
//

package zitadel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitScriptPersistsAuthoritativeLoginWithoutPrintingSecrets(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "scripts", "zitadel-init.sh")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read ZITADEL init script: %v", err)
	}
	text := string(script)

	for _, forbidden := range []string{
		`echo "  UP_TEST_ZITADEL_PASSWORD=${TEST_PASSWORD}"`,
		`echo "  UP_TEST_ZITADEL_TOTP_SECRET=${TOTP_SECRET}"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("initializer prints a secret-bearing value: %s", forbidden)
		}
	}
	for _, required := range []string{
		`--arg user "${TEST_LOGIN}"`,
		`chmod 600 "${STATE_FILE}"`,
		`UP_TEST_ZITADEL_USER=${TEST_LOGIN}`,
		`jq -r .password`,
		`jq -r .totpSecret`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("initializer missing security invariant %q", required)
		}
	}
}
