//go:build integration

package zitadel

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/GravelEvolution/united-pass/backend/internal/integrationboundary"
)

func TestMain(m *testing.M) {
	if err := validateZitadelIntegrationBoundary(); err != nil {
		fmt.Fprintln(os.Stderr, "ZITADEL integration boundary rejected:", err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func validateZitadelIntegrationBoundary() error {
	for _, name := range []string{
		"UP_TEST_ZITADEL_BASE_URL",
		"UP_TEST_ZITADEL_KEY_FILE",
		"UP_TEST_ZITADEL_USER",
		"UP_TEST_ZITADEL_PASSWORD",
		"UP_TEST_ZITADEL_TOTP_SECRET",
		"UP_TEST_ZITADEL_PROJECT_ID",
	} {
		if os.Getenv(name) != "" {
			return fmt.Errorf("direct %s override is forbidden; the immutable matrix snapshot is mandatory", name)
		}
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve ZITADEL integration working directory")
	}
	repositoryRoot, err := filepath.Abs(filepath.Join(workingDirectory, "..", "..", "..", ".."))
	if err != nil {
		return fmt.Errorf("resolve integration repository root")
	}
	token := os.Getenv(integrationboundary.RunTokenEnvironment)
	if err := integrationboundary.ValidateZitadelSnapshot(
		os.Getenv("UP_TEST_ZITADEL_STATE_FILE"), repositoryRoot, token,
	); err != nil {
		return err
	}
	return integrationboundary.ValidatePostgres(
		os.Getenv("UP_TEST_DATABASE_URL"),
		os.Getenv("UP_TEST_DATABASE_SCHEMA"),
		token,
	)
}
