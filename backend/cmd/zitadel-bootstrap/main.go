package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/GravelEvolution/united-pass/backend/internal/localzitadel"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "zitadel-bootstrap:", err)
		os.Exit(1)
	}
}

func run() error {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}
	defaultOutDir := defaultOutputDirectory(workingDirectory)
	baseURL := flag.String("base-url", envOrDefault("ZITADEL_BASE_URL", "http://localhost:8080"), "bare loopback URL for the disposable ZITADEL instance")
	outDir := flag.String("out-dir", defaultOutDir, "directory for ignored local bootstrap state")
	initKeyFile := flag.String("init-key-file", os.Getenv("ZITADEL_INIT_SA_KEY_FILE"), "first-instance IAM owner key; defaults to <out-dir>/init-sa.json")
	readyTimeout := flag.Duration("ready-timeout", 5*time.Minute, "maximum readiness wait")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}

	result, err := localzitadel.Run(context.Background(), localzitadel.Config{
		BaseURL:       *baseURL,
		OutDir:        *outDir,
		InitKeyFile:   *initKeyFile,
		TestUser:      os.Getenv("ZITADEL_TEST_USER"),
		TestPassword:  os.Getenv("ZITADEL_TEST_PASSWORD"),
		TestFirstName: os.Getenv("ZITADEL_TEST_FIRST_NAME"),
		TestLastName:  os.Getenv("ZITADEL_TEST_LAST_NAME"),
		TestDisplay:   os.Getenv("ZITADEL_TEST_DISPLAY_NAME"),
		ProjectName:   os.Getenv("ZITADEL_PROJECT_NAME"),
		ReadyTimeout:  *readyTimeout,
		Output:        os.Stdout,
	})
	if err != nil {
		return err
	}

	// These values are identifiers and local paths only. Secret values remain
	// exclusively in the mode-0600 state file and are never written to stdout.
	fmt.Println("[zitadel-bootstrap] done")
	fmt.Println("  UP_TEST_ZITADEL_BASE_URL=" + result.BaseURL)
	fmt.Println("  UP_TEST_ZITADEL_KEY_FILE=" + result.ServiceKey)
	fmt.Println("  UP_TEST_ZITADEL_PROJECT_ID=" + result.ProjectID)
	fmt.Println("  UP_TEST_ZITADEL_USER=" + result.UserLogin)
	fmt.Println("  UP_TEST_ZITADEL_STATE_FILE=" + result.StateFile)
	return nil
}

// defaultOutputDirectory preserves the legacy zitadel-init.sh contract:
// BACKEND_DIR names the backend root, while generated secrets live in its
// ignored .zitadel child. Callers that need another location must use
// -out-dir explicitly.
func defaultOutputDirectory(workingDirectory string) string {
	backendDirectory := os.Getenv("BACKEND_DIR")
	if backendDirectory != "" {
		return filepath.Join(backendDirectory, ".zitadel")
	}
	return filepath.Join(workingDirectory, ".zitadel")
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
