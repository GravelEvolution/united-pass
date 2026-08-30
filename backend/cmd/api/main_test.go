package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunDoesNotLoadDotEnvFilesWhenProductionIsExplicit(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, ".env.local"), []byte("UP_API_LOCAL_FILE_TEST=loaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDirectory) })

	originalEnvironment, wasSet := os.LookupEnv("UP_ENVIRONMENT")
	originalMarker, markerWasSet := os.LookupEnv("UP_API_LOCAL_FILE_TEST")
	t.Cleanup(func() {
		if wasSet {
			_ = os.Setenv("UP_ENVIRONMENT", originalEnvironment)
		} else {
			_ = os.Unsetenv("UP_ENVIRONMENT")
		}
		if markerWasSet {
			_ = os.Setenv("UP_API_LOCAL_FILE_TEST", originalMarker)
		} else {
			_ = os.Unsetenv("UP_API_LOCAL_FILE_TEST")
		}
	})
	_ = os.Unsetenv("UP_API_LOCAL_FILE_TEST")
	if err := os.Setenv("UP_ENVIRONMENT", "production"); err != nil {
		t.Fatal(err)
	}

	if err := loadLocalEnvironment(); err != nil {
		t.Fatal(err)
	}
	if _, exists := os.LookupEnv("UP_API_LOCAL_FILE_TEST"); exists {
		t.Fatal("production process loaded a working-directory environment file")
	}
}
