package main

import (
	"path/filepath"
	"testing"
)

func TestDefaultOutputDirectory(t *testing.T) {
	tests := []struct {
		name             string
		workingDirectory string
		backendDirectory string
		want             string
	}{
		{
			name:             "working directory default",
			workingDirectory: filepath.Join("workspace", "united-pass-api"),
			want:             filepath.Join("workspace", "united-pass-api", ".zitadel"),
		},
		{
			name:             "legacy BACKEND_DIR is a backend root",
			workingDirectory: filepath.Join("ignored", "working-directory"),
			backendDirectory: filepath.Join("workspace", "united-pass-api"),
			want:             filepath.Join("workspace", "united-pass-api", ".zitadel"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("BACKEND_DIR", test.backendDirectory)
			if got := defaultOutputDirectory(test.workingDirectory); got != test.want {
				t.Fatalf("defaultOutputDirectory(%q) with BACKEND_DIR=%q = %q, want %q", test.workingDirectory, test.backendDirectory, got, test.want)
			}
		})
	}
}
