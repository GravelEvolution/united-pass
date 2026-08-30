package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestReleaseBuildInformationIsMachineReadableAndSourceBound(t *testing.T) {
	setBuildInformationForTest(t,
		"0123456789abcdef0123456789abcdef01234567",
		"89abcdef0123456789abcdef0123456789abcdef",
		releaseBuildProfile,
	)
	if err := validateBuildInformation("production"); err != nil {
		t.Fatalf("valid release metadata rejected: %v", err)
	}

	var output bytes.Buffer
	if err := writeBuildInformation(&output); err != nil {
		t.Fatal(err)
	}
	var information buildInformation
	if err := json.Unmarshal(output.Bytes(), &information); err != nil {
		t.Fatal(err)
	}
	if information.SourceCommit != buildSourceCommit || information.SourceTree != buildSourceTree {
		t.Fatalf("source binding = %q/%q", information.SourceCommit, information.SourceTree)
	}
	if information.Profile != releaseBuildProfile || information.GOOS == "" || information.GOARCH == "" || information.GoVersion == "" {
		t.Fatalf("incomplete build information: %+v", information)
	}
}

func TestProductionRejectsUnversionedOrMalformedReleaseBinaries(t *testing.T) {
	if err := validateBuildInformation("production"); err == nil {
		t.Fatal("production accepted the unversioned development binary")
	}

	setBuildInformationForTest(t,
		"0123456789abcdef0123456789abcdef0123456G",
		"89abcdef0123456789abcdef0123456789abcdef",
		releaseBuildProfile,
	)
	if err := validateBuildInformation("production"); err == nil {
		t.Fatal("production accepted malformed source metadata")
	}
}

func setBuildInformationForTest(t *testing.T, commit, tree, profile string) {
	t.Helper()
	originalCommit, originalTree, originalProfile := buildSourceCommit, buildSourceTree, buildProfile
	buildSourceCommit, buildSourceTree, buildProfile = commit, tree, profile
	t.Cleanup(func() {
		buildSourceCommit, buildSourceTree, buildProfile = originalCommit, originalTree, originalProfile
	})
}
