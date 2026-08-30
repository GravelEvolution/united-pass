package main

import (
	"encoding/json"
	"errors"
	"io"
	"runtime"
)

const (
	developmentBuildProfile = "development"
	releaseBuildProfile     = "release"
	unversionedBuildValue   = "unversioned"
)

// These values are intentionally supplied only by the reviewed release
// builder. A production process refuses a development or unversioned binary.
var (
	buildSourceCommit = unversionedBuildValue
	buildSourceTree   = unversionedBuildValue
	buildProfile      = developmentBuildProfile
)

type buildInformation struct {
	SourceCommit string `json:"sourceCommit"`
	SourceTree   string `json:"sourceTree"`
	Profile      string `json:"profile"`
	GoVersion    string `json:"goVersion"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
}

func writeBuildInformation(output io.Writer) error {
	if err := validateBuildInformation(""); err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(buildInformation{
		SourceCommit: buildSourceCommit,
		SourceTree:   buildSourceTree,
		Profile:      buildProfile,
		GoVersion:    runtime.Version(),
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
	})
}

func validateBuildInformation(environment string) error {
	if buildProfile == developmentBuildProfile &&
		buildSourceCommit == unversionedBuildValue &&
		buildSourceTree == unversionedBuildValue {
		if environment == "production" {
			return errors.New("production requires a source-bound release binary")
		}
		return nil
	}
	if buildProfile != releaseBuildProfile {
		return errors.New("build profile is invalid")
	}
	if !isLowerHexDigest(buildSourceCommit) || !isLowerHexDigest(buildSourceTree) {
		return errors.New("release source commit and tree must be lowercase SHA-1 object IDs")
	}
	return nil
}

func isLowerHexDigest(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
