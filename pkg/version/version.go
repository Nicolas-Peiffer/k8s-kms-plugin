// MIT License
//
// Copyright (c) 2024 Thales. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Command "k8s-kms-plugin version" gives not only the semantic x.y.z version of
// the tool but gives also references to the git commit ID and Go version.
// It includes functionality to output version details in different formats
// such as JSON and YAML. The version information includes details like the
// semantic version (major, minor, patch), Git commit IDs, Go version,
// build date, and platform information.
package version

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"strings"

	"github.com/blang/semver/v4"
	go_version "github.com/hashicorp/go-version"
	"gopkg.in/yaml.v2"
)

var (
	RawGitDescribe     string
	GitCommitIdShort   string
	GitCommitIdLong    string
	GitCommitTimestamp string
	OutputFormat       string
	GoVersion          string
	BuildPlatform      string
	BuildDate          string
)

// Command "k8s-kms-plugin version" output can be formated in JSON.
type VersionOutput struct {
	VersionData VersionData `json:"k8s-kms-plugin-cli"`
}

type VersionData struct {
	Major              uint64 `json:"major"`
	Minor              uint64 `json:"minor"`
	Patch              uint64 `json:"patch"`
	Version            string `json:"version"`
	GitCommitIdLong    string `json:"gitCommitIdLong"`
	GitCommitIdShort   string `json:"gitCommitIdShort"`
	GitCommitTimestamp string `json:"gitCommitTimestamp"`
	GoVersion          string `json:"goVersion"`
	BuildDate          string `json:"buildDate"`
	BuildPlatform      string `json:"buildPlatform"`
}

// getVersionData returns a VersionData struct with information from git
// from LDFLAGS such as the raw git describe output, git commit ID (long and
// short) and commit timestamp, Go version, build date, and build platform. It parses
// the raw git describe output and converts it in semantic versioning (major,
// minor, patch) and stores it in the VersionData struct. If the raw git describe
// output is not parsable as semantic versioning, it sets the major, minor, and
// patch fields to 0 and returns an error.
func getVersionData() (VersionData, error) {
	slog.Debug("check LDFLAGS from git", "raw-git-describe", RawGitDescribe)
	slog.Debug("check LDFLAGS from git", "git-commit-id-long", GitCommitIdLong)
	slog.Debug("check LDFLAGS from git", "git-commit-id-short", GitCommitIdShort)
	slog.Debug("check LDFLAGS from git", "git-commit-timestamp", GitCommitTimestamp)
	slog.Debug("check LDFLAGS from git", "go-version", GoVersion)
	slog.Debug("check LDFLAGS from git", "build-date", BuildDate)
	slog.Debug("check LDFLAGS from git", "build-platform", BuildPlatform)

	// Initialize VersionData to hold information from git from LDFLAGS
	versionData := VersionData{
		Version:            RawGitDescribe,
		GitCommitIdLong:    GitCommitIdLong,
		GitCommitIdShort:   GitCommitIdShort,
		GitCommitTimestamp: GitCommitTimestamp,
		GoVersion:          GoVersion,
		BuildDate:          BuildDate,
		BuildPlatform:      BuildPlatform,
	}

	// Parses the raw git describe output and convert it in sementic versioning.
	version, err := go_version.NewVersion(RawGitDescribe)
	if err != nil {
		slog.Error("Raw git describe --tags --always version is not parsable as semantic versioning. Set major, minor and patch to 0 ",
			"raw_git_describe", RawGitDescribe,
			"error", err)
		return versionData, err
	}

	versionSegments := version.Segments()
	if len(versionSegments) < 3 {
		err = fmt.Errorf("raw git describe --tags --always version %s is not parsable as "+
			"semantic versioning. Expected 3 segments (major, minor, patch) but got %d",
			RawGitDescribe, len(versionSegments))
		return versionData, err
	}

	// set major, minor and patch to values that has been parsed by go_version
	versionData.Major = uint64(versionSegments[0])
	versionData.Minor = uint64(versionSegments[1])
	versionData.Patch = uint64(versionSegments[2])
	return versionData, err
}

func getVersionOutput() (VersionOutput, error) {
	versionData, err := getVersionData()
	versionOutput := VersionOutput{
		VersionData: versionData,
	}
	return versionOutput, err
}

// Output from "k8s-kms-plugin version -o json" is formated in JSON.
// You can choose to output pretty JSON with indentation or a single line JSON.
func returnJsonVersion(prettyPrint bool) ([]byte, error) {
	versionOutput, _ := getVersionOutput()

	// if prettyPrint is true then pretty print JSON with indentation.
	if !prettyPrint {
		jsonData, err := json.Marshal(&versionOutput)
		if err != nil {
			// first log then panic
			log.Println("Error while Marshaling to JSON (no indentation)", err)
			panic(fmt.Sprint("Error while Marshaling to JSON (no indentation)", err))
		}
		return jsonData, err
	} else {
		jsonData, err := json.MarshalIndent(&versionOutput, "", "  ")
		if err != nil {
			// first log then panic
			log.Println("Error while Marshaling to JSON with "+
				"indentation (pretty print).", err)
			panic(fmt.Sprint("Error while Marshaling to JSON with "+
				"indentation (pretty print).", err))
		}
		return jsonData, err
	}
}

// Output from "k8s-kms-plugin version -o yaml" is formated in YAML.
func returnYamlVersion() ([]byte, error) {
	// no JSON indentation is needed here so pretty printing is set to false.
	jsonData, _ := returnJsonVersion(false)

	// Define a map to unmarshal JSON data
	var data map[string]interface{}

	// Unmarshal JSON data into the map
	err := json.Unmarshal(jsonData, &data)
	if err != nil {
		panic(err)
	}

	yamlData, err := yaml.Marshal(data)
	if err != nil {
		log.Printf("Error while Marshaling to YAML. %v", err)
		panic(err)
	}
	return yamlData, err
}

// SlogOutput prints the version information to the standard logger.
// It is used in the server logger to print the version information
// when the server is started by the cobra CLI.
func SlogOutput() {
	versionData, _ := getVersionData()
	slog.Info("k8s-kms-plugin", "version", versionData.Version)
	slog.Debug("k8s-kms-plugin", "commit", versionData.GitCommitIdLong)
	slog.Debug("k8s-kms-plugin", "short-commit", versionData.GitCommitIdShort)
	slog.Debug("Go version", "go-version", versionData.GoVersion)
	slog.Debug("k8s-kms-plugin build", "date", versionData.BuildDate)
	slog.Debug("k8s-kms-plugin build", "platform", versionData.BuildPlatform)
}

func VersionOutputToString(outputFormat string, prettyPrint bool) string {
	if outputFormat == "json" {
		data, _ := returnJsonVersion(prettyPrint)
		return string(data)
	} else if outputFormat == "yaml" {
		data, _ := returnYamlVersion()
		return (string(data))
	} else {
		version, _ := semver.Parse(RawGitDescribe)
		return "k8s-kms-plugin: v" + strconv.FormatUint(version.Major, 10) + "." +
			strconv.FormatUint(version.Minor, 10) + "." +
			strconv.FormatUint(version.Patch, 10)
	}
}

// ParseVersion is a method that parses a version string that may be in
// major.minor or major.minor.patch format.
func SafeParseVersion(versionString string) (semver.Version, error) {
	// Preprocess the version string to add ".0" if it's missing the patch version
	if strings.Count(versionString, ".") == 1 {
		versionString += ".0"
	}

	// Parse the version string
	version, err := semver.Parse(versionString)
	if err != nil {
		return semver.Version{}, fmt.Errorf("error parsing version: %v", err)
	}

	return version, nil
}
