// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blang/semver/v4"
)

var (
	tableRowMatch = regexp.MustCompile("[|] `v")

	versions string
)

func init() {
	flag.StringVar(&versions, "versions", "versions.json", "Path to release versions JSON")
}

type release struct {
	Version semver.Version
	Date    time.Time
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s -versions FILE < INPUT\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Substitute the versions in README.rst tables with versions from a local JSON file.\n\n")
	flag.PrintDefaults()
}

func fatal(fmt string, msg ...any) {
	slog.Error(fmt, msg...)
	os.Exit(1)
}

// ParseReleases returns the current pre-release and three stable maintained
// release versions as determined from the GitHub releases page.
// The major.minor version for each returned version is different. The first
// three versions are the latest releases in order of newest to oldest. The
// last element of the slice is the latest pre-release, which may be older or
// newer than the most recent stable release.
//
// Returns a non-nil error if the latest four versions cannot be determined.
func ParseReleases(r io.Reader) (result []release, err error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading releases file: %w", err)
	}
	parsed := make([]struct {
		Version string
		Date    time.Time
	}, 0, 4)
	err = json.Unmarshal(raw, &parsed)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling json: %w", err)
	}

	releases := make([]release, len(parsed))
	for i := range parsed {
		version, err := semver.Parse(strings.TrimPrefix(parsed[i].Version, "v"))
		if err != nil {
			return nil, fmt.Errorf("parsing version %s (iter %d): %w", parsed[i].Version, i, err)
		}
		releases[i] = release{
			Version: version,
			Date:    parsed[i].Date,
		}
	}
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].Version.GE(releases[j].Version)
	})

	var prerelease release
	for _, r := range releases {
		if len(r.Version.Pre) > 0 {
			prerelease = r
			break
		}
	}
	if err := prerelease.Version.Validate(); err != nil {
		return nil, fmt.Errorf("no prerelease found in versions input")
	}
	recordedReleases := make(map[string]struct{})
	result = make([]release, 0, 4)
	for _, r := range releases {
		if len(result) == 3 {
			break
		}
		if len(r.Version.Pre) > 0 {
			continue
		}
		shortVer := fmt.Sprintf("v%d.%d", r.Version.Major, r.Version.Minor)
		if _, ok := recordedReleases[shortVer]; !ok {
			result = append(result, r)
			recordedReleases[shortVer] = struct{}{}
		}
	}
	result = append(result, prerelease)
	if len(result) < 4 {
		return nil, fmt.Errorf("insufficient stable releases found in versions input")
	}

	return result, err
}

// processLine takes an input line of the README and scans for lines that
// specify Cilium versions. If the line does not refer to a Cilium version, it
// returns the line verbatim. If the line refers to a Cilium version, it
// returns the line with the version replaced with the latest version for that
// branch (as determined by the 'version' parameter). Returns true if the line
// was modified, false otherwise.
func processLine(line []byte, r release) ([]byte, bool) {
	if !tableRowMatch.Match(line) {
		return line, false
	}

	urlTag := "https://github.com/cilium/cilium/releases/tag/"
	urlBase := "https://github.com/cilium/cilium/tree/"
	shortVer := fmt.Sprintf("v%d.%d", r.Version.Major, r.Version.Minor)
	format := "| %-55s | %s | %-34s | %-74s |"
	if len(r.Version.Pre) > 0 {
		urlBase = "https://github.com/cilium/cilium/commits/"
		shortVer = "v" + r.Version.String()
		format = "| %-74s | %s | %-39s | %-74s |"
	}

	col1 := "`" + shortVer + " <" + urlBase + shortVer + ">`__"
	col2 := r.Date.Format(time.DateOnly)
	col3 := "``quay.io/cilium/cilium:" + "v" + r.Version.String() + "``"
	col4 := "`Release Notes <" + urlTag + "v" + r.Version.String() + ">`__"

	result := fmt.Sprintf(format, col1, col2, col3, col4)
	return []byte(result), true
}

func main() {
	flag.Parse()
	if len(os.Args) != 3 {
		usage()
		os.Exit(1)
	}

	file, err := os.Open(versions)
	if err != nil {
		fatal("Failed to read versions from %s: %s", versions, err)
	}
	defer file.Close()

	releases, err := ParseReleases(file)
	if err != nil {
		fatal("Failed to %s\n", err)
	}

	output := bufio.NewWriter(os.Stdout)
	defer output.Flush()

	idx := 0
	r := releases[idx]
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line, updatedVersion := processLine(scanner.Bytes(), r)
		_, err := fmt.Fprintf(output, "%s\n", line)
		if err != nil {
			fatal("Failed to write output: %s\n", err)
		}
		if updatedVersion {
			idx++
			if idx < len(releases) {
				r = releases[idx]
			} else {
				r = release{}
			}
		}
	}
}
