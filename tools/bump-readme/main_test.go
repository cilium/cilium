// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	_ "embed"
	"strings"
	"testing"
	"time"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata/versions.json
var testReleases string

func TestParseReleasesFile(t *testing.T) {
	reader := strings.NewReader(testReleases)
	expected := []release{
		{
			Version: semver.MustParse("1.17.1"),
			Date:    time.Date(2025, 2, 12, 0, 0, 0, 0, time.UTC),
		},
		{
			Version: semver.MustParse("1.16.7"),
			Date:    time.Date(2025, 2, 13, 0, 0, 0, 0, time.UTC),
		},
		{
			Version: semver.MustParse("1.15.14"),
			Date:    time.Date(2025, 2, 18, 0, 0, 0, 0, time.UTC),
		},
		{
			Version: semver.MustParse("1.18.0-pre.0"),
			Date:    time.Date(2025, 3, 3, 0, 0, 0, 0, time.UTC),
		},
	}

	result, err := ParseReleases(reader)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, len(expected), len(result))
	for i := range result {
		assert.Equal(t, expected[i].Version.String(), result[i].Version.String())
		assert.Equal(t, expected[i].Date.String(), result[i].Date.String())
	}
}

func TestParseReleasesSort(t *testing.T) {
	input := `[
		{"version": "v1.17.0-rc.3"},
		{"version": "v1.17.0-rc.2"},
		{"version": "v1.17.1"},
		{"version": "v1.17.0"},
		{"version": "v1.16.6"},
		{"version": "v1.16.7"},
		{"version": "v1.15.14"},
		{"version": "v1.15.13"},
		{"version": "v1.15.12"}
	]`

	reader := strings.NewReader(input)
	expected := []release{
		{
			Version: semver.MustParse("1.17.1"),
		},
		{
			Version: semver.MustParse("1.16.7"),
		},
		{
			Version: semver.MustParse("1.15.14"),
		},
		{
			Version: semver.MustParse("1.17.0-rc.3"),
		},
	}
	result, err := ParseReleases(reader)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, len(expected), len(result))
	for i := range result {
		assert.Equal(t, expected[i].Version.String(), result[i].Version.String(), "Unexpected version at index %d", i)
		assert.Equal(t, expected[i].Date.String(), result[i].Date.String(), "Unexpected date at index %d", i)
	}
}

func TestProcessLine(t *testing.T) {
	stableRelease := release{
		Version: semver.MustParse("1.17.1"),
		Date:    time.Date(2025, 2, 12, 0, 0, 0, 0, time.UTC),
	}
	prerelease := release{
		Version: semver.MustParse("1.18.0-pre.1"),
		Date:    time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	type test struct {
		release  release
		input    string
		expected string
	}
	for _, tt := range []test{
		{
			release:  prerelease,
			input:    "| `v1.18.0-pre.0 <https://github.com/cilium/cilium/commits/v1.18.0-pre.0>`__ | 2025-03-03 | ``quay.io/cilium/cilium:v1.18.0-pre.0`` | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.18.0-pre.0>`__ |",
			expected: "| `v1.18.0-pre.1 <https://github.com/cilium/cilium/commits/v1.18.0-pre.1>`__ | 0001-01-01 | ``quay.io/cilium/cilium:v1.18.0-pre.1`` | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.18.0-pre.1>`__ |",
		},
		{
			release:  stableRelease,
			input:    "| `v1.16 <https://github.com/cilium/cilium/tree/v1.16>`__ | 2025-02-12 | ``quay.io/cilium/cilium:v1.16.1``  | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.16.1>`__ |",
			expected: "| `v1.17 <https://github.com/cilium/cilium/tree/v1.17>`__ | 2025-02-12 | ``quay.io/cilium/cilium:v1.17.1``  | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.17.1>`__ |",
		},
		{
			release:  stableRelease,
			input:    "| `v1.17 <https://github.com/cilium/cilium/tree/v1.17>`__ | 2025-02-12 | ``quay.io/cilium/cilium:v1.17.1``  | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.17.1>`__ |",
			expected: "| `v1.17 <https://github.com/cilium/cilium/tree/v1.17>`__ | 2025-02-12 | ``quay.io/cilium/cilium:v1.17.1``  | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.17.1>`__ |",
		},
	} {
		result, diff := processLine([]byte(tt.input), tt.release)
		assert.Equal(t, true, diff)
		assert.Equal(t, string(tt.expected), string(result))
	}
}
