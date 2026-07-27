// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conn

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestParseVersionFromHeader(t *testing.T) {
	tests := []struct {
		name      string
		header    metadata.MD
		key       string
		expected  semver.Version
		expectErr bool
	}{
		{
			name:     "missing-key",
			header:   metadata.Pairs("another-key", "1.1.1"),
			key:      "my-key",
			expected: zeroVersion,
		},
		{
			name:      "invalid-version",
			header:    metadata.Pairs("my-key", "1,1.1"),
			key:       "my-key",
			expectErr: true,
		},
		{
			name:     "valid-version",
			header:   metadata.Pairs("my-key", "1.1.1-alpha-1+123456.789"), // Build is not compared
			key:      "my-key",
			expected: semver.Version{Major: 1, Minor: 1, Patch: 1, Pre: []semver.PRVersion{{VersionStr: "alpha-1"}}},
		},
		{
			name:     "valid-version-whitespaces",
			header:   metadata.Pairs("my-key", "    1.1.1-alpha-1+123456.789 "), // Build is not compared
			key:      "my-key",
			expected: semver.Version{Major: 1, Minor: 1, Patch: 1, Pre: []semver.PRVersion{{VersionStr: "alpha-1"}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseVersionFromHeader(tc.header, tc.key)
			if tc.expectErr {
				assert.Error(t, err)
				return
			}
			assert.Truef(t, tc.expected.EQ(parsed), "expected: %+v got: +%v", tc.expected, parsed)
		})
	}
}

func TestIsVersionlowerThanCLI(t *testing.T) {
	tests := []struct {
		name       string
		version    semver.Version
		cliVersion semver.Version
		isLower    bool
	}{
		{
			name:       "major-lower",
			version:    semver.Version{Major: 2, Minor: 0, Patch: 0},
			cliVersion: semver.Version{Major: 1, Minor: 0, Patch: 0},
			isLower:    true,
		},
		{
			name:       "minor-lower",
			version:    semver.Version{Major: 1, Minor: 1, Patch: 0},
			cliVersion: semver.Version{Major: 1, Minor: 0, Patch: 0},
			isLower:    true,
		},
		{
			name:       "patch-not-lower",
			version:    semver.Version{Major: 1, Minor: 0, Patch: 1},
			cliVersion: semver.Version{Major: 1, Minor: 0, Patch: 0},
			isLower:    false,
		},
		{
			name:       "pre-not-lower",
			version:    semver.Version{Major: 1, Minor: 0, Patch: 0, Pre: []semver.PRVersion{{VersionNum: 1, IsNum: true}}},
			cliVersion: semver.Version{Major: 1, Minor: 0, Patch: 0},
			isLower:    false,
		},
		{
			name:       "build-not-lower",
			version:    semver.Version{Major: 1, Minor: 0, Patch: 0, Build: []string{"my-build"}},
			cliVersion: semver.Version{Major: 1, Minor: 0, Patch: 0},
			isLower:    false,
		},
		{
			name:       "zero-version-not-lower",
			version:    zeroVersion,
			cliVersion: semver.Version{Major: 1, Minor: 0, Patch: 0},
			isLower:    false,
		},
		{
			name:       "cli-version-major-not-lower",
			version:    semver.Version{Major: 1, Minor: 0, Patch: 0},
			cliVersion: semver.Version{Major: 2, Minor: 0, Patch: 0},
			isLower:    false,
		},
		{
			name:       "cli-version-minor-not-lower",
			version:    semver.Version{Major: 1, Minor: 0, Patch: 0},
			cliVersion: semver.Version{Major: 1, Minor: 1, Patch: 0},
			isLower:    false,
		},
		{
			name:       "cli-version-patch-not-lower",
			version:    semver.Version{Major: 1, Minor: 0, Patch: 0},
			cliVersion: semver.Version{Major: 1, Minor: 0, Patch: 1},
			isLower:    false,
		},
		{
			name:       "cli-version-pre-not-lower",
			version:    semver.Version{Major: 1, Minor: 0, Patch: 0},
			cliVersion: semver.Version{Major: 1, Minor: 0, Patch: 1, Pre: []semver.PRVersion{{VersionNum: 1, IsNum: true}}},
			isLower:    false,
		},
		{
			name:       "cli-version-build-not-lower",
			version:    semver.Version{Major: 1, Minor: 0, Patch: 0},
			cliVersion: semver.Version{Major: 1, Minor: 0, Patch: 1, Build: []string{"my-build"}},
			isLower:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			comparator := newMinorVersionComparator(tc.cliVersion)
			isLower := comparator.IsLowerThan(tc.version)
			assert.Equal(t, tc.isLower, isLower)
		})
	}
}
