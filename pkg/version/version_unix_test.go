// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package version

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/versioncheck"
)

func mustHaveVersion(t *testing.T, v string) semver.Version {
	ver, err := versioncheck.Version(v)
	require.NoError(t, err)
	return ver
}

func TestParseKernelVersion(t *testing.T) {
	var flagtests = []struct {
		in  string
		out semver.Version
	}{
		{"4.10.0", mustHaveVersion(t, "4.10.0")},
		{"4.10", mustHaveVersion(t, "4.10.0")},
		{"4.12.0+", mustHaveVersion(t, "4.12.0")},
		{"4.12.8", mustHaveVersion(t, "4.12.8")},
		{"4.14.0-rc7+", mustHaveVersion(t, "4.14.0")},
		{"4.9.17-040917-generic", mustHaveVersion(t, "4.9.17")},
		{"4.9.generic", mustHaveVersion(t, "4.9.0")},
		{"6.5.0-15-generic", mustHaveVersion(t, "6.5.0")},
		{"6.7-amd64", mustHaveVersion(t, "6.7.0")},
		{"6.5-15-generic", mustHaveVersion(t, "6.5.0")},
		{"6.5.2-rc8+", mustHaveVersion(t, "6.5.2")},
		{"6-generic", mustHaveVersion(t, "6.0.0")},
		// Test cases for versions with more than 3 dot-separated components
		{"6.15.8-200.fc42.x86_64", mustHaveVersion(t, "6.15.8")},
		{"5.4.0-42.46.1-generic", mustHaveVersion(t, "5.4.0")},
		{"6.1.21-1.el9.x86_64", mustHaveVersion(t, "6.1.21")},
		{"6.2.0-20.20.1.el9_1.x86_64", mustHaveVersion(t, "6.2.0")},
		// Test cases with null bytes (from C strings)
		{"6.15.8-200.fc42.x86_64\x00\x00\x00", mustHaveVersion(t, "6.15.8")},
		{"5.4.0-generic\x00\x00\x00\x00\x00", mustHaveVersion(t, "5.4.0")},
		// Test cases with whitespace
		{"6.1.0-generic ", mustHaveVersion(t, "6.1.0")},
		{" 5.15.0-generic", mustHaveVersion(t, "5.15.0")},
		{" 6.0.0-generic ", mustHaveVersion(t, "6.0.0")},
	}
	for _, tt := range flagtests {
		s, err := ParseKernelVersion(tt.in)
		require.NoError(t, err)
		require.Equal(t, tt.out, s)
	}
}
