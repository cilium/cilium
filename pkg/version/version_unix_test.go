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
		// RHEL style kernel versions include release and arch bits.
		{"4.18.0-240", mustHaveVersion(t, "4.18.0")},
		{"4.18.0-240.el8", mustHaveVersion(t, "4.18.0")},
		{"4.18.0-477.10.1", mustHaveVersion(t, "4.18.0")},
		{"4.18.0-477.10.1.el8", mustHaveVersion(t, "4.18.0")},
		{"4.18.0-477.10.1.el8.x86_64", mustHaveVersion(t, "4.18.0")},
		{"5.14.0-284.11.1.el9", mustHaveVersion(t, "5.14.0")},
		{"5.14.0-427.42.1.el9_4.x86_64", mustHaveVersion(t, "5.14.0")},
	}
	for _, tt := range flagtests {
		s, err := parseKernelVersion(tt.in)
		require.NoError(t, err)
		require.Equal(t, tt.out, s)
	}
}
