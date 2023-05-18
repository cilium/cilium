// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package version

import (
	"github.com/blang/semver/v4"
	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/versioncheck"
)

func (vs *VersionSuite) TestParseKernelVersion(c *C) {
	mustHaveVersion := func(v string) semver.Version {
		ver, err := versioncheck.Version(v)
		c.Assert(err, IsNil)
		return ver
	}

	var flagtests = []struct {
		in  string
		out semver.Version
	}{
		{"4.10.0", mustHaveVersion("4.10.0")},
		{"4.10", mustHaveVersion("4.10.0")},
		{"4.12.0+", mustHaveVersion("4.12.0")},
		{"4.12.8", mustHaveVersion("4.12.8")},
		{"4.14.0-rc7+", mustHaveVersion("4.14.0")},
		{"4.9.17-040917-generic", mustHaveVersion("4.9.17")},
		{"4.9.generic", mustHaveVersion("4.9.0")},
	}
	for _, tt := range flagtests {
		s, err := parseKernelVersion(tt.in)
		c.Assert(err, IsNil)
		c.Assert(tt.out.Equals(s), Equals, true)
	}
}
