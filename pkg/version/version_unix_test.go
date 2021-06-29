// Copyright 2017-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !windows
// +build !privileged_tests

package version

import (
	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/blang/semver/v4"
	. "gopkg.in/check.v1"
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
