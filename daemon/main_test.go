// Copyright 2017 Authors of Cilium
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

// +build !privileged_tests

package main

import (
	go_version "github.com/hashicorp/go-version"

	. "gopkg.in/check.v1"
)

func (ds *DaemonSuite) TestParseKernelVersion(c *C) {
	mustHaveVersion := func(v string) *go_version.Version {
		ver, err := go_version.NewVersion(v)
		c.Assert(err, IsNil)
		return ver
	}

	var flagtests = []struct {
		in  string
		out *go_version.Version
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
		c.Assert(tt.out.Equal(s), Equals, true)
	}
}
