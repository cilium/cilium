// Copyright 2019-2021 Authors of Cilium
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

package sysctl

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type SysctlLinuxTestSuite struct{}

var _ = Suite(&SysctlLinuxTestSuite{})

func (s *SysctlLinuxTestSuite) TestFullPath(c *C) {
	testCases := []struct {
		name        string
		expected    string
		expectedErr bool
	}{
		{
			name:     "net.ipv4.ip_forward",
			expected: "/proc/sys/net/ipv4/ip_forward",
		},
		{
			name:     "net.ipv4.conf.all.forwarding",
			expected: "/proc/sys/net/ipv4/conf/all/forwarding",
		},
		{
			name:     "net.ipv6.conf.all.forwarding",
			expected: "/proc/sys/net/ipv6/conf/all/forwarding",
		},
		{
			name:     "foo.bar",
			expected: "/proc/sys/foo/bar",
		},
		{
			name:        "double..dot",
			expectedErr: true,
		},
		{
			name:        "invalid.char$",
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		path, err := parameterPath(tc.name)
		if tc.expectedErr {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)
			c.Assert(path, Equals, tc.expected)
		}
	}
}
