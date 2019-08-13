// Copyright 2019 Authors of Cilium
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

// +build linux,privileged_tests

package sysctl

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type SysctlLinuxPrivilegedTestSuite struct{}

var _ = Suite(&SysctlLinuxPrivilegedTestSuite{})

func (s *SysctlLinuxPrivilegedTestSuite) TestWriteSysctl(c *C) {
	testCases := []struct {
		name        string
		value       []byte
		oldValue    []byte
		expectedErr bool
	}{
		{
			name:        "net.ipv4.ip_forward",
			value:       "1",
			expectedErr: false,
		},
		{
			name:        "net.ipv4.conf.all.forwarding",
			value:       "1",
			expectedErr: false,
		},
		{
			name:        "net.ipv6.conf.all.forwarding",
			value:       "1",
			expectedErr: false,
		},
		{
			name:        "foo.bar",
			value:       "1",
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		err := writeSysctl(tc.name, tc.value)
		if tc.expectedErr {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)
		}
	}
}

func (s *SysctlLinuxPrivilegedTestSuite) TestDisableEnable(c *C) {
	testCases := []struct {
		name        string
		expectedErr bool
	}{
		{
			name:        "net.ipv4.ip_forward",
			expectedErr: false,
		},
		{
			name:        "net.ipv4.conf.all.forwarding",
			expectedErr: false,
		},
		{
			name:        "net.ipv6.conf.all.forwarding",
			expectedErr: false,
		},
		{
			name:        "foo.bar",
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		err := Enable(tc.name)
		if tc.expectedErr {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)
		}
		err = Disable(tc.name)
		if tc.expectedErr {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)
		}
	}
}
