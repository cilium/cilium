// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2021 Authors of Cilium

//go:build !privileged_tests
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
