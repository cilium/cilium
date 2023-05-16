// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package sysctl

import (
	"github.com/cilium/cilium/pkg/testutils"

	. "github.com/cilium/checkmate"
)

type SysctlLinuxPrivilegedTestSuite struct{}

var _ = Suite(&SysctlLinuxPrivilegedTestSuite{})

func (s *SysctlLinuxPrivilegedTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

func (s *SysctlLinuxPrivilegedTestSuite) TestWriteSysctl(c *C) {
	testCases := []struct {
		name        string
		value       string
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

			val, err := Read(tc.name)
			c.Assert(err, IsNil)
			c.Assert(val, Equals, "1")
		}
		err = Disable(tc.name)
		if tc.expectedErr {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)

			val, err := Read(tc.name)
			c.Assert(err, IsNil)
			c.Assert(val, Equals, "0")
		}
	}
}

func (s *SysctlLinuxPrivilegedTestSuite) TestApplySettings(c *C) {
	testCases := []struct {
		settings    []Setting
		expectedErr bool
	}{
		{
			settings: []Setting{
				{
					Name:      "net.ipv4.ip_forward",
					Val:       "1",
					IgnoreErr: false,
				},
				{
					Name:      "net.ipv4.conf.all.forwarding",
					Val:       "1",
					IgnoreErr: false,
				},
				{
					Name:      "net.ipv6.conf.all.forwarding",
					Val:       "1",
					IgnoreErr: false,
				},
			},
			expectedErr: false,
		},
		{
			settings: []Setting{
				{
					Name:      "net.ipv4.ip_forward",
					Val:       "1",
					IgnoreErr: false,
				},
				{
					Name:      "foo.bar",
					Val:       "1",
					IgnoreErr: false,
				},
			},
			expectedErr: true,
		},
		{
			settings: []Setting{
				{
					Name:      "net.ipv4.ip_forward",
					Val:       "1",
					IgnoreErr: false,
				},
				{
					Name:      "foo.bar",
					Val:       "1",
					IgnoreErr: true,
				},
			},
		},
	}

	for _, tc := range testCases {
		err := ApplySettings(tc.settings)
		if tc.expectedErr {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)
		}
	}
}
