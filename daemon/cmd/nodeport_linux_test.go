// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"fmt"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/testutils"
)

type NodePortSuite struct {
	prevEphemeralPortRange string
	prevReservedPortRanges string
}

var _ = Suite(&NodePortSuite{})

func (s *NodePortSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

func (s *NodePortSuite) SetUpTest(c *C) {
	prevEphemeralPortRange, err := sysctl.Read("net.ipv4.ip_local_port_range")
	c.Assert(err, IsNil)
	s.prevEphemeralPortRange = prevEphemeralPortRange
	prevReservedPortRanges, err := sysctl.Read("net.ipv4.ip_local_reserved_ports")
	c.Assert(err, IsNil)
	s.prevReservedPortRanges = prevReservedPortRanges
}

func (s *NodePortSuite) TearDownTest(c *C) {
	err := sysctl.Write("net.ipv4.ip_local_port_range", s.prevEphemeralPortRange)
	c.Assert(err, IsNil)
	err = sysctl.Write("net.ipv4.ip_local_reserved_ports", s.prevReservedPortRanges)
	c.Assert(err, IsNil)
}

func (s *NodePortSuite) TestCheckNodePortAndEphemeralPortRanges(c *C) {
	cases := []struct {
		npMin       int
		npMax       int
		epMin       int
		epMax       int
		resPorts    string
		autoProtect bool

		expResPorts string
		expErr      bool
		expErrMatch string
	}{
		{32000, 32999, 10000, 40000, "\n", true, "32000-32999", false, ""},
		{32000, 32999, 10000, 40000, "\n", false, "", true, ".* must not clash.*"},
		{32000, 32999, 10000, 40000, "32000-32500\n", true, "32000-32999", false, ""},
		{32000, 32999, 10000, 40000, "32000-33000\n", false, "32000-33000", false, ""},
		{32000, 32999, 33000, 40000, "\n", false, "", false, ""},
		{32000, 32999, 10000, 40000, "20000\n", true, "20000,32000-32999", false, ""},
		{32000, 32999, 10000, 20000, "\n", true, "", true, ".* after ephemeral.*"},
	}

	for _, test := range cases {
		option.Config.NodePortMin = test.npMin
		option.Config.NodePortMax = test.npMax
		option.Config.EnableAutoProtectNodePortRange = test.autoProtect
		err := sysctl.Write("net.ipv4.ip_local_port_range",
			fmt.Sprintf("%d %d", test.epMin, test.epMax))
		c.Assert(err, IsNil)
		err = sysctl.Write("net.ipv4.ip_local_reserved_ports", test.resPorts)
		c.Assert(err, IsNil)

		err = checkNodePortAndEphemeralPortRanges()
		if test.expErr {
			c.Assert(err, ErrorMatches, test.expErrMatch)
		} else {
			c.Assert(err, IsNil)
			resPorts, err := sysctl.Read("net.ipv4.ip_local_reserved_ports")
			c.Assert(err, IsNil)
			c.Assert(resPorts, Equals, test.expResPorts)
		}
	}
}
