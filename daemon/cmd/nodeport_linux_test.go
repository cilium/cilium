// Copyright 2020 Authors of Cilium
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

package cmd

import (
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
)

type NodePortSuite struct {
	prevEphemeralPortRange string
	prevReservedPortRanges string
}

var _ = Suite(&NodePortSuite{})

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
