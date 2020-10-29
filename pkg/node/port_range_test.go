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

package node

import (
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/sysctl"
)

type PortRangeSuite struct {
	prevEphemeralPortRange string
}

var _ = Suite(&PortRangeSuite{})

func (s *PortRangeSuite) SetUpTest(c *C) {
	prevEphemeralPortRange, err := sysctl.Read("net.ipv4.ip_local_port_range")
	c.Assert(err, IsNil)
	s.prevEphemeralPortRange = prevEphemeralPortRange
}

func (s *PortRangeSuite) TearDownTest(c *C) {
	err := sysctl.Write("net.ipv4.ip_local_port_range", s.prevEphemeralPortRange)
	c.Assert(err, IsNil)
}

func (s *PortRangeSuite) TestEphemeralPortRangeDefault(c *C) {
	_, _, _, err := EphemeralPortRange()
	c.Assert(err, IsNil)
}

func (s *PortRangeSuite) TestEphemralPortRangeCustom(c *C) {
	tests := []struct {
		epRange string
		expMin  int
		expMax  int
	}{
		{
			"32000\t32999",
			32000,
			32999,
		},
		{
			"32768\t60999",
			32768,
			60999,
		},
	}

	for _, test := range tests {
		err := sysctl.Write("net.ipv4.ip_local_port_range", test.epRange)
		c.Assert(err, IsNil)

		epRange, epMin, epMax, err := EphemeralPortRange()
		c.Assert(epRange, Equals, test.epRange)
		c.Assert(epMin, Equals, test.expMin)
		c.Assert(epMax, Equals, test.expMax)
	}
}
