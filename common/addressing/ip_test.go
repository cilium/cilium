//
// Copyright 2016 Authors of Cilium
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
//
package addressing

import (
	"net"

	. "gopkg.in/check.v1"
)

var _ = Suite(&AddressingSuite{})

func (s *AddressingSuite) TestCiliumIPv6(c *C) {
	ip, err := NewCiliumIPv6("b007::")
	c.Assert(err, Equals, nil)
	c.Assert(ip.ValidContainerIP(), Equals, false)
	c.Assert(ip.ValidNodeIP(), Equals, false)
	c.Assert(ip.EndpointID(), Equals, uint16(0))
	c.Assert(ip.NodeID(), Equals, uint32(0))
	c.Assert(ip.NodeIP(), DeepEquals, net.ParseIP("b007::"))

	ip, err = NewCiliumIPv6("b007::aaaa:bbbb:0:0")
	c.Assert(err, Equals, nil)
	c.Assert(ip.ValidContainerIP(), Equals, false)
	c.Assert(ip.ValidNodeIP(), Equals, true)
	c.Assert(ip.EndpointID(), Equals, uint16(0))
	c.Assert(ip.NodeID(), Equals, uint32(0xaaaabbbb))
	c.Assert(ip.String(), Equals, "b007::aaaa:bbbb:0:0")
	c.Assert(ip.NodeIP(), DeepEquals, net.ParseIP("b007::aaaa:bbbb:0:0"))
}

func (s *AddressingSuite) TestCiliumIPv4(c *C) {
	ip, err := NewCiliumIPv4("10.1.0.0")
	c.Assert(err, Equals, nil)
	c.Assert(ip.EndpointID(), Equals, uint16(0))
	c.Assert(ip.NodeID(), Equals, uint32(0xa010000))

	ip, err = NewCiliumIPv4("b007::")
	c.Assert(err, Not(Equals), nil)
}

func (s *AddressingSuite) TestCiliumIPv6NodeIP(c *C) {
	ip, err := NewCiliumIPv6("b007::aaaa:bbbb:0:1")
	c.Assert(err, Equals, nil)
	c.Assert(ip.ValidContainerIP(), Equals, true)
	c.Assert(ip.ValidNodeIP(), Equals, false)
	c.Assert(ip.NodeIP(), DeepEquals, net.ParseIP("b007::aaaa:bbbb:0:0"))
}
