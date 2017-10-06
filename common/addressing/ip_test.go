// Copyright 2016-2017 Authors of Cilium
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

package addressing

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/comparator"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type AddressingSuite struct{}

var _ = Suite(&AddressingSuite{})

func (s *AddressingSuite) TestCiliumIPv6(c *C) {
	ip, err := NewCiliumIPv6("b007::")
	c.Assert(err, IsNil)
	c.Assert(ip.ValidContainerIP(), Equals, false)
	c.Assert(ip.ValidNodeIP(), Equals, false)
	c.Assert(ip.EndpointID(), Equals, uint16(0))
	c.Assert(ip.NodeID(), Equals, uint32(0))
	c.Assert(ip.NodeIP(), comparator.DeepEquals, net.ParseIP("b007::"))
	c.Assert(ip.HostIP(), comparator.DeepEquals, net.ParseIP("b007::ffff"))
	ip2, _ := NewCiliumIPv6("")
	// Lacking a better Equals method, checking if the stringified IP is consistent
	c.Assert(ip.String() == ip2.String(), Equals, false)
	marsh, _ := ip.MarshalJSON()
	ip2.UnmarshalJSON(marsh)
	c.Assert(ip.String() == ip2.String(), Equals, true)

	ip, err = NewCiliumIPv6("b007::aaaa:bbbb:0:0")
	c.Assert(err, IsNil)
	c.Assert(ip.ValidContainerIP(), Equals, false)
	c.Assert(ip.ValidNodeIP(), Equals, true)
	c.Assert(ip.EndpointID(), Equals, uint16(0))
	c.Assert(ip.NodeID(), Equals, uint32(0xaaaabbbb))
	c.Assert(ip.String(), Equals, "b007::aaaa:bbbb:0:0")
	c.Assert(ip.NodeIP(), comparator.DeepEquals, net.ParseIP("b007::aaaa:bbbb:0:0"))
}

func (s *AddressingSuite) TestCiliumIPv4(c *C) {
	ip, err := NewCiliumIPv4("10.1.0.0")
	c.Assert(err, IsNil)
	c.Assert(ip.EndpointID(), Equals, uint16(0))
	c.Assert(ip.NodeID(), Equals, uint32(0xa010000))
	c.Assert(ip.ValidContainerIP(), Equals, false)
	c.Assert(ip.ValidNodeIP(), Equals, false)
	c.Assert(ip.NodeIP().String(), Equals, "10.1.0.1")
	ip2, _ := NewCiliumIPv4("")
	// Lacking a better Equals method, checking if the stringified IP is consistent
	c.Assert(ip.String() == ip2.String(), Equals, false)
	marsh, _ := ip.MarshalJSON()
	ip2.UnmarshalJSON(marsh)
	c.Assert(ip.String() == ip2.String(), Equals, true)

	ip, err = NewCiliumIPv4("b007::")
	c.Assert(err, Not(Equals), nil)
}

func (s *AddressingSuite) TestCiliumIPv6NodeIP(c *C) {
	ip, err := NewCiliumIPv6("b007::aaaa:bbbb:0:1")
	c.Assert(err, IsNil)
	c.Assert(ip.ValidContainerIP(), Equals, true)
	c.Assert(ip.ValidNodeIP(), Equals, false)
	c.Assert(ip.NodeIP(), comparator.DeepEquals, net.ParseIP("b007::aaaa:bbbb:0:0"))
}

func (s *AddressingSuite) TestCiliumIPv6Negative(c *C) {
	ip, err := NewCiliumIPv6("")
	c.Assert(err, NotNil)
	c.Assert(ip, IsNil)
	c.Assert(ip.String(), Equals, "")
	marsh, _ := ip.MarshalJSON()
	// Unmarshal nil IP
	c.Assert(ip.UnmarshalJSON(marsh), IsNil)
	// Unmarshal IP of invalid length
	c.Assert(ip.UnmarshalJSON([]byte{0x01}), NotNil)
	// Unmarshal IPv4
	c.Assert(ip.UnmarshalJSON(
		[]byte{'1', '0', '.', '1', '.', '0', '.', '0'}), NotNil)

	ip, err = NewCiliumIPv6("192.168.0.1")
	c.Assert(err, NotNil)
	c.Assert(ip, IsNil)
}

func (s *AddressingSuite) TestCiliumIPv6State(c *C) {
	ip, _ := NewCiliumIPv6("b007::")
	c.Assert(ip.State(), Equals, uint16(0x0))
	ip.SetState(uint16(0xAABB))
	c.Assert(ip.State(), Equals, uint16(0xAABB))
}

func (s *AddressingSuite) TestCiliumIPv4Negative(c *C) {
	ip, err := NewCiliumIPv4("")
	c.Assert(err, NotNil)
	c.Assert(ip, IsNil)
	c.Assert(ip.String(), Equals, "")
	marsh, _ := ip.MarshalJSON()
	// Unmarshal nil IP
	c.Assert(ip.UnmarshalJSON(marsh), IsNil)
	// Unmarshal IP of invalid length
	c.Assert(ip.UnmarshalJSON([]byte{0x01}), NotNil)
	// Unmarshal IPv6
	c.Assert(ip.UnmarshalJSON([]byte{'f', 'a', 'c', 'e', ':', ':'}), NotNil)
}
