// Copyright 2016-2018 Authors of Cilium
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

package node

import (
	"net"
	"testing"

	. "gopkg.in/check.v1"
	"k8s.io/api/core/v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type NodeSuite struct{}

var _ = Suite(&NodeSuite{})

func (s *NodeSuite) TestGetNodeIP(c *C) {
	n := Node{
		Name: "node-1",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.0.2.3"), AddressType: v1.NodeExternalIP},
		},
	}
	ip := n.GetNodeIP(false)
	// Return the only IP present
	c.Assert(ip.Equal(net.ParseIP("192.0.2.3")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("192.0.2.3"), AddressType: v1.NodeExternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeExternalIP
	c.Assert(ip.Equal(net.ParseIP("192.0.2.3")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), AddressType: v1.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeInternalIP
	c.Assert(ip.Equal(net.ParseIP("198.51.100.2")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::1"), AddressType: v1.NodeExternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeExternalIP and IPv6
	c.Assert(ip.Equal(net.ParseIP("2001:DB8::1")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::2"), AddressType: v1.NodeInternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeInternalIP and IPv6
	c.Assert(ip.Equal(net.ParseIP("2001:DB8::2")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), AddressType: v1.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// Should still return NodeInternalIP and IPv4
	c.Assert(ip.Equal(net.ParseIP("198.51.100.2")), Equals, true)

}

func (s *NodeSuite) TestAddressEqual(c *C) {
	addr1 := Address{AddressType: v1.NodeExternalIP, IP: net.ParseIP("10.1.1.1")}
	addr2 := Address{AddressType: v1.NodeInternalIP, IP: net.ParseIP("10.1.1.1")}
	addr3 := Address{AddressType: v1.NodeInternalIP, IP: net.ParseIP("10.2.2.2")}
	addr4 := Address{AddressType: v1.NodeExternalIP, IP: net.ParseIP("::1")}
	addr5 := Address{}

	c.Assert(addr1.Equal(addr1), Equals, true)
	c.Assert(addr1.Equal(addr2), Equals, false)
	c.Assert(addr1.Equal(addr3), Equals, false)
	c.Assert(addr1.Equal(addr4), Equals, false)
	c.Assert(addr1.Equal(addr5), Equals, false)

	c.Assert(addr2.Equal(addr1), Equals, false)
	c.Assert(addr2.Equal(addr2), Equals, true)
	c.Assert(addr2.Equal(addr3), Equals, false)
	c.Assert(addr2.Equal(addr4), Equals, false)
	c.Assert(addr2.Equal(addr5), Equals, false)

	c.Assert(addr3.Equal(addr1), Equals, false)
	c.Assert(addr3.Equal(addr2), Equals, false)
	c.Assert(addr3.Equal(addr3), Equals, true)
	c.Assert(addr3.Equal(addr4), Equals, false)
	c.Assert(addr3.Equal(addr5), Equals, false)

	c.Assert(addr4.Equal(addr1), Equals, false)
	c.Assert(addr4.Equal(addr2), Equals, false)
	c.Assert(addr4.Equal(addr3), Equals, false)
	c.Assert(addr4.Equal(addr4), Equals, true)
	c.Assert(addr4.Equal(addr5), Equals, false)

	c.Assert(addr5.Equal(addr1), Equals, false)
	c.Assert(addr5.Equal(addr2), Equals, false)
	c.Assert(addr5.Equal(addr3), Equals, false)
	c.Assert(addr5.Equal(addr4), Equals, false)
	c.Assert(addr5.Equal(addr5), Equals, true)
}
