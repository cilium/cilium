// Copyright 2018 Authors of Cilium
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

package node

import (
	"net"

	. "gopkg.in/check.v1"
)

func (s *NodeSuite) TestTunnelCIDRDeletionRequired(c *C) {
	_, c1, err := net.ParseCIDR("10.1.0.0/16")
	c.Assert(err, IsNil)
	_, c2, err := net.ParseCIDR("10.2.0.0/16")
	c.Assert(err, IsNil)

	c.Assert(tunnelCIDRDeletionRequired(nil, nil), Equals, false) // disabled -> disabled
	c.Assert(tunnelCIDRDeletionRequired(nil, c1), Equals, false)  // c1 -> disabled
	c.Assert(tunnelCIDRDeletionRequired(c1, c1), Equals, false)   // c1 -> c1
	c.Assert(tunnelCIDRDeletionRequired(c1, c2), Equals, true)    // c1 -> c2
	c.Assert(tunnelCIDRDeletionRequired(c2, nil), Equals, true)   // c2 -> disabled

	_, c1, err = net.ParseCIDR("f00d::a0a:0:0:0/96")
	c.Assert(err, IsNil)
	_, c2, err = net.ParseCIDR("f00d::b0b:0:0:0/96")
	c.Assert(err, IsNil)

	c.Assert(tunnelCIDRDeletionRequired(nil, nil), Equals, false) // disabled -> disabled
	c.Assert(tunnelCIDRDeletionRequired(nil, c1), Equals, false)  // c1 -> disabled
	c.Assert(tunnelCIDRDeletionRequired(c1, c1), Equals, false)   // c1 -> c1
	c.Assert(tunnelCIDRDeletionRequired(c1, c2), Equals, true)    // c1 -> c2
	c.Assert(tunnelCIDRDeletionRequired(c2, nil), Equals, true)   // c2 -> disabled
}
