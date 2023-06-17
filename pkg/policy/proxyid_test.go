// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	. "github.com/cilium/checkmate"
)

func (s *PolicyTestSuite) TestProxyID(c *C) {
	id := ProxyID(123, true, "TCP", uint16(8080))
	endpointID, ingress, protocol, port, err := ParseProxyID(id)
	c.Assert(endpointID, Equals, uint16(123))
	c.Assert(ingress, Equals, true)
	c.Assert(protocol, Equals, "TCP")
	c.Assert(port, Equals, uint16(8080))
	c.Assert(err, IsNil)
}
