// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	. "gopkg.in/check.v1"
)

func (s *PolicyTestSuite) TestProxyID(c *C) {
	id := ProxyID(123, true, "TCP", uint16(8080), "http", "")
	endpointID, ingress, protocol, port, parser, listener, err := ParseProxyID(id)
	c.Assert(endpointID, Equals, uint16(123))
	c.Assert(ingress, Equals, true)
	c.Assert(protocol, Equals, "TCP")
	c.Assert(port, Equals, uint16(8080))
	c.Assert(parser, Equals, ParserTypeHTTP)
	c.Assert(listener, Equals, "")
	c.Assert(err, IsNil)

	id = ProxyID(321, false, "TCP", uint16(80), "crd", "myListener")
	endpointID, ingress, protocol, port, parser, listener, err = ParseProxyID(id)
	c.Assert(endpointID, Equals, uint16(321))
	c.Assert(ingress, Equals, false)
	c.Assert(protocol, Equals, "TCP")
	c.Assert(port, Equals, uint16(80))
	c.Assert(parser, Equals, ParserTypeCRD)
	c.Assert(listener, Equals, "myListener")
	c.Assert(err, IsNil)
}
