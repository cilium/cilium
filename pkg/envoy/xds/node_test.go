// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	. "github.com/cilium/checkmate"
)

type NodeSuite struct{}

var _ = Suite(&NodeSuite{})

func (s *NodeSuite) TestEnvoyNodeToIP(c *C) {
	var ip string
	var err error

	ip, err = EnvoyNodeIdToIP("host~127.0.0.1~no-id~localdomain")
	c.Assert(err, IsNil)
	c.Check(ip, Equals, "127.0.0.1")

	_, err = EnvoyNodeIdToIP("host~127.0.0.1~localdomain")
	c.Assert(err, Not(IsNil))

	_, err = EnvoyNodeIdToIP("host~not-an-ip~v0.default~default.svc.cluster.local")
	c.Assert(err, Not(IsNil))
}
