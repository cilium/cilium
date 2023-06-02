// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"net"

	check "github.com/cilium/checkmate"
)

func (e *AllocatorSuite) TestNoOpAllocator(c *check.C) {
	g := &NoOpAllocator{}

	quota := g.GetPoolQuota()
	c.Assert(quota["s1"].AvailableIPs, check.Equals, 0)

	err := g.Allocate("s1", net.ParseIP("1.1.1.1"))
	c.Assert(err, check.Not(check.IsNil))
	ips, err := g.AllocateMany("s1", 10)
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(len(ips), check.Equals, 0)
	err = g.ReleaseMany("s1", []net.IP{net.ParseIP("1.1.1.1")})
	c.Assert(err, check.IsNil)
}
