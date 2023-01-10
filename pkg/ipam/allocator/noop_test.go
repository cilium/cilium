// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"net"

	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/ipam/types"
)

func (e *AllocatorSuite) TestNoOpAllocator(c *check.C) {
	g := &NoOpAllocator{}

	c.Assert(g.PoolExists("s1"), check.Equals, false)

	quota := g.GetPoolQuota()
	c.Assert(quota["s1"].AvailableIPs, check.Equals, 0)

	poolID, available := g.FirstPoolWithAvailableQuota([]types.PoolID{})
	c.Assert(poolID, check.Equals, types.PoolNotExists)
	c.Assert(available, check.Equals, 0)

	err := g.Allocate("s1", net.ParseIP("1.1.1.1"))
	c.Assert(err, check.Not(check.IsNil))
	ips, err := g.AllocateMany("s1", 10)
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(len(ips), check.Equals, 0)
	err = g.ReleaseMany("s1", []net.IP{net.ParseIP("1.1.1.1")})
	c.Assert(err, check.IsNil)
}
