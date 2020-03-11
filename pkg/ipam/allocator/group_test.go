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

// +build !privileged_tests

package allocator

import (
	"math"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam/types"

	"gopkg.in/check.v1"
)

func (e *AllocatorSuite) TestPoolGroupAllocator(c *check.C) {
	g, err := NewPoolGroupAllocator(types.SubnetMap{
		"s1": &types.Subnet{ID: "s1", CIDR: cidr.MustParseCIDR("10.10.0.0/16")},
		"s2": &types.Subnet{ID: "s2", CIDR: cidr.MustParseCIDR("10.20.0.0/16")},
	})
	c.Assert(err, check.IsNil)
	c.Assert(g, check.Not(check.IsNil))
	c.Assert(g.PoolExists("s1"), check.Equals, true)
	c.Assert(g.PoolExists("s2"), check.Equals, true)
	c.Assert(g.PoolExists("s3"), check.Equals, false)
	quota := g.GetPoolQuota()
	c.Assert(quota["s1"].AvailableIPs, check.Equals, int(math.Pow(2.0, 16.0))-2)
	c.Assert(quota["s2"].AvailableIPs, check.Equals, int(math.Pow(2.0, 16.0))-2)
}

func (e *AllocatorSuite) TestPoolGroupAllocatorLimit(c *check.C) {
	g, err := NewPoolGroupAllocator(types.SubnetMap{
		"s1": &types.Subnet{ID: "s1", CIDR: cidr.MustParseCIDR("10.10.0.0/24")},
		"s2": &types.Subnet{ID: "s2", CIDR: cidr.MustParseCIDR("10.20.0.0/24")},
	})
	c.Assert(err, check.IsNil)
	c.Assert(g, check.Not(check.IsNil))

	// .0 is reserved
	maxAvailablePerPool := int(math.Pow(2.0, 8.0)) - 2
	quota := g.GetPoolQuota()
	c.Assert(quota["s1"].AvailableIPs, check.Equals, maxAvailablePerPool)
	c.Assert(quota["s2"].AvailableIPs, check.Equals, maxAvailablePerPool)

	for i := 0; i < 2*maxAvailablePerPool; i++ {
		poolID, available := g.FirstPoolWithAvailableQuota([]types.PoolID{})
		c.Assert(poolID, check.Not(check.Equals), types.PoolNotExists)
		c.Assert(available, check.Not(check.Equals), 0)

		ips, err := g.AllocateMany(poolID, 1)
		c.Assert(err, check.IsNil)
		c.Assert(len(ips), check.Equals, 1)
	}

	quota = g.GetPoolQuota()
	c.Assert(quota["s1"].AvailableIPs, check.Equals, 0)
	c.Assert(quota["s2"].AvailableIPs, check.Equals, 0)

	// Allocation must fail
	_, err = g.AllocateMany("s1", 1)
	c.Assert(err, check.Not(check.IsNil))
}

func (e *AllocatorSuite) TestPoolGroupAllocatorAlloxate(c *check.C) {
	g, err := NewPoolGroupAllocator(types.SubnetMap{
		"s1": &types.Subnet{ID: "s1", CIDR: cidr.MustParseCIDR("10.10.0.0/24")},
		"s2": &types.Subnet{ID: "s2", CIDR: cidr.MustParseCIDR("10.20.0.0/24")},
	})
	c.Assert(err, check.IsNil)
	c.Assert(g, check.Not(check.IsNil))

	// .0 is reserved
	maxAvailablePerPool := int(math.Pow(2.0, 8.0)) - 2
	quota := g.GetPoolQuota()
	c.Assert(quota["s1"].AvailableIPs, check.Equals, maxAvailablePerPool)
	c.Assert(quota["s2"].AvailableIPs, check.Equals, maxAvailablePerPool)

	err = g.Allocate("s1", net.ParseIP("10.10.0.10"))
	c.Assert(err, check.IsNil)
	err = g.Allocate("s1", net.ParseIP("10.10.0.11"))
	c.Assert(err, check.IsNil)
	err = g.Allocate("s2", net.ParseIP("10.20.0.10"))
	c.Assert(err, check.IsNil)
	err = g.Allocate("s2", net.ParseIP("10.20.0.11"))
	c.Assert(err, check.IsNil)

	quota = g.GetPoolQuota()
	c.Assert(quota["s1"].AvailableIPs, check.Equals, maxAvailablePerPool-2)
	c.Assert(quota["s2"].AvailableIPs, check.Equals, maxAvailablePerPool-2)

	// release addresses which have been allocated
	g.ReleaseMany("s1", []net.IP{net.ParseIP("10.10.0.10"), net.ParseIP("10.10.0.11")})
	g.ReleaseMany("s2", []net.IP{net.ParseIP("10.20.0.10"), net.ParseIP("10.20.0.11")})

	// release addresses which have not been allocated, this should have no effect
	g.ReleaseMany("s1", []net.IP{net.ParseIP("10.10.0.20"), net.ParseIP("10.10.0.21")})
	g.ReleaseMany("s2", []net.IP{net.ParseIP("10.20.0.20"), net.ParseIP("10.20.0.21")})

	// .0 is reserved
	quota = g.GetPoolQuota()
	c.Assert(quota["s1"].AvailableIPs, check.Equals, maxAvailablePerPool)
	c.Assert(quota["s2"].AvailableIPs, check.Equals, maxAvailablePerPool)
}
