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
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam/types"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type AllocatorSuite struct{}

var _ = check.Suite(&AllocatorSuite{})

func (e *AllocatorSuite) TestSubnetID(c *check.C) {
	s, err := NewAllocator("s-1", cidr.MustParseCIDR("1.1.1.0/24"))
	c.Assert(err, check.IsNil)
	c.Assert(s.SubnetID, check.Equals, "s-1")
}

func (e *AllocatorSuite) TestAllocator(c *check.C) {
	_, ipnet, err := net.ParseCIDR("10.10.0.0/16")
	c.Assert(err, check.IsNil)

	s, err := NewAllocator("s-1", &cidr.CIDR{ipnet})
	c.Assert(err, check.IsNil)
	c.Assert(s, check.Not(check.IsNil))

	// .0 is reserved
	maxAvailable := int(math.Pow(2.0, 16.0)) - 2
	c.Assert(s.Free(), check.Equals, maxAvailable)

	// Allocate the next available IP
	ip, err := s.AllocateNext()
	c.Assert(err, check.IsNil)
	c.Assert(ipnet.Contains(ip), check.Equals, true)
	c.Assert(s.Free(), check.Equals, maxAvailable-1)
}

func (e *AllocatorSuite) TestAllocatorLimit(c *check.C) {
	_, ipnet, err := net.ParseCIDR("10.10.0.0/24")
	c.Assert(err, check.IsNil)

	s, err := NewAllocator("s-1", &cidr.CIDR{ipnet})
	c.Assert(err, check.IsNil)
	c.Assert(s, check.Not(check.IsNil))

	// .0 is reserved
	maxAvailable := int(math.Pow(2.0, 8.0)) - 2
	c.Assert(s.Free(), check.Equals, maxAvailable)

	// Allocate all available IPs
	for i := 0; i < maxAvailable; i++ {
		ip, err := s.AllocateNext()
		c.Assert(err, check.IsNil)
		c.Assert(ipnet.Contains(ip), check.Equals, true)
		c.Assert(s.Free(), check.Equals, maxAvailable-i-1)
	}

	// Allocation must fail
	ip, err := s.AllocateNext()
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(ip, check.IsNil)
}

func (e *AllocatorSuite) TestAllocatorRelease(c *check.C) {
	_, ipnet, err := net.ParseCIDR("10.10.10.0/24")
	c.Assert(err, check.IsNil)

	s, err := NewAllocator("s-1", &cidr.CIDR{ipnet})
	c.Assert(err, check.IsNil)
	c.Assert(s, check.Not(check.IsNil))

	// .0 is reserved
	maxAvailable := int(math.Pow(2.0, 8.0)) - 2
	c.Assert(s.Free(), check.Equals, maxAvailable)

	// Allocate all available IPs
	for i := 0; i < maxAvailable; i++ {
		ip, err := s.AllocateNext()
		c.Assert(err, check.IsNil)
		c.Assert(ipnet.Contains(ip), check.Equals, true)
		c.Assert(s.Free(), check.Equals, maxAvailable-i-1)
	}

	// No more IPs should be available
	c.Assert(s.Free(), check.Equals, 0)

	// Release a single IP
	err = s.Release(net.ParseIP("10.10.10.10"))
	c.Assert(err, check.IsNil)
	// 1 IP should be available
	c.Assert(s.Free(), check.Equals, 1)

	// Release an IP that is not available
	s.ReleaseMany([]net.IP{net.ParseIP("10.10.10.11"), net.ParseIP("10.10.10.12")})
	// 3 IPs should be available
	c.Assert(s.Free(), check.Equals, 3)

	// Attempt to allocate 4 IPs, only 3 should be available
	ips, err := s.AllocateMany(4)
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(ips, check.IsNil)
	// 3 IPs should still be available
	c.Assert(s.Free(), check.Equals, 3)

	// Allocate all 3 IPs
	ips, err = s.AllocateMany(3)
	c.Assert(err, check.IsNil)
	c.Assert(len(ips), check.Equals, 3)
}

func (e *AllocatorSuite) TestGroupAllocator(c *check.C) {
	g, err := NewGroupAllocator(types.SubnetMap{
		"s1": &types.Subnet{ID: "s1", CIDR: cidr.MustParseCIDR("10.10.0.0/16")},
		"s2": &types.Subnet{ID: "s2", CIDR: cidr.MustParseCIDR("10.20.0.0/16")},
	})
	c.Assert(err, check.IsNil)
	c.Assert(g, check.Not(check.IsNil))
	c.Assert(g.GetAllocator("s1"), check.Not(check.IsNil))
	c.Assert(g.GetAllocator("s2"), check.Not(check.IsNil))
	c.Assert(g.GetAllocator("s3"), check.IsNil)
	c.Assert(len(g.SubnetIDs()), check.Equals, 2)
	quota := g.GetPoolQuota()
	c.Assert(quota["s1"].AvailableIPs, check.Equals, int(math.Pow(2.0, 16.0))-2)
	c.Assert(quota["s2"].AvailableIPs, check.Equals, int(math.Pow(2.0, 16.0))-2)
}
