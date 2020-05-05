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
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam/types"

	"gopkg.in/check.v1"
)

func (e *AllocatorSuite) TestPoolID(c *check.C) {
	poolID := types.PoolID("s-1")
	s, err := NewPoolAllocator(poolID, cidr.MustParseCIDR("1.1.1.0/24"))
	c.Assert(err, check.IsNil)
	c.Assert(s.PoolID, check.Equals, poolID)
}

func (e *AllocatorSuite) TestPoolAllocator(c *check.C) {
	_, ipnet, err := net.ParseCIDR("10.10.0.0/16")
	c.Assert(err, check.IsNil)

	s, err := NewPoolAllocator(types.PoolID("s-1"), &cidr.CIDR{IPNet: ipnet})
	c.Assert(err, check.IsNil)
	c.Assert(s, check.Not(check.IsNil))

	// .0 is reserved
	maxAvailable := 1<<16 - 2
	c.Assert(s.Free(), check.Equals, maxAvailable)

	// Allocate the next available IP
	ip, err := s.allocator.AllocateNext()
	c.Assert(err, check.IsNil)
	c.Assert(ipnet.Contains(ip), check.Equals, true)
	c.Assert(s.Free(), check.Equals, maxAvailable-1)
}

func (e *AllocatorSuite) TestPoolAllocatorLimit(c *check.C) {
	_, ipnet, err := net.ParseCIDR("10.10.0.0/24")
	c.Assert(err, check.IsNil)

	s, err := NewPoolAllocator("s-1", &cidr.CIDR{IPNet: ipnet})
	c.Assert(err, check.IsNil)
	c.Assert(s, check.Not(check.IsNil))

	// .0 is reserved
	maxAvailable := 1<<8 - 2
	c.Assert(s.Free(), check.Equals, maxAvailable)

	// Allocate all available IPs
	ips, err := s.AllocateMany(maxAvailable)
	c.Assert(err, check.IsNil)
	for _, ip := range ips {
		c.Assert(ipnet.Contains(ip), check.Equals, true)
	}

	// No more IPs should be available
	c.Assert(s.Free(), check.Equals, 0)

	// Allocation must fail
	ip, err := s.allocator.AllocateNext()
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(ip, check.IsNil)
}

func (e *AllocatorSuite) TestPoolAllocatorRelease(c *check.C) {
	_, ipnet, err := net.ParseCIDR("10.10.10.0/24")
	c.Assert(err, check.IsNil)

	s, err := NewPoolAllocator(types.PoolID("s-1"), &cidr.CIDR{IPNet: ipnet})
	c.Assert(err, check.IsNil)
	c.Assert(s, check.Not(check.IsNil))

	// .0 is reserved
	maxAvailable := 1<<8 - 2
	c.Assert(s.Free(), check.Equals, maxAvailable)

	// Allocate all available IPs
	ips, err := s.AllocateMany(maxAvailable)
	c.Assert(err, check.IsNil)
	for _, ip := range ips {
		c.Assert(ipnet.Contains(ip), check.Equals, true)
	}

	// No more IPs should be available
	c.Assert(s.Free(), check.Equals, 0)

	// Release a single IP
	s.ReleaseMany([]net.IP{net.ParseIP("10.10.10.10")})
	// 1 IP should be available
	c.Assert(s.Free(), check.Equals, 1)

	// Release an IP that is not available
	s.ReleaseMany([]net.IP{net.ParseIP("10.10.10.11"), net.ParseIP("10.10.10.12")})
	// 3 IPs should be available
	c.Assert(s.Free(), check.Equals, 3)

	// Attempt to allocate 4 IPs, only 3 should be available
	ips, err = s.AllocateMany(4)
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(ips, check.IsNil)
	// 3 IPs should still be available
	c.Assert(s.Free(), check.Equals, 3)

	// Allocate all 3 IPs
	ips, err = s.AllocateMany(3)
	c.Assert(err, check.IsNil)
	c.Assert(len(ips), check.Equals, 3)
}
