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

	"github.com/cilium/cilium/pkg/ipam/types"

	"gopkg.in/check.v1"
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
