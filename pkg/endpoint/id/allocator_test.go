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

package id

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type AllocatorSuite struct{}

var _ = Suite(&AllocatorSuite{})

func (s *AllocatorSuite) TestAllocation(c *C) {
	ReallocatePool()

	idsReturned := map[uint16]struct{}{}

	for i := minID; i <= maxID; i++ {
		id := Allocate()
		c.Assert(id, Not(Equals), uint16(0))

		// check if same ID is returned more than once
		_, ok := idsReturned[id]
		c.Assert(ok, Equals, false)

		idsReturned[id] = struct{}{}
	}

	// We should be out of allocations
	c.Assert(Allocate(), Equals, uint16(0))
}

func (s *AllocatorSuite) TestReuse(c *C) {
	ReallocatePool()

	idsReturned := map[uint16]struct{}{}

	c.Assert(Reuse(uint16(2)), IsNil)
	idsReturned[uint16(2)] = struct{}{}

	c.Assert(Reuse(uint16(8)), IsNil)
	idsReturned[uint16(8)] = struct{}{}

	for i := minID; i <= maxID-2; i++ {
		id := Allocate()
		c.Assert(id, Not(Equals), uint16(0))

		// check if same ID is returned more than once
		_, ok := idsReturned[id]
		c.Assert(ok, Equals, false)

		idsReturned[id] = struct{}{}
	}

	// We should be out of allocations
	c.Assert(Allocate(), Equals, uint16(0))

	// 2nd reuse should fail
	c.Assert(Reuse(uint16(2)), Not(IsNil))

	// reuse of allocated id should fail
	c.Assert(Reuse(uint16(3)), Not(IsNil))

	// relese 5
	c.Assert(Release(uint16(5)), IsNil)
	delete(idsReturned, uint16(5))

	// relese 6
	c.Assert(Release(uint16(6)), IsNil)
	delete(idsReturned, uint16(6))

	// reuse 5 after release
	c.Assert(Reuse(uint16(5)), IsNil)
	idsReturned[uint16(5)] = struct{}{}

	// allocate only avaiable id 6
	c.Assert(Allocate(), Equals, uint16(6))
}

func (s *AllocatorSuite) TestRelease(c *C) {
	ReallocatePool()

	for i := minID; i <= maxID; i++ {
		c.Assert(Reuse(uint16(i)), IsNil)
	}

	// must be out of IDs
	c.Assert(Allocate(), Equals, uint16(0))

	for i := minID; i <= maxID; i++ {
		c.Assert(Release(uint16(i)), IsNil)
	}
}
