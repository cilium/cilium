// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package idallocator

import (
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type IDSuite struct{}

var _ = Suite(&IDSuite{})

func (s *IDSuite) TestAllocation(c *C) {
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

func (s *IDSuite) TestReuse(c *C) {
	ReallocatePool()

	// Reusing IDs greater than the maxID is allowed
	c.Assert(Reuse(uint16(maxID+10)), IsNil)

	// Reusing IDs lesser than the minID is not allowed
	c.Assert(Reuse(uint16(minID-1)), Not(IsNil))

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

	// release 5
	c.Assert(Release(uint16(5)), IsNil)
	delete(idsReturned, uint16(5))

	// release 6
	c.Assert(Release(uint16(6)), IsNil)
	delete(idsReturned, uint16(6))

	// reuse 5 after release
	c.Assert(Reuse(uint16(5)), IsNil)
	idsReturned[uint16(5)] = struct{}{}

	// allocate only available id 6
	c.Assert(Allocate(), Equals, uint16(6))
}

func (s *IDSuite) TestRelease(c *C) {
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
