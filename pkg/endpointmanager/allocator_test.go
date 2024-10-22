// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// reallocatePool starts over with a new pool. This function is only used for
// tests and its implementation is not optimized for production.
func (a *epIDAllocator) reallocatePool(t testing.TB) {
	for i := uint16(minID); i <= uint16(maxID); i++ {
		a.release(i)
	}
}

func TestAllocation(t *testing.T) {
	p := newEPIDAllocator()

	idsReturned := map[uint16]struct{}{}

	for i := minID; i <= maxID; i++ {
		id := p.allocate()
		assert.NotZero(t, id)

		// check if same ID is returned more than once
		assert.NotContains(t, idsReturned, id)

		idsReturned[id] = struct{}{}
	}

	// We should be out of allocations
	assert.Zero(t, p.allocate())
}

func TestReuse(t *testing.T) {
	p := newEPIDAllocator()

	// Reusing IDs greater than the maxID is allowed
	assert.Nil(t, p.reuse(uint16(maxID+10)))

	// Reusing IDs lesser than the minID is not allowed
	assert.NotNil(t, p.reuse(uint16(minID-1)))

	idsReturned := map[uint16]struct{}{}

	assert.Nil(t, p.reuse(uint16(2)))
	idsReturned[uint16(2)] = struct{}{}

	assert.Nil(t, p.reuse(uint16(8)))
	idsReturned[uint16(8)] = struct{}{}

	for i := minID; i <= maxID-2; i++ {
		id := p.allocate()
		assert.NotZero(t, id)

		// check if same ID is returned more than once
		assert.NotContains(t, idsReturned, id)

		idsReturned[id] = struct{}{}
	}

	// We should be out of allocations
	assert.Zero(t, p.allocate())

	// 2nd reuse should fail
	assert.NotNil(t, p.reuse(uint16(2)))

	// reuse of allocated id should fail
	assert.NotNil(t, p.reuse(uint16(3)))

	// release 5
	assert.Nil(t, p.release(uint16(5)))
	delete(idsReturned, uint16(5))

	// release 6
	assert.Nil(t, p.release(uint16(6)))
	delete(idsReturned, uint16(6))

	// reuse 5 after release
	assert.Nil(t, p.reuse(uint16(5)))
	idsReturned[uint16(5)] = struct{}{}

	// allocate only available id 6
	assert.Equal(t, uint16(6), p.allocate())
}

func TestRelease(t *testing.T) {
	p := newEPIDAllocator()

	for i := minID; i <= maxID; i++ {
		assert.Nil(t, p.reuse(uint16(i)))
	}

	// must be out of IDs
	assert.Zero(t, p.allocate())

	for i := minID; i <= maxID; i++ {
		assert.Nil(t, p.release(uint16(i)))
	}
}
