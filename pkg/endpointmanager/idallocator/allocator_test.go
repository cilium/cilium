// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package idallocator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllocation(t *testing.T) {
	ReallocatePool()

	idsReturned := map[uint16]struct{}{}

	for i := minID; i <= maxID; i++ {
		id := Allocate()
		assert.NotZero(t, id)

		// check if same ID is returned more than once
		assert.NotContains(t, idsReturned, id)

		idsReturned[id] = struct{}{}
	}

	// We should be out of allocations
	assert.Zero(t, Allocate())
}

func TestReuse(t *testing.T) {
	ReallocatePool()

	// Reusing IDs greater than the maxID is allowed
	assert.Nil(t, Reuse(uint16(maxID+10)))

	// Reusing IDs lesser than the minID is not allowed
	assert.NotNil(t, Reuse(uint16(minID-1)))

	idsReturned := map[uint16]struct{}{}

	assert.Nil(t, Reuse(uint16(2)))
	idsReturned[uint16(2)] = struct{}{}

	assert.Nil(t, Reuse(uint16(8)))
	idsReturned[uint16(8)] = struct{}{}

	for i := minID; i <= maxID-2; i++ {
		id := Allocate()
		assert.NotZero(t, id)

		// check if same ID is returned more than once
		assert.NotContains(t, idsReturned, id)

		idsReturned[id] = struct{}{}
	}

	// We should be out of allocations
	assert.Zero(t, Allocate())

	// 2nd reuse should fail
	assert.NotNil(t, Reuse(uint16(2)))

	// reuse of allocated id should fail
	assert.NotNil(t, Reuse(uint16(3)))

	// release 5
	assert.Nil(t, Release(uint16(5)))
	delete(idsReturned, uint16(5))

	// release 6
	assert.Nil(t, Release(uint16(6)))
	delete(idsReturned, uint16(6))

	// reuse 5 after release
	assert.Nil(t, Reuse(uint16(5)))
	idsReturned[uint16(5)] = struct{}{}

	// allocate only available id 6
	assert.Equal(t, uint16(6), Allocate())
}

func TestRelease(t *testing.T) {
	ReallocatePool()

	for i := minID; i <= maxID; i++ {
		assert.Nil(t, Reuse(uint16(i)))
	}

	// must be out of IDs
	assert.Zero(t, Allocate())

	for i := minID; i <= maxID; i++ {
		assert.Nil(t, Release(uint16(i)))
	}
}
