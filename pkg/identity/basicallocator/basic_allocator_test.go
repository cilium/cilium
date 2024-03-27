// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package basicallocator

import (
	"testing"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/stretchr/testify/assert"
)

func TestBasicAllocator(t *testing.T) {
	midID, maxID := 10, 20
	a := NewBasicIDAllocator(idpool.ID(midID), idpool.ID(maxID))
	assert.NoError(t, a.Allocate(idpool.ID(15)), "ID 15 inserted")
	assert.Error(t, a.Allocate(idpool.ID(15)), "ID 15 insert conflict")
	assert.NoError(t, a.ReturnToAvailablePool(idpool.ID(15)), "ID 15 returned to the pool")
	assert.NoError(t, a.Allocate(idpool.ID(15)), "ID 15 inserted again")
	assert.Error(t, a.ReturnToAvailablePool(idpool.ID(10)), "ID 10 cannot be returned to the pool because it isn't used")

	for i := 0; i < 10; i++ {
		_, err := a.AllocateRandom()
		assert.NoError(t, err, "Fill out all available spaces")
	}

	_, err := a.AllocateRandom()
	assert.Error(t, err, "Unable to allocate when there aren't any available")

	assert.NoError(t, a.ReturnToAvailablePool(idpool.ID(15)), "ID 15 returned to the pool")
	id, err := a.AllocateRandom()
	assert.Equal(t, idpool.ID(15), id, "ID 15 allocated")

	assert.Error(t, a.Allocate(idpool.ID(30)), "ID 30 cannot be inserted because it's outside the pool's range")
	assert.Error(t, a.ReturnToAvailablePool(idpool.ID(30)), "ID 30 cannot be returned to the pool because it's outside the pool's range")
}

func TestValidateIDString(t *testing.T) {
	midID, maxID := 10, 20
	a := NewBasicIDAllocator(idpool.ID(midID), idpool.ID(maxID))

	type tc struct {
		description string
		cidName     string
		expectedID  int64
		expectErr   bool
	}

	testCases := []tc{
		{
			description: "The ID must be convertable to an integer",
			cidName:     "cid-name-1",
			expectedID:  0,
			expectErr:   true,
		},
		{
			description: "The ID cannot be negative",
			cidName:     "-1",
			expectedID:  0,
			expectErr:   true,
		},
		{
			description: "The ID cannot be outside the ID pool",
			cidName:     "9",
			expectedID:  0,
			expectErr:   true,
		},
		{
			description: "The ID cannot be outside the ID pool",
			cidName:     "21",
			expectedID:  0,
			expectErr:   true,
		},
		{
			description: "The ID is inside the ID pool",
			cidName:     "10",
			expectedID:  10,
			expectErr:   false,
		},
		{
			description: "The ID is inside the ID pool",
			cidName:     "15",
			expectedID:  15,
			expectErr:   false,
		},
		{
			description: "The ID is inside the ID pool",
			cidName:     "20",
			expectedID:  20,
			expectErr:   false,
		},
	}

	for _, tc := range testCases {
		id, err := a.ValidateIDString(tc.cidName)
		hasErr := err != nil

		assert.Equal(t, tc.expectedID, id, tc.description)
		assert.Equal(t, tc.expectErr, hasErr, tc.description)
	}
}
