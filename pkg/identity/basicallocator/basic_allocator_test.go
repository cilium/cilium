// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package basicallocator

import (
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/idpool"
)

func TestBasicIDAllocator_AllocateRandom(t *testing.T) {
	minID, maxID := 10, 20
	poolSize := maxID - minID + 1

	testCases := []struct {
		name        string
		midID       idpool.ID
		maxID       idpool.ID
		allocations int
		expectedErr error
	}{
		{
			name:        "Allocates from empty pool",
			midID:       10,
			maxID:       20,
			allocations: 1,
			expectedErr: nil,
		},
		{
			name:        "Fails when pool is full",
			midID:       10,
			maxID:       20,
			allocations: 12, // One more than the pool size
			expectedErr: fmt.Errorf("failed to allocate random ID"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allocator := NewBasicIDAllocator(idpool.ID(minID), idpool.ID(maxID))

			for i := range tc.allocations {
				_, err := allocator.AllocateRandom()

				if i < poolSize && err != nil {
					t.Fatalf("Unexpected error during allocation: %v", err)
				} else if i >= poolSize && err.Error() != tc.expectedErr.Error() {
					t.Fatalf("Expected error %v, got: %v", tc.expectedErr, err)
				}
			}
		})
	}
}

func TestBasicIDAllocator_Allocate(t *testing.T) {
	minID, maxID := 10, 20

	testCases := []struct {
		name        string
		allocateIDs []idpool.ID
		expectError bool
	}{
		{
			"Multiple valid allocations",
			[]idpool.ID{12, 17, 19},
			false,
		},
		{
			"Allocation below range",
			[]idpool.ID{9},
			true,
		},
		{
			"Allocation above range",
			[]idpool.ID{25},
			true,
		},
		{
			"Duplicate allocation",
			[]idpool.ID{15, 15},
			true,
		},
		{
			"Exhausting all IDs",
			[]idpool.ID{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			false,
		},
		{
			"Allocating after exhaustion",
			[]idpool.ID{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allocator := NewBasicIDAllocator(idpool.ID(minID), idpool.ID(maxID))

			errFound := false
			for _, id := range tc.allocateIDs {
				err := allocator.Allocate(id)

				if err != nil && !tc.expectError {
					t.Errorf("Unexpected error: %v", err)
				}
				if err != nil {
					errFound = true
				}
			}

			if !errFound && tc.expectError {
				t.Error("Expected an error, but got none")
			}

		})
	}
}

func TestBasicIDAllocator_ReturnToAvailablePool(t *testing.T) {
	minID, maxID := 10, 20

	testCases := []struct {
		name                string
		allocateIDs         []idpool.ID
		returnIDs           []idpool.ID
		expectErrors        []bool
		reAllocateIDs       []idpool.ID
		reAllocExpectErrors []bool
	}{
		{
			name:                "Allocate, return, allocate again",
			allocateIDs:         []idpool.ID{15},
			returnIDs:           []idpool.ID{15},
			expectErrors:        []bool{false, false},
			reAllocateIDs:       []idpool.ID{15},
			reAllocExpectErrors: []bool{false},
		},
		{
			name:                "Attempt reallocation before return",
			allocateIDs:         []idpool.ID{12},
			returnIDs:           []idpool.ID{},
			expectErrors:        []bool{},
			reAllocateIDs:       []idpool.ID{12},
			reAllocExpectErrors: []bool{true},
		},
		{
			name:                "Return unallocated ID then allocate",
			allocateIDs:         []idpool.ID{},
			returnIDs:           []idpool.ID{15},
			expectErrors:        []bool{true},
			reAllocateIDs:       []idpool.ID{15, 16},
			reAllocExpectErrors: []bool{false, false},
		},
		{
			name:                "Return ID below and above range",
			allocateIDs:         []idpool.ID{},
			returnIDs:           []idpool.ID{9, 21},
			expectErrors:        []bool{true, true},
			reAllocateIDs:       []idpool.ID{},
			reAllocExpectErrors: []bool{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allocator := NewBasicIDAllocator(idpool.ID(minID), idpool.ID(maxID))

			for _, id := range tc.allocateIDs {
				err := allocator.Allocate(id)
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}

			for i, id := range tc.returnIDs {
				err := allocator.ReturnToAvailablePool(id)
				if (err != nil) != tc.expectErrors[i] {
					t.Errorf("Unexpected error behavior for return %d with ID(%d): %v", i+1, id, err)
				}
			}

			for i, id := range tc.reAllocateIDs {
				err := allocator.Allocate(id)
				if (err != nil) != tc.reAllocExpectErrors[i] {
					t.Errorf("Unexpected error behavior for reallocation %d with ID(%d): %v", i+1, id, err)
				}
			}

		})
	}

}

func TestBasicIDAllocator_ValidateIDString(t *testing.T) {
	minID, maxID := 10, 20

	testCases := []struct {
		name       string
		cidName    string
		expectedID int64
		expectErr  bool
	}{
		{
			name:       "The ID must be convertable to an integer",
			cidName:    "cid-name-1",
			expectedID: 0,
			expectErr:  true,
		},
		{
			name:       "The ID cannot be negative",
			cidName:    "-1",
			expectedID: 0,
			expectErr:  true,
		},
		{
			name:       "The ID cannot be outside the ID pool",
			cidName:    "9",
			expectedID: 0,
			expectErr:  true,
		},
		{
			name:       "The ID cannot be outside the ID pool",
			cidName:    "21",
			expectedID: 0,
			expectErr:  true,
		},
		{
			name:       "The ID is inside the ID pool",
			cidName:    "10",
			expectedID: 10,
			expectErr:  false,
		},
		{
			name:       "The ID is inside the ID pool",
			cidName:    "15",
			expectedID: 15,
			expectErr:  false,
		},
		{
			name:       "The ID is inside the ID pool",
			cidName:    "20",
			expectedID: 20,
			expectErr:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allocator := NewBasicIDAllocator(idpool.ID(minID), idpool.ID(maxID))

			id, err := allocator.ValidateIDString(tc.cidName)
			hasErr := err != nil

			if id != tc.expectedID {
				t.Errorf("Expected ID: %d, but got: %d", tc.expectedID, id)
			}

			if hasErr != tc.expectErr {
				if tc.expectErr {
					t.Errorf("Expected an error, but got none")
				} else {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
