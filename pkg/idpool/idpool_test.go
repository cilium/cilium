// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package idpool

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLeaseAvailableID(t *testing.T) {
	minID, maxID := 1, 5
	p := NewIDPool(ID(minID), ID(maxID))

	leaseAllIDs(p, minID, maxID, t)
}

func TestInsertIDs(t *testing.T) {
	minID, maxID := 2, 6
	p := NewIDPool(ID(minID), ID(maxID))

	// Insert IDs beyond minID, maxID range.
	for i := minID - 1; i <= maxID+1; i++ {
		require.Equal(t, i < minID || i > maxID, p.Insert(ID(i)))
		require.False(t, p.Insert(ID(i)))
	}

	leaseAllIDs(p, minID-1, maxID+1, t)
}

func TestInsertRemoveIDs(t *testing.T) {
	minID, maxID := 1, 5
	p := NewIDPool(ID(minID), ID(maxID))

	// Remove all IDs.
	for i := minID; i <= maxID; i++ {
		require.True(t, p.Remove(ID(i)))
		require.False(t, p.Remove(ID(i)))
	}
	// We should be out of IDs.
	id := p.LeaseAvailableID()
	require.Equal(t, NoID, id)

	// Re-insert all IDs.
	for i := minID; i <= maxID; i++ {
		require.True(t, p.Insert(ID(i)))
		require.False(t, p.Insert(ID(i)))
	}

	// Remove odd-numbered IDs.
	for i := minID; i <= maxID; i++ {
		if i%2 != 0 {
			require.True(t, p.Remove(ID(i)))
		}
	}

	// Only even-numbered IDs should be left.
	evenIDs := make([]int, 0)
	actualIDs := make([]int, 0)
	for i := minID; i <= maxID; i++ {
		if i%2 == 0 {
			id := p.LeaseAvailableID()
			require.NotEqual(t, NoID, id)
			actualIDs = append(actualIDs, int(id))
			evenIDs = append(evenIDs, i)
		}
	}
	// We should be out of IDs.
	id = p.LeaseAvailableID()
	require.Equal(t, NoID, id)

	require.ElementsMatch(t, evenIDs, actualIDs)
}

func TestReleaseID(t *testing.T) {
	minID, maxID := 1, 5
	p := NewIDPool(ID(minID), ID(maxID))

	// Lease all ids and release them.
	for i := minID; i <= maxID; i++ {
		id := p.LeaseAvailableID()
		require.NotEqual(t, NoID, id)
	}
	// We should be out of IDs.
	id := p.LeaseAvailableID()
	require.Equal(t, NoID, id)

	for i := minID; i <= maxID; i++ {
		require.True(t, p.Release(ID(i)))
		require.False(t, p.Release(ID(i)))
	}

	// Lease all ids. This time, remove them before
	// releasing them.
	leaseAllIDs(p, minID, maxID, t)
	for i := minID; i <= maxID; i++ {
		require.False(t, p.Remove(ID(i)))
	}
	// Release should not have any effect.
	for i := minID; i <= maxID; i++ {
		require.False(t, p.Release(ID(i)))
	}
}

func TestOperationsOnAvailableIDs(t *testing.T) {
	minID, maxID := 1, 5

	// Leasing available IDs should move its state to leased.
	p0 := NewIDPool(ID(minID), ID(maxID))
	leaseAllIDs(p0, minID, maxID, t)
	// Check all IDs are in leased state.
	for i := minID; i <= maxID; i++ {
		require.True(t, p0.Release(ID(i)))
	}
	leaseAllIDs(p0, minID, maxID, t)

	// Releasing available IDs should not have any effect.
	p1 := NewIDPool(ID(minID), ID(maxID))
	for i := minID; i <= maxID; i++ {
		require.False(t, p1.Release(ID(i)))
	}
	leaseAllIDs(p1, minID, maxID, t)

	// Using available IDs should not have any effect.
	p2 := NewIDPool(ID(minID), ID(maxID))
	for i := minID; i <= maxID; i++ {
		require.False(t, p2.Use(ID(i)))
	}
	leaseAllIDs(p2, minID, maxID, t)

	// Inserting available IDs should not have any effect.
	p3 := NewIDPool(ID(minID), ID(maxID))
	for i := minID; i <= maxID; i++ {
		require.False(t, p3.Insert(ID(i)))
	}
	leaseAllIDs(p3, minID, maxID, t)

	// Removing available IDs should make them unavailable.
	p4 := NewIDPool(ID(minID), ID(maxID))
	for i := minID; i <= maxID; i++ {
		require.True(t, p4.Remove(ID(i)))
	}
	leaseAllIDs(p4, minID, minID-1, t)
	for i := minID; i <= maxID; i++ {
		require.False(t, p4.Release(ID(i)))
	}
}

func TestOperationsOnLeasedIDs(t *testing.T) {
	minID, maxID := 1, 5
	var poolWithAllIDsLeased = func() *IDPool {
		p := NewIDPool(ID(minID), ID(maxID))
		leaseAllIDs(p, minID, maxID, t)
		return p
	}

	// Releasing leased IDs should make it available again.
	p0 := poolWithAllIDsLeased()
	for i := minID; i <= maxID; i++ {
		require.True(t, p0.Release(ID(i)))
	}
	leaseAllIDs(p0, minID, maxID, t)

	// Using leased IDs should make it unavailable again.
	p1 := poolWithAllIDsLeased()
	for i := minID; i <= maxID; i++ {
		require.True(t, p1.Use(ID(i)))
		// It should no longer be leased.
		require.False(t, p1.Use(ID(i)))
	}
	leaseAllIDs(p1, minID, minID-1, t)

	// Inserting leased IDs should not have any effect.
	p2 := poolWithAllIDsLeased()
	for i := minID; i <= maxID; i++ {
		require.False(t, p2.Insert(ID(i)))
	}
	// The IDs should still be leased.
	for i := minID; i <= maxID; i++ {
		require.True(t, p2.Release(ID(i)))
	}
	leaseAllIDs(p2, minID, maxID, t)

	// Removing leased IDs should make them unavailable.
	p3 := poolWithAllIDsLeased()
	for i := minID; i <= maxID; i++ {
		require.False(t, p3.Remove(ID(i)))
	}
	// The IDs should not be leased anymore.
	for i := minID; i <= maxID; i++ {
		require.False(t, p3.Use(ID(i)))
	}
	// They should be unavailable.
	leaseAllIDs(p3, minID, minID-1, t)
}

func TestOperationsOnUnavailableIDs(t *testing.T) {
	minID, maxID := 1, 5
	var poolWithAllIDsUnavailable = func() *IDPool {
		p := NewIDPool(ID(minID), ID(maxID))
		for i := minID; i <= maxID; i++ {
			require.True(t, p.Remove(ID(i)))
		}
		return p
	}

	// Releasing unavailable IDs should not have any effect.
	p1 := poolWithAllIDsUnavailable()
	for i := minID; i <= maxID; i++ {
		require.False(t, p1.Release(ID(i)))
	}
	leaseAllIDs(p1, minID, minID-1, t)

	// Using unavailable IDs should not have any effect.
	p2 := poolWithAllIDsUnavailable()
	for i := minID; i <= maxID; i++ {
		require.False(t, p2.Use(ID(i)))
	}
	leaseAllIDs(p2, minID, minID-1, t)

	// Inserting unavailable IDs should make them available.
	p3 := poolWithAllIDsUnavailable()
	for i := minID; i <= maxID; i++ {
		require.True(t, p3.Insert(ID(i)))
	}
	// They should not be leased.
	for i := minID; i <= maxID; i++ {
		require.False(t, p3.Use(ID(i)))
		require.False(t, p3.Release(ID(i)))
	}
	leaseAllIDs(p3, minID, maxID, t)

	// Removing unavailable IDs should not have any effect.
	p4 := poolWithAllIDsUnavailable()
	for i := minID; i <= maxID; i++ {
		require.False(t, p4.Remove(ID(i)))
	}
	leaseAllIDs(p4, minID, minID-1, t)
}

func leaseAllIDs(p *IDPool, minID int, maxID int, t *testing.T) {
	expected := make([]int, 0)
	actual := make([]int, 0)
	for i := minID; i <= maxID; i++ {
		id := p.LeaseAvailableID()
		require.NotEqual(t, NoID, id)
		actual = append(actual, int(id))
		expected = append(expected, i)
	}
	// We should be out of IDs.
	id := p.LeaseAvailableID()
	require.Equal(t, NoID, id)

	// Unique ids must have been leased.
	require.ElementsMatch(t, actual, expected)
}

func BenchmarkRemoveIDs(b *testing.B) {
	minID, maxID := 1, b.N
	p := NewIDPool(ID(minID), ID(maxID))

	b.ResetTimer()
	for i := minID; i <= maxID; i++ {
		require.True(b, p.Remove(ID(i)))
	}
}

func BenchmarkLeaseIDs(b *testing.B) {
	minID, maxID := 1, b.N
	p := NewIDPool(ID(minID), ID(maxID))

	b.ResetTimer()
	for i := 1; i <= b.N; i++ {
		id := p.LeaseAvailableID()
		require.True(b, p.Release(ID(id)))
	}
}

func BenchmarkUseAndRelease(b *testing.B) {
	minID, maxID := 1, b.N
	p := NewIDPool(ID(minID), ID(maxID))

	b.ResetTimer()
	for i := 1; i <= b.N; i++ {
		id := p.LeaseAvailableID()
		require.True(b, p.Use(ID(id)))
	}

	for i := 1; i <= b.N; i++ {
		require.True(b, p.Insert(ID(i)))
	}
}

func testAllocatedID(t *testing.T, nGoRoutines int) {
	bufferChannelSize := 100
	minID, maxID := 1, 6000
	if maxID-minID < nGoRoutines+bufferChannelSize {
		panic(fmt.Sprintf("Number of goroutines and size of the buffered channel (%d) "+
			"should be lower than the number of IDs to be tested (%d)",
			nGoRoutines+bufferChannelSize, maxID-minID))
	}

	p := NewIDPool(ID(minID), ID(maxID))

	allocated := make(chan ID, bufferChannelSize)
	var allocators sync.WaitGroup

	for range nGoRoutines {
		allocators.Add(1)
		go func() {
			for i := 1; i <= maxID; i++ {
				id := p.AllocateID()
				if id == NoID {
					t.Error("ID expected to be allocated")
				}
				allocated <- id
			}
			allocators.Done()
		}()
	}

	go func() {
		allocators.Wait()
		close(allocated)
	}()

	for id := range allocated {
		if p.Insert(id) != true {
			t.Error("ID insertion failed")
		}
	}
}
