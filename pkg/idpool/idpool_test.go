// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package idpool

import (
	"fmt"
	"sort"
	"sync"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

func Test(t *testing.T) {
	TestingT(t)
}

type IDPoolTestSuite struct{}

var _ = Suite(&IDPoolTestSuite{})

func (s *IDPoolTestSuite) TestLeaseAvailableID(c *C) {
	minID, maxID := 1, 5
	p := NewIDPool(ID(minID), ID(maxID))

	leaseAllIDs(&p, minID, maxID, c)
}

func (s *IDPoolTestSuite) TestInsertIDs(c *C) {
	minID, maxID := 2, 6
	p := NewIDPool(ID(minID), ID(maxID))

	// Insert IDs beyond minID, maxID range.
	for i := minID - 1; i <= maxID+1; i++ {
		c.Assert(p.Insert(ID(i)), Equals, i < minID || i > maxID)
		c.Assert(p.Insert(ID(i)), Equals, false)
	}

	leaseAllIDs(&p, minID-1, maxID+1, c)
}

func (s *IDPoolTestSuite) TestInsertRemoveIDs(c *C) {
	minID, maxID := 1, 5
	p := NewIDPool(ID(minID), ID(maxID))

	// Remove all IDs.
	for i := minID; i <= maxID; i++ {
		c.Assert(p.Remove(ID(i)), Equals, true)
		c.Assert(p.Remove(ID(i)), Equals, false)
	}
	// We should be out of IDs.
	id := p.LeaseAvailableID()
	c.Assert(id, Equals, NoID)

	// Re-insert all IDs.
	for i := minID; i <= maxID; i++ {
		c.Assert(p.Insert(ID(i)), Equals, true)
		c.Assert(p.Insert(ID(i)), Equals, false)
	}

	// Remove odd-numbered IDs.
	for i := minID; i <= maxID; i++ {
		if i%2 != 0 {
			c.Assert(p.Remove(ID(i)), Equals, true)
		}
	}

	// Only even-numbered IDs should be left.
	evenIDs := make([]int, 0)
	actualIDs := make([]int, 0)
	for i := minID; i <= maxID; i++ {
		if i%2 == 0 {
			id := p.LeaseAvailableID()
			c.Assert(id, Not(Equals), NoID)
			actualIDs = append(actualIDs, int(id))
			evenIDs = append(evenIDs, i)
		}
	}
	// We should be out of IDs.
	id = p.LeaseAvailableID()
	c.Assert(id, Equals, NoID)

	sort.Ints(actualIDs)
	c.Assert(actualIDs, checker.DeepEquals, evenIDs)
}

func (s *IDPoolTestSuite) TestReleaseID(c *C) {
	minID, maxID := 1, 5
	p := NewIDPool(ID(minID), ID(maxID))

	// Lease all ids and release them.
	for i := minID; i <= maxID; i++ {
		id := p.LeaseAvailableID()
		c.Assert(id, Not(Equals), NoID)
	}
	// We should be out of IDs.
	id := p.LeaseAvailableID()
	c.Assert(id, Equals, NoID)

	for i := minID; i <= maxID; i++ {
		c.Assert(p.Release(ID(i)), Equals, true)
		c.Assert(p.Release(ID(i)), Equals, false)
	}

	// Lease all ids. This time, remove them before
	// releasing them.
	leaseAllIDs(&p, minID, maxID, c)
	for i := minID; i <= maxID; i++ {
		c.Assert(p.Remove(ID(i)), Equals, false)
	}
	// Release should not have any effect.
	for i := minID; i <= maxID; i++ {
		c.Assert(p.Release(ID(i)), Equals, false)
	}
}

func (s *IDPoolTestSuite) TestOperationsOnAvailableIDs(c *C) {
	minID, maxID := 1, 5

	// Leasing available IDs should move its state to leased.
	p0 := NewIDPool(ID(minID), ID(maxID))
	leaseAllIDs(&p0, minID, maxID, c)
	// Check all IDs are in leased state.
	for i := minID; i <= maxID; i++ {
		c.Assert(p0.Release(ID(i)), Equals, true)
	}
	leaseAllIDs(&p0, minID, maxID, c)

	// Releasing available IDs should not have any effect.
	p1 := NewIDPool(ID(minID), ID(maxID))
	for i := minID; i <= maxID; i++ {
		c.Assert(p1.Release(ID(i)), Equals, false)
	}
	leaseAllIDs(&p1, minID, maxID, c)

	// Using available IDs should not have any effect.
	p2 := NewIDPool(ID(minID), ID(maxID))
	for i := minID; i <= maxID; i++ {
		c.Assert(p2.Use(ID(i)), Equals, false)
	}
	leaseAllIDs(&p2, minID, maxID, c)

	// Inserting available IDs should not have any effect.
	p3 := NewIDPool(ID(minID), ID(maxID))
	for i := minID; i <= maxID; i++ {
		c.Assert(p3.Insert(ID(i)), Equals, false)
	}
	leaseAllIDs(&p3, minID, maxID, c)

	// Removing available IDs should make them unavailable.
	p4 := NewIDPool(ID(minID), ID(maxID))
	for i := minID; i <= maxID; i++ {
		c.Assert(p4.Remove(ID(i)), Equals, true)
	}
	leaseAllIDs(&p4, minID, minID-1, c)
	for i := minID; i <= maxID; i++ {
		c.Assert(p4.Release(ID(i)), Equals, false)
	}
}

func (s *IDPoolTestSuite) TestOperationsOnLeasedIDs(c *C) {
	minID, maxID := 1, 5
	var poolWithAllIDsLeased = func() *IDPool {
		p := NewIDPool(ID(minID), ID(maxID))
		leaseAllIDs(&p, minID, maxID, c)
		return &p
	}

	// Releasing leased IDs should make it available again.
	p0 := poolWithAllIDsLeased()
	for i := minID; i <= maxID; i++ {
		c.Assert(p0.Release(ID(i)), Equals, true)
	}
	leaseAllIDs(p0, minID, maxID, c)

	// Using leased IDs should make it unavailable again.
	p1 := poolWithAllIDsLeased()
	for i := minID; i <= maxID; i++ {
		c.Assert(p1.Use(ID(i)), Equals, true)
		// It should no longer be leased.
		c.Assert(p1.Use(ID(i)), Equals, false)
	}
	leaseAllIDs(p1, minID, minID-1, c)

	// Inserting leased IDs should not have any effect.
	p2 := poolWithAllIDsLeased()
	for i := minID; i <= maxID; i++ {
		c.Assert(p2.Insert(ID(i)), Equals, false)
	}
	// The IDs should still be leased.
	for i := minID; i <= maxID; i++ {
		c.Assert(p2.Release(ID(i)), Equals, true)
	}
	leaseAllIDs(p2, minID, maxID, c)

	// Removing leased IDs should make them unavailable.
	p3 := poolWithAllIDsLeased()
	for i := minID; i <= maxID; i++ {
		c.Assert(p3.Remove(ID(i)), Equals, false)
	}
	// The IDs should not be leased anymore.
	for i := minID; i <= maxID; i++ {
		c.Assert(p3.Use(ID(i)), Equals, false)
	}
	// They should be unavailable.
	leaseAllIDs(p3, minID, minID-1, c)
}

func (s *IDPoolTestSuite) TestOperationsOnUnavailableIDs(c *C) {
	minID, maxID := 1, 5
	var poolWithAllIDsUnavailable = func() *IDPool {
		p := NewIDPool(ID(minID), ID(maxID))
		for i := minID; i <= maxID; i++ {
			c.Assert(p.Remove(ID(i)), Equals, true)
		}
		return &p
	}

	// Releasing unavailable IDs should not have any effect.
	p1 := poolWithAllIDsUnavailable()
	for i := minID; i <= maxID; i++ {
		c.Assert(p1.Release(ID(i)), Equals, false)
	}
	leaseAllIDs(p1, minID, minID-1, c)

	// Using unavailable IDs should not have any effect.
	p2 := poolWithAllIDsUnavailable()
	for i := minID; i <= maxID; i++ {
		c.Assert(p2.Use(ID(i)), Equals, false)
	}
	leaseAllIDs(p2, minID, minID-1, c)

	// Inserting unavailable IDs should make them available.
	p3 := poolWithAllIDsUnavailable()
	for i := minID; i <= maxID; i++ {
		c.Assert(p3.Insert(ID(i)), Equals, true)
	}
	// They should not be leased.
	for i := minID; i <= maxID; i++ {
		c.Assert(p3.Use(ID(i)), Equals, false)
		c.Assert(p3.Release(ID(i)), Equals, false)
	}
	leaseAllIDs(p3, minID, maxID, c)

	// Removing unavailable IDs should not have any effect.
	p4 := poolWithAllIDsUnavailable()
	for i := minID; i <= maxID; i++ {
		c.Assert(p4.Remove(ID(i)), Equals, false)
	}
	leaseAllIDs(p4, minID, minID-1, c)
}

func leaseAllIDs(p *IDPool, minID int, maxID int, c *C) {
	expected := make([]int, 0)
	actual := make([]int, 0)
	for i := minID; i <= maxID; i++ {
		id := p.LeaseAvailableID()
		c.Assert(id, Not(Equals), NoID)
		actual = append(actual, int(id))
		expected = append(expected, i)
	}
	// We should be out of IDs.
	id := p.LeaseAvailableID()
	c.Assert(id, Equals, NoID)

	// Unique ids must have been leased.
	sort.Ints(actual)
	c.Assert(actual, checker.DeepEquals, expected)
}

func (s *IDPoolTestSuite) BenchmarkRemoveIDs(c *C) {
	minID, maxID := 1, c.N
	p := NewIDPool(ID(minID), ID(maxID))

	c.ResetTimer()
	for i := minID; i <= maxID; i++ {
		c.Assert(p.Remove(ID(i)), Equals, true)
	}
}

func (s *IDPoolTestSuite) BenchmarkLeaseIDs(c *C) {
	minID, maxID := 1, c.N
	p := NewIDPool(ID(minID), ID(maxID))

	c.ResetTimer()
	for i := 1; i <= c.N; i++ {
		id := p.LeaseAvailableID()
		c.Assert(p.Release(ID(id)), Equals, true)
	}
}

func (s *IDPoolTestSuite) BenchmarkUseAndRelease(c *C) {
	minID, maxID := 1, c.N
	p := NewIDPool(ID(minID), ID(maxID))

	c.ResetTimer()
	for i := 1; i <= c.N; i++ {
		id := p.LeaseAvailableID()
		c.Assert(p.Use(ID(id)), Equals, true)
	}

	for i := 1; i <= c.N; i++ {
		c.Assert(p.Insert(ID(i)), Equals, true)
	}
}

func (s *IDPoolTestSuite) testAllocatedID(c *C, nGoRoutines int) {
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

	for i := 0; i < nGoRoutines; i++ {
		allocators.Add(1)
		go func() {
			for i := 1; i <= maxID; i++ {
				id := p.AllocateID()
				if id == NoID {
					c.Error("ID expected to be allocated")
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
			c.Error("ID insertion failed")
		}
	}
}
