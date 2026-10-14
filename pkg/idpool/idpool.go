// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package idpool

import (
	"math/rand/v2"
	"strconv"

	"github.com/cilium/cilium/pkg/lock"
)

// ID is a numeric identifier
type ID uint64

// NoID is a special ID that represents "no ID available"
const NoID ID = 0

// String returns the string representation of an allocated ID
func (i ID) String() string {
	return strconv.FormatUint(uint64(i), 10)
}

// IDPool represents a pool of IDs that can be managed concurrently
// via local usage and external events.
//
// An intermediate state (leased) is introduced to the life cycle
// of an ID in the pool, in order to prevent lost updates to the
// pool that can occur as a result of employing both management schemes
// simultaneously.
// Local usage of an ID becomes a two stage process of leasing
// the ID from the pool, and later, Use()ing or Release()ing the ID on
// the pool upon successful or unsuccessful usage respectively,
//
// The table below shows the state transitions in the ID's life cycle.
// In the case of LeaseAvailableID() the ID is returned rather
// than provided as an input to the operation.
// All ID's begin in the available state.
/*
---------------------------------------------------------------------
|state\event   | LeaseAvailableID | Release | Use | Insert | Remove |
---------------------------------------------------------------------
|1 available   |        2         |    *    |  *  |   *    |   3    |
---------------------------------------------------------------------
|2 leased      |        **        |    1    |  3  |   *    |   3    |
---------------------------------------------------------------------
|3 unavailable |        **        |    *    |  *  |   1    |   *    |
---------------------------------------------------------------------
*  The event has no effect.
** This is guaranteed never to occur.
*/
type IDPool struct {
	// mutex protects all IDPool data structures
	mutex lock.Mutex

	// min is the lower limit when leasing IDs. The pool will never
	// return an ID lesser than this value.
	minID ID

	// max is the upper limit when leasing IDs. The pool will never
	// return an ID greater than this value.
	maxID ID

	// idCache is a cache of IDs backing the pool.
	idCache *idCache
}

// NewIDPool returns a new ID pool
func NewIDPool(minID ID, maxID ID) *IDPool {
	return &IDPool{
		minID:   minID,
		maxID:   maxID,
		idCache: newIDCache(minID, maxID),
	}
}

// LeaseAvailableID returns an available ID at random from the pool.
// Returns an ID or NoID if no there is no available ID in the pool.
func (p *IDPool) LeaseAvailableID() ID {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.idCache.leaseAvailableID()
}

// AllocateID returns a random available ID. Unlike LeaseAvailableID, the ID is
// immediately marked for use and there is no need to call Use().
func (p *IDPool) AllocateID() ID {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.idCache.allocateID()
}

// Release returns a leased ID back to the pool.
// This operation accounts for IDs that were previously leased
// from the pool but were unused, e.g if allocation was unsuccessful.
// Thus, it has no effect if the ID is not currently leased in the
// pool, or the pool has since been refreshed.
//
// Returns true if the ID was returned back to the pool as
// a result of this call.
func (p *IDPool) Release(id ID) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.idCache.release(id)
}

// Use makes a leased ID unavailable in the pool and has no effect
// otherwise. Returns true if the ID was made unavailable
// as a result of this call.
func (p *IDPool) Use(id ID) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.idCache.use(id)
}

// Insert makes an unavailable ID available in the pool
// and has no effect otherwise. Returns true if the ID
// was added back to the pool.
func (p *IDPool) Insert(id ID) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.idCache.insert(id)
}

// Remove makes an ID unavailable in the pool.
// Returns true if the ID was previously available in the pool.
func (p *IDPool) Remove(id ID) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.idCache.remove(id)
}

type idCache struct {
	minID ID
	maxID ID

	// numAllocated tracks the total number of IDs currently unavailable (allocated, leased, or removed).
	numAllocated uint64

	// allocated contains unleased IDs currently allocated.
	allocated map[ID]struct{}

	// freed contains IDs that were leased/allocated and then released/inserted.
	freed map[ID]struct{}

	// leased contains IDs that are currently leased out.
	leased map[ID]struct{}

	// removed contains IDs that were explicitly removed.
	removed map[ID]struct{}
}

func newIDCache(minID ID, maxID ID) *idCache {
	return &idCache{
		minID:     minID,
		maxID:     maxID,
		allocated: make(map[ID]struct{}),
		freed:     make(map[ID]struct{}),
		leased:    make(map[ID]struct{}),
		removed:   make(map[ID]struct{}),
	}
}

func (c *idCache) isAvailable(id ID) bool {
	if id < c.minID || id > c.maxID {
		return false
	}
	if _, ok := c.allocated[id]; ok {
		return false
	}
	if _, ok := c.leased[id]; ok {
		return false
	}
	if _, ok := c.removed[id]; ok {
		return false
	}
	return true
}

// allocateID returns a random available ID without leasing it.
func (c *idCache) allocateID() ID {
	for id := range c.freed {
		delete(c.freed, id)
		c.allocated[id] = struct{}{}
		return id
	}

	if c.minID > c.maxID {
		return NoID
	}
	totalIDs := uint64(c.maxID - c.minID + 1)
	if c.numAllocated >= totalIDs {
		return NoID
	}

	// 1. Try random sampling probes across range [minID, maxID]
	for i := 0; i < 20; i++ {
		candidate := c.minID + ID(rand.Uint64N(totalIDs))
		if c.isAvailable(candidate) {
			c.allocated[candidate] = struct{}{}
			c.numAllocated++
			return candidate
		}
	}

	// 2. Fallback for dense pool: scan from a random start offset
	startOffset := ID(rand.Uint64N(totalIDs))
	for offset := uint64(0); offset < totalIDs; offset++ {
		candidate := c.minID + ID((uint64(startOffset)+offset)%totalIDs)
		if c.isAvailable(candidate) {
			c.allocated[candidate] = struct{}{}
			c.numAllocated++
			return candidate
		}
	}

	return NoID
}

// leaseAvailableID returns a random available ID.
func (c *idCache) leaseAvailableID() ID {
	id := c.allocateID()
	if id == NoID {
		return NoID
	}

	delete(c.allocated, id)
	c.leased[id] = struct{}{}

	return id
}

// release makes the ID available again if it is currently
// leased and has no effect otherwise. Returns true if the
// ID was made available as a result of this call.
func (c *idCache) release(id ID) bool {
	if _, exists := c.leased[id]; !exists {
		return false
	}

	delete(c.leased, id)
	c.freed[id] = struct{}{}
	if c.numAllocated > 0 {
		c.numAllocated--
	}

	return true
}

// use makes the ID unavailable if it is currently
// leased and has no effect otherwise. Returns true if the
// ID was made unavailable as a result of this call.
func (c *idCache) use(id ID) bool {
	if _, exists := c.leased[id]; !exists {
		return false
	}

	delete(c.leased, id)
	c.allocated[id] = struct{}{}
	return true
}

// insert adds the ID into the cache if it is currently unavailable.
// Returns true if the ID was added to the cache.
func (c *idCache) insert(id ID) bool {
	if _, exists := c.leased[id]; exists {
		return false
	}
	if _, exists := c.freed[id]; exists {
		return false
	}

	if _, exists := c.allocated[id]; exists {
		delete(c.allocated, id)
		c.freed[id] = struct{}{}
		if c.numAllocated > 0 {
			c.numAllocated--
		}
		return true
	}

	if _, exists := c.removed[id]; exists {
		delete(c.removed, id)
		c.freed[id] = struct{}{}
		if c.numAllocated > 0 {
			c.numAllocated--
		}
		return true
	}

	if id < c.minID || id > c.maxID {
		c.freed[id] = struct{}{}
		return true
	}

	// Was available in range minID..maxID
	return false
}

// remove removes the ID from the cache.
// Returns true if the ID was available in the cache.
func (c *idCache) remove(id ID) bool {
	if _, exists := c.leased[id]; exists {
		delete(c.leased, id)
		c.allocated[id] = struct{}{}
		return false
	}

	if _, exists := c.freed[id]; exists {
		delete(c.freed, id)
		c.removed[id] = struct{}{}
		c.numAllocated++
		return true
	}

	if _, exists := c.allocated[id]; exists {
		return false
	}

	if _, exists := c.removed[id]; exists {
		return false
	}

	if id < c.minID || id > c.maxID {
		return false
	}

	c.removed[id] = struct{}{}
	c.numAllocated++
	return true
}
