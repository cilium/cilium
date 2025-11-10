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
// If seed is supplied, it is used to seed a random number generator
// for ID selection. This can make identity selection deterministic
// but difficult to predict.
//
// If seed is supplied, it must be at least 32 bytes long
func (p *IDPool) LeaseAvailableID(seed []byte) ID {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.leaseAvailableID(seed)
}

// AllocateID returns a random available ID. Unlike LeaseAvailableID, the ID is
// immediately marked for use and there is no need to call Use().
func (p *IDPool) AllocateID() ID {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.allocateID(nil)
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
	// ids is a slice of IDs available in this idCache.
	ids map[ID]struct{}

	// leased is the set of IDs that are leased in this idCache.
	leased map[ID]struct{}
}

func newIDCache(minID ID, maxID ID) *idCache {
	n := max(int(maxID-minID+1), 0)

	c := &idCache{
		ids:    make(map[ID]struct{}, n),
		leased: make(map[ID]struct{}),
	}

	for id := minID; id < maxID+1; id++ {
		c.ids[id] = struct{}{}
	}

	return c
}

// allocateID returns a random available ID without leasing it
func (p *IDPool) allocateID(seed []byte) ID {
	if len(seed) < 32 {
		for id := range p.idCache.ids {
			delete(p.idCache.ids, id)
			return id
		}
		return NoID
	}

	r := rand.NewChaCha8(([32]byte)(seed[0:32]))
	count := uint64(p.maxID - p.minID)
	for range 1000 {
		id := ID(r.Uint64()%count) + p.minID
		if _, ok := p.idCache.ids[id]; ok {
			delete(p.idCache.ids, id)
			return id
		}
	}

	// fallback to non-seeded selection
	return p.allocateID(nil)
}

// leaseAvailableID returns a random available ID.
func (p *IDPool) leaseAvailableID(seed []byte) ID {
	id := p.allocateID(seed)
	if id == NoID {
		return NoID
	}

	// Mark as leased
	p.idCache.leased[id] = struct{}{}

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
	c.insert(id)

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
	return true
}

// insert adds the ID into the cache if it is currently unavailable.
// Returns true if the ID was added to the cache.
func (c *idCache) insert(id ID) bool {
	if _, ok := c.ids[id]; ok {
		return false
	}

	if _, exists := c.leased[id]; exists {
		return false
	}

	c.ids[id] = struct{}{}
	return true
}

// remove removes the ID from the cache.
// Returns true if the ID was available in the cache.
func (c *idCache) remove(id ID) bool {
	delete(c.leased, id)

	if _, ok := c.ids[id]; ok {
		delete(c.ids, id)
		return true
	}

	return false
}
