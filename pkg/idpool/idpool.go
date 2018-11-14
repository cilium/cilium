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

package idpool

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

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

	// Upon a refresh of the pool, idCache will be pointed to
	// nextIDCache.
	nextIDCache *idCache
}

// NewIDPool returns a new ID pool
func NewIDPool(minID ID, maxID ID) *IDPool {
	p := &IDPool{
		minID: minID,
		maxID: maxID,
	}
	p.StartRefresh()
	p.FinishRefresh()

	return p
}

// Dump returns the IDPool as formatted structure for debugging
func (p *IDPool) Dump() string {
	return fmt.Sprintf("pool: %+v, cache: %+v", p, p.nextIDCache)
}

// StartRefresh creates a new cache backing the pool.
// This cache becomes live when FinishRefresh() is called.
func (p *IDPool) StartRefresh() {
	c := newIDCache(p.minID, p.maxID)

	p.mutex.Lock()
	p.nextIDCache = c
	p.mutex.Unlock()
}

// FinishRefresh makes the most recent cache created by the pool live.
func (p *IDPool) FinishRefresh() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.idCache = p.nextIDCache
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

	return p.nextIDCache.insert(id)
}

// Remove makes an ID unavailable in the pool.
// Returns true if the ID was previously available in the pool.
func (p *IDPool) Remove(id ID) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.nextIDCache.remove(id)
}

type idCache struct {
	// ids is a slice of IDs available in this idCache.
	ids []ID

	// index tracks the position of IDs in the above ids slice.
	index map[ID]int

	// leased is the set of IDs that are leased in this idCache.
	leased map[ID]struct{}
}

func newIDCache(minID ID, maxID ID) *idCache {
	n := int(maxID - minID + 1)
	if n < 0 {
		n = 0
	}

	c := &idCache{
		ids:    make([]ID, n),
		index:  make(map[ID]int, n),
		leased: make(map[ID]struct{}, n),
	}

	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	seq := random.Perm(n)
	for i := 0; i < n; i++ {
		id := ID(seq[i]) + minID
		c.ids[i] = id
		c.index[id] = i
	}

	return c
}

// allocateID returns a random available ID without leasing it
func (c *idCache) allocateID() ID {
	if len(c.ids) == 0 {
		return NoID
	}

	// Dequeue the next available ID from the random sequence
	id := c.ids[0]
	c.ids = c.ids[1:]

	// Remove from slice of avaiable IDs
	delete(c.index, id)

	return id
}

// leaseAvailableID returns a random available ID.
func (c *idCache) leaseAvailableID() ID {
	id := c.allocateID()
	if id == NoID {
		return NoID
	}

	// Mark as leased
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
	if _, exists := c.index[id]; exists {
		return false
	}

	if _, exists := c.leased[id]; exists {
		return false
	}

	c.ids = append(c.ids, id)
	c.index[id] = len(c.ids) - 1

	return true
}

// remove removes the ID from the cache.
// Returns true if the ID was available in the cache.
func (c *idCache) remove(id ID) bool {
	removed := c.doRemove(id)
	// If the id is leased, update it.
	delete(c.leased, id)

	return removed
}

func (c *idCache) doRemove(id ID) bool {
	i, exists := c.index[id]
	if !exists {
		return false
	}

	delete(c.index, id)

	N := len(c.ids)
	if N == 0 {
		return false
	}

	tmp := c.ids[N-1]
	c.ids[i] = tmp
	if N > 1 {
		c.ids = c.ids[:N-1]
	} else {
		c.ids = c.ids[:0]
	}

	if id != tmp {
		c.index[tmp] = i
	}

	return true
}
