// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	"sync"
)

type ConsumableCache struct {
	cacheMU sync.RWMutex // Protects the `cache` map
	cache   map[NumericIdentity]*Consumable
	// List of consumables representing the reserved identities
	reserved  []*Consumable
	iteration int
}

func NewConsumableCache() *ConsumableCache {
	return &ConsumableCache{
		cache:     map[NumericIdentity]*Consumable{},
		reserved:  make([]*Consumable, 0),
		iteration: 1,
	}
}

func (c *ConsumableCache) GetOrCreate(id NumericIdentity, lbls *Identity) *Consumable {
	c.cacheMU.Lock()
	defer c.cacheMU.Unlock()
	if cons, ok := c.cache[id]; ok {
		return cons
	}

	c.cache[id] = NewConsumable(id, lbls, c)
	return c.cache[id]
}

func (c *ConsumableCache) Lookup(id NumericIdentity) *Consumable {
	c.cacheMU.RLock()
	v, _ := c.cache[id]
	c.cacheMU.RUnlock()
	return v
}

func (c *ConsumableCache) Remove(elem *Consumable) {
	c.cacheMU.Lock()
	delete(c.cache, elem.ID)
	c.cacheMU.Unlock()
}

func (c *ConsumableCache) AddReserved(elem *Consumable) {
	c.cacheMU.Lock()
	c.reserved = append(c.reserved, elem)
	c.cacheMU.Unlock()
}

// GetReservedIDs returns a slice of NumericIdentity present in the
// ConsumableCache.
func (c *ConsumableCache) GetReservedIDs() []NumericIdentity {
	identities := []NumericIdentity{}
	c.cacheMU.RLock()
	for _, id := range c.reserved {
		identities = append(identities, id.ID)
	}
	c.cacheMU.RUnlock()
	return identities
}

// GetIteration returns the current iteration of the ConsumableCache.
func (c *ConsumableCache) GetIteration() int {
	c.cacheMU.RLock()
	defer c.cacheMU.RUnlock()
	return c.iteration
}

// IncrementIteration increments by 1 the current iteration of the
// ConsumableCache.
func (c *ConsumableCache) IncrementIteration() {
	c.cacheMU.Lock()
	c.iteration++
	if c.iteration == 0 {
		c.iteration = 1
	}
	c.cacheMU.Unlock()
}
