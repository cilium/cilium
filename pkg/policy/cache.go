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
	"github.com/cilium/cilium/pkg/lock"
)

var (
	consumableCache = newConsumableCache()
)

type ConsumableCache struct {
	cacheMU lock.RWMutex // Protects the `cache` map
	cache   map[NumericIdentity]*Consumable
	// List of consumables representing the reserved identities
	reserved  []*Consumable
	iteration int
}

// GetConsumableCache returns the consumable cache. The cache is a list of all
// identities which are in use by local endpoints, either as consumable or
// consumer.
func GetConsumableCache() *ConsumableCache {
	return consumableCache
}

func newConsumableCache() *ConsumableCache {
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

// GetConsumables returns a map of consumables numeric identity mapped to
// consumers numeric identities.
func (c *ConsumableCache) GetConsumables() map[NumericIdentity][]NumericIdentity {
	consumables := map[NumericIdentity][]NumericIdentity{}
	c.cacheMU.RLock()
	for _, consumable := range c.cache {
		consumers := []NumericIdentity{}
		for _, consumer := range consumable.Consumers {
			consumers = append(consumers, consumer.ID)
		}
		consumables[consumable.ID] = consumers
	}
	c.cacheMU.RUnlock()
	return consumables
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

// ConsumablesInANotInB returns a map of consumables numeric identity mapped to
// consumers numeric identities which are present in `a` but not in `b`.
// Example:
// a = {3: [1, 2, 4], 4: [2, 1]}
// b = {1: [5, 1, 7], 3: [1, 2, 5]}
// c := ConsumablesInANotInB(a, b)
// println(c)
// {3: [4], 4: [2, 1]}
func ConsumablesInANotInB(a, b map[NumericIdentity][]NumericIdentity) map[NumericIdentity][]NumericIdentity {
	c := map[NumericIdentity][]NumericIdentity{}
	for oldConsumable, oldConsumers := range a {
		if newConsumers, ok := b[oldConsumable]; ok {
			consumersFound := []NumericIdentity{}
			for _, oldConsumer := range oldConsumers {
				found := false
				for _, newConsumer := range newConsumers {
					if oldConsumer == newConsumer {
						found = true
						break
					}
				}
				if !found {
					consumersFound = append(consumersFound, oldConsumer)
				}
			}
			c[oldConsumable] = consumersFound
		} else {
			c[oldConsumable] = oldConsumers
		}
	}
	return c
}
