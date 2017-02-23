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

type ConsumableCache struct {
	cache map[NumericIdentity]*Consumable
	// List of consumables representing the reserved identities
	Reserved  []*Consumable
	Iteration int
}

func NewConsumableCache() *ConsumableCache {
	return &ConsumableCache{
		cache:     map[NumericIdentity]*Consumable{},
		Reserved:  make([]*Consumable, 0),
		Iteration: 1,
	}
}

func (c *ConsumableCache) GetOrCreate(id NumericIdentity, lbls *Identity) *Consumable {
	if _, ok := c.cache[id]; ok {
		return c.cache[id]
	}

	c.cache[id] = NewConsumable(id, lbls, c)
	return c.cache[id]
}

func (c *ConsumableCache) Lookup(id NumericIdentity) *Consumable {
	v, _ := c.cache[id]
	return v
}

func (c *ConsumableCache) Remove(elem *Consumable) {
	delete(c.cache, elem.ID)
}

func (c *ConsumableCache) AddReserved(elem *Consumable) {
	c.Reserved = append(c.Reserved, elem)
}
