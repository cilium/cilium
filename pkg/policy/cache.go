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
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
)

var (
	consumableCache = newConsumableCache()
)

type ConsumableCache struct {
	cacheMU lock.RWMutex // Protects the `cache` map
	cache   map[NumericIdentity]*Consumable
	// List of consumables representing the reserved identities
	reserved []*Consumable
}

// GetConsumableCache returns the consumable cache. The cache is a list of all
// identities which are in use by local endpoints, either as consumable or
// consumer.
func GetConsumableCache() *ConsumableCache {
	return consumableCache
}

func newConsumableCache() *ConsumableCache {
	return &ConsumableCache{
		cache:    map[NumericIdentity]*Consumable{},
		reserved: make([]*Consumable, 0),
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

func (c *ConsumableCache) addReserved(elem *Consumable) {
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

// ResolveIdentityLabels resolves a numeric identity to the identity's labels
// or nil
func ResolveIdentityLabels(id NumericIdentity) labels.LabelArray {
	// Check if we have the source security context in our local
	// consumable cache
	if c := consumableCache.Lookup(id); c != nil {
		return c.LabelArray
	}

	if identity := LookupIdentityByID(id); identity != nil {
		return identity.Labels.ToSlice()
	}

	return nil
}

// Init must be called to initialize the
func Init() {
	for key, val := range ReservedIdentities {
		log.WithField(logfields.Identity, key).Debug("creating policy for identity")

		policyMapPath := bpf.MapPath(fmt.Sprintf("%sreserved_%d", policymap.MapName, int(val)))

		policyMap, _, err := policymap.OpenMap(policyMapPath)
		if err != nil {
			log.WithError(err).Fatalf("Could not create policy BPF map for reserved identity '%s'", policyMapPath)
		}

		identity := NewIdentity(val, labels.Labels{
			key: labels.NewLabel(val.String(), "", labels.LabelSourceReserved),
		})
		c := GetConsumableCache().GetOrCreate(val, identity)
		if c == nil {
			log.WithField(logfields.Identity, identity).Fatal("Unable to initialize consumable")
		}
		GetConsumableCache().addReserved(c)
		c.AddMap(policyMap)
	}
}
