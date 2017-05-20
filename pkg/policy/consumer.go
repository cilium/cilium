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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Consumer is the entity that consumes a Consumable.
type Consumer struct {
	ID           NumericIdentity
	Reverse      *Consumer
	DeletionMark bool
	Decision     api.Decision
}

func (c *Consumer) DeepCopy() *Consumer {
	cpy := &Consumer{
		ID:           c.ID,
		DeletionMark: c.DeletionMark,
		Decision:     c.Decision,
	}
	if c.Reverse != nil {
		cpy.Reverse = c.Reverse.DeepCopy()
	}
	return cpy
}

func (c *Consumer) StringID() string {
	return c.ID.String()
}

func NewConsumer(id NumericIdentity) *Consumer {
	return &Consumer{ID: id, Decision: api.Allowed}
}

// Consumable is the entity that is being consumed by a Consumer.
type Consumable struct {
	// ID of the consumable
	ID NumericIdentity `json:"id"`
	// Mutex protects all variables from this structure below this line
	Mutex sync.RWMutex
	// Labels are the Identity of this consumable
	Labels *Identity `json:"labels"`
	// LabelList contains the same labels from identity in a form of a list, used for faster lookup
	LabelList []*labels.Label `json:"-"`
	// Iteration policy of the Consumable
	Iteration int `json:"-"`
	// FIXME what is this for?
	Maps map[int]*policymap.PolicyMap `json:"-"`
	// Consumers contains the list of consumers where the key is the Consumers ID
	// FIXME change key to NumericIdentity?
	Consumers map[string]*Consumer `json:"consumers"`
	// ReverseRules contains the consumers that are allowed to receive a reply from this Consumable
	ReverseRules map[NumericIdentity]*Consumer `json:"-"`
	// L4Policy contains the policy of this consumable
	L4Policy *L4Policy `json:"l4-policy"`
	cache    *ConsumableCache
}

// NewConsumable creates a new consumable
func NewConsumable(id NumericIdentity, lbls *Identity, cache *ConsumableCache) *Consumable {
	consumable := &Consumable{
		ID:           id,
		Iteration:    0,
		Labels:       lbls,
		Maps:         map[int]*policymap.PolicyMap{},
		Consumers:    map[string]*Consumer{},
		ReverseRules: map[NumericIdentity]*Consumer{},
		cache:        cache,
	}
	if lbls != nil {
		consumable.LabelList = lbls.Labels.ToSlice()
	}

	return consumable
}

func (c *Consumable) DeepCopy() *Consumable {
	c.Mutex.RLock()
	cpy := &Consumable{
		ID:           c.ID,
		Iteration:    c.Iteration,
		LabelList:    make([]*labels.Label, len(c.LabelList)),
		Maps:         make(map[int]*policymap.PolicyMap, len(c.Maps)),
		Consumers:    make(map[string]*Consumer, len(c.Consumers)),
		ReverseRules: make(map[NumericIdentity]*Consumer, len(c.ReverseRules)),
		cache:        c.cache,
	}
	copy(cpy.LabelList, c.LabelList)
	if c.Labels != nil {
		cpy.Labels = c.Labels.DeepCopy()
	}
	if c.L4Policy != nil {
		cpy.L4Policy = c.L4Policy.DeepCopy()
	}
	for k, v := range c.Maps {
		cpy.Maps[k] = v.DeepCopy()
	}
	for k, v := range c.Consumers {
		cpy.Consumers[k] = v.DeepCopy()
	}
	for k, v := range c.ReverseRules {
		cpy.ReverseRules[k] = v.DeepCopy()
	}
	c.Mutex.RUnlock()
	return cpy
}

func (c *Consumable) GetModel() *models.EndpointPolicy {
	if c == nil {
		return nil
	}
	c.Mutex.RLock()
	defer c.Mutex.RUnlock()

	consumers := []int64{}
	for _, v := range c.Consumers {
		consumers = append(consumers, int64(v.ID))
	}

	return &models.EndpointPolicy{
		ID:               int64(c.ID),
		Build:            int64(c.Iteration),
		AllowedConsumers: consumers,
		L4:               c.L4Policy.GetModel(),
	}
}

func (c *Consumable) AddMap(m *policymap.PolicyMap) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if c.Maps == nil {
		c.Maps = make(map[int]*policymap.PolicyMap)
	}

	// Check if map is already associated with this consumable
	if _, ok := c.Maps[m.Fd]; ok {
		return
	}

	log.Debugf("Adding map %v to consumable %v", m, c)
	c.Maps[m.Fd] = m

	// Populate the new map with the already established consumers of
	// this consumable
	for _, c := range c.Consumers {
		if err := m.AllowConsumer(c.ID.Uint32()); err != nil {
			log.Warningf("Update of policy map failed: %s\n", err)
		}
	}
}

func (c *Consumable) deleteReverseRule(consumable NumericIdentity, consumer NumericIdentity) {
	if c.cache == nil {
		log.Errorf("Consumable without cache association: %+v", consumer)
		return
	}

	if reverse := c.cache.Lookup(consumable); reverse != nil {
		delete(reverse.ReverseRules, consumer)
		if reverse.wasLastRule(consumer) {
			reverse.removeFromMaps(consumer)
		}
	}
}

func (c *Consumable) delete() {
	for _, consumer := range c.Consumers {
		// FIXME: This explicit removal could be removed eventually to
		// speed things up as the policy map should get deleted anyway
		if c.wasLastRule(consumer.ID) {
			c.removeFromMaps(consumer.ID)
		}

		c.deleteReverseRule(consumer.ID, c.ID)
	}

	if c.cache != nil {
		c.cache.Remove(c)
	}
}

func (c *Consumable) RemoveMap(m *policymap.PolicyMap) {
	if m != nil {
		c.Mutex.Lock()
		delete(c.Maps, m.Fd)
		log.Debugf("Removing map %v from consumable %v, new len %d", m, c, len(c.Maps))

		// If the last map of the consumable is gone the consumable is no longer
		// needed and should be removed from the cache and all cross references
		// must be undone.
		if len(c.Maps) == 0 {
			c.delete()
		}
		c.Mutex.Unlock()
	}

}

func (c *Consumable) getConsumer(id NumericIdentity) *Consumer {
	val, _ := c.Consumers[id.StringID()]
	return val
}

func (c *Consumable) addToMaps(id NumericIdentity) {
	for _, m := range c.Maps {
		if m.ConsumerExists(id.Uint32()) {
			continue
		}

		log.Debugf("Updating policy BPF map %s: allowing %d\n", m.String(), id)
		if err := m.AllowConsumer(id.Uint32()); err != nil {
			log.Warningf("Update of policy map failed: %s\n", err)
		}
	}
}

func (c *Consumable) wasLastRule(id NumericIdentity) bool {
	return c.ReverseRules[id] == nil && c.Consumers[id.StringID()] == nil
}

func (c *Consumable) removeFromMaps(id NumericIdentity) {
	for _, m := range c.Maps {
		log.Debugf("Updating policy BPF map %s: denying %d\n", m.String(), id)
		if err := m.DeleteConsumer(id.Uint32()); err != nil {
			log.Warningf("Update of policy map failed: %s\n", err)
		}
	}
}

// AllowConsumerLocked adds the given consumer ID to the Consumable's
// consumers map. Must be called with Consumable mutex Locked.
func (c *Consumable) AllowConsumerLocked(cache *ConsumableCache, id NumericIdentity) {
	if consumer := c.getConsumer(id); consumer == nil {
		log.Debugf("New consumer %d for consumable %+v", id, c)
		c.addToMaps(id)
		c.Consumers[id.StringID()] = NewConsumer(id)
	} else {
		consumer.DeletionMark = false
	}
}

// AllowConsumerAndReverseLocked adds the given consumer ID to the Consumable's
// consumers map and the given consumable to the given consumer's consumers map.
// Must be called with Consumable mutex Locked.
func (c *Consumable) AllowConsumerAndReverseLocked(cache *ConsumableCache, id NumericIdentity) {
	log.Debugf("Allowing direction %d -> %d\n", id, c.ID)
	c.AllowConsumerLocked(cache, id)

	if reverse := cache.Lookup(id); reverse != nil {
		log.Debugf("Allowing reverse direction %d -> %d\n", c.ID, id)
		if _, ok := reverse.ReverseRules[c.ID]; !ok {
			reverse.addToMaps(c.ID)
			reverse.ReverseRules[c.ID] = NewConsumer(c.ID)
		}
	} else {
		log.Warningf("Allowed a consumer %d->%d which can't be found in the reverse direction", c.ID, id)
	}
}

// BanConsumerLocked removes the given consumer from the Consumable's consumers
// map. Must be called with the Consumable mutex locked.
func (c *Consumable) BanConsumerLocked(id NumericIdentity) {
	if consumer, ok := c.Consumers[id.StringID()]; ok {
		log.Debugf("Removing consumer %v\n", consumer)
		delete(c.Consumers, id.StringID())

		if c.wasLastRule(id) {
			c.removeFromMaps(id)
		}

		if consumer.Reverse != nil {
			c.deleteReverseRule(id, c.ID)
		}
	}
}

func (c *Consumable) Allows(id NumericIdentity) bool {
	c.Mutex.RLock()
	consumer := c.getConsumer(id)
	c.Mutex.RUnlock()
	return consumer != nil && consumer.Decision == api.Allowed
}
