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
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/policymap"
)

// Consumer is the entity that consumes a Consumable.
type Consumer struct {
	ID           NumericIdentity
	Reverse      *Consumer
	DeletionMark bool
	Decision     ConsumableDecision
}

func (c *Consumer) DeepCopy() *Consumer {
	cpy := &Consumer{ID: c.ID,
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
	return &Consumer{ID: id, Decision: ACCEPT}
}

// Consumable is the entity that is being consumed by a Consumable.
type Consumable struct {
	ID           NumericIdentity               `json:"id"`
	Iteration    int                           `json:"-"`
	Labels       *Identity                     `json:"labels"`
	LabelList    []*labels.Label               `json:"-"`
	Maps         map[int]*policymap.PolicyMap  `json:"-"`
	Consumers    map[string]*Consumer          `json:"consumers"`
	ReverseRules map[NumericIdentity]*Consumer `json:"-"`
	L4Policy     *L4Policy                     `json:"l4-policy"`
	cache        *ConsumableCache
}

func (c *Consumable) DeepCopy() *Consumable {
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
	return cpy
}

func (c *Consumable) GetModel() *models.EndpointPolicy {
	if c == nil {
		return nil
	}

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
		consumable.LabelList = make([]*labels.Label, len(lbls.Labels))
		idx := 0
		for k, v := range lbls.Labels {
			consumable.LabelList[idx] = &labels.Label{
				Key:    k,
				Value:  v.Value,
				Source: v.Source,
			}
			idx++
		}
	}

	return consumable
}

func (c *Consumable) AddMap(m *policymap.PolicyMap) {
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

func (c *Consumable) Delete() {
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
		delete(c.Maps, m.Fd)
		log.Debugf("Removing map %v from consumable %v, new len %d", m, c, len(c.Maps))

		// If the last map of the consumable is gone the consumable is no longer
		// needed and should be removed from the cache and all cross references
		// must be undone.
		if len(c.Maps) == 0 {
			c.Delete()
		}
	}

}

func (c *Consumable) GetConsumer(id NumericIdentity) *Consumer {
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

func (c *Consumable) AllowConsumer(cache *ConsumableCache, id NumericIdentity) *Consumer {
	var consumer *Consumer

	if consumer = c.GetConsumer(id); consumer == nil {
		log.Debugf("New consumer %d for consumable %+v", id, c)
		c.addToMaps(id)
		c.Consumers[id.StringID()] = NewConsumer(id)
	} else {
		consumer.DeletionMark = false
	}

	return consumer
}

func (c *Consumable) AllowConsumerAndReverse(cache *ConsumableCache, id NumericIdentity) {
	log.Debugf("Allowing direction %d -> %d\n", id, c.ID)
	c.AllowConsumer(cache, id)

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

func (c *Consumable) BanConsumer(id NumericIdentity) {
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
	if consumer := c.GetConsumer(id); consumer != nil {
		if consumer.Decision == ACCEPT {
			return true
		}
	}

	return false
}
