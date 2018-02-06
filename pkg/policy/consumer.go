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
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

// Consumer is the entity that consumes a Consumable. It identifies a source
// security identity and an allow/deny decision for traffic from that identity.
type Consumer struct {
	ID           NumericIdentity
	Reverse      *Consumer
	DeletionMark bool
	Decision     api.Decision
}

func (c *Consumer) StringID() string {
	return c.ID.String()
}

func NewConsumer(id NumericIdentity) *Consumer {
	return &Consumer{ID: id, Decision: api.Allowed}
}

// Consumable is the entity that is being consumed by a Consumer. It holds all
// of the policies relevant to this security identity, including label-based
// policies which act on Consumers, and L4Policy.
type Consumable struct {
	// ID of the consumable (same as security ID)
	ID NumericIdentity `json:"id"`
	// Mutex protects all variables from this structure below this line
	Mutex lock.RWMutex
	// Labels are the Identity of this consumable
	Labels *Identity `json:"labels"`
	// LabelArray contains the same labels from identity in a form of a list, used for faster lookup
	LabelArray labels.LabelArray `json:"-"`
	// Iteration policy of the Consumable
	Iteration uint64 `json:"-"`
	// Map from bpf map fd to the policymap, the go representation of an endpoint's bpf policy map.
	Maps map[int]*policymap.PolicyMap `json:"-"`
	// Consumers contains the list of consumers where the key is the Consumers ID
	Consumers map[NumericIdentity]*Consumer `json:"consumers"`
	// ReverseRules contains the consumers that are allowed to receive a reply from this Consumable
	ReverseRules map[NumericIdentity]*Consumer `json:"-"`
	// L4Policy contains the policy of this consumable
	L4Policy *L4Policy `json:"l4-policy"`
	// L3L4Policy contains the L3, L4 and L7 ingress policy of this consumable
	L3L4Policy *SecurityIDContexts `json:"l3-l4-policy"`
	cache      *ConsumableCache
}

// NewConsumable creates a new consumable
func NewConsumable(id NumericIdentity, lbls *Identity, cache *ConsumableCache) *Consumable {
	consumable := &Consumable{
		ID:           id,
		Iteration:    0,
		Labels:       lbls,
		Maps:         map[int]*policymap.PolicyMap{},
		Consumers:    map[NumericIdentity]*Consumer{},
		ReverseRules: map[NumericIdentity]*Consumer{},
		cache:        cache,
	}
	if lbls != nil {
		consumable.LabelArray = lbls.Labels.ToSlice()
	}

	return consumable
}

// ResolveIdentityFromCache fetches Consumable from ConsumableCache using
// security identity as key, and returns labels for that identity.
func (c *Consumable) ResolveIdentityFromCache(id NumericIdentity) *Identity {
	c.Mutex.RLock()
	defer c.Mutex.RUnlock()
	cc := c.cache.Lookup(id)
	if cc != nil {
		return cc.Labels
	}
	return nil
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

	log.WithFields(logrus.Fields{
		"policymap":  m,
		"consumable": c,
	}).Debug("Adding policy map to consumable")
	c.Maps[m.Fd] = m

	// Populate the new map with the already established consumers of
	// this consumable
	for _, c := range c.Consumers {
		if err := m.AllowConsumer(c.ID.Uint32()); err != nil {
			log.WithError(err).Warn("Update of policy map failed")
		}
	}
}

func (c *Consumable) deleteReverseRule(consumable NumericIdentity, consumer NumericIdentity) {
	if c.cache == nil {
		log.WithField("consumer", consumer).Error("Consumable without cache association")
		return
	}

	if reverse := c.cache.Lookup(consumable); reverse != nil {
		// In case Conntrack is disabled, we'll find a reverse
		// policy rule here that we can delete.
		if _, ok := reverse.ReverseRules[consumer]; ok {
			delete(reverse.ReverseRules, consumer)
			if reverse.wasLastRule(consumer) {
				reverse.removeFromMaps(consumer)
			}
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
		log.WithFields(logrus.Fields{
			"policymap":  m,
			"consumable": c,
			"count":      len(c.Maps),
		}).Debug("Removing map from consumable")

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
	val, _ := c.Consumers[id]
	return val
}

func (c *Consumable) addToMaps(id NumericIdentity) {
	for _, m := range c.Maps {
		if m.ConsumerExists(id.Uint32()) {
			continue
		}

		scopedLog := log.WithFields(logrus.Fields{
			"policymap":        m,
			logfields.Identity: id,
		})

		scopedLog.Debug("Updating policy BPF map: allowing Identity")
		if err := m.AllowConsumer(id.Uint32()); err != nil {
			scopedLog.WithError(err).Warn("Update of policy map failed")
		}
	}
}

func (c *Consumable) wasLastRule(id NumericIdentity) bool {
	return c.ReverseRules[id] == nil && c.Consumers[id] == nil
}

func (c *Consumable) removeFromMaps(id NumericIdentity) {
	for _, m := range c.Maps {
		scopedLog := log.WithFields(logrus.Fields{
			"policymap":        m,
			logfields.Identity: id,
		})

		scopedLog.Debug("Updating policy BPF map: denying Identity")
		if err := m.DeleteConsumer(id.Uint32()); err != nil {
			scopedLog.WithError(err).Warn("Update of policy map failed")
		}
	}
}

// AllowConsumerLocked adds the given consumer ID to the Consumable's
// consumers map. Must be called with Consumable mutex Locked.
// returns true if changed, false if not
func (c *Consumable) AllowConsumerLocked(cache *ConsumableCache, id NumericIdentity) bool {
	consumer := c.getConsumer(id)
	if consumer == nil {
		log.WithFields(logrus.Fields{
			logfields.Identity: id,
			"consumable":       logfields.Repr(c),
		}).Debug("New consumer Identity for consumable")
		c.addToMaps(id)
		c.Consumers[id] = NewConsumer(id)
		return true
	}
	consumer.DeletionMark = false
	return false // not changed.
}

// AllowConsumerAndReverseLocked adds the given consumer ID to the Consumable's
// consumers map and the given consumable to the given consumer's consumers map.
// Must be called with Consumable mutex Locked.
// returns true if changed, false if not
func (c *Consumable) AllowConsumerAndReverseLocked(cache *ConsumableCache, id NumericIdentity) bool {
	log.WithFields(logrus.Fields{
		logfields.Identity + ".from": id,
		logfields.Identity + ".to":   c.ID,
	}).Debug("Allowing direction")
	changed := c.AllowConsumerLocked(cache, id)

	if reverse := cache.Lookup(id); reverse != nil {
		log.WithFields(logrus.Fields{
			logfields.Identity + ".from": c.ID,
			logfields.Identity + ".to":   id,
		}).Debug("Allowing reverse direction")
		if _, ok := reverse.ReverseRules[c.ID]; !ok {
			reverse.addToMaps(c.ID)
			reverse.ReverseRules[c.ID] = NewConsumer(c.ID)
			return true
		}
	}
	log.WithFields(logrus.Fields{
		logfields.Identity + ".from": c.ID,
		logfields.Identity + ".to":   id,
	}).Warn("Allowed a consumer which can't be found in the reverse direction")
	return changed
}

// BanConsumerLocked removes the given consumer from the Consumable's consumers
// map. Must be called with the Consumable mutex locked.
func (c *Consumable) BanConsumerLocked(id NumericIdentity) {
	if consumer, ok := c.Consumers[id]; ok {
		log.WithField("consumer", logfields.Repr(consumer)).Debug("Removing consumer")
		delete(c.Consumers, id)

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
