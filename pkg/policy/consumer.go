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

	"github.com/sirupsen/logrus"
)

// Consumer identifies a security identity which is allowed communication with
// a Consumable. Its lifetime is defined by the policy calculation and
// generation of a Consumable. Consumers are added to various structures within
// a Consumable. The addition of a Consumer to these structures within a Consumable
// specifies whether the Consumable is allowed to communicate with said Consumer.
type Consumer struct {
	// ID is the security identity of this consumer.
	ID NumericIdentity

	// DeletionMark specifies whether this Consumer should be kept as part of a
	// Consumable after the Consumable's policy. If marked as true, this
	// Consumer has been determined to not be allowed to communicate with this consumer's
	// Consumable.
	DeletionMark bool
}

func NewConsumer(id NumericIdentity) *Consumer {
	return &Consumer{ID: id}
}

// Consumable is the entity that is being consumed by a Consumer. It holds all
// of the policies relevant to this security identity, including label-based
// policies which act on Consumers, and L4Policy. A Consumable is shared amongst
// all endpoints on the same node which possess the same security identity.
type Consumable struct {
	// ID of the consumable (same as security ID)
	ID NumericIdentity `json:"id"`
	// Mutex protects all variables from this structure below this line
	Mutex lock.RWMutex
	// Labels are the Identity of this consumable.
	Labels *Identity `json:"labels"`
	// LabelArray contains the same labels from identity in a form of a list, used for faster lookup
	LabelArray labels.LabelArray `json:"-"`
	// Iteration policy of the Consumable
	Iteration uint64 `json:"-"`
	// Maps from bpf map file-descriptor to the IngressPolicyMap, the go representation
	// of an endpoint's bpf policy map, of specific endpoint.
	IngressMaps map[int]*policymap.PolicyMap `json:"-"`
	// IngressIdentities is a list of security identities from which ingress traffic
	// is allowed for this Consumable / NumericIdentity. The identities in this map
	// are used to populate the ingress policy BPF maps.
	// Indexed by NumericIdentity (security identity) of each Consumer.
	IngressIdentities map[NumericIdentity]bool `json:"ingress-identities"`
	// ReverseRules contains the consumers that are allowed to receive a reply from this Consumable
	ReverseRules map[NumericIdentity]*Consumer `json:"-"`
	// L4Policy contains the L4-only policy of this consumable
	L4Policy *L4Policy `json:"l4-policy"`
	// L3L4Policy contains the L3, L4 and L7 ingress policy of this consumable
	L3L4Policy *SecurityIDContexts `json:"l3-l4-policy"`
	cache      *ConsumableCache

	// TODO (ianvernon) Added for egress...
	// TODO (ianvernon)
	EgressMaps map[int]*policymap.PolicyMap `json:"-"`

	// TODO (ianvernon)
	EgressIdentities map[NumericIdentity]*Consumer `json:"egress-identities"`
}

func (c *Consumable) LogContents() {
	for _, v := range c.IngressMaps {
		log.Debugf("Consumable %d has ingress map: %s", c.ID, v.String())
	}

	for _, v := range c.EgressMaps {
		log.Debugf("Consumable %d has egress map %s", c.ID, v.String())
	}
}

// NewConsumable creates a new consumable
func NewConsumable(id NumericIdentity, lbls *Identity, cache *ConsumableCache) *Consumable {
	consumable := &Consumable{
		ID:                id,
		Iteration:         0,
		Labels:            lbls,
		IngressMaps:       map[int]*policymap.PolicyMap{},
		IngressIdentities: map[NumericIdentity]bool{},
		ReverseRules:      map[NumericIdentity]*Consumer{},
		cache:             cache,
		EgressMaps:        map[int]*policymap.PolicyMap{},
		EgressIdentities:  map[NumericIdentity]*Consumer{},
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

// AddIngressMap adds all of identities contained in the consumable's ingress
// policy map to the specified PolicyMap.
func (c *Consumable) AddIngressMap(m *policymap.PolicyMap) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if c.IngressMaps == nil {
		c.IngressMaps = make(map[int]*policymap.PolicyMap)
	}

	// Check if map is already associated with this consumable
	if _, ok := c.IngressMaps[m.Fd]; ok {
		return
	}

	log.WithFields(logrus.Fields{
		"policymap":  m,
		"consumable": c,
	}).Debug("Adding ingress policy map to consumable")
	c.IngressMaps[m.Fd] = m

	// Populate the new map with the already established consumers of
	// this consumable
	for ingressIdentity := range c.IngressIdentities {
		if err := m.AllowConsumer(ingressIdentity.Uint32()); err != nil {
			log.WithError(err).Warn("Update of policy map failed")
		}
	}
}

// TODO (ianvernon) documentation
func (c *Consumable) AddEgressMap(m *policymap.PolicyMap) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if c.EgressMaps == nil {
		c.EgressMaps = make(map[int]*policymap.PolicyMap)
	}

	// Check if map is already associated with this consumable
	if _, ok := c.EgressMaps[m.Fd]; ok {
		return
	}

	log.WithFields(logrus.Fields{
		"policymap":  m,
		"consumable": c,
	}).Debug("Adding egress policy map to consumable")
	c.EgressMaps[m.Fd] = m

	// Populate the new map with the already established consumers of
	// this consumable
	for _, c := range c.EgressIdentities {
		if err := m.AllowConsumer(c.ID.Uint32()); err != nil {
			log.WithError(err).Warn("Update of egress policy map failed")
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
			if reverse.wasLastIngressRule(consumer) {
				reverse.removeFromIngressMaps(consumer)
			}
		}
	}
}

func (c *Consumable) deleteIngress() {
	for ingressID := range c.IngressIdentities {
		// FIXME: This explicit removal could be removed eventually to
		// speed things up as the policy map should get deleted anyway
		if c.wasLastIngressRule(ingressID) {
			c.removeFromIngressMaps(ingressID)
		}

		// TODO (ianvernon) look into this
		c.deleteReverseRule(ingressID, c.ID)
	}

	// TODO (ianvernon) revisit this
	if c.cache != nil {
		c.cache.Remove(c)
	}
}

func (c *Consumable) deleteEgress() {
	for _, consumer := range c.EgressIdentities {
		// FIXME: This explicit removal could be removed eventually to
		// speed things up as the policy map should get deleted anyway
		if c.wasLastEgressRule(consumer.ID) {
			c.removeFromEgressMaps(consumer.ID)
		}

		// TODO (ianvernon) look into this
		c.deleteReverseRule(consumer.ID, c.ID)
	}

	// TODO (ianvernon) revisit this
	if c.cache != nil {
		c.cache.Remove(c)
	}
}

func (c *Consumable) RemoveIngressMap(m *policymap.PolicyMap) {
	if m != nil {
		c.Mutex.Lock()
		delete(c.IngressMaps, m.Fd)
		log.WithFields(logrus.Fields{
			"policymap":  m,
			"consumable": c,
			"count":      len(c.IngressMaps),
		}).Debug("Removing ingress map from consumable")

		// If the last map of the consumable is gone the consumable is no longer
		// needed and should be removed from the cache and all cross references
		// must be undone.
		if len(c.IngressMaps) == 0 && len(c.EgressMaps) == 0 {
			c.deleteIngress()
		}

		c.Mutex.Unlock()
	}

}

func (c *Consumable) RemoveEgressMap(m *policymap.PolicyMap) {
	if m != nil {
		c.Mutex.Lock()
		delete(c.IngressMaps, m.Fd)
		log.WithFields(logrus.Fields{
			"policymap":  m,
			"consumable": c,
			"count":      len(c.IngressMaps),
		}).Debug("Removing ingress map from consumable")

		// If the last map of the consumable is gone the consumable is no longer
		// needed and should be removed from the cache and all cross references
		// must be undone.
		if len(c.EgressMaps) == 0 {
			c.deleteEgress()
		}

		// TODO if len of Egress and Ingress Maps 0, then delete from cache.
		c.Mutex.Unlock()
	}

}

func (c *Consumable) getEgressConsumer(id NumericIdentity) *Consumer {
	val, _ := c.EgressIdentities[id]
	return val
}

func (c *Consumable) addToIngressMaps(id NumericIdentity) {
	for _, m := range c.IngressMaps {
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

func (c *Consumable) addToEgressMaps(id NumericIdentity) {
	for _, m := range c.EgressMaps {
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

func (c *Consumable) wasLastIngressRule(id NumericIdentity) bool {
	_, existsInIngressIdentitiesMap := c.IngressIdentities[id]
	_, existsInReverseRulesMap := c.IngressIdentities[id]
	return existsInReverseRulesMap && existsInIngressIdentitiesMap
}

func (c *Consumable) wasLastEgressRule(id NumericIdentity) bool {
	return c.ReverseRules[id] == nil && c.EgressIdentities[id] == nil
}

func (c *Consumable) removeFromIngressMaps(id NumericIdentity) {
	for _, m := range c.IngressMaps {
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

func (c *Consumable) removeFromEgressMaps(id NumericIdentity) {
	for _, m := range c.EgressMaps {
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

// AllowIngressConsumerLocked adds the given consumer ID to the Consumable's
// consumers map. Must be called with Consumable mutex Locked.
// Returns true if the consumer was not present in this Consumable's consumer map,
// and thus had to be added, false if it is already added.
func (c *Consumable) AllowIngressConsumerLocked(cache *ConsumableCache, id NumericIdentity) bool {
	_, ok := c.IngressIdentities[id]
	if !ok {
		log.WithFields(logrus.Fields{
			logfields.Identity: id,
			"consumable":       logfields.Repr(c),
		}).Debug("New consumer Identity for consumable")
		c.addToIngressMaps(id)
		c.IngressIdentities[id] = true
		return true
	}
	return false // not changed.
}

// AllowEgressConsumerLocked adds the given consumer ID to the Consumable's
// consumers map. Must be called with Consumable mutex Locked.
// Returns true if the consumer was not present in this Consumable's consumer map,
// and thus had to be added, false if it is already added.
func (c *Consumable) AllowEgressConsumerLocked(cache *ConsumableCache, id NumericIdentity) bool {
	consumer := c.getEgressConsumer(id)
	if consumer == nil {
		log.WithFields(logrus.Fields{
			logfields.Identity: id,
			"consumable":       logfields.Repr(c),
		}).Debug("New consumer Identity for consumable")
		c.addToEgressMaps(id)
		c.EgressIdentities[id] = NewConsumer(id)
		return true
	}
	consumer.DeletionMark = false
	return false // not changed.
}

// AllowIngressConsumerAndReverseLocked adds the given consumer ID to the Consumable's
// consumers map and the given consumable to the given consumer's consumers map.
// Must be called with Consumable mutex Locked.
// returns true if changed, false if not
func (c *Consumable) AllowIngressConsumerAndReverseLocked(cache *ConsumableCache, id NumericIdentity) bool {
	log.WithFields(logrus.Fields{
		logfields.Identity + ".from": id,
		logfields.Identity + ".to":   c.ID,
	}).Debug("Allowing direction")
	changed := c.AllowIngressConsumerLocked(cache, id)

	if reverse := cache.Lookup(id); reverse != nil {
		log.WithFields(logrus.Fields{
			logfields.Identity + ".from": c.ID,
			logfields.Identity + ".to":   id,
		}).Debug("Allowing reverse direction")
		if _, ok := reverse.ReverseRules[c.ID]; !ok {
			reverse.addToIngressMaps(c.ID)
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

// AllowEgressConsumerAndReverseLocked adds the given consumer ID to the Consumable's
// consumers map and the given consumable to the given consumer's consumers map.
// Must be called with Consumable mutex Locked.
// returns true if changed, false if not
func (c *Consumable) AllowEgressConsumerAndReverseLocked(cache *ConsumableCache, id NumericIdentity) bool {
	log.WithFields(logrus.Fields{
		logfields.Identity + ".from": id,
		logfields.Identity + ".to":   c.ID,
	}).Debug("Allowing direction")
	changed := c.AllowEgressConsumerLocked(cache, id)

	if reverse := cache.Lookup(id); reverse != nil {
		log.WithFields(logrus.Fields{
			logfields.Identity + ".from": c.ID,
			logfields.Identity + ".to":   id,
		}).Debug("Allowing reverse direction")
		if _, ok := reverse.ReverseRules[c.ID]; !ok {
			reverse.addToEgressMaps(c.ID)
			// TODO (ianvernon) - how does this map play into egress policy?
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

// BanIngressConsumerLocked removes the given consumer from the Consumable's consumers
// map. Must be called with the Consumable mutex locked.
func (c *Consumable) BanIngressConsumerLocked(id NumericIdentity) {
	if _, ok := c.IngressIdentities[id]; ok {
		// TODO (ianvernon) add log field for consumer ID
		log.WithField(logfields.Identity, id).Debug("Removing ingress identity")
		delete(c.IngressIdentities, id)

		if c.wasLastIngressRule(id) {
			c.removeFromIngressMaps(id)
		}

		// TODO (ianvernon): see if commenting this out causes test failures
		//if consumer.Reverse != nil {
		//	c.deleteReverseRule(id, c.ID)
		//}
	}
}

// BanIngressConsumerLocked removes the given consumer from the Consumable's consumers
// map. Must be called with the Consumable mutex locked.
func (c *Consumable) BanEgressConsumerLocked(id NumericIdentity) {
	if consumer, ok := c.EgressIdentities[id]; ok {
		log.WithField("consumer", logfields.Repr(consumer)).Debug("Removing consumer")
		delete(c.EgressIdentities, id)

		if c.wasLastEgressRule(id) {
			c.removeFromEgressMaps(id)
		}

		// TODO (ianvernon) see if commenting this out causes test failures
		//if consumer.Reverse != nil {
		//	c.deleteReverseRule(id, c.ID)
		//}
	}
}

// TODO (ianvernon) - something fishy is going on man
func (c *Consumable) Allows(id NumericIdentity) bool {
	c.Mutex.RLock()
	_, ok := c.IngressIdentities[id]
	c.Mutex.RUnlock()
	return ok
}
