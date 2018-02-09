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

// Consumable holds all of the policies relevant to this security identity,
// including label-based policies, L4Policy, and L7 policy.
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
	// IngressIdentities is the set of security identities from which ingress
	// traffic is allowed. The value corresponds to whether the corresponding
	// key (security identity) should be garbage collected upon policy calculation.
	IngressIdentities map[NumericIdentity]bool `json:"consumers"`
	// ReverseRules contains the security identities that are allowed to receive
	// a reply from this Consumable. The value represents whether the element is
	// valid after policy recalculation.
	ReverseRules map[NumericIdentity]bool `json:"-"`
	// L4Policy contains the policy of this consumable
	L4Policy *L4Policy `json:"l4-policy"`
	// L3L4Policy contains the L3, L4 and L7 ingress policy of this consumable
	L3L4Policy *SecurityIDContexts `json:"l3-l4-policy"`
	cache      *ConsumableCache
}

// NewConsumable creates a new consumable
func NewConsumable(id NumericIdentity, lbls *Identity, cache *ConsumableCache) *Consumable {
	consumable := &Consumable{
		ID:                id,
		Iteration:         0,
		Labels:            lbls,
		Maps:              map[int]*policymap.PolicyMap{},
		IngressIdentities: map[NumericIdentity]bool{},
		ReverseRules:      map[NumericIdentity]bool{},
		cache:             cache,
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

	// Populate the new map with the already established allowed identities from
	// which ingress traffic is allowed.
	for ingressIdentity := range c.IngressIdentities {
		if err := m.AllowIdentity(ingressIdentity.Uint32()); err != nil {
			log.WithError(err).Warn("Update of policy map failed")
		}
	}
}

func (c *Consumable) deleteReverseRule(reverseConsumable NumericIdentity, identityToRemove NumericIdentity) {
	if c.cache == nil {
		log.WithField("identityToRemove", identityToRemove).Error("Consumable without cache association")
		return
	}

	if reverse := c.cache.Lookup(reverseConsumable); reverse != nil {
		// In case Conntrack is disabled, we'll find a reverse
		// policy rule here that we can delete.
		if _, ok := reverse.ReverseRules[identityToRemove]; ok {
			delete(reverse.ReverseRules, identityToRemove)
			if reverse.wasLastRule(identityToRemove) {
				reverse.removeFromMaps(identityToRemove)
			}
		}
	}
}

func (c *Consumable) delete() {
	for ingressIdentity := range c.IngressIdentities {
		// FIXME: This explicit removal could be removed eventually to
		// speed things up as the policy map should get deleted anyway
		if c.wasLastRule(ingressIdentity) {
			c.removeFromMaps(ingressIdentity)
		}

		c.deleteReverseRule(ingressIdentity, c.ID)
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

func (c *Consumable) isIdentityAllowed(id NumericIdentity) bool {
	val, _ := c.IngressIdentities[id]
	return val
}

func (c *Consumable) addToMaps(id NumericIdentity) {
	for _, m := range c.Maps {
		if m.IdentityExists(id.Uint32()) {
			continue
		}

		scopedLog := log.WithFields(logrus.Fields{
			"policymap":        m,
			logfields.Identity: id,
		})

		scopedLog.Debug("Updating policy BPF map: allowing Identity")
		if err := m.AllowIdentity(id.Uint32()); err != nil {
			scopedLog.WithError(err).Warn("Update of policy map failed")
		}
	}
}

func (c *Consumable) wasLastRule(id NumericIdentity) bool {
	return c.ReverseRules[id] == false && c.IngressIdentities[id] == false
}

func (c *Consumable) removeFromMaps(id NumericIdentity) {
	for _, m := range c.Maps {
		scopedLog := log.WithFields(logrus.Fields{
			"policymap":        m,
			logfields.Identity: id,
		})

		scopedLog.Debug("Updating policy BPF map: denying Identity")
		if err := m.DeleteIdentity(id.Uint32()); err != nil {
			scopedLog.WithError(err).Warn("Update of policy map failed")
		}
	}
}

// AllowIngressIdentityLocked adds the given security identity to the Consumable's
// IngressIdentities map. Must be called with Consumable mutex Locked.
// Returns true if the identity was not present in this Consumable's
// IngressIdentities map, and thus had to be added, false if it is already added.
func (c *Consumable) AllowIngressIdentityLocked(cache *ConsumableCache, id NumericIdentity) bool {
	isIdentityAllowed := c.isIdentityAllowed(id)
	if isIdentityAllowed == false {
		log.WithFields(logrus.Fields{
			logfields.Identity: id,
			"consumable":       logfields.Repr(c),
		}).Debug("New ingress security identity for consumable")
		c.addToMaps(id)
		c.IngressIdentities[id] = true
		return true
	}

	return false // not changed.
}

// AllowIngressIdentityAndReverseLocked adds the given security identity to the
// Consumable's IngressIdentities map and BPF policy map, as well as this
// Consumable's security identity to the Consumable representing id's Ingress
// Identities map and its BPF policy map.
// Must be called with Consumable mutex Locked.
// Returns true if changed, false if not.
func (c *Consumable) AllowIngressIdentityAndReverseLocked(cache *ConsumableCache, id NumericIdentity) bool {
	log.WithFields(logrus.Fields{
		logfields.Identity + ".from": id,
		logfields.Identity + ".to":   c.ID,
	}).Debug("Allowing direction")
	changed := c.AllowIngressIdentityLocked(cache, id)

	if reverse := cache.Lookup(id); reverse != nil {
		log.WithFields(logrus.Fields{
			logfields.Identity + ".from": c.ID,
			logfields.Identity + ".to":   id,
		}).Debug("Allowing reverse direction")
		if _, ok := reverse.ReverseRules[c.ID]; !ok {
			reverse.addToMaps(c.ID)
			reverse.ReverseRules[c.ID] = true
			return true
		}
	}
	log.WithFields(logrus.Fields{
		logfields.Identity + ".from": c.ID,
		logfields.Identity + ".to":   id,
	}).Warn("Allowed an ingress security identity which can't be found in the reverse direction")
	return changed
}

// RemoveIngressIdentityLocked removes the given security identity from Consumable's
// IngressIdentities map.
// Must be called with the Consumable mutex locked.
func (c *Consumable) RemoveIngressIdentityLocked(id NumericIdentity) {
	if _, ok := c.IngressIdentities[id]; ok {
		log.WithField(logfields.Identity, id).Debug("Removing ingress identity")
		delete(c.IngressIdentities, id)

		if c.wasLastRule(id) {
			c.removeFromMaps(id)
		}
	}
}

func (c *Consumable) Allows(id NumericIdentity) bool {
	c.Mutex.RLock()
	identityAllowed := c.isIdentityAllowed(id)
	c.Mutex.RUnlock()
	return identityAllowed != false
}
