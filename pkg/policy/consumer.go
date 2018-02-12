// Copyright 2016-2018 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"

	"github.com/sirupsen/logrus"
)

// Consumable holds all of the policies relevant to this security identity,
// including label-based policies, L4Policy, and L7 policy. A Consumable is
// shared amongst all endpoints on the same node which possess the same security
// identity.
type Consumable struct {
	// ID of the consumable (same as security ID)
	ID identity.NumericIdentity `json:"id"`
	// Mutex protects all variables from this structure below this line
	Mutex lock.RWMutex
	// Labels are the SecurityIdentity of this consumable
	Labels *identity.Identity `json:"labels"`
	// LabelArray contains the same labels from identity in a form of a list, used for faster lookup
	LabelArray labels.LabelArray `json:"-"`
	// Iteration policy of the Consumable
	Iteration uint64 `json:"-"`

	// PolicyMaps maps the file descriptor of the BPF PolicyMap in the BPF filesystem
	// to the golang representation of the same BPF PolicyPap. Each key-value
	// pair corresponds to the BPF PolicyMap for a given endpoint.
	PolicyMaps map[int]*policymap.PolicyMap `json:"-"`

	// IngressIdentities is the set of security identities from which ingress
	// traffic is allowed. The value corresponds to whether the corresponding
	// key (security identity) should be garbage collected upon policy calculation.
	IngressIdentities map[identity.NumericIdentity]bool `json:"ingress-identities"`

	// EgressMaps maps the file descriptor of the BPF PolicyMap in the BPF filesystem
	// to the golang representation of the same BPF PolicyPap. Each key-value
	// pair corresponds to the BPF PolicyMap for a given endpoint.
	EgressMaps map[int]*policymap.PolicyMap `json:"-"`

	// EgressIdentities is the set of security identities from which egress
	// traffic is allowed. The value corresponds to whether the corresponding
	// key (security identity) should be garbage collected upon policy calculation.
	EgressIdentities map[identity.NumericIdentity]bool `json:"egress-identities"`

	// L4Policy contains the policy of this consumable
	L4Policy *L4Policy `json:"l4-policy"`
	// L3L4Policy contains the L3, L4 and L7 ingress policy of this consumable
	L3L4Policy *SecurityIDContexts `json:"l3-l4-policy"`
	cache      *ConsumableCache
}

// NewConsumable creates a new consumable
func NewConsumable(id identity.NumericIdentity, lbls *identity.Identity, cache *ConsumableCache) *Consumable {
	consumable := &Consumable{
		ID:                id,
		Iteration:         0,
		Labels:            lbls,
		PolicyMaps:        map[int]*policymap.PolicyMap{},
		IngressIdentities: map[identity.NumericIdentity]bool{},
		EgressIdentities:  map[identity.NumericIdentity]bool{},
		cache:             cache,
	}
	if lbls != nil {
		consumable.LabelArray = lbls.Labels.ToSlice()
	}

	return consumable
}

// AddMap adds m to the Consumable's PolicyMaps. This represents
// the PolicyMap being added for a specific endpoint.
func (c *Consumable) AddMap(m *policymap.PolicyMap) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if c.PolicyMaps == nil {
		c.PolicyMaps = make(map[int]*policymap.PolicyMap)
	}

	// Check if map is already associated with this consumable
	if _, ok := c.PolicyMaps[m.Fd]; ok {
		return
	}

	log.WithFields(logrus.Fields{
		"policymap":  m,
		"consumable": c,
	}).Debug("Adding policy map to consumable")
	c.PolicyMaps[m.Fd] = m

	// Populate the new map with the already established allowed identities from
	// which ingress traffic is allowed.
	for ingressIdentity := range c.IngressIdentities {
		if err := m.AllowIdentity(ingressIdentity.Uint32(), policymap.Ingress); err != nil {
			log.WithError(err).Warn("Update of policy map failed")
		}
	}

	for egressIdentity := range c.EgressIdentities {
		if err := m.AllowIdentity(egressIdentity.Uint32(), policymap.Egress); err != nil {
			log.WithError(err).Warn("Update of policy map failed")
		}
	}
}

func (c *Consumable) delete() {

	for ingressIdentity := range c.IngressIdentities {
		// FIXME: This explicit removal could be removed eventually to
		// speed things up as the policy map should get deleted anyway.
		c.removeFromMaps(ingressIdentity, policymap.Ingress)
	}

	for egressIdentity := range c.EgressIdentities {
		// FIXME: This explicit removal could be removed eventually to
		// speed things up as the policy map should get deleted anyway.
		c.removeFromMaps(egressIdentity, policymap.Egress)
	}

	if c.cache != nil {
		c.cache.Remove(c)
	}
}

// RemovePolicyMap removes m from the Consumable's PolicyMaps. This represents
// the PolicyMap being deleted for a specific endpoint.
func (c *Consumable) RemovePolicyMap(m *policymap.PolicyMap) {
	if m != nil {
		c.Mutex.Lock()
		delete(c.PolicyMaps, m.Fd)
		log.WithFields(logrus.Fields{
			"policymap":  m,
			"consumable": c,
			"count":      len(c.PolicyMaps),
		}).Debug("Removing policy map from consumable")

		// If there are no more PolicyMaps for this Consumable, then the
		// Consumable is no longer needed and should be removed from the cache,
		// and all cross references must be undone.
		if len(c.PolicyMaps) == 0 {
			c.delete()
		}
		c.Mutex.Unlock()
	}

}

func (c *Consumable) addToPolicyMaps(id identity.NumericIdentity, trafficDirection policymap.TrafficDirection) {
	for _, m := range c.PolicyMaps {
		if m.IdentityExists(id.Uint32(), trafficDirection) {
			continue
		}

		scopedLog := log.WithFields(logrus.Fields{
			"policymap":                m,
			logfields.Identity:         id,
			logfields.TrafficDirection: trafficDirection.String(),
		})

		scopedLog.Debug("Updating policy BPF map: allowing Identity")
		if err := m.AllowIdentity(id.Uint32(), trafficDirection); err != nil {
			scopedLog.WithError(err).Warn("Update of policy map failed")
		}
	}
}

// A rule is the 'last rule' for an identity if it does not exist as a key
// in any of the maps for this Consumable.
func (c *Consumable) wasLastRule(id identity.NumericIdentity) bool {
	_, existsIngressIdentity := c.IngressIdentities[id]
	_, existsEgressIdentity := c.EgressIdentities[id]
	return !existsIngressIdentity && !existsEgressIdentity
}

func (c *Consumable) removeFromMaps(id identity.NumericIdentity, trafficDirection policymap.TrafficDirection) {
	for _, m := range c.PolicyMaps {
		scopedLog := log.WithFields(logrus.Fields{
			"policymap":                m,
			logfields.Identity:         id,
			logfields.TrafficDirection: trafficDirection.String(),
		})

		scopedLog.Debug("Updating policy BPF map: denying Identity")
		if err := m.DeleteIdentity(id.Uint32(), trafficDirection); err != nil {
			scopedLog.WithError(err).Warn("Update of policy map failed")
		}
	}
}

// AllowIngressIdentityLocked adds the given security identity to the Consumable's
// IngressIdentities map. Must be called with Consumable mutex Locked.
// Returns true if the identity was not present in this Consumable's
// IngressIdentities map, and thus had to be added, false if it is already added.
func (c *Consumable) AllowIngressIdentityLocked(cache *ConsumableCache, id identity.NumericIdentity) bool {
	_, exists := c.IngressIdentities[id]
	if !exists {
		log.WithFields(logrus.Fields{
			logfields.Identity: id,
			"consumable":       logfields.Repr(c),
		}).Debug("Allowing security identity on ingress for consumable")
		c.addToPolicyMaps(id, policymap.Ingress)

		// If id corresponds to a reserved identity, Consumable corresponding to
		// that security identity needs to be updated explicitly, as reserved
		// identities do not have a corresponding endpoint for which policy
		// recalculation (when Consumables are updated) is done.
		if id.IsReservedIdentity() {
			reservedConsumable := cache.Lookup(id)
			if reservedConsumable != nil {
				// If we are accessing the same Consumable (allowing traffic
				// to itself), we don't need to take its mutex because it was
				// already taken before calling this function.
				if id != c.ID {
					reservedConsumable.Mutex.Lock()
					reservedConsumable.AllowIngressIdentityLocked(cache, c.ID)
					reservedConsumable.Mutex.Unlock()
				} else {
					reservedConsumable.AllowIngressIdentityLocked(cache, c.ID)
				}
			} else {
				log.WithField(logfields.Identity, id).Warningf("unable to allow ingress from identity %d", c.ID)
			}
		}
	}

	c.IngressIdentities[id] = true

	return !exists // not changed, was already in map.
}

// AllowEgressIdentityLocked adds the given security identity to the Consumable's
// EgressIdentities map. Must be called with Consumable mutex Locked.
// Returns true if the identity was not present in this Consumable's
// EgressIdentities map, and thus had to be added, false if it is already added.
func (c *Consumable) AllowEgressIdentityLocked(cache *ConsumableCache, id identity.NumericIdentity) bool {
	_, exists := c.EgressIdentities[id]
	if !exists {
		log.WithFields(logrus.Fields{
			logfields.Identity: id,
			"consumable":       logfields.Repr(c),
		}).Debug("New egress security identity for consumable")

		c.addToPolicyMaps(id, policymap.Egress)

		// If id corresponds to a reserved identity, Consumable corresponding to
		// that security identity needs to be updated explicitly, as reserved
		// identities do not have a corresponding endpoint for which policy
		// recalculation (when Consumables are updated) is done.
		if id.IsReservedIdentity() {
			reservedConsumable := cache.Lookup(id)
			if reservedConsumable != nil {
				// Avoid deadlock ; is this necessary? Being cautious.
				if id != c.ID {
					reservedConsumable.Mutex.Lock()
					reservedConsumable.AllowEgressIdentityLocked(cache, c.ID)
					reservedConsumable.Mutex.Unlock()
				} else {
					reservedConsumable.AllowEgressIdentityLocked(cache, c.ID)
				}
			} else {
				log.WithField(logfields.Identity, id).Warningf("unable to allow egress to identity %d", c.ID)
			}
		}
	}
	c.EgressIdentities[id] = true
	return !exists // not changed.
}

// RemoveIngressIdentityLocked removes the given security identity from Consumable's
// IngressIdentities map.
// Must be called with the Consumable mutex locked.
func (c *Consumable) RemoveIngressIdentityLocked(id identity.NumericIdentity) {
	if _, ok := c.IngressIdentities[id]; ok {
		log.WithField(logfields.Identity, id).Debug("Removing identity from ingress map")
		delete(c.IngressIdentities, id)

		// Consumables corresponding to reserved identities need to be updated
		// explicitly because they are not updated or regenerated.
		if id.IsReservedIdentity() {
			reservedConsumable := c.cache.Lookup(id)
			if reservedConsumable != nil {
				// If we are accessing the same Consumable (allowing traffic
				// to itself), we don't need to take its mutex because it was
				// already taken before calling this function.
				if id != c.ID {
					reservedConsumable.Mutex.Lock()
					reservedConsumable.RemoveIngressIdentityLocked(c.ID)
					reservedConsumable.Mutex.Unlock()
				} else {
					reservedConsumable.RemoveIngressIdentityLocked(c.ID)
				}
			} else {
				log.WithField(logfields.Identity, id).Warningf("unable to disallow ingress from identity %d", c.ID)
			}

		}
		c.removeFromMaps(id, policymap.Ingress)
	}
}

// RemoveEgressIdentityLocked removes the given security identity from Consumable's
// EgressIdentities map.
// Must be called with the Consumable mutex locked.
func (c *Consumable) RemoveEgressIdentityLocked(id identity.NumericIdentity) {
	if _, ok := c.EgressIdentities[id]; ok {
		log.WithField(logfields.Identity, id).Debug("Removing egress identity")
		delete(c.EgressIdentities, id)

		// Consumables corresponding to reserved identities need to be updated
		// explicitly because they are not updated or regenerated.
		if id.IsReservedIdentity() {
			reservedConsumable := c.cache.Lookup(id)
			if reservedConsumable != nil {
				// Avoid deadlock!
				if id != c.ID {
					reservedConsumable.Mutex.Lock()
					reservedConsumable.RemoveEgressIdentityLocked(c.ID)
					reservedConsumable.Mutex.Unlock()
				} else {
					reservedConsumable.RemoveEgressIdentityLocked(c.ID)
				}
			} else {
				log.WithField(logfields.Identity, id).Warningf("unable to disallow egress to identity %d", c.ID)
			}
		}

		c.removeFromMaps(id, policymap.Egress)
	}
}

// AllowsIngress returns whether id is is in the list of allowed identities
// from which ingress traffic is allowed for this Consumable.
func (c *Consumable) AllowsIngress(id identity.NumericIdentity) bool {
	c.Mutex.RLock()
	isIdentityAllowed, _ := c.IngressIdentities[id]
	c.Mutex.RUnlock()
	return isIdentityAllowed
}
