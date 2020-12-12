// Copyright 2016-2019 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"

	"github.com/sirupsen/logrus"
)

var (
	// localHostKey represents an ingress L3 allow from the local host.
	localHostKey = Key{
		Identity:         identity.ReservedIdentityHost.Uint32(),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}
	// localRemoteNodeKey represents an ingress L3 allow from remote nodes.
	localRemoteNodeKey = Key{
		Identity:         identity.ReservedIdentityRemoteNode.Uint32(),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}
)

const (
	LabelKeyPolicyDerivedFrom  = "io.cilium.policy.derived-from"
	LabelAllowLocalHostIngress = "allow-localhost-ingress"
	LabelAllowAnyIngress       = "allow-any-ingress"
	LabelAllowAnyEgress        = "allow-any-egress"
	LabelVisibilityAnnotation  = "visibility-annotation"
)

// MapState is a state of a policy map.
type MapState map[Key]MapStateEntry

// Key is the userspace representation of a policy key in BPF. It is
// intentionally duplicated from pkg/maps/policymap to avoid pulling in the
// BPF dependency to this package.
type Key struct {
	// Identity is the numeric identity to / from which traffic is allowed.
	Identity uint32
	// DestPort is the port at L4 to / from which traffic is allowed, in
	// host-byte order.
	DestPort uint16
	// NextHdr is the protocol which is allowed.
	Nexthdr uint8
	// TrafficDirection indicates in which direction Identity is allowed
	// communication (egress or ingress).
	TrafficDirection uint8
}

// String returns a string representation of the Key
func (k Key) String() string {
	return fmt.Sprintf("Identity=%d,DestPort=%d,Nexthdr=%d,TrafficDirection=%d", k.Identity, k.DestPort, k.Nexthdr, k.TrafficDirection)
}

// IsIngress returns true if the key refers to an ingress policy key
func (k Key) IsIngress() bool {
	return k.TrafficDirection == trafficdirection.Ingress.Uint8()
}

// IsEgress returns true if the key refers to an egress policy key
func (k Key) IsEgress() bool {
	return k.TrafficDirection == trafficdirection.Egress.Uint8()
}

// MapStateEntry is the configuration associated with a Key in a
// MapState. This is a minimized version of policymap.PolicyEntry.
type MapStateEntry struct {
	// The proxy port, in host byte order.
	// If 0 (default), there is no proxy redirection for the corresponding
	// Key. Any other value signifies proxy redirection.
	ProxyPort uint16

	// DerivedFromRules tracks the policy rules this entry derives from
	DerivedFromRules labels.LabelArrayList

	// Selectors collects the selectors in the policy that require this key to be present.
	// TODO: keep track which selector needed the entry to be a redirect, or just allow.
	selectors map[CachedSelector]struct{}
}

// NewMapStateEntry creates a map state entry. If redirect is true, the
// caller is expected to replace the ProxyPort field before it is added to
// the actual BPF map.
// 'cs' is used to keep track of which policy selectors need this entry. If it is 'nil' this entry
// will become sticky and cannot be completely removed via incremental updates.
func NewMapStateEntry(cs CachedSelector, derivedFrom labels.LabelArrayList, redirect bool) MapStateEntry {
	var proxyPort uint16
	if redirect {
		// Any non-zero value will do, as the callers replace this with the
		// actual proxy listening port number before the entry is added to the
		// actual bpf map.
		proxyPort = 1
	}

	return MapStateEntry{
		ProxyPort:        proxyPort,
		DerivedFromRules: derivedFrom,
		selectors:        map[CachedSelector]struct{}{cs: {}},
	}
}

// MergeSelectors adds selectors from entry 'b' to 'e'. 'b' is not modified.
func (e *MapStateEntry) MergeSelectors(b *MapStateEntry) {
	for cs, v := range b.selectors {
		e.selectors[cs] = v
	}
}

// IsRedirectEntry returns true if e contains a redirect
func (e *MapStateEntry) IsRedirectEntry() bool {
	return e.ProxyPort != 0
}

// Equal returns true of two entries are equal
func (e *MapStateEntry) Equal(o *MapStateEntry) bool {
	if e == nil || o == nil {
		return e == o
	}

	return e.ProxyPort == o.ProxyPort && e.DerivedFromRules.Equals(o.DerivedFromRules)
}

// String returns a string representation of the MapStateEntry
func (e MapStateEntry) String() string {
	return fmt.Sprintf("ProxyPort=%d", e.ProxyPort)
}

// RedirectPreferredInsert inserts a new entry giving priority to L7-redirects by
// not overwriting a L7-redirect entry with a non-redirect entry
// This form may be used when a full policy is computed and we are not yet interested
// in accumulating incremental changes.
func (keys MapState) RedirectPreferredInsert(key Key, entry MapStateEntry) {
	keys.redirectPreferredInsertWithChanges(key, entry, nil, nil)
}

// addKeyWithChanges adds a 'key' with value 'entry' to 'keys' keeping track of incremental changes in 'adds' and 'deletes'
func (keys MapState) addKeyWithChanges(key Key, entry MapStateEntry, adds, deletes MapState) {
	// Keep all selectors that need this entry so that it is deleted only if all the selectors delete their contribution
	updatedEntry := entry
	oldEntry, exists := keys[key]
	if exists {
		// keep the existing selectors map of the old entry
		updatedEntry.selectors = oldEntry.selectors
	} else if len(entry.selectors) > 0 {
		// create a new selectors map
		updatedEntry.selectors = make(map[CachedSelector]struct{}, len(entry.selectors))
	}

	// TODO: Do we need to merge labels as well?
	// Merge new selectors to the updated entry without modifying 'entry' as it is being reused by the caller
	updatedEntry.MergeSelectors(&entry)
	// Update (or insert) the entry
	keys[key] = updatedEntry

	// Record an incremental Add if desired and entry is new or changed
	if adds != nil && (!exists || oldEntry.ProxyPort != entry.ProxyPort) {
		adds[key] = updatedEntry
		// Key add overrides any previous delete of the same key
		if deletes != nil {
			delete(deletes, key)
		}
	}
}

// deleteKeyWithChanges deletes a 'key' from 'keys' keeping track of incremental changes in 'adds' and 'deletes'.
// The key is unconditionally deleted if 'cs' is nil, otherwise only the contribution of this 'cs' is removed.
func (keys MapState) deleteKeyWithChanges(key Key, cs CachedSelector, adds, deletes MapState) {
	if entry, exists := keys[key]; exists {
		if cs != nil {
			// remove the contribution of the given selector only
			if _, exists = entry.selectors[cs]; exists {
				// Remove the contribution of this selector from the entry
				delete(entry.selectors, cs)
				// key is not deleted if other selectors still need it
				if len(entry.selectors) > 0 {
					return
				}
			} else {
				// 'cs' was not found, do not change anything
				return
			}
		}
		if deletes != nil {
			deletes[key] = entry
			// Remove a potential previously added key
			if adds != nil {
				delete(adds, key)
			}
		}
		delete(keys, key)
	}
}

// redirectPreferredInsertWithChanges inserts a new entry giving priority to L7-redirects by
// not overwriting a L7-redirect entry with a non-redirect entry.
func (keys MapState) redirectPreferredInsertWithChanges(key Key, entry MapStateEntry, adds, deletes MapState) {
	// Do not overwrite the entry, but only merge selectors if the old entry is a redirect.
	// This prevents an existing redirect being overridden by a non-redirect.
	if oldEntry, exists := keys[key]; exists && oldEntry.IsRedirectEntry() {
		oldEntry.MergeSelectors(&entry)
		keys[key] = oldEntry
		// For compatibility with old redirect management code we'll have to pass on
		// redirect entry if the oldEntry is also a redirect, even if they are equal.
		// We store the new entry here, the proxy port of it will be fixed up before
		// insertion to the bpf map.
		if adds != nil && entry.IsRedirectEntry() {
			adds[key] = entry
		}
		return
	}
	// Otherwise write the entry to the map
	keys.addKeyWithChanges(key, entry, adds, deletes)
}

// DetermineAllowLocalhostIngress determines whether communication should be allowed
// from the localhost. It inserts the Key corresponding to the localhost in
// the desiredPolicyKeys if the localhost is allowed to communicate with the
// endpoint.
func (keys MapState) DetermineAllowLocalhostIngress(l4Policy *L4Policy) {
	if option.Config.AlwaysAllowLocalhost() {
		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowLocalHostIngress, labels.LabelSourceReserved),
			},
		}
		keys[localHostKey] = NewMapStateEntry(nil, derivedFrom, false)
		if !option.Config.EnableRemoteNodeIdentity {
			keys[localRemoteNodeKey] = NewMapStateEntry(nil, derivedFrom, false)
		}
	}
}

// AllowAllIdentities translates all identities in selectorCache to their
// corresponding Keys in the specified direction (ingress, egress) which allows
// all at L3.
func (keys MapState) AllowAllIdentities(ingress, egress bool) {
	if ingress {
		keyToAdd := Key{
			Identity:         0,
			DestPort:         0,
			Nexthdr:          0,
			TrafficDirection: trafficdirection.Ingress.Uint8(),
		}
		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowLocalHostIngress, labels.LabelSourceReserved),
			},
		}
		keys[keyToAdd] = NewMapStateEntry(nil, derivedFrom, false)
	}
	if egress {
		keyToAdd := Key{
			Identity:         0,
			DestPort:         0,
			Nexthdr:          0,
			TrafficDirection: trafficdirection.Egress.Uint8(),
		}
		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved),
			},
		}
		keys[keyToAdd] = NewMapStateEntry(nil, derivedFrom, false)
	}
}

// MapChanges collects updates to the endpoint policy on the
// granularity of individual mapstate key-value pairs for both adds
// and deletes. 'mutex' must be held for any access.
type MapChanges struct {
	mutex   lock.Mutex
	changes []MapChange
}

type MapChange struct {
	add   bool // false deletes
	key   Key
	value MapStateEntry
}

// AccumulateMapChanges accumulates the given changes to the
// MapChanges.
//
// The caller is responsible for making sure the same identity is not
// present in both 'adds' and 'deletes'.
func (mc *MapChanges) AccumulateMapChanges(cs CachedSelector, adds, deletes []identity.NumericIdentity,
	port uint16, proto uint8, direction trafficdirection.TrafficDirection,
	redirect bool, derivedFrom labels.LabelArrayList) {
	key := Key{
		// The actual identity is set in the loops below
		Identity: 0,
		// NOTE: Port is in host byte-order!
		DestPort:         port,
		Nexthdr:          proto,
		TrafficDirection: direction.Uint8(),
	}

	value := NewMapStateEntry(cs, derivedFrom, redirect)

	if option.Config.Debug {
		log.WithFields(logrus.Fields{
			logfields.EndpointSelector: cs,
			logfields.AddedPolicyID:    adds,
			logfields.DeletedPolicyID:  deletes,
			logfields.Port:             port,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
			logfields.IsRedirect:       redirect,
		}).Debug("AccumulateMapChanges")
	}

	mc.mutex.Lock()
	for _, id := range adds {
		key.Identity = id.Uint32()
		mc.changes = append(mc.changes, MapChange{true, key, value})
	}
	for _, id := range deletes {
		key.Identity = id.Uint32()
		mc.changes = append(mc.changes, MapChange{false, key, value})
	}
	mc.mutex.Unlock()
}

// consumeMapChanges transfers the incremental changes from MapChanges to the caller,
// while applying the changes to PolicyMapState.
func (mc *MapChanges) consumeMapChanges(policyMapState MapState) (adds, deletes MapState) {
	mc.mutex.Lock()
	adds = make(MapState, len(mc.changes))
	deletes = make(MapState, len(mc.changes))

	for i := range mc.changes {
		if mc.changes[i].add {
			// Insert but do not allow non-redirect entries to overwrite a redirect entry.
			// Collect the incremental changes to the overall state in 'adds' and 'deletes'.
			policyMapState.redirectPreferredInsertWithChanges(mc.changes[i].key, mc.changes[i].value, adds, deletes)
		} else {
			// Delete the contribution of this cs to the key and collect incremental changes
			for cs := range mc.changes[i].value.selectors { // get the sole selector
				policyMapState.deleteKeyWithChanges(mc.changes[i].key, cs, adds, deletes)
			}
		}
	}
	mc.changes = nil
	mc.mutex.Unlock()
	return adds, deletes
}
