// Copyright 2016-2020 Authors of Cilium
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
	// allKey represents a key for unknown traffic, i.e., all traffic.
	allKey = Key{
		Identity: identity.IdentityUnknown.Uint32(),
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

	// IsDeny is true when the policy should be denied.
	IsDeny bool

	// DerivedFromRules tracks the policy rules this entry derives from
	DerivedFromRules labels.LabelArrayList

	// Selectors collects the selectors in the policy that require this key to be present.
	// TODO: keep track which selector needed the entry to be deny, redirect, or just allow.
	selectors map[CachedSelector]struct{}
}

// NewMapStateEntry creates a map state entry. If redirect is true, the
// caller is expected to replace the ProxyPort field before it is added to
// the actual BPF map.
// 'cs' is used to keep track of which policy selectors need this entry. If it is 'nil' this entry
// will become sticky and cannot be completely removed via incremental updates. Even in this case
// the entry may be overridden or removed by a deny entry.
func NewMapStateEntry(cs CachedSelector, derivedFrom labels.LabelArrayList, redirect, deny bool) MapStateEntry {
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
		IsDeny:           deny,
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

// DatapathEqual returns true of two entries are equal in the datapath's PoV,
// i.e., both Deny and ProxyPort are the same for both entries.
func (e *MapStateEntry) DatapathEqual(o *MapStateEntry) bool {
	if e == nil || o == nil {
		return e == o
	}

	return e.IsDeny == o.IsDeny && e.ProxyPort == o.ProxyPort
}

// String returns a string representation of the MapStateEntry
func (e MapStateEntry) String() string {
	return fmt.Sprintf("ProxyPort=%d", e.ProxyPort)
}

// DenyPreferredInsert inserts a key and entry into the map by given preference
// to deny entries, and L3-only deny entries over L3-L4 allows.
// This form may be used when a full policy is computed and we are not yet interested
// in accumulating incremental changes.
func (keys MapState) DenyPreferredInsert(newKey Key, newEntry MapStateEntry) {
	keys.denyPreferredInsertWithChanges(newKey, newEntry, nil, nil)
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
	if adds != nil && (!exists || !oldEntry.DatapathEqual(&entry)) {
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

// denyPreferredInsertWithChanges inserts a key and entry into the map by giving preference
// to deny entries, and L3-only deny entries over L3-L4 allows.
// Incremental changes performed are recorded in 'adds' and 'deletes', if not nil.
func (keys MapState) denyPreferredInsertWithChanges(newKey Key, newEntry MapStateEntry, adds, deletes MapState) {
	allCpy := allKey
	allCpy.TrafficDirection = newKey.TrafficDirection
	// If we have a deny "all" we don't accept any kind of map entry
	if v, ok := keys[allCpy]; ok && v.IsDeny {
		return
	}

	if newEntry.IsDeny {
		// case for an existing allow L4-only and we are inserting deny L3-only
		switch {
		case newKey.DestPort == 0 && newKey.Nexthdr == 0 && newKey.Identity != 0:
			l4OnlyAllows := MapState{}
			for k, v := range keys {
				if newKey.TrafficDirection == k.TrafficDirection &&
					!v.IsDeny &&
					k.Identity == 0 {
					// create a deny L3-L4 with the same allowed L4 port and proto
					newKeyCpy := newKey
					newKeyCpy.DestPort = k.DestPort
					newKeyCpy.Nexthdr = k.Nexthdr
					keys.addKeyWithChanges(newKeyCpy, newEntry, adds, deletes)

					l4OnlyAllows[k] = v
				}
			}
			// Delete all L3-L4 if we are inserting a deny L3-only and
			// there aren't allow L4-only for the existing deny L3-L4
			for k := range keys {
				if k.TrafficDirection == newKey.TrafficDirection &&
					k.DestPort != 0 && k.Nexthdr != 0 &&
					k.Identity == newKey.Identity {

					kCpy := k
					kCpy.Identity = 0
					if _, ok := l4OnlyAllows[kCpy]; !ok {
						keys.deleteKeyWithChanges(k, nil, adds, deletes)
					}
				}
			}
		case allCpy == newKey:
			// If we adding a deny "all" entry, then we will remove all entries
			// from the map state for that direction.
			for k := range keys {
				if k.TrafficDirection == allCpy.TrafficDirection {
					keys.deleteKeyWithChanges(k, nil, adds, deletes)
				}
			}
		default:
			// Do not insert 'newKey' if the map state already denies traffic
			// which is a superset of (or equal to) 'newKey'
			newKeyCpy := newKey
			newKeyCpy.DestPort = 0
			newKeyCpy.Nexthdr = 0
			v, ok := keys[newKeyCpy]
			if ok && v.IsDeny {
				// Found a L3-only Deny so we won't accept any L3-L4 policies
				return
			}
		}

		keys.addKeyWithChanges(newKey, newEntry, adds, deletes)
		return
	} else if newKey.Identity == 0 && newKey.DestPort != 0 {
		// case for an existing deny L3-only and we are inserting allow L4
		for k, v := range keys {
			if newKey.TrafficDirection == k.TrafficDirection {
				if v.IsDeny && k.Identity != 0 && k.DestPort == 0 && k.Nexthdr == 0 {
					// create a deny L3-L4 with the same deny L3
					newKeyCpy := newKey
					newKeyCpy.Identity = k.Identity
					keys.addKeyWithChanges(newKeyCpy, v, adds, deletes)
				}
			}
		}
		keys.addKeyWithChanges(newKey, newEntry, adds, deletes)
		return
	}
	// branch for adding a new allow L3-L4

	newKeyCpy := newKey
	newKeyCpy.DestPort = 0
	newKeyCpy.Nexthdr = 0
	v, ok := keys[newKeyCpy]
	if ok && v.IsDeny {
		// Found a L3-only Deny so we won't accept any L3-L4 allow policies
		return
	}

	keys.RedirectPreferredInsert(newKey, newEntry, adds, deletes)
}

// RedirectPreferredInsert inserts a new entry giving priority to L7-redirects by
// not overwriting a L7-redirect entry with a non-redirect entry.
func (keys MapState) RedirectPreferredInsert(key Key, entry MapStateEntry, adds, deletes MapState) {
	// Do not overwrite the entry, but only merge selectors if the old entry is a deny or redirect.
	// This prevents an existing deny or redirect being overridden by a non-deny or a non-redirect.
	// Merging selectors from the new entry to the eisting one has no datapath impact so we skip
	// adding anything to 'adds' here.
	if oldEntry, exists := keys[key]; exists && (oldEntry.IsRedirectEntry() || oldEntry.IsDeny) {
		oldEntry.MergeSelectors(&entry)
		keys[key] = oldEntry
		return
	}
	// Otherwise write the entry to the map
	keys.addKeyWithChanges(key, entry, adds, deletes)
}

// DetermineAllowLocalhostIngress determines whether communication should be allowed
// from the localhost. It inserts the Key corresponding to the localhost in
// the desiredPolicyKeys if the localhost is allowed to communicate with the
// endpoint.
func (keys MapState) DetermineAllowLocalhostIngress() {
	if option.Config.AlwaysAllowLocalhost() {
		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowLocalHostIngress, labels.LabelSourceReserved),
			},
		}
		es := NewMapStateEntry(nil, derivedFrom, false, false)
		keys.DenyPreferredInsert(localHostKey, es)
		if !option.Config.EnableRemoteNodeIdentity {
			var isHostDenied bool
			v, ok := keys[localHostKey]
			isHostDenied = ok && v.IsDeny
			es := NewMapStateEntry(nil, derivedFrom, false, isHostDenied)
			keys.DenyPreferredInsert(localRemoteNodeKey, es)
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
		keys[keyToAdd] = NewMapStateEntry(nil, derivedFrom, false, false)
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
		keys[keyToAdd] = NewMapStateEntry(nil, derivedFrom, false, false)
	}
}

func (keys MapState) AllowsL4(policyOwner PolicyOwner, l4 *L4Filter) bool {
	port := uint16(l4.Port)
	proto := uint8(l4.U8Proto)

	// resolve named port
	if port == 0 && l4.PortName != "" {
		port = policyOwner.GetNamedPortLocked(l4.Ingress, l4.PortName, proto)
		if port == 0 {
			return false
		}
	}

	var dir uint8
	if l4.Ingress {
		dir = trafficdirection.Ingress.Uint8()
	} else {
		dir = trafficdirection.Egress.Uint8()
	}
	anyKey := Key{
		Identity:         0,
		DestPort:         0,
		Nexthdr:          0,
		TrafficDirection: dir,
	}
	// Are we explicitly denying any traffic?
	v, ok := keys[anyKey]
	if ok && v.IsDeny {
		return false
	}

	// Are we explicitly denying this L4-only traffic?
	anyKey.DestPort = port
	anyKey.Nexthdr = proto
	v, ok = keys[anyKey]
	if ok && v.IsDeny {
		return false
	}

	return true
}

func (pms MapState) GetIdentities(log *logrus.Logger) (ingIdentities, egIdentities []int64) {
	return pms.getIdentities(log, false)
}

func (pms MapState) GetDenyIdentities(log *logrus.Logger) (ingIdentities, egIdentities []int64) {
	return pms.getIdentities(log, true)
}

// GetIdentities returns the ingress and egress identities stored in the
// MapState.
func (pms MapState) getIdentities(log *logrus.Logger, denied bool) (ingIdentities, egIdentities []int64) {
	for policyMapKey, policyMapValue := range pms {
		if denied != policyMapValue.IsDeny {
			continue
		}
		if policyMapKey.DestPort != 0 {
			// If the port is non-zero, then the Key no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			continue
		}
		switch trafficdirection.TrafficDirection(policyMapKey.TrafficDirection) {
		case trafficdirection.Ingress:
			ingIdentities = append(ingIdentities, int64(policyMapKey.Identity))
		case trafficdirection.Egress:
			egIdentities = append(egIdentities, int64(policyMapKey.Identity))
		default:
			td := trafficdirection.TrafficDirection(policyMapKey.TrafficDirection)
			log.WithField(logfields.TrafficDirection, td).
				Errorf("Unexpected traffic direction present in policy map state for endpoint")
		}
	}
	return ingIdentities, egIdentities
}

// MapChanges collects updates to the endpoint policy on the
// granularity of individual mapstate key-value pairs for both adds
// and deletes. 'mutex' must be held for any access.
type MapChanges struct {
	mutex   lock.Mutex
	changes []MapChange
}

type MapChange struct {
	Add   bool // false deletes
	Key   Key
	Value MapStateEntry
}

// AccumulateMapChanges accumulates the given changes to the
// MapChanges.
//
// The caller is responsible for making sure the same identity is not
// present in both 'adds' and 'deletes'.
func (mc *MapChanges) AccumulateMapChanges(cs CachedSelector, adds, deletes []identity.NumericIdentity,
	port uint16, proto uint8, direction trafficdirection.TrafficDirection,
	redirect, isDeny bool, derivedFrom labels.LabelArrayList) {
	key := Key{
		// The actual identity is set in the loops below
		Identity: 0,
		// NOTE: Port is in host byte-order!
		DestPort:         port,
		Nexthdr:          proto,
		TrafficDirection: direction.Uint8(),
	}

	value := NewMapStateEntry(cs, derivedFrom, redirect, isDeny)

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
		mc.changes = append(mc.changes, MapChange{Add: true, Key: key, Value: value})
	}
	for _, id := range deletes {
		key.Identity = id.Uint32()
		mc.changes = append(mc.changes, MapChange{Add: false, Key: key, Value: value})
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
		if mc.changes[i].Add {
			// insert but do not allow non-redirect entries to overwrite a redirect entry,
			// nor allow non-deny entries to overwrite deny entries.
			// Collect the incremental changes to the overall state in 'mc.adds' and 'mc.deletes'.
			policyMapState.denyPreferredInsertWithChanges(mc.changes[i].Key, mc.changes[i].Value, adds, deletes)
		} else {
			// Delete the contribution of this cs to the key and collect incremental changes
			for cs := range mc.changes[i].Value.selectors { // get the sole selector
				policyMapState.deleteKeyWithChanges(mc.changes[i].Key, cs, adds, deletes)
			}
		}
	}
	mc.changes = nil
	mc.mutex.Unlock()
	return adds, deletes
}
