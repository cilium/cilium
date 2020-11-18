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

	// DerivedFromRules tracks the policy rules this entry derives from
	DerivedFromRules labels.LabelArrayList

	// IsDeny is true when the policy should be denied.
	IsDeny bool
}

// NewMapStateEntry creates a map state entry. If redirect is true, the
// caller is expected to replace the ProxyPort field before it is added to
// the actual BPF map.
func NewMapStateEntry(derivedFrom labels.LabelArrayList, redirect, deny bool) MapStateEntry {
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
func (keys MapState) DenyPreferredInsert(newKey Key, newEntry MapStateEntry) {
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
					keys[newKeyCpy] = newEntry

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
						delete(keys, k)
					}
				}
			}
		case allCpy == newKey:
			// If we adding a deny "all" entry, then we will remove all entries
			// from the map state for that direction.
			for k := range keys {
				if k.TrafficDirection == allCpy.TrafficDirection {
					delete(keys, k)
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

		keys[newKey] = newEntry
		return
	} else if newKey.Identity == 0 && newKey.DestPort != 0 {
		// case for an existing deny L3-only and we are inserting allow L4
		for k, v := range keys {
			if newKey.TrafficDirection == k.TrafficDirection {
				if v.IsDeny && k.Identity != 0 && k.DestPort == 0 && k.Nexthdr == 0 {
					// create a deny L3-L4 with the same deny L3
					newKeyCpy := newKey
					newKeyCpy.Identity = k.Identity
					keys[newKeyCpy] = v
				}
			}
		}
		keys[newKey] = newEntry
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

	keys.RedirectPreferredInsert(newKey, newEntry)
}

// RedirectPreferredInsert inserts a new entry giving priority to L7-redirects by
// not overwriting a L7-redirect entry with a non-redirect entry.
func (keys MapState) RedirectPreferredInsert(key Key, entry MapStateEntry) {
	if !entry.IsRedirectEntry() {
		if _, ok := keys[key]; ok {
			// Key already exist, keep the existing entry so that
			// a redirect entry is never overwritten by a non-redirect
			// entry
			return
		}
	}
	keys[key] = entry
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
		es := NewMapStateEntry(derivedFrom, false, false)
		keys.DenyPreferredInsert(localHostKey, es)
		if !option.Config.EnableRemoteNodeIdentity {
			var isHostDenied bool
			v, ok := keys[localHostKey]
			isHostDenied = ok && v.IsDeny
			es := NewMapStateEntry(derivedFrom, false, isHostDenied)
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
		keys[keyToAdd] = NewMapStateEntry(derivedFrom, false, false)
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
		keys[keyToAdd] = NewMapStateEntry(derivedFrom, false, false)
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
	adds    MapState
	deletes MapState
}

// AccumulateMapChanges accumulates the given changes to the
// MapChanges, updating both maps for each add and delete, as
// applicable.
//
// The caller is responsible for making sure the same identity is not
// present in both 'adds' and 'deletes'.  Across multiple calls we
// maintain the adds and deletes within the MapChanges are disjoint in
// cases where an identity is first added and then deleted, or first
// deleted and then added.
func (mc *MapChanges) AccumulateMapChanges(adds, deletes []identity.NumericIdentity,
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

	value := NewMapStateEntry(derivedFrom, redirect, isDeny)

	if option.Config.Debug {
		log.WithFields(logrus.Fields{
			logfields.AddedPolicyID:    adds,
			logfields.DeletedPolicyID:  deletes,
			logfields.Port:             port,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
			logfields.IsRedirect:       redirect,
		}).Debug("AccumulateMapChanges")
	}

	mc.mutex.Lock()
	if len(adds) > 0 {
		if mc.adds == nil {
			mc.adds = make(MapState)
		}
		for _, id := range adds {
			key.Identity = id.Uint32()
			// insert but do not allow non-redirect entries to overwrite a redirect entry
			mc.adds.DenyPreferredInsert(key, value)

			// Remove a potential previously deleted key
			if mc.deletes != nil {
				delete(mc.deletes, key)
			}
		}
	}
	if len(deletes) > 0 {
		if mc.deletes == nil {
			mc.deletes = make(MapState)
		}
		for _, id := range deletes {
			key.Identity = id.Uint32()
			mc.deletes[key] = value
			// Remove a potential previously added key
			if mc.adds != nil {
				delete(mc.adds, key)
			}
		}
	}
	mc.mutex.Unlock()
}

// consumeMapChanges transfers the changes from MapChanges to the caller.
// May return nil maps.
func (mc *MapChanges) consumeMapChanges() (adds, deletes MapState) {
	mc.mutex.Lock()
	adds = mc.adds
	mc.adds = nil
	deletes = mc.deletes
	mc.deletes = nil
	mc.mutex.Unlock()
	return adds, deletes
}
