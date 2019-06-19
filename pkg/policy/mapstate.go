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
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

var (
	// localHostKey represents an ingress L3 allow from the local host.
	localHostKey = Key{
		Identity:         identity.ReservedIdentityHost.Uint32(),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}
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
	// Key.
	ProxyPort uint16
}

// DetermineAllowLocalhostIngress determines whether communication should be allowed
// from the localhost. It inserts the Key corresponding to the localhost in
// the desiredPolicyKeys if the localhost is allowed to communicate with the
// endpoint.
func (keys MapState) DetermineAllowLocalhostIngress(l4Policy *L4Policy) {

	if option.Config.AlwaysAllowLocalhost() || (l4Policy != nil && l4Policy.HasRedirect()) {
		keys[localHostKey] = MapStateEntry{}
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
		keys[keyToAdd] = MapStateEntry{}
	}
	if egress {
		keyToAdd := Key{
			Identity:         0,
			DestPort:         0,
			Nexthdr:          0,
			TrafficDirection: trafficdirection.Egress.Uint8(),
		}
		keys[keyToAdd] = MapStateEntry{}
	}
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
func (mc *MapChanges) AccumulateMapChanges(adds, deletes []identity.NumericIdentity,
	port uint16, proto uint8, direction trafficdirection.TrafficDirection) {
	key := Key{
		// The actual identity is set in the loops below
		Identity: 0,
		// NOTE: Port is in host byte-order!
		DestPort:         port,
		Nexthdr:          proto,
		TrafficDirection: direction.Uint8(),
	}
	value := MapStateEntry{
		ProxyPort: 0, // Will be updated by the caller when applicable
	}

	log.Debugf("MapChanges: AccumulateMapChanges(adds: %v, deletes: %v, port: %d, proto: %d, direction: %d)",
		adds, deletes, port, proto, direction.Uint8())

	mc.mutex.Lock()
	if len(adds) > 0 {
		if mc.adds == nil {
			mc.adds = make(MapState)
		}
		for _, id := range adds {
			key.Identity = id.Uint32()
			mc.adds[key] = value
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

// ConsumeMapChanges transfers the changes from MapChanges to the caller.
// May return nil maps.
func (mc *MapChanges) ConsumeMapChanges() (adds, deletes MapState) {
	mc.mutex.Lock()
	adds = mc.adds
	mc.adds = nil
	deletes = mc.deletes
	mc.deletes = nil
	mc.mutex.Unlock()
	return adds, deletes
}
