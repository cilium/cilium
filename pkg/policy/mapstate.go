// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
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
	LabelKeyPolicyDerivedFrom   = "io.cilium.policy.derived-from"
	LabelAllowLocalHostIngress  = "allow-localhost-ingress"
	LabelAllowRemoteHostIngress = "allow-remotehost-ingress"
	LabelAllowAnyIngress        = "allow-any-ingress"
	LabelAllowAnyEgress         = "allow-any-egress"
	LabelVisibilityAnnotation   = "visibility-annotation"
)

// MapState is a state of a policy map.
type MapState map[Key]MapStateEntry

type Identities interface {
	GetLabels(identity.NumericIdentity) labels.LabelArray
}

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

// PortProtoIsBroader returns true if the receiver Key has broader
// port-protocol than the argument Key. That is a port-protocol
// that covers the argument Key's port-protocol and is larger.
// An equal port-protocol will return false.
func (k Key) PortProtoIsBroader(c Key) bool {
	return k.DestPort == 0 && c.DestPort != 0 ||
		k.Nexthdr == 0 && c.Nexthdr != 0
}

// PortProtoIsEqual returns true if the port-protocols of the
// two keys are exactly equal.
func (k Key) PortProtoIsEqual(c Key) bool {
	return k.DestPort == c.DestPort && k.Nexthdr == c.Nexthdr
}

type Keys map[Key]struct{}

type MapStateOwner interface{}

// MapStateEntry is the configuration associated with a Key in a
// MapState. This is a minimized version of policymap.PolicyEntry.
type MapStateEntry struct {
	// The proxy port, in host byte order.
	// If 0 (default), there is no proxy redirection for the corresponding
	// Key. Any other value signifies proxy redirection.
	ProxyPort uint16

	// IsDeny is true when the policy should be denied.
	IsDeny bool

	// AuthType is non-zero when authentication is required for the traffic to be allowed.
	AuthType AuthType

	// DerivedFromRules tracks the policy rules this entry derives from
	DerivedFromRules labels.LabelArrayList

	// Owners collects the keys in the map and selectors in the policy that require this key to be present.
	// TODO: keep track which selector needed the entry to be deny, redirect, or just allow.
	owners map[MapStateOwner]struct{}

	// dependents contains the keys for entries create based on this entry. These entries
	// will be deleted once all of the owners are deleted.
	dependents Keys

	// cachedNets caches the subnets (if any) associated with this MapStateEntry.
	cachedNets []*net.IPNet
}

// NewMapStateEntry creates a map state entry. If redirect is true, the
// caller is expected to replace the ProxyPort field before it is added to
// the actual BPF map.
// 'cs' is used to keep track of which policy selectors need this entry. If it is 'nil' this entry
// will become sticky and cannot be completely removed via incremental updates. Even in this case
// the entry may be overridden or removed by a deny entry.
func NewMapStateEntry(cs MapStateOwner, derivedFrom labels.LabelArrayList, redirect, deny bool, authType AuthType) MapStateEntry {
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
		AuthType:         authType,
		owners:           map[MapStateOwner]struct{}{cs: {}},
	}
}

// AddDependent adds 'key' to the set of dependent keys.
func (e *MapStateEntry) AddDependent(key Key) {
	if e.dependents == nil {
		e.dependents = make(Keys, 1)
	}
	e.dependents[key] = struct{}{}
}

// RemoveDependent removes 'key' from the set of dependent keys.
func (e *MapStateEntry) RemoveDependent(key Key) {
	delete(e.dependents, key)
	// Nil the map when empty. This is mainly to make unit testing easier.
	if len(e.dependents) == 0 {
		e.dependents = nil
	}
}

// HasDependent returns true if the 'key' is contained
// within the set of dependent keys
func (e *MapStateEntry) HasDependent(key Key) bool {
	if e.dependents == nil {
		return false
	}
	_, ok := e.dependents[key]
	return ok
}

// getNets returns the most specific CIDR for an identity. For the "World" identity
// it returns both IPv4 and IPv6.
func (e *MapStateEntry) getNets(identities Identities, ident uint32) []*net.IPNet {
	// Caching results is not dangerous in this situation as the entry
	// is ephemerally tied to the lifecycle of the MapState object that
	// it will be in.
	if e.cachedNets != nil {
		return e.cachedNets
	}
	id := identity.NumericIdentity(ident)
	if id == identity.ReservedIdentityWorld {
		e.cachedNets = []*net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, net.IPv4len*8)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, net.IPv6len*8)},
		}
		return e.cachedNets
	}
	if identities == nil {
		return nil
	}
	lbls := identities.GetLabels(id)
	nets := make([]*net.IPNet, 0, 1)
	var (
		maskSize         int
		mostSpecificCidr *net.IPNet
	)
	for _, lbl := range lbls {
		if lbl.Source == labels.LabelSourceCIDR {
			_, netIP, err := net.ParseCIDR(lbl.Key)
			if err == nil {
				if ms, _ := netIP.Mask.Size(); ms > maskSize {
					mostSpecificCidr = netIP
					maskSize = ms
				}
			}
		}
	}
	if mostSpecificCidr != nil {
		nets = append(nets, mostSpecificCidr)
	}
	e.cachedNets = nets
	return nets
}

// AddDependent adds 'key' to the set of dependent keys.
func (owner Key) AddDependent(keys MapState, key Key) {
	if e, exists := keys[owner]; exists {
		e.AddDependent(key)
		keys[owner] = e
	}
}

// RemoveDependent removes 'key' from the list of dependent keys.
// This is called when a dependent entry is being deleted.
func (keys MapState) RemoveDependent(owner Key, dependent Key) {
	if e, exists := keys[owner]; exists {
		e.RemoveDependent(dependent)
		keys[owner] = e
	}
}

// MergeReferences adds owners and dependents from entry 'entry' to 'e'. 'entry' is not modified.
func (e *MapStateEntry) MergeReferences(entry *MapStateEntry) {
	if e.owners == nil && len(entry.owners) > 0 {
		e.owners = make(map[MapStateOwner]struct{}, len(entry.owners))
	}
	for k, v := range entry.owners {
		e.owners[k] = v
	}

	// merge dependents
	for k := range entry.dependents {
		e.AddDependent(k)
	}
}

// IsRedirectEntry returns true if e contains a redirect
func (e *MapStateEntry) IsRedirectEntry() bool {
	return e.ProxyPort != 0
}

// DatapathEqual returns true of two entries are equal in the datapath's PoV,
// i.e., IsDeny, ProxyPort and AuthType are the same for both entries.
func (e *MapStateEntry) DatapathEqual(o *MapStateEntry) bool {
	if e == nil || o == nil {
		return e == o
	}

	return e.IsDeny == o.IsDeny && e.ProxyPort == o.ProxyPort && e.AuthType == o.AuthType
}

// String returns a string representation of the MapStateEntry
func (e MapStateEntry) String() string {
	return fmt.Sprintf("ProxyPort=%d", e.ProxyPort)
}

// DenyPreferredInsert inserts a key and entry into the map by given preference
// to deny entries, and L3-only deny entries over L3-L4 allows.
// This form may be used when a full policy is computed and we are not yet interested
// in accumulating incremental changes.
func (keys MapState) DenyPreferredInsert(newKey Key, newEntry MapStateEntry, identities Identities) {
	keys.denyPreferredInsertWithChanges(newKey, newEntry, nil, nil, identities)
}

// addKeyWithChanges adds a 'key' with value 'entry' to 'keys' keeping track of incremental changes in 'adds' and 'deletes'
func (keys MapState) addKeyWithChanges(key Key, entry MapStateEntry, adds, deletes Keys) {
	// Keep all owners that need this entry so that it is deleted only if all the owners delete their contribution
	updatedEntry := entry
	oldEntry, exists := keys[key]
	if exists {
		// keep the existing owners of the old entry
		updatedEntry.owners = oldEntry.owners
		// keep the existing dependent entries
		updatedEntry.dependents = oldEntry.dependents
	} else if len(entry.owners) > 0 {
		// create a new owners map
		updatedEntry.owners = make(map[MapStateOwner]struct{}, len(entry.owners))
	}

	// TODO: Do we need to merge labels as well?
	// Merge new owner to the updated entry without modifying 'entry' as it is being reused by the caller
	updatedEntry.MergeReferences(&entry)
	// Update (or insert) the entry
	keys[key] = updatedEntry

	// Record an incremental Add if desired and entry is new or changed
	if adds != nil && (!exists || !oldEntry.DatapathEqual(&entry)) {
		adds[key] = struct{}{}
		// Key add overrides any previous delete of the same key
		if deletes != nil {
			delete(deletes, key)
		}
	}
}

// deleteKeyWithChanges deletes a 'key' from 'keys' keeping track of incremental changes in 'adds' and 'deletes'.
// The key is unconditionally deleted if 'cs' is nil, otherwise only the contribution of this 'cs' is removed.
func (keys MapState) deleteKeyWithChanges(key Key, owner MapStateOwner, adds, deletes Keys) {
	if entry, exists := keys[key]; exists {
		if owner != nil {
			// remove the contribution of the given selector only
			if _, exists = entry.owners[owner]; exists {
				// Remove the contribution of this selector from the entry
				delete(entry.owners, owner)
				if ownerKey, ok := owner.(Key); ok {
					keys.RemoveDependent(ownerKey, key)
				}
				// key is not deleted if other owners still need it
				if len(entry.owners) > 0 {
					return
				}
			} else {
				// 'owner' was not found, do not change anything
				return
			}
		}

		// Remove this key from all owners' dependents maps if no owner was given.
		// Owner is nil when deleting more specific entries (e.g., L3/L4) when
		// adding deny entries that cover them (e.g., L3-deny).
		if owner == nil {
			for owner := range entry.owners {
				if owner != nil {
					if ownerKey, ok := owner.(Key); ok {
						keys.RemoveDependent(ownerKey, key)
					}
				}
			}
		}

		// Check if dependent entries need to be deleted as well
		for k := range entry.dependents {
			keys.deleteKeyWithChanges(k, key, adds, deletes)
		}
		if deletes != nil {
			deletes[key] = struct{}{}
			// Remove a potential previously added key
			if adds != nil {
				delete(adds, key)
			}
		}

		delete(keys, key)
	}
}

// entryIdentityIsSupersetOf compares two entries and keys to see if the primary identity contains
// the compared identity. This means that either that primary identity is 0 (i.e. it is a superset
// of every other identity), or one of the subnets of the primary identity fully contains or is
// equal to one of the subnets in the compared identity (note:this covers cases like "reserved:world").
func entryIdentityIsSupersetOf(primaryKey Key, primaryEntry MapStateEntry, compareKey Key, compareEntry MapStateEntry, identities Identities) bool {
	// If the identities are equal then neither is a superset (for the purposes of our business logic).
	if primaryKey.Identity == compareKey.Identity {
		return false
	}
	return primaryKey.Identity == 0 && compareKey.Identity != 0 ||
		ip.NetsContainsAny(primaryEntry.getNets(identities, primaryKey.Identity),
			compareEntry.getNets(identities, compareKey.Identity))
}

// protocolsMatch checks to see if two given keys match on protocol.
// This means that either one of them covers all protocols or they
// are equal.
func protocolsMatch(a, b Key) bool {
	return a.Nexthdr == 0 || b.Nexthdr == 0 || a.Nexthdr == b.Nexthdr
}

// denyPreferredInsertWithChanges contains the most important business logic for policy insertions. It inserts
// a key and entry into the map by giving preference to deny entries, and L3-only deny entries over L3-L4 allows.
// Incremental changes performed are recorded in 'adds' and 'deletes', if not nil.
// See https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw#gid=2109052536 for details
func (keys MapState) denyPreferredInsertWithChanges(newKey Key, newEntry MapStateEntry, adds, deletes Keys, identities Identities) {
	allCpy := allKey
	allCpy.TrafficDirection = newKey.TrafficDirection
	// If we have a deny "all" we don't accept any kind of map entry.
	if v, ok := keys[allCpy]; ok && v.IsDeny {
		return
	}
	if newEntry.IsDeny {
		for k, v := range keys {
			// Protocols and traffic directions that don't match ensure that the policies
			// do not interact in anyway.
			if newKey.TrafficDirection != k.TrafficDirection || !protocolsMatch(newKey, k) {
				continue
			}
			if !v.IsDeny {
				if entryIdentityIsSupersetOf(k, v, newKey, newEntry, identities) {
					if newKey.PortProtoIsBroader(k) {
						// If this iterated-allow-entry is a superset of the new-entry
						// and it has a more specific port-protocol than the new-entry
						// then an additional copy of the new-entry with the more
						// specific port-protocol of the iterated-allow-entry must be inserted.
						newKeyCpy := newKey
						newKeyCpy.DestPort = k.DestPort
						newKeyCpy.Nexthdr = k.Nexthdr
						l3l4DenyEntry := NewMapStateEntry(newKey, newEntry.DerivedFromRules, false, true, AuthTypeNone)
						keys.addKeyWithChanges(newKeyCpy, l3l4DenyEntry, adds, deletes)
						// L3-only entries can be deleted incrementally so we need to track their
						// effects on other entries so that those effects can be reverted when the
						// identity is removed.
						newEntry.AddDependent(newKeyCpy)
					}
				} else if (newKey.Identity == k.Identity ||
					entryIdentityIsSupersetOf(newKey, newEntry, k, v, identities)) &&
					(newKey.PortProtoIsBroader(k) || newKey.PortProtoIsEqual(k)) {
					// If the new-entry is a superset (or equal) of the iterated-allow-entry and
					// the new-entry has a broader (or equal) port-protocol then we
					// should delete the iterated-allow-entry
					keys.deleteKeyWithChanges(k, nil, adds, deletes)
				}
			} else if (newKey.Identity == k.Identity ||
				entryIdentityIsSupersetOf(k, v, newKey, newEntry, identities)) &&
				k.DestPort == 0 && k.Nexthdr == 0 &&
				!v.HasDependent(newKey) {
				// If this iterated-deny-entry is a supserset (or equal) of the new-entry and
				// the iterated-deny-entry is an L3-only policy then we
				// should not insert the new entry (as long as it is not one
				// of the special L4-only denies we created to cover the special
				// case of a superset-allow with a more specific port-protocol).
				//
				// NOTE: This condition could be broader to reject more deny entries,
				// but there *may* be performance tradeoffs.
				return
			} else if (newKey.Identity == k.Identity ||
				entryIdentityIsSupersetOf(newKey, newEntry, k, v, identities)) &&
				newKey.DestPort == 0 && newKey.Nexthdr == 0 &&
				!newEntry.HasDependent(k) {
				// If this iterated-deny-entry is a subset (or equal) of the new-entry and
				// the new-entry is an L3-only policy then we
				// should delete the iterated-deny-entry (as long as it is not one
				// of the special L4-only denies we created to cover the special
				// case of a superset-allow with a more specific port-protocol).
				//
				// NOTE: This condition could be broader to reject more deny entries,
				// but there *may* be performance tradeoffs.
				keys.deleteKeyWithChanges(k, nil, adds, deletes)
			}
		}
		keys.addKeyWithChanges(newKey, newEntry, adds, deletes)
	} else {
		for k, v := range keys {
			// Protocols and traffic directions that don't match ensure that the policies
			// do not interact in anyway.
			if newKey.TrafficDirection != k.TrafficDirection || !protocolsMatch(newKey, k) {
				continue
			}
			// NOTE: We do not delete redundant allow entries.
			if v.IsDeny {
				if entryIdentityIsSupersetOf(newKey, newEntry, k, v, identities) {
					if k.PortProtoIsBroader(newKey) {
						// If the new-entry is *only* superset of the iterated-deny-entry
						// and the new-entry has a more specific port-protocol than the
						// iterated-deny-entry then an additional copy of the iterated-deny-entry
						// with the more specific port-porotocol of the new-entry must
						// be added.
						denyKeyCpy := k
						denyKeyCpy.DestPort = newKey.DestPort
						denyKeyCpy.Nexthdr = newKey.Nexthdr
						l3l4DenyEntry := NewMapStateEntry(k, v.DerivedFromRules, false, true, AuthTypeNone)
						keys.addKeyWithChanges(denyKeyCpy, l3l4DenyEntry, adds, deletes)
						// L3-only entries can be deleted incrementally so we need to track their
						// effects on other entries so that those effects can be reverted when the
						// identity is removed.
						v.AddDependent(denyKeyCpy)
						keys[k] = v
					}
				} else if (k.Identity == newKey.Identity ||
					entryIdentityIsSupersetOf(k, v, newKey, newEntry, identities)) &&
					(k.PortProtoIsBroader(newKey) || k.PortProtoIsEqual(newKey)) &&
					!v.HasDependent(newKey) {
					// If the iterated-deny-entry is a superset (or equal) of the new-entry and has a
					// broader (or equal) port-protocol than the new-entry then the new
					// entry should not be inserted.
					return
				}
			}
		}
		keys.redirectPreferredInsert(newKey, newEntry, adds, deletes)
	}
}

// redirectPreferredInsert inserts a new entry giving priority to L7-redirects by
// not overwriting a L7-redirect entry with a non-redirect entry.
func (keys MapState) redirectPreferredInsert(key Key, entry MapStateEntry, adds, deletes Keys) {
	// Do not overwrite the entry, but only merge owners if the old entry is a deny or redirect.
	// This prevents an existing deny or redirect being overridden by a non-deny or a non-redirect.
	// Merging owners from the new entry to the existing one has no datapath impact so we skip
	// adding anything to 'adds' here.
	if oldEntry, exists := keys[key]; exists && (oldEntry.IsRedirectEntry() || oldEntry.IsDeny) {
		oldEntry.MergeReferences(&entry)
		keys[key] = oldEntry
		return
	}
	// Otherwise write the entry to the map
	keys.addKeyWithChanges(key, entry, adds, deletes)
}

var visibilityDerivedFromLabels = labels.LabelArray{
	labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelVisibilityAnnotation, labels.LabelSourceReserved),
}

var visibilityDerivedFrom = labels.LabelArrayList{visibilityDerivedFromLabels}

func (keys MapState) insertIfNotExists(key Key, entry MapStateEntry) {
	if keys != nil {
		if _, exists := keys[key]; !exists {
			keys[key] = entry
		}
	}
}

// AddVisibilityKeys adjusts and expands PolicyMapState keys
// and values to redirect for visibility on the port of the visibility
// annotation while still denying traffic on this port for identities
// for which the traffic is denied.
//
// Datapath lookup order is, from highest to lowest precedence:
// 1. L3/L4
// 2. L4-only (wildcard L3)
// 3. L3-only (wildcard L4)
// 4. Allow-all
//
// This means that the L4-only allow visibility key can only be added if there is an
// allow-all key, and all L3-only deny keys are expanded to L3/L4 keys. If no
// L4-only key is added then also the L3-only allow keys need to be expanded to
// L3/L4 keys for visibility redirection. In addition the existing L3/L4 and L4-only
// allow keys need to be redirected to the proxy port, if not already redirected.
//
// The above can be accomplished by:
//
//  1. Change existing L4-only ALLOW key on matching port that does not already
//     redirect to redirect.
//     - e.g., 0:80=allow,0 -> 0:80=allow,<proxyport>
//  2. If allow-all policy exists, add L4-only visibility redirect key if the L4-only
//     key does not already exist.
//     - e.g., 0:0=allow,0 -> add 0:80=allow,<proxyport> if 0:80 does not exist
//     - this allows all traffic on port 80, but see step 5 below.
//  3. Change all L3/L4 ALLOW keys on matching port that do not already redirect to
//     redirect.
//     - e.g, <ID1>:80=allow,0 -> <ID1>:80=allow,<proxyport>
//  4. For each L3-only ALLOW key add the corresponding L3/L4 ALLOW redirect if no
//     L3/L4 key already exists and no L4-only key already exists and one is not added.
//     - e.g., <ID2>:0=allow,0 -> add <ID2>:80=allow,<proxyport> if <ID2>:80
//     and 0:80 do not exist
//  5. If a new L4-only key was added: For each L3-only DENY key add the
//     corresponding L3/L4 DENY key if no L3/L4 key already exists.
//     - e.g., <ID3>:0=deny,0 -> add <ID3>:80=deny,0 if <ID3>:80 does not exist
//
// With the above we only change/expand existing allow keys to redirect, and
// expand existing drop keys to also drop on the port of interest, if a new
// L4-only key allowing the port is added.
//
// 'adds' and 'oldValues' are updated with the changes made. 'adds' contains both the added and
// changed keys. 'oldValues' contains the old values for changed keys. This function does not
// delete any keys.
func (keys MapState) AddVisibilityKeys(e PolicyOwner, redirectPort uint16, visMeta *VisibilityMetadata, adds Keys, oldValues MapState) {
	direction := trafficdirection.Egress
	if visMeta.Ingress {
		direction = trafficdirection.Ingress
	}

	allowAllKey := Key{
		TrafficDirection: direction.Uint8(),
	}
	key := Key{
		DestPort:         visMeta.Port,
		Nexthdr:          uint8(visMeta.Proto),
		TrafficDirection: direction.Uint8(),
	}

	entry := NewMapStateEntry(nil, visibilityDerivedFrom, true, false, AuthTypeNone)
	entry.ProxyPort = redirectPort

	_, haveAllowAllKey := keys[allowAllKey]
	l4Only, haveL4OnlyKey := keys[key]
	addL4OnlyKey := false
	if haveL4OnlyKey && !l4Only.IsDeny && l4Only.ProxyPort == 0 {
		// 1. Change existing L4-only ALLOW key on matching port that does not already
		//    redirect to redirect.
		e.PolicyDebug(logrus.Fields{
			logfields.BPFMapKey:   key,
			logfields.BPFMapValue: entry,
		}, "AddVisibilityKeys: Changing L4-only ALLOW key for visibility redirect")

		// keep the original value for reverting purposes
		oldValues.insertIfNotExists(key, l4Only)

		l4Only.ProxyPort = redirectPort
		l4Only.DerivedFromRules = append(l4Only.DerivedFromRules, visibilityDerivedFromLabels)
		keys[key] = l4Only
		adds[key] = struct{}{}
	}
	if haveAllowAllKey && !haveL4OnlyKey {
		// 2. If allow-all policy exists, add L4-only visibility redirect key if the L4-only
		//    key does not already exist.
		e.PolicyDebug(logrus.Fields{
			logfields.BPFMapKey:   key,
			logfields.BPFMapValue: entry,
		}, "AddVisibilityKeys: Adding L4-only ALLOW key for visibilty redirect")
		addL4OnlyKey = true
		keys[key] = entry
		adds[key] = struct{}{}
	}
	//
	// Loop through all L3 keys in the traffic direction of the new key
	//
	for k, v := range keys {
		if k.TrafficDirection != key.TrafficDirection || k.Identity == 0 {
			continue
		}
		if k.DestPort == key.DestPort && k.Nexthdr == key.Nexthdr {
			//
			// Same L4
			//
			if !v.IsDeny && v.ProxyPort == 0 {
				// 3. Change all L3/L4 ALLOW keys on matching port that do not
				//    already redirect to redirect.

				// keep the original value for reverting purposes
				oldValues.insertIfNotExists(k, v)

				v.ProxyPort = redirectPort
				v.DerivedFromRules = append(v.DerivedFromRules, visibilityDerivedFromLabels)
				e.PolicyDebug(logrus.Fields{
					logfields.BPFMapKey:   k,
					logfields.BPFMapValue: v,
				}, "AddVisibilityKeys: Changing L3/L4 ALLOW key for visibility redirect")
				keys[k] = v
				adds[k] = struct{}{}
			}
		} else if k.DestPort == 0 && k.Nexthdr == 0 {
			//
			// Wildcarded L4, i.e., L3-only
			//
			k2 := k
			k2.DestPort = key.DestPort
			k2.Nexthdr = key.Nexthdr
			if !v.IsDeny && !haveL4OnlyKey && !addL4OnlyKey {
				// 4. For each L3-only ALLOW key add the corresponding L3/L4
				//    ALLOW redirect if no L3/L4 key already exists and no
				//    L4-only key already exists and one is not added.
				if _, ok := keys[k2]; !ok {
					d2 := append(labels.LabelArrayList{visibilityDerivedFromLabels}, v.DerivedFromRules...)
					v2 := NewMapStateEntry(k, d2, true, false, v.AuthType)
					v2.ProxyPort = redirectPort
					e.PolicyDebug(logrus.Fields{
						logfields.BPFMapKey:   k2,
						logfields.BPFMapValue: v2,
					}, "AddVisibilityKeys: Extending L3-only ALLOW key to L3/L4 key for visibilty redirect")
					keys[k2] = v2
					adds[k2] = struct{}{}

					// keep the original value for reverting purposes
					oldValues.insertIfNotExists(k, v)

					// Mark the new entry as a dependent of 'v'
					v.AddDependent(k2)
					keys[k] = v
					adds[k] = struct{}{} // dependent was added
				}
			} else if addL4OnlyKey && v.IsDeny {
				// 5. If a new L4-only key was added: For each L3-only DENY
				//    key add the corresponding L3/L4 DENY key if no L3/L4
				//    key already exists.
				if _, ok := keys[k2]; !ok {
					v2 := NewMapStateEntry(k, v.DerivedFromRules, false, true, AuthTypeNone)
					e.PolicyDebug(logrus.Fields{
						logfields.BPFMapKey:   k2,
						logfields.BPFMapValue: v2,
					}, "AddVisibilityKeys: Extending L3-only DENY key to L3/L4 key to deny a port with visibility annotation")
					keys[k2] = v2
					adds[k2] = struct{}{}

					// keep the original value for reverting purposes
					oldValues.insertIfNotExists(k, v)

					// Mark the new entry as a dependent of 'v'
					v.AddDependent(k2)
					keys[k] = v
					adds[k] = struct{}{} // dependent was added
				}
			}
		}
	}
}

// DetermineAllowLocalhostIngress determines whether communication should be allowed
// from the localhost. It inserts the Key corresponding to the localhost in
// the desiredPolicyKeys if the localhost is allowed to communicate with the
// endpoint. Authentication for localhost traffic is not required.
func (keys MapState) DetermineAllowLocalhostIngress() {
	if option.Config.AlwaysAllowLocalhost() {
		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowLocalHostIngress, labels.LabelSourceReserved),
			},
		}
		es := NewMapStateEntry(nil, derivedFrom, false, false, AuthTypeNone)
		keys.DenyPreferredInsert(localHostKey, es, nil)
		if !option.Config.EnableRemoteNodeIdentity {
			var isHostDenied bool
			v, ok := keys[localHostKey]
			isHostDenied = ok && v.IsDeny
			derivedFrom := labels.LabelArrayList{
				labels.LabelArray{
					labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowRemoteHostIngress, labels.LabelSourceReserved),
				},
			}
			es := NewMapStateEntry(nil, derivedFrom, false, isHostDenied, AuthTypeNone)
			keys.DenyPreferredInsert(localRemoteNodeKey, es, nil)
		}
	}
}

// AllowAllIdentities translates all identities in selectorCache to their
// corresponding Keys in the specified direction (ingress, egress) which allows
// all at L3, without requiring authentication.
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
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyIngress, labels.LabelSourceReserved),
			},
		}
		keys[keyToAdd] = NewMapStateEntry(nil, derivedFrom, false, false, AuthTypeNone)
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
		keys[keyToAdd] = NewMapStateEntry(nil, derivedFrom, false, false, AuthTypeNone)
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
	redirect, isDeny bool, authType AuthType, derivedFrom labels.LabelArrayList) {
	key := Key{
		// The actual identity is set in the loops below
		Identity: 0,
		// NOTE: Port is in host byte-order!
		DestPort:         port,
		Nexthdr:          proto,
		TrafficDirection: direction.Uint8(),
	}

	value := NewMapStateEntry(cs, derivedFrom, redirect, isDeny, authType)

	if option.Config.Debug {
		log.WithFields(logrus.Fields{
			logfields.EndpointSelector: cs,
			logfields.AddedPolicyID:    adds,
			logfields.DeletedPolicyID:  deletes,
			logfields.Port:             port,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
			logfields.IsRedirect:       redirect,
			logfields.AuthType:         authType.String(),
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
func (mc *MapChanges) consumeMapChanges(policyMapState MapState, identities Identities) (adds, deletes Keys) {
	mc.mutex.Lock()
	adds = make(Keys, len(mc.changes))
	deletes = make(Keys, len(mc.changes))

	for i := range mc.changes {
		if mc.changes[i].Add {
			// insert but do not allow non-redirect entries to overwrite a redirect entry,
			// nor allow non-deny entries to overwrite deny entries.
			// Collect the incremental changes to the overall state in 'mc.adds' and 'mc.deletes'.
			policyMapState.denyPreferredInsertWithChanges(mc.changes[i].Key, mc.changes[i].Value, adds, deletes, identities)
		} else {
			// Delete the contribution of this cs to the key and collect incremental changes
			for cs := range mc.changes[i].Value.owners { // get the sole selector
				policyMapState.deleteKeyWithChanges(mc.changes[i].Key, cs, adds, deletes)
			}
		}
	}
	mc.changes = nil
	mc.mutex.Unlock()
	return adds, deletes
}
