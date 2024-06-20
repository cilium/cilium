// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"net"
	"slices"
	"strconv"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

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

// MapState is a map interface for policy maps
type MapState interface {
	Get(Key) (MapStateEntry, bool)
	Insert(Key, MapStateEntry)
	Delete(Key)
	// ForEach allows iteration over the MapStateEntries. It returns true iff
	// the iteration was not stopped early by the callback.
	ForEach(func(Key, MapStateEntry) (cont bool)) (complete bool)
	// ForEachAllow behaves like ForEach, but only iterates MapStateEntries which are not denies.
	ForEachAllow(func(Key, MapStateEntry) (cont bool)) (complete bool)
	// ForEachDeny behaves like ForEach, but only iterates MapStateEntries which are denies.
	ForEachDeny(func(Key, MapStateEntry) (cont bool)) (complete bool)
	GetIdentities(*logrus.Logger) ([]int64, []int64)
	GetDenyIdentities(*logrus.Logger) ([]int64, []int64)
	RevertChanges(ChangeState)
	AddVisibilityKeys(PolicyOwner, uint16, *VisibilityMetadata, ChangeState)
	Len() int

	allowAllIdentities(ingress, egress bool)
	determineAllowLocalhostIngress()
	deniesL4(policyOwner PolicyOwner, l4 *L4Filter) bool
	denyPreferredInsertWithChanges(newKey Key, newEntry MapStateEntry, identities Identities, features policyFeatures, changes ChangeState)
	deleteKeyWithChanges(key Key, owner MapStateOwner, changes ChangeState)

	// For testing from other packages only
	Equals(MapState) bool
	Diff(expected MapState) string
}

// mapState is a state of a policy map.
type mapState struct {
	allows mapStateMap
	denies mapStateMap
}

// mapStateMap is a convience type representing the actual structure mapping
// policymap keys to policymap entries.
type mapStateMap map[Key]MapStateEntry

func (m mapStateMap) insert(k Key, e MapStateEntry) {
	if m == nil {
		n := make(mapStateMap)
		m = n
	}
	m[k] = e
}

type Identities interface {
	GetNetsLocked(identity.NumericIdentity) []*net.IPNet
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
	return "Identity=" + strconv.FormatUint(uint64(k.Identity), 10) +
		",DestPort=" + strconv.FormatUint(uint64(k.DestPort), 10) +
		",Nexthdr=" + strconv.FormatUint(uint64(k.Nexthdr), 10) +
		",TrafficDirection=" + strconv.FormatUint(uint64(k.TrafficDirection), 10)
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

	// hasAuthType is 'DefaultAuthType' when policy has no explicit AuthType set. In this case the
	// value of AuthType is derived from more generic entries covering this entry.
	hasAuthType HasAuthType

	// AuthType is non-zero when authentication is required for the traffic to be allowed.
	AuthType AuthType

	// DerivedFromRules tracks the policy rules this entry derives from
	// In sorted order.
	DerivedFromRules labels.LabelArrayList

	// Owners collects the keys in the map and selectors in the policy that require this key to be present.
	// TODO: keep track which selector needed the entry to be deny, redirect, or just allow.
	owners map[MapStateOwner]struct{}

	// dependents contains the keys for entries create based on this entry. These entries
	// will be deleted once all of the owners are deleted.
	dependents Keys
}

// NewMapStateEntry creates a map state entry. If redirect is true, the
// caller is expected to replace the ProxyPort field before it is added to
// the actual BPF map.
// 'cs' is used to keep track of which policy selectors need this entry. If it is 'nil' this entry
// will become sticky and cannot be completely removed via incremental updates. Even in this case
// the entry may be overridden or removed by a deny entry.
func NewMapStateEntry(cs MapStateOwner, derivedFrom labels.LabelArrayList, redirect, deny bool, hasAuth HasAuthType, authType AuthType) MapStateEntry {
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
		hasAuthType:      hasAuth,
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

var worldNets = map[identity.NumericIdentity][]*net.IPNet{
	identity.ReservedIdentityWorld: {
		{IP: net.IPv4zero, Mask: net.CIDRMask(0, net.IPv4len*8)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, net.IPv6len*8)},
	},
	identity.ReservedIdentityWorldIPv4: {
		{IP: net.IPv4zero, Mask: net.CIDRMask(0, net.IPv4len*8)},
	},
	identity.ReservedIdentityWorldIPv6: {
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, net.IPv6len*8)},
	},
}

// getNets returns the most specific CIDR for an identity. For the "World" identity
// it returns both IPv4 and IPv6.
func getNets(identities Identities, ident uint32) []*net.IPNet {
	// World identities are handled explicitly for two reasons:
	// 1. 'identities' may be nil, but world identities are still expected to be considered
	// 2. SelectorCache is not be informed of reserved/world identities in all test cases
	id := identity.NumericIdentity(ident)
	if id <= identity.ReservedIdentityWorldIPv6 {
		return worldNets[id]
	}
	// CIDR identities have a local scope, so we can skip the rest if id is not of local scope.
	if !id.HasLocalScope() || identities == nil {
		return nil
	}
	return identities.GetNetsLocked(id)
}

// NewMapState creates a new MapState interface
func NewMapState(initMap map[Key]MapStateEntry) MapState {
	return newMapState(initMap)
}

func newMapState(initMap map[Key]MapStateEntry) *mapState {
	m := &mapState{
		allows: make(map[Key]MapStateEntry),
		denies: make(map[Key]MapStateEntry),
	}
	for k, v := range initMap {
		m.Insert(k, v)
	}
	return m
}

// Get the MapStateEntry that matches the Key.
func (ms *mapState) Get(k Key) (MapStateEntry, bool) {
	v, ok := ms.denies[k]
	if ok {
		return v, ok
	}
	v, ok = ms.allows[k]
	return v, ok
}

// Insert the Key and matcthing MapStateEntry into the
// MapState
func (ms *mapState) Insert(k Key, v MapStateEntry) {
	if v.IsDeny {
		delete(ms.allows, k)
		ms.denies.insert(k, v)
	} else {
		delete(ms.denies, k)
		ms.allows.insert(k, v)
	}
}

// Delete removes the Key an related MapStateEntry.
func (ms *mapState) Delete(k Key) {
	delete(ms.allows, k)
	delete(ms.denies, k)
}

// ForEach iterates over every Key MapStateEntry and stops when the function
// argument returns false. It returns false iff the iteration was cut short.
func (ms *mapState) ForEach(f func(Key, MapStateEntry) (cont bool)) (complete bool) {
	if complete := ms.ForEachAllow(f); !complete {
		return complete
	}

	return ms.ForEachDeny(f)
}

// ForEachAllow iterates over every Key MapStateEntry that isn't a deny and
// stops when the function argument returns false
func (ms *mapState) ForEachAllow(f func(Key, MapStateEntry) (cont bool)) (complete bool) {
	for k, v := range ms.allows {
		if !f(k, v) {
			return false
		}
	}
	return true
}

// ForEachDeny iterates over every Key MapStateEntry that is a deny and
// stops when the function argument returns false
func (ms *mapState) ForEachDeny(f func(Key, MapStateEntry) (cont bool)) (complete bool) {
	for k, v := range ms.denies {
		if !f(k, v) {
			return false
		}
	}
	return true
}

// Len returns the length of the map
func (ms *mapState) Len() int {
	return len(ms.allows) + len(ms.denies)
}

// Equals determines if this MapState is equal to the
// argument MapState
func (msA *mapState) Equals(msB MapState) bool {
	if msA.Len() != msB.Len() {
		return false
	}

	return msA.ForEach(func(kA Key, vA MapStateEntry) bool {
		if vB, ok := msB.Get(kA); ok {
			return (&vB).DatapathEqual(&vA)
		}
		return false
	})
}

// Diff returns the string of differences between 'obtained' and 'expected' prefixed with
// '+ ' or '- ' for obtaining something unexpected, or not obtaining the expected, respectively.
// For use in debugging.
func (obtained *mapState) Diff(expected MapState) (res string) {
	expected.ForEach(func(kE Key, vE MapStateEntry) bool {
		if vO, ok := obtained.Get(kE); ok {
			if !(&vO).DatapathEqual(&vE) {
				res += "- " + kE.String() + ": " + vE.String() + "\n"
				res += "+ " + kE.String() + ": " + vO.String() + "\n"
			}
		} else {
			res += "- " + kE.String() + ": " + vE.String() + "\n"
		}
		return true
	})
	obtained.ForEach(func(kE Key, vE MapStateEntry) bool {
		if _, ok := expected.Get(kE); !ok {
			res += "+ " + kE.String() + ": " + vE.String() + "\n"
		}
		return true
	})
	return res
}

// AddDependent adds 'key' to the set of dependent keys.
func (ms *mapState) AddDependent(owner Key, dependent Key, changes ChangeState) {
	if e, exists := ms.allows[owner]; exists {
		ms.addDependentOnEntry(owner, e, dependent, changes)
	} else if e, exists := ms.denies[owner]; exists {
		ms.addDependentOnEntry(owner, e, dependent, changes)
	}
}

// addDependentOnEntry adds 'dependent' to the set of dependent keys of 'e'.
func (ms *mapState) addDependentOnEntry(owner Key, e MapStateEntry, dependent Key, changes ChangeState) {
	if _, exists := e.dependents[dependent]; !exists {
		if changes.Old != nil {
			changes.Old[owner] = e
		}
		e.AddDependent(dependent)
		ms.Insert(owner, e)
	}
}

// RemoveDependent removes 'key' from the list of dependent keys.
// This is called when a dependent entry is being deleted.
// If 'old' is not nil, then old value is added there before any modifications.
func (ms *mapState) RemoveDependent(owner Key, dependent Key, changes ChangeState) {
	if e, exists := ms.allows[owner]; exists {
		changes.insertOldIfNotExists(owner, e)
		e.RemoveDependent(dependent)
		delete(ms.denies, owner)
		ms.allows.insert(owner, e)
		return
	}

	if e, exists := ms.denies[owner]; exists {
		changes.insertOldIfNotExists(owner, e)
		e.RemoveDependent(dependent)
		delete(ms.allows, owner)
		ms.denies.insert(owner, e)
	}
}

// Merge adds owners, dependents, and DerivedFromRules from a new 'entry' to an existing
// entry 'e'. 'entry' is not modified.
// IsDeny, ProxyPort, and AuthType are merged by giving precedence to deny over non-deny, proxy
// redirection over no proxy redirection, and explicit auth type over default auth type.
func (e *MapStateEntry) Merge(entry *MapStateEntry) {
	// Deny is sticky
	if !e.IsDeny {
		e.IsDeny = entry.IsDeny
	}

	// Deny entries have no proxy redirection nor auth requirement
	if e.IsDeny {
		e.ProxyPort = 0
		e.hasAuthType = DefaultAuthType
		e.AuthType = AuthTypeDisabled
	} else {
		// Proxy port takes precedence, but may be updated
		if entry.ProxyPort != 0 {
			e.ProxyPort = entry.ProxyPort
		}

		// Explicit auth takes precedence over defaulted one.
		if entry.hasAuthType == ExplicitAuthType {
			if e.hasAuthType == ExplicitAuthType {
				// Numerically higher AuthType takes precedence when both are explicitly defined
				if entry.AuthType > e.AuthType {
					e.AuthType = entry.AuthType
				}
			} else {
				e.hasAuthType = ExplicitAuthType
				e.AuthType = entry.AuthType
			}
		} else if e.hasAuthType == DefaultAuthType {
			e.AuthType = entry.AuthType // new default takes precedence
		}
	}

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

	// merge DerivedFromRules
	if len(entry.DerivedFromRules) > 0 {
		e.DerivedFromRules.MergeSorted(entry.DerivedFromRules)
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

// DeepEqual is a manually generated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
// Defined manually due to deepequal-gen not supporting interface types.
// 'cachedNets' member is ignored in comparison, as it is a cached value and
// makes no functional difference.
func (e *MapStateEntry) DeepEqual(o *MapStateEntry) bool {
	if !e.DatapathEqual(o) {
		return false
	}

	if !e.DerivedFromRules.DeepEqual(&o.DerivedFromRules) {
		return false
	}

	if len(e.owners) != len(o.owners) {
		return false
	}
	for k := range o.owners {
		if _, exists := e.owners[k]; !exists {
			return false
		}
	}

	if len(e.dependents) != len(o.dependents) {
		return false
	}
	for k := range o.dependents {
		if _, exists := e.dependents[k]; !exists {
			return false
		}
	}

	// ignoring cachedNets

	return true
}

// String returns a string representation of the MapStateEntry
func (e MapStateEntry) String() string {
	return "ProxyPort=" + strconv.FormatUint(uint64(e.ProxyPort), 10) +
		",IsDeny=" + strconv.FormatBool(e.IsDeny) +
		",AuthType=" + e.AuthType.String() +
		",DerivedFromRules=" + fmt.Sprintf("%v", e.DerivedFromRules)
}

// denyPreferredInsert inserts a key and entry into the map by given preference
// to deny entries, and L3-only deny entries over L3-L4 allows.
// This form may be used when a full policy is computed and we are not yet interested
// in accumulating incremental changes.
// Caller may insert the same MapStateEntry multiple times for different Keys, but all from the same
// owner.
func (ms *mapState) denyPreferredInsert(newKey Key, newEntry MapStateEntry, identities Identities, features policyFeatures) {
	// Enforce nil values from NewMapStateEntry
	newEntry.dependents = nil

	ms.denyPreferredInsertWithChanges(newKey, newEntry, identities, features, ChangeState{})
}

// addKeyWithChanges adds a 'key' with value 'entry' to 'keys' keeping track of incremental changes in 'adds' and 'deletes', and any changed or removed old values in 'old', if not nil.
func (ms *mapState) addKeyWithChanges(key Key, entry MapStateEntry, changes ChangeState) {
	// Keep all owners that need this entry so that it is deleted only if all the owners delete their contribution
	var datapathEqual bool
	oldEntry, exists := ms.Get(key)
	if exists {
		// Deny entry can only be overridden by another deny entry
		if oldEntry.IsDeny && !entry.IsDeny {
			return
		}

		if entry.DeepEqual(&oldEntry) {
			return // nothing to do
		}

		// Save old value before any changes, if desired
		if changes.Old != nil {
			changes.insertOldIfNotExists(key, oldEntry)
		}

		// Compare for datapath equalness before merging, as the old entry is updated in
		// place!
		datapathEqual = oldEntry.DatapathEqual(&entry)
		oldEntry.Merge(&entry)
		ms.Insert(key, oldEntry)
	} else {
		// Newly inserted entries must have their own containers, so that they
		// remain separate when new owners/dependents are added to existing entries
		entry.DerivedFromRules = slices.Clone(entry.DerivedFromRules)
		entry.owners = maps.Clone(entry.owners)
		entry.dependents = maps.Clone(entry.dependents)
		ms.Insert(key, entry)
	}

	// Record an incremental Add if desired and entry is new or changed
	if changes.Adds != nil && (!exists || !datapathEqual) {
		changes.Adds[key] = struct{}{}
		// Key add overrides any previous delete of the same key
		if changes.Deletes != nil {
			delete(changes.Deletes, key)
		}
	}
}

// deleteKeyWithChanges deletes a 'key' from 'keys' keeping track of incremental changes in 'adds' and 'deletes'.
// The key is unconditionally deleted if 'cs' is nil, otherwise only the contribution of this 'cs' is removed.
func (ms *mapState) deleteKeyWithChanges(key Key, owner MapStateOwner, changes ChangeState) {
	if entry, exists := ms.Get(key); exists {
		// Save old value before any changes, if desired
		oldAdded := changes.insertOldIfNotExists(key, entry)
		if owner != nil {
			// remove the contribution of the given selector only
			if _, exists = entry.owners[owner]; exists {
				// Remove the contribution of this selector from the entry
				delete(entry.owners, owner)
				if ownerKey, ok := owner.(Key); ok {
					ms.RemoveDependent(ownerKey, key, changes)
				}
				// key is not deleted if other owners still need it
				if len(entry.owners) > 0 {
					return
				}
			} else {
				// 'owner' was not found, do not change anything
				if oldAdded {
					delete(changes.Old, key)
				}
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
						ms.RemoveDependent(ownerKey, key, changes)
					}
				}
			}
		}

		// Check if dependent entries need to be deleted as well
		for k := range entry.dependents {
			ms.deleteKeyWithChanges(k, key, changes)
		}
		if changes.Deletes != nil {
			changes.Deletes[key] = struct{}{}
			// Remove a potential previously added key
			if changes.Adds != nil {
				delete(changes.Adds, key)
			}
		}

		delete(ms.allows, key)
		delete(ms.denies, key)
	}
}

// identityIsSupersetOf compares two entries and keys to see if the primary identity contains
// the compared identity. This means that either that primary identity is 0 (i.e. it is a superset
// of every other identity), or one of the subnets of the primary identity fully contains or is
// equal to one of the subnets in the compared identity (note:this covers cases like "reserved:world").
func identityIsSupersetOf(primaryIdentity, compareIdentity uint32, identities Identities) bool {
	// If the identities are equal then neither is a superset (for the purposes of our business logic).
	if primaryIdentity == compareIdentity {
		return false
	}

	// Consider an identity that selects a broader CIDR as a superset of
	// an identity that selects a narrower CIDR. For instance, an identity
	// corresponding to 192.0.0.0/16 is a superset of the identity that
	// corresponds to 192.0.2.3/32.
	//
	// The reasons we need to do this are surprisingly complex, taking into
	// consideration design decisions around the handling of ToFQDNs policy
	// and how L4PolicyMap/L4Filter structures cache the policies with
	// respect to specific CIDRs. More specifically:
	// - At the time of initial L4Filter creation, it is not known which
	//   specific CIDRs (or corresponding identities) are selected by a
	//   toFQDNs rule in the policy engine.
	// - It is possible to have a CIDR deny rule that should deny peers
	//   that are allowed by a ToFQDNs statement. The precedence rules in
	//   the API for such policy conflicts define that the deny should take
	//   precedence.
	// - Consider a case where there is a deny rule for 192.0.0.0/16 with
	//   an allow rule for cilium.io, and one of the IP addresses for
	//   cilium.io is 192.0.2.3.
	// - If the IP for cilium.io was known at initial policy computation
	//   time, then we would calculate the MapState from the L4Filters and
	//   immediately determine that there is a conflict between the
	//   L4Filter that denies 192.0.0.0/16 vs. the allow for 192.0.2.3.
	//   From this we could immediately discard the "allow to 192.0.2.3"
	//   policymap entry during policy calculation. This would satisfy the
	//   API constraint that deny rules take precedence over allow rules.
	//   However, this is not the case for ToFQDNs -- the IPs are not known
	//   until DNS resolution time by the selected application / endpoint.
	// - In order to make ToFQDNs policy implementation efficient, it uses
	//   a shorter incremental policy computation path that attempts to
	//   directly implement the ToFQDNs allow into a MapState entry without
	//   reaching back up to the L4Filter layer to iterate all selectors
	//   to determine traffic reachability for this newly learned IP.
	// - As such, when the new ToFQDNs allow for the 192.0.2.3 IP address
	//   is implemented, we must iterate back through all existing MapState
	//   entries to determine whether any of the other map entries already
	//   denies this traffic by virtue of the IP prefix being a superset of
	//   this new allow. This allows us to ensure that the broader CIDR
	//   deny semantics are correctly applied when there is a combination
	//   of CIDR deny rules and ToFQDNs allow rules.
	//
	// An alternative to this approach might be to change the ToFQDNs
	// policy calculation layer to reference back to the L4Filter layer,
	// and perhaps introduce additional CIDR caching somewhere there so
	// that this policy computation can be efficient while handling DNS
	// responses. As of the writing of this message, such there is no
	// active proposal to implement this proposal. As a result, any time
	// there is an incremental policy update for a new map entry, we must
	// iterate through all entries in the map and re-evaluate superset
	// relationships for deny entries to ensure that policy precedence is
	// correctly implemented between the new and old entries, taking into
	// account whether the identities may represent CIDRs that have a
	// superset relationship.
	return primaryIdentity == 0 && compareIdentity != 0 ||
		ip.NetsContainsAny(getNets(identities, primaryIdentity),
			getNets(identities, compareIdentity))
}

// protocolsMatch checks to see if two given keys match on protocol.
// This means that either one of them covers all protocols or they
// are equal.
func protocolsMatch(a, b Key) bool {
	return a.Nexthdr == 0 || b.Nexthdr == 0 || a.Nexthdr == b.Nexthdr
}

// RevertChanges undoes changes to 'keys' as indicated by 'changes.adds' and 'changes.old' collected via
// denyPreferredInsertWithChanges().
func (ms *mapState) RevertChanges(changes ChangeState) {
	for k := range changes.Adds {
		delete(ms.allows, k)
		delete(ms.denies, k)
	}
	// 'old' contains all the original values of both modified and deleted entries
	for k, v := range changes.Old {
		ms.Insert(k, v)
	}
}

// denyPreferredInsertWithChanges contains the most important business logic for policy insertions. It inserts
// a key and entry into the map by giving preference to deny entries, and L3-only deny entries over L3-L4 allows.
// Incremental changes performed are recorded in 'adds' and 'deletes', if not nil.
// See https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw#gid=2109052536 for details
func (ms *mapState) denyPreferredInsertWithChanges(newKey Key, newEntry MapStateEntry, identities Identities, features policyFeatures, changes ChangeState) {
	// Skip deny rules processing if the policy in this direction has no deny rules
	if !features.contains(denyRules) {
		ms.authPreferredInsert(newKey, newEntry, features, changes)
		return
	}

	allCpy := allKey
	allCpy.TrafficDirection = newKey.TrafficDirection
	// If we have a deny "all" we don't accept any kind of map entry.
	if _, ok := ms.denies[allCpy]; ok {
		return
	}
	if newEntry.IsDeny {
		ms.ForEachAllow(func(k Key, v MapStateEntry) bool {
			// Protocols and traffic directions that don't match ensure that the policies
			// do not interact in anyway.
			if newKey.TrafficDirection != k.TrafficDirection || !protocolsMatch(newKey, k) {
				return true
			}

			if identityIsSupersetOf(k.Identity, newKey.Identity, identities) {
				if newKey.PortProtoIsBroader(k) {
					// If this iterated-allow-entry is a superset of the new-entry
					// and it has a more specific port-protocol than the new-entry
					// then an additional copy of the new-entry with the more
					// specific port-protocol of the iterated-allow-entry must be inserted.
					newKeyCpy := newKey
					newKeyCpy.DestPort = k.DestPort
					newKeyCpy.Nexthdr = k.Nexthdr
					l3l4DenyEntry := NewMapStateEntry(newKey, newEntry.DerivedFromRules, false, true, DefaultAuthType, AuthTypeDisabled)
					ms.addKeyWithChanges(newKeyCpy, l3l4DenyEntry, changes)
					// L3-only entries can be deleted incrementally so we need to track their
					// effects on other entries so that those effects can be reverted when the
					// identity is removed.
					newEntry.AddDependent(newKeyCpy)
				}
			} else if (newKey.Identity == k.Identity ||
				identityIsSupersetOf(newKey.Identity, k.Identity, identities)) &&
				(newKey.PortProtoIsBroader(k) || newKey.PortProtoIsEqual(k)) {
				// If the new-entry is a superset (or equal) of the iterated-allow-entry and
				// the new-entry has a broader (or equal) port-protocol then we
				// should delete the iterated-allow-entry
				ms.deleteKeyWithChanges(k, nil, changes)
			}
			return true
		})

		bailed := false
		ms.ForEachDeny(func(k Key, v MapStateEntry) bool {
			// Protocols and traffic directions that don't match ensure that the policies
			// do not interact in anyway.
			if newKey.TrafficDirection != k.TrafficDirection || !protocolsMatch(newKey, k) {
				return true
			}

			if (newKey.Identity == k.Identity ||
				identityIsSupersetOf(k.Identity, newKey.Identity, identities)) &&
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
				bailed = true
				return false
			} else if (newKey.Identity == k.Identity ||
				identityIsSupersetOf(newKey.Identity, k.Identity, identities)) &&
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
				ms.deleteKeyWithChanges(k, nil, changes)
			}
			return true
		})

		if !bailed {
			ms.addKeyWithChanges(newKey, newEntry, changes)
		}
	} else {
		// NOTE: We do not delete redundant allow entries.
		bailed := false
		ms.ForEachDeny(func(k Key, v MapStateEntry) bool {
			// Protocols and traffic directions that don't match ensure that the policies
			// do not interact in anyway.
			if newKey.TrafficDirection != k.TrafficDirection || !protocolsMatch(newKey, k) {
				return true
			}
			if identityIsSupersetOf(newKey.Identity, k.Identity, identities) {
				if k.PortProtoIsBroader(newKey) {
					// If the new-entry is *only* superset of the iterated-deny-entry
					// and the new-entry has a more specific port-protocol than the
					// iterated-deny-entry then an additional copy of the iterated-deny-entry
					// with the more specific port-porotocol of the new-entry must
					// be added.
					denyKeyCpy := k
					denyKeyCpy.DestPort = newKey.DestPort
					denyKeyCpy.Nexthdr = newKey.Nexthdr
					l3l4DenyEntry := NewMapStateEntry(k, v.DerivedFromRules, false, true, DefaultAuthType, AuthTypeDisabled)
					ms.addKeyWithChanges(denyKeyCpy, l3l4DenyEntry, changes)
					// L3-only entries can be deleted incrementally so we need to track their
					// effects on other entries so that those effects can be reverted when the
					// identity is removed.
					ms.addDependentOnEntry(k, v, denyKeyCpy, changes)
				}
			} else if (k.Identity == newKey.Identity ||
				identityIsSupersetOf(k.Identity, newKey.Identity, identities)) &&
				(k.PortProtoIsBroader(newKey) || k.PortProtoIsEqual(newKey)) &&
				!v.HasDependent(newKey) {
				// If the iterated-deny-entry is a superset (or equal) of the new-entry and has a
				// broader (or equal) port-protocol than the new-entry then the new
				// entry should not be inserted.
				bailed = true
				return false
			}

			return true
		})

		if !bailed {
			ms.authPreferredInsert(newKey, newEntry, features, changes)
		}
	}
}

// IsSuperSetOf checks if the receiver Key is a superset of the argument Key, and returns a
// specificity score of the receiver key (higher score is more specific), if so. Being a superset
// means that the receiver key would match all the traffic of the argument key without being the
// same key. Hence, a L3-only key is not a superset of a L4-only key, as the L3-only key would match
// the traffic for the given L3 only, while the L4-only key matches traffic on the given port for
// all the L3's.
// Returns 0 if the receiver key is not a superset of the argument key.
//
// Specificity score for all possible superset wildcard patterns. Datapath requires proto to be specified if port is specified.
// x. L3/proto/port
//  1. */*/*
//  2. */proto/*
//  3. */proto/port
//  4. ID/*/*
//  5. ID/proto/*
//     ( ID/proto/port can not be superset of anything )
func (k Key) IsSuperSetOf(other Key) int {
	if k.TrafficDirection != other.TrafficDirection {
		return 0 // TrafficDirection must match for 'k' to be a superset of 'other'
	}
	if k.Identity == 0 {
		if other.Identity == 0 {
			if k.Nexthdr == 0 { // k.DestPort == 0 is implied
				if other.Nexthdr != 0 {
					return 1 // */*/* is a superset of */proto/x
				} // else both are */*/*
			} else if k.Nexthdr == other.Nexthdr {
				if k.DestPort == 0 && other.DestPort != 0 {
					return 2 // */proto/* is a superset of */proto/port
				} // else more specific or different ports
			} // else more specific or different protocol
		} else {
			// Wildcard L3 is a superset of a specific L3 only if wildcard L3 is also wildcard L4, or the L4's match between the keys
			if k.Nexthdr == 0 { // k.DestPort == 0 is implied
				return 1 // */*/* is a superset of ID/x/x
			} else if k.Nexthdr == other.Nexthdr {
				if k.DestPort == 0 {
					return 2 // */proto/* is a superset of ID/proto/x
				} else if k.DestPort == other.DestPort {
					return 3 // */proto/port is a superset of ID/proto/port
				} // else more specific or different ports
			} // else more specific or different protocol
		}
	} else if k.Identity == other.Identity {
		if k.Nexthdr == 0 {
			if other.Nexthdr != 0 {
				return 4 // ID/*/* is a superset of ID/proto/x
			} // else both are ID/*/*
		} else if k.Nexthdr == other.Nexthdr {
			if k.DestPort == 0 && other.DestPort != 0 {
				return 5 // ID/proto/* is a superset of ID/proto/port
			} // else more specific or different ports
		} // else more specific or different protocol
	} // else more specific or different identity
	return 0
}

// authPreferredInsert applies AuthType of a more generic entry to more specific entries, if not
// explicitly specified.
//
// This function is expected to be called for a map insertion after deny
// entry evaluation. If there is a map entry that is a superset of 'newKey'
// which denies traffic matching 'newKey', then this function should not be called.
func (ms *mapState) authPreferredInsert(newKey Key, newEntry MapStateEntry, features policyFeatures, changes ChangeState) {
	if features.contains(authRules) {
		if newEntry.hasAuthType == DefaultAuthType {
			// New entry has a default auth type.
			// Fill in the AuthType from more generic entries with an explicit auth type
			maxSpecificity := 0
			l3l4State := newMapState(nil)

			ms.ForEachAllow(func(k Key, v MapStateEntry) bool {
				// Only consider the same Traffic direction
				if newKey.TrafficDirection != k.TrafficDirection {
					return true
				}

				// Nothing to be done if entry has default AuthType
				if v.hasAuthType == DefaultAuthType {
					return true
				}

				// Find out if 'k' is an identity-port-proto superset of 'newKey'
				if specificity := k.IsSuperSetOf(newKey); specificity > 0 {
					if specificity > maxSpecificity {
						// AuthType from the most specific superset is
						// applied to 'newEntry'
						newEntry.AuthType = v.AuthType
						maxSpecificity = specificity
					}
				} else {
					// Check if a new L3L4 entry must be created due to L3-only
					// 'k' specifying an explicit AuthType and an L4-only 'newKey' not
					// having an explicit AuthType. In this case AuthType should
					// only override the AuthType for the L3 & L4 combination,
					// not L4 in general.
					//
					// These need to be collected and only added if there is a
					// superset key of newKey with an explicit auth type. In
					// this case AuthType of the new L4-only entry was
					// overridden by a more generic entry and 'max_specificity >
					// 0' after the loop.
					if k.Identity != 0 && k.Nexthdr == 0 && newKey.Identity == 0 && newKey.Nexthdr != 0 {
						newKeyCpy := k
						newKeyCpy.DestPort = newKey.DestPort
						newKeyCpy.Nexthdr = newKey.Nexthdr
						l3l4AuthEntry := NewMapStateEntry(k, v.DerivedFromRules, false, false, DefaultAuthType, v.AuthType)
						l3l4AuthEntry.DerivedFromRules.MergeSorted(newEntry.DerivedFromRules)
						l3l4State.allows[newKeyCpy] = l3l4AuthEntry
					}
				}
				return true
			})
			// Add collected L3/L4 entries if the auth type of the new entry was not
			// overridden by a more generic entry. If it was overridden, the new L3L4
			// entries are not needed as the L4-only entry with an overridden AuthType
			// will be matched before the L3-only entries in the datapath.
			if maxSpecificity == 0 {
				l3l4State.ForEach(func(k Key, v MapStateEntry) bool {
					ms.addKeyWithChanges(k, v, changes)
					// L3-only entries can be deleted incrementally so we need to track their
					// effects on other entries so that those effects can be reverted when the
					// identity is removed.
					newEntry.AddDependent(k)
					return true
				})
			}
		} else {
			// New entry has an explicit auth type.
			// Check if the new entry is the most specific superset of any other entry
			// with the default auth type, and propagate the auth type from the new
			// entry to such entries.
			explicitSubsetKeys := make(Keys)
			defaultSubsetKeys := make(map[Key]int)

			ms.ForEachAllow(func(k Key, v MapStateEntry) bool {
				// Only consider the same Traffic direction
				if newKey.TrafficDirection != k.TrafficDirection {
					return true
				}

				// Find out if 'newKey' is a superset of 'k'
				if specificity := newKey.IsSuperSetOf(k); specificity > 0 {
					if v.hasAuthType == ExplicitAuthType {
						// store for later comparison
						explicitSubsetKeys[k] = struct{}{}
					} else {
						defaultSubsetKeys[k] = specificity
					}
				} else if v.hasAuthType == DefaultAuthType {
					// Check if a new L3L4 entry must be created due to L3-only
					// 'newKey' with an explicit AuthType and an L4-only 'k' not
					// having an explicit AuthType. In this case AuthType should
					// only override the AuthType for the L3 & L4 combination,
					// not L4 in general.
					if newKey.Identity != 0 && newKey.Nexthdr == 0 && k.Identity == 0 && k.Nexthdr != 0 {
						newKeyCpy := newKey
						newKeyCpy.DestPort = k.DestPort
						newKeyCpy.Nexthdr = k.Nexthdr
						l3l4AuthEntry := NewMapStateEntry(newKey, newEntry.DerivedFromRules, false, false, DefaultAuthType, newEntry.AuthType)
						l3l4AuthEntry.DerivedFromRules.MergeSorted(v.DerivedFromRules)
						ms.addKeyWithChanges(newKeyCpy, l3l4AuthEntry, changes)
						// L3-only entries can be deleted incrementally so we need to track their
						// effects on other entries so that those effects can be reverted when the
						// identity is removed.
						newEntry.AddDependent(newKeyCpy)
					}
				}

				return true
			})
			// Find out if this newKey is the most specific superset for all the subset keys with default auth type
		Next:
			for k, specificity := range defaultSubsetKeys {
				for l := range explicitSubsetKeys {
					if s := l.IsSuperSetOf(k); s > specificity {
						// k has a more specific superset key than the newKey, skip
						continue Next
					}
				}
				// newKey is the most specific superset with an explicit auth type,
				// propagate auth type from newEntry to the entry of k
				v, _ := ms.Get(k)
				v.AuthType = newEntry.AuthType
				ms.addKeyWithChanges(k, v, changes) // Update the map value
			}
		}
	}
	ms.addKeyWithChanges(newKey, newEntry, changes)
}

var visibilityDerivedFromLabels = labels.LabelArray{
	labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelVisibilityAnnotation, labels.LabelSourceReserved),
}

var visibilityDerivedFrom = labels.LabelArrayList{visibilityDerivedFromLabels}

// insertIfNotExists only inserts `key=value` if `key` does not exist in keys already
// returns 'true' if 'key=entry' was added to 'keys'
func (changes *ChangeState) insertOldIfNotExists(key Key, entry MapStateEntry) bool {
	if changes == nil || changes.Old == nil {
		return false
	}
	if _, exists := changes.Old[key]; !exists {
		// Only insert the old entry if the entry was not first added on this round of
		// changes.
		if _, added := changes.Adds[key]; !added {
			// new containers to keep this entry separate from the one that may remain in 'keys'
			entry.DerivedFromRules = slices.Clone(entry.DerivedFromRules)
			entry.owners = maps.Clone(entry.owners)
			entry.dependents = maps.Clone(entry.dependents)

			changes.Old[key] = entry
			return true
		}
	}
	return false
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
func (ms *mapState) AddVisibilityKeys(e PolicyOwner, redirectPort uint16, visMeta *VisibilityMetadata, changes ChangeState) {
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

	entry := NewMapStateEntry(nil, visibilityDerivedFrom, true, false, DefaultAuthType, AuthTypeDisabled)
	entry.ProxyPort = redirectPort

	_, haveAllowAllKey := ms.Get(allowAllKey)
	l4Only, haveL4OnlyKey := ms.Get(key)
	addL4OnlyKey := false
	if haveL4OnlyKey && !l4Only.IsDeny && l4Only.ProxyPort == 0 {
		// 1. Change existing L4-only ALLOW key on matching port that does not already
		//    redirect to redirect.
		e.PolicyDebug(logrus.Fields{
			logfields.BPFMapKey:   key,
			logfields.BPFMapValue: entry,
		}, "AddVisibilityKeys: Changing L4-only ALLOW key for visibility redirect")
		ms.addKeyWithChanges(key, entry, changes)
	}
	if haveAllowAllKey && !haveL4OnlyKey {
		// 2. If allow-all policy exists, add L4-only visibility redirect key if the L4-only
		//    key does not already exist.
		e.PolicyDebug(logrus.Fields{
			logfields.BPFMapKey:   key,
			logfields.BPFMapValue: entry,
		}, "AddVisibilityKeys: Adding L4-only ALLOW key for visibility redirect")
		addL4OnlyKey = true
		ms.addKeyWithChanges(key, entry, changes)
	}
	//
	// Loop through all L3 keys in the traffic direction of the new key
	//
	ms.ForEach(func(k Key, v MapStateEntry) bool {
		if k.TrafficDirection != key.TrafficDirection || k.Identity == 0 {
			return true
		}
		if k.DestPort == key.DestPort && k.Nexthdr == key.Nexthdr {
			//
			// Same L4
			//
			if !v.IsDeny && v.ProxyPort == 0 {
				// 3. Change all L3/L4 ALLOW keys on matching port that do not
				//    already redirect to redirect.
				v.ProxyPort = redirectPort
				v.DerivedFromRules = visibilityDerivedFrom
				e.PolicyDebug(logrus.Fields{
					logfields.BPFMapKey:   k,
					logfields.BPFMapValue: v,
				}, "AddVisibilityKeys: Changing L3/L4 ALLOW key for visibility redirect")
				ms.addKeyWithChanges(k, v, changes)
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
				if _, ok := ms.Get(k2); !ok {
					d2 := labels.LabelArrayList{visibilityDerivedFromLabels}
					d2.MergeSorted(v.DerivedFromRules)
					v2 := NewMapStateEntry(k, d2, true, false, v.hasAuthType, v.AuthType)
					v2.ProxyPort = redirectPort
					e.PolicyDebug(logrus.Fields{
						logfields.BPFMapKey:   k2,
						logfields.BPFMapValue: v2,
					}, "AddVisibilityKeys: Extending L3-only ALLOW key to L3/L4 key for visibility redirect")
					ms.addKeyWithChanges(k2, v2, changes)

					// Mark the new entry as a dependent of 'v'
					ms.addDependentOnEntry(k, v, k2, changes)
				}
			} else if addL4OnlyKey && v.IsDeny {
				// 5. If a new L4-only key was added: For each L3-only DENY
				//    key add the corresponding L3/L4 DENY key if no L3/L4
				//    key already exists.
				if _, ok := ms.Get(k2); !ok {
					v2 := NewMapStateEntry(k, v.DerivedFromRules, false, true, DefaultAuthType, AuthTypeDisabled)
					e.PolicyDebug(logrus.Fields{
						logfields.BPFMapKey:   k2,
						logfields.BPFMapValue: v2,
					}, "AddVisibilityKeys: Extending L3-only DENY key to L3/L4 key to deny a port with visibility annotation")
					ms.addKeyWithChanges(k2, v2, changes)

					// Mark the new entry as a dependent of 'v'
					ms.addDependentOnEntry(k, v, k2, changes)
				}
			}
		}

		return true
	})
}

// determineAllowLocalhostIngress determines whether communication should be allowed
// from the localhost. It inserts the Key corresponding to the localhost in
// the desiredPolicyKeys if the localhost is allowed to communicate with the
// endpoint. Authentication for localhost traffic is not required.
func (ms *mapState) determineAllowLocalhostIngress() {
	if option.Config.AlwaysAllowLocalhost() {
		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowLocalHostIngress, labels.LabelSourceReserved),
			},
		}
		es := NewMapStateEntry(nil, derivedFrom, false, false, ExplicitAuthType, AuthTypeDisabled) // Authentication never required for local host ingress
		ms.denyPreferredInsert(localHostKey, es, nil, allFeatures)
		if !option.Config.EnableRemoteNodeIdentity {
			var isHostDenied bool
			v, ok := ms.Get(localHostKey)
			isHostDenied = ok && v.IsDeny
			derivedFrom := labels.LabelArrayList{
				labels.LabelArray{
					labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowRemoteHostIngress, labels.LabelSourceReserved),
				},
			}
			es := NewMapStateEntry(nil, derivedFrom, false, isHostDenied, ExplicitAuthType, AuthTypeDisabled) // Authentication never required for remote node ingress
			ms.denyPreferredInsert(localRemoteNodeKey, es, nil, allFeatures)
		}
	}
}

// allowAllIdentities translates all identities in selectorCache to their
// corresponding Keys in the specified direction (ingress, egress) which allows
// all at L3.
// Note that this is used when policy is not enforced, so authentication is explicitly not required.
func (ms *mapState) allowAllIdentities(ingress, egress bool) {
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
		ms.allows[keyToAdd] = NewMapStateEntry(nil, derivedFrom, false, false, ExplicitAuthType, AuthTypeDisabled)
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
		ms.allows[keyToAdd] = NewMapStateEntry(nil, derivedFrom, false, false, ExplicitAuthType, AuthTypeDisabled)
	}
}

func (ms *mapState) deniesL4(policyOwner PolicyOwner, l4 *L4Filter) bool {
	port := uint16(l4.Port)
	proto := uint8(l4.U8Proto)

	// resolve named port
	if port == 0 && l4.PortName != "" {
		port = policyOwner.GetNamedPort(l4.Ingress, l4.PortName, proto)
		if port == 0 {
			return true
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
	// Are we explicitly denying all traffic?
	v, ok := ms.Get(anyKey)
	if ok && v.IsDeny {
		return true
	}

	// Are we explicitly denying this L4-only traffic?
	anyKey.DestPort = port
	anyKey.Nexthdr = proto
	v, ok = ms.Get(anyKey)
	if ok && v.IsDeny {
		return true
	}

	// The given L4 is not categorically denied.
	// Traffic to/from a specific L3 on any of the selectors can still be denied.
	return false
}

func (ms *mapState) GetIdentities(log *logrus.Logger) (ingIdentities, egIdentities []int64) {
	return ms.getIdentities(log, false)
}

func (ms *mapState) GetDenyIdentities(log *logrus.Logger) (ingIdentities, egIdentities []int64) {
	return ms.getIdentities(log, true)
}

// GetIdentities returns the ingress and egress identities stored in the
// MapState.
func (ms *mapState) getIdentities(log *logrus.Logger, denied bool) (ingIdentities, egIdentities []int64) {
	ms.ForEach(func(policyMapKey Key, policyMapValue MapStateEntry) bool {
		if denied != policyMapValue.IsDeny {
			return true
		}
		if policyMapKey.DestPort != 0 {
			// If the port is non-zero, then the Key no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			return true
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
		return true
	})
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
func (mc *MapChanges) AccumulateMapChanges(cs CachedSelector, adds, deletes []identity.NumericIdentity, key Key, value MapStateEntry) {
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
func (mc *MapChanges) consumeMapChanges(policyMapState MapState, features policyFeatures, identities Identities) (adds, deletes Keys) {
	mc.mutex.Lock()
	changes := ChangeState{
		Adds:    make(Keys, len(mc.changes)),
		Deletes: make(Keys, len(mc.changes)),
	}

	for i := range mc.changes {
		if mc.changes[i].Add {
			// insert but do not allow non-redirect entries to overwrite a redirect entry,
			// nor allow non-deny entries to overwrite deny entries.
			// Collect the incremental changes to the overall state in 'mc.adds' and 'mc.deletes'.
			policyMapState.denyPreferredInsertWithChanges(mc.changes[i].Key, mc.changes[i].Value, identities, features, changes)
		} else {
			// Delete the contribution of this cs to the key and collect incremental changes
			for cs := range mc.changes[i].Value.owners { // get the sole selector
				policyMapState.deleteKeyWithChanges(mc.changes[i].Key, cs, changes)
			}
		}
	}
	mc.changes = nil
	mc.mutex.Unlock()
	return changes.Adds, changes.Deletes
}
