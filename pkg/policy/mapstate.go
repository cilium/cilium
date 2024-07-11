// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/container/bitlpm"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

// Key and Keys are types used both internally and externally.
// The types have been lifted out, but an alias is being used
// so we don't have to change all the code everywhere.
//
// Do not use these types outside of pkg/policy or pkg/endpoint,
// lest ye find yourself with hundreds of unnecessary imports.
type Key = policyTypes.Key
type Keys = policyTypes.Keys

var (
	// localHostKey represents an ingress L3 allow from the local host.
	localHostKey = Key{
		Identity:         identity.ReservedIdentityHost.Uint32(),
		InvertedPortMask: 0xffff, // This is a wildcard
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}
	// allKey represents a key for unknown traffic, i.e., all traffic.
	// We have one for each traffic direction
	allKey = [2]Key{{
		Identity:         identity.IdentityUnknown.Uint32(),
		InvertedPortMask: 0xffff,
		TrafficDirection: 0,
	}, {
		Identity:         identity.IdentityUnknown.Uint32(),
		InvertedPortMask: 0xffff,
		TrafficDirection: 1,
	}}
)

const (
	LabelKeyPolicyDerivedFrom  = "io.cilium.policy.derived-from"
	LabelAllowLocalHostIngress = "allow-localhost-ingress"
	LabelAllowAnyIngress       = "allow-any-ingress"
	LabelAllowAnyEgress        = "allow-any-egress"
	LabelVisibilityAnnotation  = "visibility-annotation"

	// Using largest possible port value since it has the lowest priority
	unrealizedRedirectPort = uint16(65535)
)

// MapState is a map interface for policy maps
type MapState interface {
	Get(Key) (MapStateEntry, bool)

	// ForEach allows iteration over the MapStateEntries. It returns true if
	// the iteration was not stopped early by the callback.
	ForEach(func(Key, MapStateEntry) (cont bool)) (complete bool)
	GetIdentities(*logrus.Logger) ([]int64, []int64)
	GetDenyIdentities(*logrus.Logger) ([]int64, []int64)
	Len() int

	// private accessors
	deniesL4(policyOwner PolicyOwner, l4 *L4Filter) bool

	//
	// modifiers are private
	//
	delete(Key, Identities)
	insert(Key, MapStateEntry, Identities)
	revertChanges(Identities, ChangeState)

	addVisibilityKeys(PolicyOwner, uint16, *VisibilityMetadata, Identities, ChangeState)
	allowAllIdentities(ingress, egress bool)
	determineAllowLocalhostIngress()
	denyPreferredInsertWithChanges(newKey Key, newEntry MapStateEntry, identities Identities, features policyFeatures, changes ChangeState)
	deleteKeyWithChanges(key Key, owner MapStateOwner, identities Identities, changes ChangeState)

	// For testing from other packages only
	Equals(MapState) bool
	Diff(expected MapState) string
	WithState(initMap map[Key]MapStateEntry, identities Identities) MapState
}

type mapStateValidator interface {
	// identity relations tests
	isSupersetOf(ancestor, descendant Key, identities Identities)
	isSupersetOrSame(ancestor, descendant Key, identities Identities)

	// trafficdirection/protocol/port tests
	isBroader(ancestor, descendant Key)
	isBroaderOrEqual(ancestor, descendant Key)
}

// mapState is a state of a policy map.
type mapState struct {
	allows mapStateMap
	denies mapStateMap

	validator mapStateValidator
}

// Identities is a convenience interface for looking up CIDRs
// associated with an identity
type Identities interface {
	GetPrefix(identity.NumericIdentity) netip.Prefix
}

// mapStateMap is a convience type representing the actual structure mapping
// policymap keys to policymap entries.
//
// The `bitlpm.Trie` indexes the TrafficDirection, Protocol, and Port of
// a policy Key but does **not** index the identity. Instead identities
// that share TrafficDirection, Protocol, and Port are indexed in a builtin
// map type that is the associated value of the key-prefix of TrafficDirection,
// Protocol, and Port. This is done so that Identity does not explode
// the size of the Trie. Consider the case of a policy that selects
// many identities. In this case, if Identity was indexed then every
// identity associated with the policy would create at least one
// intermediate node in the Trie with its own sub node associated with
// TrafficDirection, Protocol, and Port. When identity is not indexed
// then one policy will map to one key-prefix with a builtin map type
// that associates each identity with a MapStateEntry. This strategy
// greatly enhances the usefuleness of the Trie and improves lookup,
// deletion, and insertion times.
type mapStateMap struct {
	// entries is the map containing the MapStateEntries
	entries map[Key]MapStateEntry
	// trie is a Trie that indexes policy Keys without their identity
	// and stores the identities in an associated builtin map.
	trie bitlpm.Trie[bitlpm.Key[Key], IDSet]
}

type IDSet struct {
	// ids contains all IDs in the set
	ids map[identity.NumericIdentity]struct{}
	// cidr contains the subset of IDs that have a valid prefix
	// nil if not needed
	cidr *bitlpm.CIDRTrie[map[identity.NumericIdentity]struct{}]
}

func (msm *mapStateMap) Lookup(k Key) (MapStateEntry, bool) {
	v, ok := msm.entries[k]
	return v, ok
}

var ip4ZeroPrefix = netip.MustParsePrefix("0.0.0.0/0")
var ip6ZeroPrefix = netip.MustParsePrefix("::/0")

func (msm *mapStateMap) upsert(k Key, e MapStateEntry, identities Identities) {
	_, exists := msm.entries[k]

	// upsert entry
	msm.entries[k] = e

	// Update indices if 'k' is a new key
	if !exists {
		// Update trie
		idSet, ok := msm.trie.ExactLookup(k.PrefixLength(), k)
		if !ok {
			idSet = IDSet{ids: make(map[identity.NumericIdentity]struct{})}
			kCpy := k
			kCpy.Identity = 0
			msm.trie.Upsert(kCpy.PrefixLength(), kCpy, idSet)
		}

		id := identity.NumericIdentity(k.Identity)
		idSet.ids[id] = struct{}{}

		// update CIDR and ANY indices
		switch {
		case id == identity.ReservedIdentityWorld:
			msm.insertCidr(ip4ZeroPrefix, k, &idSet)
			msm.insertCidr(ip6ZeroPrefix, k, &idSet)
		case id == identity.ReservedIdentityWorldIPv4:
			msm.insertCidr(ip4ZeroPrefix, k, &idSet)
		case id == identity.ReservedIdentityWorldIPv6:
			msm.insertCidr(ip6ZeroPrefix, k, &idSet)
		case id.HasLocalScope() && identities != nil:
			prefix := identities.GetPrefix(id)
			if prefix.IsValid() {
				msm.insertCidr(prefix, k, &idSet)
			}
		}
	}
}

func (msm *mapStateMap) insertCidr(prefix netip.Prefix, k Key, idSet *IDSet) {
	if idSet.cidr == nil {
		idSet.cidr = bitlpm.NewCIDRTrie[map[identity.NumericIdentity]struct{}]()
		kCpy := k
		kCpy.Identity = 0
		msm.trie.Upsert(kCpy.PrefixLength(), kCpy, *idSet)
	}
	idMap, ok := idSet.cidr.ExactLookup(prefix)
	if !ok || idMap == nil {
		idMap = make(map[identity.NumericIdentity]struct{})
		idSet.cidr.Upsert(prefix, idMap)
	}
	idMap[identity.NumericIdentity(k.Identity)] = struct{}{}
}

func (msm *mapStateMap) delete(k Key, identities Identities) {
	_, exists := msm.entries[k]
	if exists {
		delete(msm.entries, k)

		id := identity.NumericIdentity(k.Identity)
		idSet, ok := msm.trie.ExactLookup(k.PrefixLength(), k)
		if ok {
			delete(idSet.ids, id)
			if len(idSet.ids) == 0 {
				msm.trie.Delete(k.PrefixLength(), k)
				// IDSet is no longer in the trie
				idSet.cidr = nil
			}
		}

		// update CIDR and ANY indices
		switch {
		case id == identity.ReservedIdentityWorld:
			msm.deleteCidr(ip4ZeroPrefix, k, &idSet)
			msm.deleteCidr(ip6ZeroPrefix, k, &idSet)
		case id == identity.ReservedIdentityWorldIPv4:
			msm.deleteCidr(ip4ZeroPrefix, k, &idSet)
		case id == identity.ReservedIdentityWorldIPv6:
			msm.deleteCidr(ip6ZeroPrefix, k, &idSet)
		case id.HasLocalScope() && identities != nil:
			prefix := identities.GetPrefix(id)
			if prefix.IsValid() {
				msm.deleteCidr(prefix, k, &idSet)
			}
		}
	}
}

func (msm *mapStateMap) deleteCidr(prefix netip.Prefix, k Key, idSet *IDSet) {
	if idSet.cidr != nil {
		idMap, ok := idSet.cidr.ExactLookup(prefix)
		if ok {
			if idMap != nil {
				delete(idMap, identity.NumericIdentity(k.Identity))
			}
			// remove the idMap if empty
			if len(idMap) == 0 {
				idSet.cidr.Delete(prefix)
				// remove the CIDR index if empty
				if idSet.cidr.Len() == 0 {
					idSet.cidr = nil
					kCpy := k
					kCpy.Identity = 0
					msm.trie.Upsert(kCpy.PrefixLength(), kCpy, *idSet)
				}
			}
		}
	}
}

func (msm *mapStateMap) ForEach(f func(Key, MapStateEntry) bool) bool {
	for k, e := range msm.entries {
		if !f(k, e) {
			return false
		}
	}
	return true
}

func (msm *mapStateMap) forKey(k Key, f func(Key, MapStateEntry) bool) bool {
	e, ok := msm.entries[k]
	if ok {
		return f(k, e)
	}
	stacktrace := hclog.Stacktrace()
	log.Errorf("Missing MapStateEntry for key: %v. Stacktrace: %s", k, stacktrace)
	return true
}

// ForEachNarrowerKeyWithBroaderID iterates over narrower port/proto's and broader IDs in the trie.
// Equal port/protos or identities are not included.
func (msm *mapStateMap) ForEachNarrowerKeyWithBroaderID(key Key, prefixes []netip.Prefix, f func(Key, MapStateEntry) bool) {
	msm.trie.Descendants(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.Key], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := lpmKey.Value()

		// Descendants iterates over equal port/proto, caller expects to see only narrower keys so skip it
		if k.PortProtoIsEqual(key) {
			return true
		}

		// ANY identities are not in the CIDR trie, but they are ancestors of all
		// identities, visit them first, but not if key is also ANY
		if key.Identity != 0 {
			if _, exists := idSet.ids[0]; exists {
				k.Identity = 0
				if !msm.forKey(k, f) {
					return false
				}
			}
		}

		// cidr is nil when empty
		if idSet.cidr == nil {
			return true
		}
		for _, prefix := range prefixes {
			bailed := false
			idSet.cidr.Ancestors(prefix, func(cidr netip.Prefix, ids map[identity.NumericIdentity]struct{}) bool {
				for id := range ids {
					if id != identity.NumericIdentity(key.Identity) {
						k.Identity = uint32(id)
						if !msm.forKey(k, f) {
							bailed = true
							return false
						}
					}
				}
				return true
			})
			if bailed {
				return false
			}
		}
		return true
	})
}

// ForEachBroaderOrEqualKey iterates over broader or equal keys in the trie.
func (msm *mapStateMap) ForEachBroaderOrEqualKey(key Key, prefixes []netip.Prefix, f func(Key, MapStateEntry) bool) {
	msm.trie.Ancestors(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.Key], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := lpmKey.Value()

		// ANY identities are not in the CIDR trie, but they are ancestors of all
		// identities, visit them first
		if _, exists := idSet.ids[0]; exists {
			k.Identity = 0
			if !msm.forKey(k, f) {
				return false
			}
		}

		// identities without prefixes are not in the cidr trie,
		// but need to visit all keys with the same identity
		// ANY identity was already visited above
		if len(prefixes) == 0 && key.Identity != 0 {
			_, exists := idSet.ids[identity.NumericIdentity(key.Identity)]
			if exists {
				k.Identity = key.Identity
				if !msm.forKey(k, f) {
					return false
				}
			}
			return true
		}

		// cidr is nil when empty
		if idSet.cidr == nil {
			return true
		}
		for _, prefix := range prefixes {
			bailed := false
			idSet.cidr.Ancestors(prefix, func(cidr netip.Prefix, ids map[identity.NumericIdentity]struct{}) bool {
				for id := range ids {
					k.Identity = uint32(id)
					if !msm.forKey(k, f) {
						bailed = true
						return false
					}
				}
				return true
			})
			if bailed {
				return false
			}
		}
		return true
	})
}

// ForEachNarrowerOrEqualKey iterates over narrower or equal keys in the trie.
func (msm *mapStateMap) ForEachNarrowerOrEqualKey(key Key, prefixes []netip.Prefix, f func(Key, MapStateEntry) bool) {
	msm.trie.Descendants(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.Key], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := lpmKey.Value()

		// ANY identities are not in the CIDR trie, but all identities are descendants of
		// them.
		if key.Identity == 0 {
			for id := range idSet.ids {
				k.Identity = uint32(id)
				if !msm.forKey(k, f) {
					return false
				}
			}
		}

		// identities without prefixes are not in the cidr trie,
		// but need to visit all keys with the same identity
		// ANY identity was already visited above
		if len(prefixes) == 0 && key.Identity != 0 {
			_, exists := idSet.ids[identity.NumericIdentity(key.Identity)]
			if exists {
				k.Identity = key.Identity
				if !msm.forKey(k, f) {
					return false
				}
			}
			return true
		}

		// cidr is nil when empty
		if idSet.cidr == nil {
			return true
		}
		for _, prefix := range prefixes {
			bailed := false
			idSet.cidr.Descendants(prefix, func(cidr netip.Prefix, ids map[identity.NumericIdentity]struct{}) bool {
				for id := range ids {
					k.Identity = uint32(id)
					if !msm.forKey(k, f) {
						bailed = true
						return false
					}
				}
				return true
			})
			if bailed {
				return false
			}
		}
		return true
	})
}

// ForEachBroaderKeyWithNarrowerID iterates over broader proto/port with narrower identity in the trie.
// Equal port/protos or identities are not included.
func (msm *mapStateMap) ForEachBroaderKeyWithNarrowerID(key Key, prefixes []netip.Prefix, f func(Key, MapStateEntry) bool) {
	msm.trie.Ancestors(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.Key], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := lpmKey.Value()

		// Skip equal PortProto
		if k.PortProtoIsEqual(key) {
			return true
		}

		// ANY identities are not in the CIDR trie, but all identities are descendants of
		// them.
		if key.Identity == 0 {
			for id := range idSet.ids {
				if id != 0 {
					k.Identity = uint32(id)
					if !msm.forKey(k, f) {
						return false
					}
				}
			}
		}

		// cidr is nil when empty
		if idSet.cidr == nil {
			return true
		}
		for _, prefix := range prefixes {
			bailed := false
			idSet.cidr.Descendants(prefix, func(cidr netip.Prefix, ids map[identity.NumericIdentity]struct{}) bool {
				for id := range ids {
					if id != identity.NumericIdentity(key.Identity) {
						k.Identity = uint32(id)
						if !msm.forKey(k, f) {
							bailed = true
							return false
						}
					}
				}
				return true
			})
			if bailed {
				return false
			}
		}
		return true
	})
}

// ForEachKeyWithBroaderOrEqualPortProto iterates over broader or equal port/proto entries in the trie.
func (msm *mapStateMap) ForEachKeyWithBroaderOrEqualPortProto(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Ancestors(key.PrefixLength(), key, func(prefix uint, lpmKey bitlpm.Key[Key], idSet IDSet) bool {
		k := lpmKey.Value()
		for id := range idSet.ids {
			k.Identity = uint32(id)
			if !msm.forKey(k, f) {
				return false
			}
		}
		return true
	})
}

// ForEachKeyWithNarrowerOrEqualPortProto iterates over narrower or equal port/proto entries in the trie.
func (msm *mapStateMap) ForEachKeyWithNarrowerOrEqualPortProto(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Descendants(key.PrefixLength(), key, func(prefix uint, lpmKey bitlpm.Key[Key], idSet IDSet) bool {
		k := lpmKey.Value()
		for id := range idSet.ids {
			k.Identity = uint32(id)
			if !msm.forKey(k, f) {
				return false
			}
		}
		return true
	})
}

func (msm *mapStateMap) Len() int {
	return len(msm.entries)
}

type MapStateOwner interface{}

// MapStateEntry is the configuration associated with a Key in a
// MapState. This is a minimized version of policymap.PolicyEntry.
type MapStateEntry struct {
	// The proxy port, in host byte order.
	// If 0 (default), there is no proxy redirection for the corresponding
	// Key. Any other value signifies proxy redirection.
	ProxyPort uint16

	// priority is used to select the Listener if multiple rules would apply different listeners
	// to a policy map entry. Lower numbers indicate higher priority. If left out, the proxy
	// port number (10000-20000) is used.
	priority uint16

	// Listener name for proxy redirection, if any
	Listener string

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
func NewMapStateEntry(cs MapStateOwner, derivedFrom labels.LabelArrayList, proxyPort uint16, listener string, priority uint16, deny bool, hasAuth HasAuthType, authType AuthType) MapStateEntry {
	if proxyPort == 0 {
		listener = ""
		priority = 0
	} else if priority == 0 {
		priority = proxyPort // default for tie-breaking
	}
	return MapStateEntry{
		ProxyPort:        proxyPort,
		Listener:         listener,
		priority:         priority,
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

// HasSameOwners returns true if both MapStateEntries
// have the same owners as one another (which means that
// one of the entries is redundant).
func (e *MapStateEntry) HasSameOwners(bEntry *MapStateEntry) bool {
	if e == nil && bEntry == nil {
		return true
	}
	if len(e.owners) != len(bEntry.owners) {
		return false
	}
	for _, owner := range e.owners {
		if _, ok := bEntry.owners[owner]; !ok {
			return false
		}
	}
	return true
}

var worldNets = map[identity.NumericIdentity][]netip.Prefix{
	identity.ReservedIdentityWorld: {
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	},
	identity.ReservedIdentityWorldIPv4: {
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
	},
	identity.ReservedIdentityWorldIPv6: {
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	},
}

// getNets returns the most specific CIDR for an identity. For the "World" identity
// it returns both IPv4 and IPv6.
func getNets(identities Identities, ident uint32) []netip.Prefix {
	// World identities are handled explicitly for two reasons:
	// 1. 'identities' may be nil, but world identities are still expected to be considered
	// 2. SelectorCache is not be informed of reserved/world identities in all test cases
	// 3. identities.GetPrefix() does not return world identities
	id := identity.NumericIdentity(ident)
	if id <= identity.ReservedIdentityWorldIPv6 {
		return worldNets[id]
	}
	// CIDR identities have a local scope, so we can skip the rest if id is not of local scope.
	if !id.HasLocalScope() || identities == nil {
		return nil
	}
	prefix := identities.GetPrefix(id)
	if prefix.IsValid() {
		return []netip.Prefix{prefix}
	}
	return nil
}

// NewMapState creates a new MapState interface
func NewMapState() MapState {
	return newMapState()
}

func (ms *mapState) WithState(initMap map[Key]MapStateEntry, identities Identities) MapState {
	return ms.withState(initMap, identities)
}

func (ms *mapState) withState(initMap map[Key]MapStateEntry, identities Identities) *mapState {
	for k, v := range initMap {
		ms.insert(k, v, identities)
	}
	return ms
}

func newMapStateMap() mapStateMap {
	return mapStateMap{
		entries: make(map[Key]MapStateEntry),
		trie:    bitlpm.NewTrie[Key, IDSet](policyTypes.MapStatePrefixLen),
	}
}

func newMapState() *mapState {
	return &mapState{
		allows: newMapStateMap(),
		denies: newMapStateMap(),
	}
}

// Get the MapStateEntry that matches the Key.
func (ms *mapState) Get(k Key) (MapStateEntry, bool) {
	if k.DestPort == 0 && k.InvertedPortMask != 0xffff {
		stacktrace := hclog.Stacktrace()
		log.Errorf("mapState.Get: invalid wildcard port with non-zero mask: %v. Stacktrace: %s", k, stacktrace)
	}
	v, ok := ms.denies.Lookup(k)
	if ok {
		return v, ok
	}
	return ms.allows.Lookup(k)
}

// insert the Key and matcthing MapStateEntry into the
// MapState
func (ms *mapState) insert(k Key, v MapStateEntry, identities Identities) {
	if k.DestPort == 0 && k.InvertedPortMask != 0xffff {
		stacktrace := hclog.Stacktrace()
		log.Errorf("mapState.insert: invalid wildcard port with non-zero mask: %v. Stacktrace: %s", k, stacktrace)
	}
	if v.IsDeny {
		ms.allows.delete(k, identities)
		ms.denies.upsert(k, v, identities)
	} else {
		ms.denies.delete(k, identities)
		ms.allows.upsert(k, v, identities)
	}
}

// Delete removes the Key an related MapStateEntry.
func (ms *mapState) delete(k Key, identities Identities) {
	ms.allows.delete(k, identities)
	ms.denies.delete(k, identities)
}

// ForEach iterates over every Key MapStateEntry and stops when the function
// argument returns false. It returns false iff the iteration was cut short.
func (ms *mapState) ForEach(f func(Key, MapStateEntry) (cont bool)) (complete bool) {
	return ms.allows.ForEach(f) && ms.denies.ForEach(f)
}

// Len returns the length of the map
func (ms *mapState) Len() int {
	return ms.allows.Len() + ms.denies.Len()
}

// Equals determines if this MapState is equal to the
// argument MapState
// Only used for testing, but also from the endpoint package!
func (msA *mapState) Equals(msB MapState) bool {
	if msA.Len() != msB.Len() {
		return false
	}
	return msA.ForEach(func(kA Key, vA MapStateEntry) bool {
		vB, ok := msB.Get(kA)
		return ok && (&vB).DatapathEqual(&vA)
	})
}

// Diff returns the string of differences between 'obtained' and 'expected' prefixed with
// '+ ' or '- ' for obtaining something unexpected, or not obtaining the expected, respectively.
// For use in debugging.
func (obtained *mapState) Diff(expected MapState) (res string) {
	res += "Missing (-), Unexpected (+):\n"
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
func (ms *mapState) AddDependent(owner Key, dependent Key, identities Identities, changes ChangeState) {
	if e, exists := ms.allows.Lookup(owner); exists {
		ms.addDependentOnEntry(owner, e, dependent, identities, changes)
	} else if e, exists := ms.denies.Lookup(owner); exists {
		ms.addDependentOnEntry(owner, e, dependent, identities, changes)
	}
}

// addDependentOnEntry adds 'dependent' to the set of dependent keys of 'e'.
func (ms *mapState) addDependentOnEntry(owner Key, e MapStateEntry, dependent Key, identities Identities, changes ChangeState) {
	if _, exists := e.dependents[dependent]; !exists {
		if changes.Old != nil {
			changes.Old[owner] = e
		}
		e.AddDependent(dependent)
		ms.insert(owner, e, identities)
	}
}

// RemoveDependent removes 'key' from the list of dependent keys.
// This is called when a dependent entry is being deleted.
// If 'old' is not nil, then old value is added there before any modifications.
func (ms *mapState) RemoveDependent(owner Key, dependent Key, identities Identities, changes ChangeState) {
	if e, exists := ms.allows.Lookup(owner); exists {
		changes.insertOldIfNotExists(owner, e)
		e.RemoveDependent(dependent)
		ms.denies.delete(owner, identities)
		ms.allows.upsert(owner, e, identities)
		return
	}
	if e, exists := ms.denies.Lookup(owner); exists {
		changes.insertOldIfNotExists(owner, e)
		e.RemoveDependent(dependent)
		ms.allows.delete(owner, identities)
		ms.denies.upsert(owner, e, identities)
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
		e.Listener = ""
		e.priority = 0
		e.hasAuthType = DefaultAuthType
		e.AuthType = AuthTypeDisabled
	} else {
		// Proxy port takes precedence, but may be updated due to priority
		if entry.IsRedirectEntry() {
			// Lower number has higher priority, but non-redirects have 0 priority
			// value.
			// Proxy port value is the tie-breaker when priorities have the same value.
			if !e.IsRedirectEntry() || entry.priority < e.priority || entry.priority == e.priority && entry.ProxyPort < e.ProxyPort {
				e.ProxyPort = entry.ProxyPort
				e.Listener = entry.Listener
				e.priority = entry.priority
			}
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

// IsRedirectEntry returns true if the entry redirects to a proxy port
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

	if e.Listener != o.Listener || e.priority != o.priority {
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
		",Listener=" + e.Listener +
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
func (ms *mapState) addKeyWithChanges(key Key, entry MapStateEntry, identities Identities, changes ChangeState) {
	// Keep all owners that need this entry so that it is deleted only if all the owners delete their contribution
	var datapathEqual bool
	oldEntry, exists := ms.Get(key)
	if exists {
		// Deny entry can only be overridden by another deny entry
		if oldEntry.IsDeny && !entry.IsDeny {
			return
		}

		// Do nothing if entries are equal
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
		ms.insert(key, oldEntry, identities)
	} else {
		// Newly inserted entries must have their own containers, so that they
		// remain separate when new owners/dependents are added to existing entries
		entry.DerivedFromRules = slices.Clone(entry.DerivedFromRules)
		entry.owners = maps.Clone(entry.owners)
		entry.dependents = maps.Clone(entry.dependents)
		ms.insert(key, entry, identities)
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
func (ms *mapState) deleteKeyWithChanges(key Key, owner MapStateOwner, identities Identities, changes ChangeState) {
	if entry, exists := ms.Get(key); exists {
		// Save old value before any changes, if desired
		oldAdded := changes.insertOldIfNotExists(key, entry)
		if owner != nil {
			// remove the contribution of the given selector only
			if _, exists = entry.owners[owner]; exists {
				// Remove the contribution of this selector from the entry
				delete(entry.owners, owner)
				if ownerKey, ok := owner.(Key); ok {
					ms.RemoveDependent(ownerKey, key, identities, changes)
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
						ms.RemoveDependent(ownerKey, key, identities, changes)
					}
				}
			}
		}

		// Check if dependent entries need to be deleted as well
		for k := range entry.dependents {
			ms.deleteKeyWithChanges(k, key, identities, changes)
		}
		if changes.Deletes != nil {
			changes.Deletes[key] = struct{}{}
			// Remove a potential previously added key
			if changes.Adds != nil {
				delete(changes.Adds, key)
			}
		}

		ms.allows.delete(key, identities)
		ms.denies.delete(key, identities)
	}
}

// protocolsMatch checks to see if two given keys match on protocol.
// This means that either one of them covers all protocols or they
// are equal.
func protocolsMatch(a, b Key) bool {
	return a.Nexthdr == 0 || b.Nexthdr == 0 || a.Nexthdr == b.Nexthdr
}

// RevertChanges undoes changes to 'keys' as indicated by 'changes.adds' and 'changes.old' collected via
// denyPreferredInsertWithChanges().
func (ms *mapState) revertChanges(identities Identities, changes ChangeState) {
	for k := range changes.Adds {
		ms.allows.delete(k, identities)
		ms.denies.delete(k, identities)
	}
	// 'old' contains all the original values of both modified and deleted entries
	for k, v := range changes.Old {
		ms.insert(k, v, identities)
	}
}

// denyPreferredInsertWithChanges contains the most important business logic for policy insertions. It inserts
// a key and entry into the map by giving preference to deny entries, and L3-only deny entries over L3-L4 allows.
// Incremental changes performed are recorded in 'adds' and 'deletes', if not nil.
// See https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw#gid=2109052536 for details
func (ms *mapState) denyPreferredInsertWithChanges(newKey Key, newEntry MapStateEntry, identities Identities, features policyFeatures, changes ChangeState) {
	// Skip deny rules processing if the policy in this direction has no deny rules
	if !features.contains(denyRules) {
		ms.authPreferredInsert(newKey, newEntry, identities, features, changes)
		return
	}

	// If we have a deny "all" we don't accept any kind of map entry.
	if _, ok := ms.denies.Lookup(allKey[newKey.TrafficDirection]); ok {
		return
	}

	// We cannot update the map while we are
	// iterating through it, so we record the
	// changes to be made and then apply them.
	// Additionally, we need to perform deletes
	// first so that deny entries do not get
	// merged with allows that are set to be
	// deleted.
	var (
		updates, deletes []MapChange
	)
	prefixes := getNets(identities, newKey.Identity)
	if newEntry.IsDeny {
		ms.allows.ForEachNarrowerKeyWithBroaderID(newKey, prefixes, func(k Key, v MapStateEntry) bool {
			if ms.validator != nil {
				ms.validator.isBroader(newKey, k)
				ms.validator.isSupersetOf(k, newKey, identities)
			}

			// If this iterated-allow-entry is a superset of the new-entry
			// and it has a more specific port-protocol than the new-entry
			// then an additional copy of the new-entry with the more
			// specific port-protocol of the iterated-allow-entry must be inserted.
			newKeyCpy := k
			newKeyCpy.Identity = newKey.Identity
			l3l4DenyEntry := NewMapStateEntry(newKey, newEntry.DerivedFromRules, 0, "", 0, true, DefaultAuthType, AuthTypeDisabled)
			updates = append(updates, MapChange{
				Add:   true,
				Key:   newKeyCpy,
				Value: l3l4DenyEntry,
			})
			return true
		})
		ms.allows.ForEachNarrowerOrEqualKey(newKey, prefixes, func(k Key, v MapStateEntry) bool {
			if ms.validator != nil {
				ms.validator.isBroaderOrEqual(newKey, k)
				ms.validator.isSupersetOrSame(newKey, k, identities)
			}
			// If the new-entry is a superset (or equal) of the iterated-allow-entry and
			// the new-entry has a broader (or equal) port-protocol then we
			// should delete the iterated-allow-entry
			deletes = append(deletes, MapChange{
				Key: k,
			})
			return true
		})
		for _, delete := range deletes {
			if !delete.Add {
				ms.deleteKeyWithChanges(delete.Key, nil, identities, changes)
			}
		}
		for _, update := range updates {
			if update.Add {
				ms.addKeyWithChanges(update.Key, update.Value, identities, changes)
				// L3-only entries can be deleted incrementally so we need to track their
				// effects on other entries so that those effects can be reverted when the
				// identity is removed.
				newEntry.AddDependent(update.Key)
			}
		}

		updates = nil
		bailed := false
		ms.denies.ForEachBroaderOrEqualKey(newKey, prefixes, func(k Key, v MapStateEntry) bool {
			if ms.validator != nil {
				ms.validator.isBroaderOrEqual(k, newKey)
				ms.validator.isSupersetOrSame(k, newKey, identities)
			}
			if !v.HasDependent(newKey) && v.HasSameOwners(&newEntry) {
				// If this iterated-deny-entry is a supserset (or equal) of the new-entry and
				// the iterated-deny-entry has a broader (or equal) port-protocol and
				// the ownership between the entries is the same then we
				// should not insert the new entry (as long as it is not one
				// of the special L4-only denies we created to cover the special
				// case of a superset-allow with a more specific port-protocol).
				//
				// NOTE: This condition could be broader to reject more deny entries,
				// but there *may* be performance tradeoffs.
				bailed = true
				return false
			}
			return true
		})

		ms.denies.ForEachNarrowerOrEqualKey(newKey, prefixes, func(k Key, v MapStateEntry) bool {
			if ms.validator != nil {
				ms.validator.isBroaderOrEqual(newKey, k)
				ms.validator.isSupersetOrSame(newKey, k, identities)
			}
			if !newEntry.HasDependent(k) && newEntry.HasSameOwners(&v) {
				// If this iterated-deny-entry is a subset (or equal) of the new-entry and
				// the new-entry has a broader (or equal) port-protocol and
				// the ownership between the entries is the same then we
				// should delete the iterated-deny-entry (as long as it is not one
				// of the special L4-only denies we created to cover the special
				// case of a superset-allow with a more specific port-protocol).
				//
				// NOTE: This condition could be broader to reject more deny entries,
				// but there *may* be performance tradeoffs.
				updates = append(updates, MapChange{
					Key: k,
				})
			}
			return true
		})
		for _, update := range updates {
			if !update.Add {
				ms.deleteKeyWithChanges(update.Key, nil, identities, changes)
			}
		}
		if !bailed {
			ms.addKeyWithChanges(newKey, newEntry, identities, changes)
		}
	} else {
		// NOTE: We do not delete redundant allow entries.
		updates = nil
		var dependents []MapChange
		bailed := false
		ms.denies.ForEachBroaderKeyWithNarrowerID(newKey, prefixes, func(k Key, v MapStateEntry) bool {
			if ms.validator != nil {
				ms.validator.isBroader(k, newKey)
				ms.validator.isSupersetOf(newKey, k, identities)
			}
			// If the new-entry is *only* superset of the iterated-deny-entry
			// and the new-entry has a more specific port-protocol than the
			// iterated-deny-entry then an additional copy of the iterated-deny-entry
			// with the more specific port-porotocol of the new-entry must
			// be added.
			denyKeyCpy := newKey
			denyKeyCpy.Identity = k.Identity
			l3l4DenyEntry := NewMapStateEntry(k, v.DerivedFromRules, 0, "", 0, true, DefaultAuthType, AuthTypeDisabled)
			updates = append(updates, MapChange{
				Add:   true,
				Key:   denyKeyCpy,
				Value: l3l4DenyEntry,
			})
			// L3-only entries can be deleted incrementally so we need to track their
			// effects on other entries so that those effects can be reverted when the
			// identity is removed.
			dependents = append(dependents, MapChange{
				Key:   k,
				Value: v,
			})
			return true
		})
		ms.denies.ForEachBroaderOrEqualKey(newKey, prefixes, func(k Key, v MapStateEntry) bool {
			if ms.validator != nil {
				ms.validator.isBroaderOrEqual(k, newKey)
				ms.validator.isSupersetOrSame(k, newKey, identities)
			}
			if !v.HasDependent(newKey) {
				// If the iterated-deny-entry is a superset (or equal) of the new-entry and has a
				// broader (or equal) port-protocol than the new-entry then the new
				// entry should not be inserted.
				bailed = true
				return false
			}
			return true
		})
		for i, update := range updates {
			if update.Add {
				ms.addKeyWithChanges(update.Key, update.Value, identities, changes)
				dep := dependents[i]
				ms.addDependentOnEntry(dep.Key, dep.Value, update.Key, identities, changes)
			}
		}
		if !bailed {
			ms.authPreferredInsert(newKey, newEntry, identities, features, changes)
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
func IsSuperSetOf(k, other Key) int {
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
				if k.PortIsBroader(other) {
					return 2 // */proto/* is a superset of */proto/port
				} // else more specific or different ports
			} // else more specific or different protocol
		} else {
			// Wildcard L3 is a superset of a specific L3 only if wildcard L3 is also wildcard L4, or the L4's match between the keys
			if k.Nexthdr == 0 { // k.DestPort == 0 is implied
				return 1 // */*/* is a superset of ID/x/x
			} else if k.Nexthdr == other.Nexthdr {
				if k.PortIsBroader(other) {
					return 2 // */proto/* is a superset of ID/proto/x
				} else if k.PortIsEqual(other) {
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
			if k.PortIsBroader(other) {
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
func (ms *mapState) authPreferredInsert(newKey Key, newEntry MapStateEntry, identities Identities, features policyFeatures, changes ChangeState) {
	if features.contains(authRules) {
		if newEntry.hasAuthType == DefaultAuthType {
			// New entry has a default auth type.
			// Fill in the AuthType from more generic entries with an explicit auth type
			maxSpecificity := 0
			l3l4State := newMapStateMap()

			ms.allows.ForEachKeyWithBroaderOrEqualPortProto(newKey, func(k Key, v MapStateEntry) bool {
				// Nothing to be done if entry has default AuthType
				if v.hasAuthType == DefaultAuthType {
					return true
				}

				// Find out if 'k' is an identity-port-proto superset of 'newKey'
				if specificity := IsSuperSetOf(k, newKey); specificity > 0 {
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
					if newKey.Identity == 0 && newKey.Nexthdr != 0 && newKey.DestPort != 0 &&
						k.Identity != 0 && (k.Nexthdr == 0 || k.Nexthdr == newKey.Nexthdr && k.DestPort == 0) {
						newKeyCpy := newKey
						newKeyCpy.Identity = k.Identity
						l3l4AuthEntry := NewMapStateEntry(k, v.DerivedFromRules, newEntry.ProxyPort, newEntry.Listener, newEntry.priority, false, DefaultAuthType, v.AuthType)
						l3l4AuthEntry.DerivedFromRules.MergeSorted(newEntry.DerivedFromRules)
						l3l4State.upsert(newKeyCpy, l3l4AuthEntry, identities)
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
					ms.addKeyWithChanges(k, v, identities, changes)
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

			ms.allows.ForEachKeyWithNarrowerOrEqualPortProto(newKey, func(k Key, v MapStateEntry) bool {
				// Find out if 'newKey' is a superset of 'k'
				if specificity := IsSuperSetOf(newKey, k); specificity > 0 {
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
					if newKey.Identity != 0 && (newKey.Nexthdr == 0 || newKey.Nexthdr == k.Nexthdr && newKey.DestPort == 0) &&
						k.Identity == 0 && k.Nexthdr != 0 && k.DestPort != 0 {
						newKeyCpy := k
						newKeyCpy.Identity = newKey.Identity
						l3l4AuthEntry := NewMapStateEntry(newKey, newEntry.DerivedFromRules, v.ProxyPort, v.Listener, v.priority, false, DefaultAuthType, newEntry.AuthType)
						l3l4AuthEntry.DerivedFromRules.MergeSorted(v.DerivedFromRules)
						ms.addKeyWithChanges(newKeyCpy, l3l4AuthEntry, identities, changes)
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
					if s := IsSuperSetOf(l, k); s > specificity {
						// k has a more specific superset key than the newKey, skip
						continue Next
					}
				}
				// newKey is the most specific superset with an explicit auth type,
				// propagate auth type from newEntry to the entry of k
				v, _ := ms.Get(k)
				v.AuthType = newEntry.AuthType
				ms.addKeyWithChanges(k, v, identities, changes) // Update the map value
			}
		}
	}
	ms.addKeyWithChanges(newKey, newEntry, identities, changes)
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

// ForEachKeyWithPortProto calls 'f' for each Key and MapStateEntry, where the Key has the same traffic direction and and L4 fields (protocol, destination port and mask).
func (msm *mapStateMap) ForEachKeyWithPortProto(key Key, f func(Key, MapStateEntry) bool) {
	// 'Identity' field in 'key' is ignored on by ExactLookup
	idSet, ok := msm.trie.ExactLookup(key.PrefixLength(), key)
	if ok {
		for id := range idSet.ids {
			k := key
			k.Identity = uint32(id)
			if !msm.forKey(k, f) {
				return
			}
		}
	}
}

// addVisibilityKeys adjusts and expands PolicyMapState keys
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
func (ms *mapState) addVisibilityKeys(e PolicyOwner, redirectPort uint16, visMeta *VisibilityMetadata, identities Identities, changes ChangeState) {
	direction := trafficdirection.Egress
	if visMeta.Ingress {
		direction = trafficdirection.Ingress
	}

	var invertedPortMask uint16
	if visMeta.Port == 0 {
		invertedPortMask = 0xffff
	}
	key := Key{
		DestPort:         visMeta.Port,
		InvertedPortMask: invertedPortMask,
		Nexthdr:          uint8(visMeta.Proto),
		TrafficDirection: direction.Uint8(),
	}

	entry := NewMapStateEntry(nil, visibilityDerivedFrom, redirectPort, "", 0, false, DefaultAuthType, AuthTypeDisabled)

	_, haveAllowAllKey := ms.Get(allKey[direction])
	l4Only, haveL4OnlyKey := ms.Get(key)
	addL4OnlyKey := false
	if haveL4OnlyKey && !l4Only.IsDeny && l4Only.ProxyPort == 0 {
		// 1. Change existing L4-only ALLOW key on matching port that does not already
		//    redirect to redirect.
		e.PolicyDebug(logrus.Fields{
			logfields.BPFMapKey:   key,
			logfields.BPFMapValue: entry,
		}, "addVisibilityKeys: Changing L4-only ALLOW key for visibility redirect")
		ms.addKeyWithChanges(key, entry, identities, changes)
	}
	if haveAllowAllKey && !haveL4OnlyKey {
		// 2. If allow-all policy exists, add L4-only visibility redirect key if the L4-only
		//    key does not already exist.
		e.PolicyDebug(logrus.Fields{
			logfields.BPFMapKey:   key,
			logfields.BPFMapValue: entry,
		}, "addVisibilityKeys: Adding L4-only ALLOW key for visibility redirect")
		addL4OnlyKey = true
		ms.addKeyWithChanges(key, entry, identities, changes)
	}
	// We need to make changes to the map
	// outside of iteration.
	var updates []MapChange
	//
	// Loop through all L3 keys in the traffic direction of the new key
	//

	// Find entries with the same L4
	ms.allows.ForEachKeyWithPortProto(key, func(k Key, v MapStateEntry) bool {
		if k.Identity != 0 {
			if v.ProxyPort == 0 {
				// 3. Change all L3/L4 ALLOW keys on matching port that do not
				//    already redirect to redirect.
				v.ProxyPort = redirectPort
				// redirect port is used as the default priority for tie-breaking
				// purposes when two different selectors have conflicting
				// redirects. Explicit listener references in the policy can specify
				// a priority, but only the default is used for visibility policy,
				// as visibility will be achieved by any of the redirects.
				v.priority = redirectPort
				v.Listener = ""
				v.DerivedFromRules = visibilityDerivedFrom
				e.PolicyDebug(logrus.Fields{
					logfields.BPFMapKey:   k,
					logfields.BPFMapValue: v,
				}, "addVisibilityKeys: Changing L3/L4 ALLOW key for visibility redirect")
				updates = append(updates, MapChange{
					Add:   true,
					Key:   k,
					Value: v,
				})
			}
		}
		return true
	})

	// Find Wildcarded L4 allows, i.e., L3-only entries
	if !haveL4OnlyKey && !addL4OnlyKey {
		ms.allows.ForEachKeyWithPortProto(allKey[key.TrafficDirection], func(k Key, v MapStateEntry) bool {
			if k.Identity != 0 {
				k2 := key
				k2.Identity = k.Identity
				// 4. For each L3-only ALLOW key add the corresponding L3/L4
				//    ALLOW redirect if no L3/L4 key already exists and no
				//    L4-only key already exists and one is not added.
				if _, ok := ms.Get(k2); !ok {
					d2 := labels.LabelArrayList{visibilityDerivedFromLabels}
					d2.MergeSorted(v.DerivedFromRules)
					v2 := NewMapStateEntry(k, d2, redirectPort, "", 0, false, v.hasAuthType, v.AuthType)
					e.PolicyDebug(logrus.Fields{
						logfields.BPFMapKey:   k2,
						logfields.BPFMapValue: v2,
					}, "addVisibilityKeys: Extending L3-only ALLOW key to L3/L4 key for visibility redirect")
					updates = append(updates, MapChange{
						Add:   true,
						Key:   k2,
						Value: v2,
					})
					// Mark the new entry as a dependent of 'v'
					ms.addDependentOnEntry(k, v, k2, identities, changes)
				}
			}
			return true
		})
	}

	// Find Wildcarded L4 denies, i.e., L3-only entries
	if addL4OnlyKey {
		ms.denies.ForEachKeyWithPortProto(allKey[key.TrafficDirection], func(k Key, v MapStateEntry) bool {
			if k.Identity != 0 {
				k2 := k
				k2.DestPort = key.DestPort
				k2.InvertedPortMask = key.InvertedPortMask
				k2.Nexthdr = key.Nexthdr
				// 5. If a new L4-only key was added: For each L3-only DENY
				//    key add the corresponding L3/L4 DENY key if no L3/L4
				//    key already exists.
				if _, ok := ms.Get(k2); !ok {
					v2 := NewMapStateEntry(k, v.DerivedFromRules, 0, "", 0, true, DefaultAuthType, AuthTypeDisabled)
					e.PolicyDebug(logrus.Fields{
						logfields.BPFMapKey:   k2,
						logfields.BPFMapValue: v2,
					}, "addVisibilityKeys: Extending L3-only DENY key to L3/L4 key to deny a port with visibility annotation")
					updates = append(updates, MapChange{
						Add:   true,
						Key:   k2,
						Value: v2,
					})
					// Mark the new entry as a dependent of 'v'
					ms.addDependentOnEntry(k, v, k2, identities, changes)
				}
			}
			return true
		})
	}

	for _, update := range updates {
		ms.addKeyWithChanges(update.Key, update.Value, identities, changes)
	}
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
		es := NewMapStateEntry(nil, derivedFrom, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled) // Authentication never required for local host ingress
		ms.denyPreferredInsert(localHostKey, es, nil, allFeatures)
	}
}

// allowAllIdentities translates all identities in selectorCache to their
// corresponding Keys in the specified direction (ingress, egress) which allows
// all at L3.
// Note that this is used when policy is not enforced, so authentication is explicitly not required.
func (ms *mapState) allowAllIdentities(ingress, egress bool) {
	if ingress {
		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyIngress, labels.LabelSourceReserved),
			},
		}
		ms.allows.upsert(allKey[trafficdirection.Ingress], NewMapStateEntry(nil, derivedFrom, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled), nil)
	}
	if egress {
		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved),
			},
		}
		ms.allows.upsert(allKey[trafficdirection.Egress], NewMapStateEntry(nil, derivedFrom, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled), nil)
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

	var key Key
	if l4.Ingress {
		key = allKey[trafficdirection.Ingress]
	} else {
		key = allKey[trafficdirection.Egress]
	}

	// Are we explicitly denying all traffic?
	v, ok := ms.Get(key)
	if ok && v.IsDeny {
		return true
	}

	// Are we explicitly denying this L4-only traffic?
	key.DestPort = port
	key.Nexthdr = proto
	v, ok = ms.Get(key)
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
// Used only for API requests.
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
func (mc *MapChanges) AccumulateMapChanges(cs CachedSelector, adds, deletes []identity.NumericIdentity, keys []Key, value MapStateEntry) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	for _, id := range adds {
		for _, k := range keys {
			k.Identity = id.Uint32()
			mc.changes = append(mc.changes, MapChange{Add: true, Key: k, Value: value})
		}
	}
	for _, id := range deletes {
		for _, k := range keys {
			k.Identity = id.Uint32()
			mc.changes = append(mc.changes, MapChange{Add: false, Key: k, Value: value})
		}
	}
}

// consumeMapChanges transfers the incremental changes from MapChanges to the caller,
// while applying the changes to PolicyMapState.
func (mc *MapChanges) consumeMapChanges(policyOwner PolicyOwner, policyMapState MapState, identities Identities, features policyFeatures) (adds, deletes Keys) {
	mc.mutex.Lock()
	changes := ChangeState{
		Adds:    make(Keys, len(mc.changes)),
		Deletes: make(Keys, len(mc.changes)),
	}
	var redirects map[string]uint16
	if policyOwner != nil {
		redirects = policyOwner.GetRealizedRedirects()
	}

	for i := range mc.changes {
		if mc.changes[i].Add {
			// Redirect entries for unrealized redirects come in with an invalid
			// redirect port (65535), replace it with the actual proxy port number.
			key := mc.changes[i].Key
			entry := mc.changes[i].Value
			if entry.ProxyPort == unrealizedRedirectPort {
				var exists bool
				proxyID := ProxyIDFromKey(uint16(policyOwner.GetID()), key, entry.Listener)
				entry.ProxyPort, exists = redirects[proxyID]
				if !exists {
					log.WithFields(logrus.Fields{
						logfields.PolicyKey:   key,
						logfields.PolicyEntry: entry,
					}).Warn("consumeMapChanges: Skipping entry for unrealized redirect")
					continue
				}
			}

			// insert but do not allow non-redirect entries to overwrite a redirect entry,
			// nor allow non-deny entries to overwrite deny entries.
			// Collect the incremental changes to the overall state in 'mc.adds' and 'mc.deletes'.
			policyMapState.denyPreferredInsertWithChanges(key, entry, identities, features, changes)
		} else {
			// Delete the contribution of this cs to the key and collect incremental changes
			for cs := range mc.changes[i].Value.owners { // get the sole selector
				policyMapState.deleteKeyWithChanges(mc.changes[i].Key, cs, identities, changes)
			}
		}
	}
	mc.changes = nil
	mc.mutex.Unlock()
	return changes.Adds, changes.Deletes
}
