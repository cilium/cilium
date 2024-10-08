// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/container/bitlpm"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/container/versioned"
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
type MapStateOwner = any // Key or CachedSelector

type MapStateMap map[Key]MapStateEntry

func EgressKey() policyTypes.Key {
	return policyTypes.EgressKey()
}

func IngressKey() policyTypes.Key {
	return policyTypes.IngressKey()
}

func KeyForDirection(direction trafficdirection.TrafficDirection) Key {
	return policyTypes.KeyForDirection(direction)
}

var (
	// localHostKey represents an ingress L3 allow from the local host.
	localHostKey = IngressKey().WithIdentity(identity.ReservedIdentityHost)
	// allKey represents a key for unknown traffic, i.e., all traffic.
	// We have one for each traffic direction
	allKey = [2]Key{
		IngressKey(),
		EgressKey(),
	}
)

const (
	LabelKeyPolicyDerivedFrom  = "io.cilium.policy.derived-from"
	LabelAllowLocalHostIngress = "allow-localhost-ingress"
	LabelAllowAnyIngress       = "allow-any-ingress"
	LabelAllowAnyEgress        = "allow-any-egress"

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
	delete(Key)
	insert(Key, MapStateEntry)
	revertChanges(ChangeState)

	allowAllIdentities(ingress, egress bool)
	determineAllowLocalhostIngress()
	denyPreferredInsertWithChanges(newKey Key, newEntry MapStateEntry, features policyFeatures, changes ChangeState)
	deleteKeyWithChanges(key Key, owner MapStateOwner, changes ChangeState)

	// For testing from other packages only
	Equals(MapState) bool
	Diff(expected MapState) string
	WithState(initMap MapStateMap) MapState
}

// mapState is a state of a policy map.
type mapState struct {
	allows mapStateMap
	denies mapStateMap
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
	entries MapStateMap
	// trie is a Trie that indexes policy Keys without their identity
	// and stores the identities in an associated builtin map.
	trie bitlpm.Trie[bitlpm.Key[policyTypes.LPMKey], IDSet]
}

type IDSet map[identity.NumericIdentity]struct{}

func (msm *mapStateMap) Lookup(k Key) (MapStateEntry, bool) {
	v, ok := msm.entries[k]
	return v, ok
}

func (msm *mapStateMap) upsert(k Key, e MapStateEntry) {
	_, exists := msm.entries[k]

	// upsert entry
	msm.entries[k] = e

	// Update indices if 'k' is a new key
	if !exists {
		// Update trie
		idSet, ok := msm.trie.ExactLookup(k.PrefixLength(), k)
		if !ok {
			idSet = make(IDSet)
			kCpy := k
			kCpy.Identity = 0
			msm.trie.Upsert(kCpy.PrefixLength(), kCpy, idSet)
		}

		idSet[k.Identity] = struct{}{}
	}
}

func (msm *mapStateMap) delete(k Key) {
	_, exists := msm.entries[k]
	if exists {
		delete(msm.entries, k)

		id := k.Identity
		idSet, ok := msm.trie.ExactLookup(k.PrefixLength(), k)
		if ok {
			delete(idSet, id)
			if len(idSet) == 0 {
				msm.trie.Delete(k.PrefixLength(), k)
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
	log.WithFields(logrus.Fields{
		logfields.Stacktrace: hclog.Stacktrace(),
		logfields.PolicyKey:  k,
	}).Errorf("Missing MapStateEntry")
	return true
}

// ForEachNarrowerKeyWithBroaderID iterates over narrower port/proto's and broader IDs in the trie.
// Equal port/protos or identities are not included.
func (msm *mapStateMap) ForEachNarrowerKeyWithBroaderID(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Descendants(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.LPMKey], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := Key{
			LPMKey: lpmKey.Value(),
		}

		// Descendants iterates over equal port/proto, caller expects to see only narrower keys so skip it
		if k.PortProtoIsEqual(key) {
			return true
		}

		// ANY identities are ancestors of all
		// identities, visit them first, but not if key is also ANY
		if key.Identity != 0 {
			if _, exists := idSet[0]; exists {
				k.Identity = 0
				if !msm.forKey(k, f) {
					return false
				}
			}
		}
		return true
	})
}

// ForEachBroaderOrEqualKey iterates over broader or equal keys in the trie.
func (msm *mapStateMap) ForEachBroaderOrEqualKey(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Ancestors(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.LPMKey], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := Key{
			LPMKey: lpmKey.Value(),
		}

		// ANY identity is an ancestor of all identities, visit them first
		if _, exists := idSet[0]; exists {
			k.Identity = 0
			if !msm.forKey(k, f) {
				return false
			}
		}

		// Need to visit all keys with the same identity
		// ANY identity was already visited above
		if key.Identity != 0 {
			_, exists := idSet[key.Identity]
			if exists {
				k.Identity = key.Identity
				if !msm.forKey(k, f) {
					return false
				}
			}
		}
		return true
	})
}

func (msm *mapStateMap) forDescendantIDs(keyIdentity identity.NumericIdentity, k Key, idSet IDSet, f func(Key, MapStateEntry) bool) bool {
	switch identity.NumericIdentity(keyIdentity) {
	case identity.IdentityUnknown: // 0
		// All identities are descendants of ANY
		for id := range idSet {
			if id != 0 {
				k.Identity = id
				if !msm.forKey(k, f) {
					return false
				}
			}
		}
	}
	return true
}

// ForEachNarrowerOrEqualKey iterates over narrower or equal keys in the trie.
func (msm *mapStateMap) ForEachNarrowerOrEqualKey(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Descendants(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.LPMKey], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := Key{
			LPMKey: lpmKey.Value(),
		}

		// Need to visit all keys with the same identity
		_, exists := idSet[key.Identity]
		if exists {
			k.Identity = key.Identity
			if !msm.forKey(k, f) {
				return false
			}
		}

		return msm.forDescendantIDs(key.Identity, k, idSet, f)
	})
}

// ForEachBroaderKeyWithNarrowerID iterates over broader proto/port with narrower identity in the trie.
// Equal port/protos or identities are not included.
func (msm *mapStateMap) ForEachBroaderKeyWithNarrowerID(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Ancestors(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.LPMKey], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := Key{
			LPMKey: lpmKey.Value(),
		}

		// Skip equal PortProto
		if k.PortProtoIsEqual(key) {
			return true
		}

		return msm.forDescendantIDs(key.Identity, k, idSet, f)
	})
}

// ForEachBroaderOrEqualDatapathKey iterates over broader or equal keys in the trie.
// Visits all keys that datapath would match IF the 'key' was not added to the policy map.
// NOTE that CIDRs are not considered here as datapath does not support LPM matching in security IDs.
func (msm *mapStateMap) ForEachBroaderOrEqualDatapathKey(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Ancestors(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.LPMKey], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := Key{
			LPMKey: lpmKey.Value(),
		}

		// ANY identities are ancestors of all identities, visit them first
		if _, exists := idSet[0]; exists {
			k.Identity = 0
			if !msm.forKey(k, f) {
				return false
			}
		}

		// Need to visit all keys with the same identity
		// ANY identity was already visited above
		if key.Identity != 0 {
			_, exists := idSet[key.Identity]
			if exists {
				k.Identity = key.Identity
				if !msm.forKey(k, f) {
					return false
				}
			}
		}
		return true
	})
}

// ForEachNarrowerOrEqualDatapathKey iterates over narrower or equal keys in the trie.
// Visits all keys that datapath matches that would match 'key' if those keys were not in the policy map.
// NOTE that CIDRs are not considered here as datapath does not support LPM matching in security IDs.
func (msm *mapStateMap) ForEachNarrowerOrEqualDatapathKey(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Descendants(key.PrefixLength(), key, func(_ uint, lpmKey bitlpm.Key[policyTypes.LPMKey], idSet IDSet) bool {
		// k is the key from trie with 0'ed ID
		k := Key{
			LPMKey: lpmKey.Value(),
		}

		// All identities are descendants of ANY identity.
		if key.Identity == 0 {
			for id := range idSet {
				k.Identity = id
				if !msm.forKey(k, f) {
					return false
				}
			}
		}

		// Need to visit all keys with the same identity.
		// ANY identity was already visited above.
		if key.Identity != 0 {
			_, exists := idSet[key.Identity]
			if exists {
				k.Identity = key.Identity
				if !msm.forKey(k, f) {
					return false
				}
			}
		}
		return true
	})
}

// ForEachKeyWithBroaderOrEqualPortProto iterates over broader or equal port/proto entries in the trie.
func (msm *mapStateMap) ForEachKeyWithBroaderOrEqualPortProto(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Ancestors(key.PrefixLength(), key, func(prefix uint, lpmKey bitlpm.Key[policyTypes.LPMKey], idSet IDSet) bool {
		k := Key{
			LPMKey: lpmKey.Value(),
		}
		for id := range idSet {
			k.Identity = id
			if !msm.forKey(k, f) {
				return false
			}
		}
		return true
	})
}

// ForEachKeyWithNarrowerOrEqualPortProto iterates over narrower or equal port/proto entries in the trie.
func (msm *mapStateMap) ForEachKeyWithNarrowerOrEqualPortProto(key Key, f func(Key, MapStateEntry) bool) {
	msm.trie.Descendants(key.PrefixLength(), key, func(prefix uint, lpmKey bitlpm.Key[policyTypes.LPMKey], idSet IDSet) bool {
		k := Key{
			LPMKey: lpmKey.Value(),
		}
		for id := range idSet {
			k.Identity = id
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

	// owners collects the keys in the map and selectors in the policy that require this key to be present.
	// TODO: keep track which selector needed the entry to be deny, redirect, or just allow.
	owners set.Set[MapStateOwner]

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
		owners:           set.NewSet(cs),
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

// NewMapState creates a new MapState interface
func NewMapState() MapState {
	return newMapState()
}

func (ms *mapState) WithState(initMap MapStateMap) MapState {
	return ms.withState(initMap)
}

func (ms *mapState) withState(initMap MapStateMap) *mapState {
	for k, v := range initMap {
		ms.insert(k, v)
	}
	return ms
}

func newMapStateMap() mapStateMap {
	return mapStateMap{
		entries: make(MapStateMap),
		trie:    bitlpm.NewTrie[policyTypes.LPMKey, IDSet](policyTypes.MapStatePrefixLen),
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
	if k.DestPort == 0 && k.PortPrefixLen() > 0 {
		log.WithFields(logrus.Fields{
			logfields.Stacktrace: hclog.Stacktrace(),
			logfields.PolicyKey:  k,
		}).Errorf("mapState.Get: invalid port prefix length for wildcard port")
	}
	v, ok := ms.denies.Lookup(k)
	if ok {
		return v, ok
	}
	return ms.allows.Lookup(k)
}

// insert the Key and MapStateEntry into the MapState
func (ms *mapState) insert(k Key, v MapStateEntry) {
	if k.DestPort == 0 && k.PortPrefixLen() > 0 {
		log.WithFields(logrus.Fields{
			logfields.Stacktrace: hclog.Stacktrace(),
			logfields.PolicyKey:  k,
		}).Errorf("mapState.insert: invalid port prefix length for wildcard port")
	}
	if v.IsDeny {
		ms.allows.delete(k)
		ms.denies.upsert(k, v)
	} else {
		ms.denies.delete(k)
		ms.allows.upsert(k, v)
	}
}

// updateExisting re-inserts an existing entry to its map, to be used to persist changes in the
// entry.
// NOTE: Only to be used when Key and v.IsDeny has not been changed!
func (ms *mapState) updateExisting(k Key, v MapStateEntry) {
	if v.IsDeny {
		ms.denies.entries[k] = v
	} else {
		ms.allows.entries[k] = v
	}
}

// deleteExisting removes the Key an related MapStateEntry.
func (ms *mapState) deleteExisting(k Key, v MapStateEntry) {
	if v.IsDeny {
		ms.denies.delete(k)
	} else {
		ms.allows.delete(k)
	}
}

// delete removes the Key and related MapStateEntry.
func (ms *mapState) delete(k Key) {
	ms.allows.delete(k)
	ms.denies.delete(k)
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
		return ok && (&vB).DatapathAndDerivedFromEqual(&vA)
	})
}

// Diff returns the string of differences between 'obtained' and 'expected' prefixed with
// '+ ' or '- ' for obtaining something unexpected, or not obtaining the expected, respectively.
// For use in debugging.
func (obtained *mapState) Diff(expected MapState) (res string) {
	res += "Missing (-), Unexpected (+):\n"
	expected.ForEach(func(kE Key, vE MapStateEntry) bool {
		if vO, ok := obtained.Get(kE); ok {
			if !(&vO).DatapathAndDerivedFromEqual(&vE) {
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
	if e, exists := ms.allows.Lookup(owner); exists {
		ms.addDependentOnEntry(owner, e, dependent, changes)
	} else if e, exists := ms.denies.Lookup(owner); exists {
		ms.addDependentOnEntry(owner, e, dependent, changes)
	}
}

// addDependentOnEntry adds 'dependent' to the set of dependent keys of 'e'.
func (ms *mapState) addDependentOnEntry(owner Key, e MapStateEntry, dependent Key, changes ChangeState) {
	if _, exists := e.dependents[dependent]; !exists {
		changes.insertOldIfNotExists(owner, e)
		e.AddDependent(dependent)
		ms.insert(owner, e)
	}
}

// RemoveDependent removes 'key' from the list of dependent keys.
// This is called when a dependent entry is being deleted.
// If 'old' is not nil, then old value is added there before any modifications.
func (ms *mapState) RemoveDependent(owner Key, dependent Key, changes ChangeState) {
	if e, exists := ms.allows.Lookup(owner); exists {
		changes.insertOldIfNotExists(owner, e)
		e.RemoveDependent(dependent)
		// update the value in the allows map
		ms.allows.upsert(owner, e)
		return
	}
	if e, exists := ms.denies.Lookup(owner); exists {
		changes.insertOldIfNotExists(owner, e)
		e.RemoveDependent(dependent)
		// update the value in the denies map
		ms.denies.upsert(owner, e)
	}
}

// merge adds owners, dependents, and DerivedFromRules from a new 'entry' to an existing
// entry 'e'. 'entry' is not modified.
// Merge is only called if both entries are allow or deny entries, so deny precedence is not
// considered here.
// ProxyPort, and AuthType are merged by giving precedence to proxy redirection over no proxy
// redirection, and explicit auth type over default auth type.
func (e *MapStateEntry) merge(entry *MapStateEntry) {
	// Bail out loudly if both entries are not denies or allows
	if e.IsDeny != entry.IsDeny {
		log.WithField(logfields.Stacktrace, hclog.Stacktrace()).
			Errorf("MapStateEntry.merge: both entries must be allows or denies")
		return
	}
	// Only allow entries have proxy redirection or auth requirement
	if !e.IsDeny {
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

	e.owners.Merge(entry.owners)

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

// DatapathAndDerivedFromEqual returns true of two entries are equal in the datapath's PoV,
// i.e., IsDeny, ProxyPort and AuthType are the same for both entries, and the DerivedFromRules
// fields are also equal.
// This is used for testing only via mapState.Equal and mapState.Diff.
func (e *MapStateEntry) DatapathAndDerivedFromEqual(o *MapStateEntry) bool {
	if e == nil || o == nil {
		return e == o
	}

	return e.IsDeny == o.IsDeny && e.ProxyPort == o.ProxyPort && e.AuthType == o.AuthType &&
		e.DerivedFromRules.DeepEqual(&o.DerivedFromRules)
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

	if !e.owners.Equal(o.owners) {
		return false
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
		",DerivedFromRules=" + fmt.Sprintf("%v", e.DerivedFromRules) +
		",priority=" + strconv.FormatUint(uint64(e.priority), 10) +
		",owners=" + e.owners.String() +
		",dependents=" + fmt.Sprintf("%v", e.dependents)
}

// denyPreferredInsert inserts a key and entry into the map by given preference
// to deny entries, and L3-only deny entries over L3-L4 allows.
// This form may be used when a full policy is computed and we are not yet interested
// in accumulating incremental changes.
// Caller may insert the same MapStateEntry multiple times for different Keys, but all from the same
// owner.
func (ms *mapState) denyPreferredInsert(newKey Key, newEntry MapStateEntry, features policyFeatures) {
	// Enforce nil values from NewMapStateEntry
	newEntry.dependents = nil

	ms.denyPreferredInsertWithChanges(newKey, newEntry, features, ChangeState{})
}

// addKeyWithChanges adds a 'key' with value 'entry' to 'keys' keeping track of incremental changes in 'adds' and 'deletes', and any changed or removed old values in 'old', if not nil.
func (ms *mapState) addKeyWithChanges(key Key, entry MapStateEntry, changes ChangeState) {
	// Keep all owners that need this entry so that it is deleted only if all the owners delete their contribution
	var datapathEqual bool
	oldEntry, exists := ms.Get(key)
	// Only merge if both old and new are allows or denies
	if exists && (oldEntry.IsDeny == entry.IsDeny) {
		// Do nothing if entries are equal
		if entry.DeepEqual(&oldEntry) {
			return // nothing to do
		}

		// Save old value before any changes, if desired
		changes.insertOldIfNotExists(key, oldEntry)

		// Compare for datapath equalness before merging, as the old entry is updated in
		// place!
		datapathEqual = oldEntry.DatapathEqual(&entry)

		oldEntry.merge(&entry)
		ms.insert(key, oldEntry)
	} else if !exists || entry.IsDeny {
		// Insert a new entry if one did not exist or a deny entry is overwriting an allow
		// entry.
		// Newly inserted entries must have their own containers, so that they
		// remain separate when new owners/dependents are added to existing entries
		entry.DerivedFromRules = slices.Clone(entry.DerivedFromRules)
		entry.owners = entry.owners.Clone()
		entry.dependents = maps.Clone(entry.dependents)
		ms.insert(key, entry)
	} else {
		// Do not record and incremental add if nothing was done
		return
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
			if entry.owners.Has(owner) {
				// remove the contribution of the given selector only
				changed := entry.owners.Remove(owner)
				if changed {
					// re-insert entry due to owner change
					ms.updateExisting(key, entry)
				}
				// Remove the contribution of this key from the entry
				if ownerKey, ok := owner.(Key); ok {
					ms.RemoveDependent(ownerKey, key, changes)
				}
				// key is not deleted if other owners still need it
				if entry.owners.Len() > 0 {
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
			for ownerKey := range set.MembersOfType[Key](entry.owners) {
				ms.RemoveDependent(ownerKey, key, changes)
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

		// delete entry from the map it exists in
		ms.deleteExisting(key, entry)
	}
}

// RevertChanges undoes changes to 'keys' as indicated by 'changes.adds' and 'changes.old' collected via
// denyPreferredInsertWithChanges().
func (ms *mapState) revertChanges(changes ChangeState) {
	for k := range changes.Adds {
		ms.allows.delete(k)
		ms.denies.delete(k)
	}
	// 'old' contains all the original values of both modified and deleted entries
	for k, v := range changes.Old {
		ms.insert(k, v)
	}
}

// denyPreferredInsertWithChanges contains the most important business logic for policy insertions. It inserts
// a key and entry into the map by giving preference to deny entries, and L3-only deny entries over L3-L4 allows.
// Incremental changes performed are recorded in 'adds' and 'deletes', if not nil.
// See https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw#gid=2109052536 for details
func (ms *mapState) denyPreferredInsertWithChanges(newKey Key, newEntry MapStateEntry, features policyFeatures, changes ChangeState) {
	// Sanity check on the newKey
	if newKey.TrafficDirection() >= trafficdirection.Invalid {
		log.WithFields(logrus.Fields{
			logfields.Stacktrace:       hclog.Stacktrace(),
			logfields.TrafficDirection: newKey.TrafficDirection,
		}).Errorf("mapState.denyPreferredInsertWithChanges: invalid traffic direction in key")
		return
	}
	// Skip deny rules processing if the policy in this direction has no deny rules
	if !features.contains(denyRules) {
		ms.authPreferredInsert(newKey, newEntry, features, changes)
		return
	}

	// If we have a deny "all" we don't accept any kind of map entry.
	if _, ok := ms.denies.Lookup(allKey[newKey.TrafficDirection()]); ok {
		return
	}

	// Since bpf datapath denies by default, we only need to add deny entries to carve out more
	// specific holes to less specific allow rules. But since we don't if allow entries will be
	// added later (e.g., incrementally due to FQDN rules), we must generally add deny entries
	// even if there are no allow entries yet.

	// Datapath matches security IDs exactly, or completely wildcards them (ID == 0). Datapath
	// has no LPM/CIDR logic for security IDs. We use LPM/CIDR logic here to find out if allow
	// entries are "covered" by deny entries and change them to deny entries if so. We can not
	// rely on the default deny as a broad allow could be added later.

	// We cannot update the map while we are
	// iterating through it, so we record the
	// changes to be made and then apply them.
	// Additionally, we need to perform deletes
	// first so that deny entries do not get
	// merged with allows that are set to be
	// deleted.
	var (
		updates []MapChange
		deletes []Key
	)
	if newEntry.IsDeny {
		// Test for bailed case first so that we avoid unnecessary computation if entry is
		// not going to be added.
		bailed := false
		// If there is an ANY or equal deny key, then do not add a more specific one.
		// A narrower of two deny keys is redundant in the datapath only if the broader ID
		// is 0, or the IDs are the same. This is because the ID will be assigned from the
		// ipcache and datapath has no notion of one ID being related to another.
		ms.denies.ForEachBroaderOrEqualDatapathKey(newKey, func(k Key, v MapStateEntry) bool {
			// Identical key needs to be added if the entries are different (to merge
			// them).
			if k != newKey || v.DeepEqual(&newEntry) {
				// If the ID of this iterated-deny-entry is ANY or equal of
				// the new-entry and the iterated-deny-entry has a broader (or
				// equal) port-protocol then we need not insert the new entry.
				bailed = true
				return false
			}
			return true
		})
		if bailed {
			return
		}

		// Only a non-wildcard key can have a wildcard superset key
		if newKey.Identity != 0 {
			ms.allows.ForEachNarrowerKeyWithBroaderID(newKey, func(k Key, v MapStateEntry) bool {
				// If this iterated-allow-entry is a wildcard superset of the new-entry
				// and it has a more specific port-protocol than the new-entry
				// then an additional copy of the new deny entry with the more
				// specific port-protocol of the iterated-allow-entry must be inserted.
				if k.Identity != 0 {
					return true // skip non-wildcard
				}
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
		}

		ms.allows.ForEachNarrowerOrEqualKey(newKey, func(k Key, v MapStateEntry) bool {
			// If newKey has a broader (or equal) port-protocol and the newKey's
			// identity is a superset (or same) of the iterated identity, then we should
			// either delete the iterated-allow-entry (if the identity is the same or
			// the newKey is L3 wildcard), or change it to a deny entry otherwise
			if newKey.Identity == 0 || newKey.Identity == k.Identity {
				deletes = append(deletes, k)
			} else {
				// When newKey.Identity is not ANY and is different from the subset
				// key, we must keep the subset key and make it a deny instead.
				// Note that these security identities have no numerical relation to
				// each other (e.g, they could be any numbers X and Y) and the
				// datapath does an exact match on them.
				l3l4DenyEntry := NewMapStateEntry(newKey, newEntry.DerivedFromRules, 0, "", 0, true, DefaultAuthType, AuthTypeDisabled)
				updates = append(updates, MapChange{
					Add:   true,
					Key:   k,
					Value: l3l4DenyEntry,
				})
			}
			return true
		})
		// Not adding the new L3/L4 deny entries yet so that we do not need to worry about
		// them below.

		ms.denies.ForEachNarrowerOrEqualDatapathKey(newKey, func(k Key, v MapStateEntry) bool {
			// Identical key needs to remain if owners are different to merge them
			if k != newKey || v.DeepEqual(&newEntry) {
				// If this iterated-deny-entry is a subset (or equal) of the
				// new-entry and the new-entry has a broader (or equal)
				// port-protocol the newKey will match all the packets the iterated
				// key would, given that there are no more specific or L4-only allow
				// entries, and then we can delete the iterated-deny-entry.
				deletes = append(deletes, k)
			}
			return true
		})

		for _, key := range deletes {
			ms.deleteKeyWithChanges(key, nil, changes)
		}
		for _, update := range updates {
			ms.addKeyWithChanges(update.Key, update.Value, changes)
			// L3-only entries can be deleted incrementally so we need to track their
			// effects on other entries so that those effects can be reverted when the
			// identity is removed.
			newEntry.AddDependent(update.Key)
		}
		ms.addKeyWithChanges(newKey, newEntry, changes)
	} else {
		// NOTE: We do not delete redundant allow entries.
		var dependents []MapChange

		// Test for bailed case first so that we avoid unnecessary computation if entry is
		// not going to be added, or is going to be changed to a deny entry.
		bailed := false
		insertAsDeny := false
		var denyEntry MapStateEntry
		ms.denies.ForEachBroaderOrEqualKey(newKey, func(k Key, v MapStateEntry) bool {
			// If the iterated-deny-entry is a wildcard or has the same identity then it
			// can be bailed out.
			if k.Identity == 0 || k.Identity == newKey.Identity {
				bailed = true
				return false
			}
			// if any deny key covers this new allow key, then it needs to be inserted
			// as deny, if not bailed out.
			if !insertAsDeny {
				insertAsDeny = true
				denyEntry = NewMapStateEntry(k, v.DerivedFromRules, 0, "", 0, true, DefaultAuthType, AuthTypeDisabled)
			} else {
				// Collect the owners and labels of all the contributing deny rules
				denyEntry.merge(&v)
			}
			return true
		})
		if bailed {
			return
		}
		if insertAsDeny {
			ms.authPreferredInsert(newKey, denyEntry, features, changes)
			return
		}

		if newKey.Identity == 0 {
			ms.denies.ForEachBroaderKeyWithNarrowerID(newKey, func(k Key, v MapStateEntry) bool {
				// If the new-entry is a wildcard superset of the iterated-deny-entry
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
		}

		for i, update := range updates {
			if update.Add {
				ms.addKeyWithChanges(update.Key, update.Value, changes)
				dep := dependents[i]
				ms.addDependentOnEntry(dep.Key, dep.Value, update.Key, changes)
			}
		}
		ms.authPreferredInsert(newKey, newEntry, features, changes)
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
	if k.TrafficDirection() != other.TrafficDirection() {
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
func (ms *mapState) authPreferredInsert(newKey Key, newEntry MapStateEntry, features policyFeatures, changes ChangeState) {
	if features.contains(authRules) {
		if newEntry.hasAuthType == DefaultAuthType {
			// New entry has a default auth type.
			// Fill in the AuthType from more generic entries with an explicit auth type
			maxSpecificity := 0
			var l3l4State MapStateMap

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

						if l3l4State == nil {
							l3l4State = make(MapStateMap)
						}
						l3l4State[newKeyCpy] = l3l4AuthEntry
					}
				}
				return true
			})
			// Add collected L3/L4 entries if the auth type of the new entry was not
			// overridden by a more generic entry. If it was overridden, the new L3L4
			// entries are not needed as the L4-only entry with an overridden AuthType
			// will be matched before the L3-only entries in the datapath.
			if maxSpecificity == 0 {
				for k, v := range l3l4State {
					ms.addKeyWithChanges(k, v, changes)
					// L3-only entries can be deleted incrementally so we need to track their
					// effects on other entries so that those effects can be reverted when the
					// identity is removed.
					newEntry.AddDependent(k)
				}
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
					if s := IsSuperSetOf(l, k); s > specificity {
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

// insertIfNotExists only inserts an entry in 'changes.Old' if 'key' does not exist in there already
// and 'key' does not already exist in 'changes.Adds'. This prevents recording "old" values for
// newly added keys. When an entry is updated, we are called before the key is added to
// 'changes.Adds' so we'll record the old value as expected.
// Returns 'true' if an old entry was added.
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
			entry.owners = entry.owners.Clone()
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
		for id := range idSet {
			k := key
			k.Identity = id
			if !msm.forKey(k, f) {
				return
			}
		}
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
		ms.denyPreferredInsert(localHostKey, es, allFeatures)
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
		ms.allows.upsert(allKey[trafficdirection.Ingress], NewMapStateEntry(nil, derivedFrom, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled))
	}
	if egress {
		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved),
			},
		}
		ms.allows.upsert(allKey[trafficdirection.Egress], NewMapStateEntry(nil, derivedFrom, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled))
	}
}

func (ms *mapState) deniesL4(policyOwner PolicyOwner, l4 *L4Filter) bool {
	port := uint16(l4.Port)
	proto := l4.U8Proto

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
	ms.ForEach(func(key Key, entry MapStateEntry) bool {
		if denied != entry.IsDeny {
			return true
		}
		if key.DestPort != 0 {
			// If the port is non-zero, then the Key no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			return true
		}
		switch key.TrafficDirection() {
		case trafficdirection.Ingress:
			ingIdentities = append(ingIdentities, int64(key.Identity))
		case trafficdirection.Egress:
			egIdentities = append(egIdentities, int64(key.Identity))
		default:
			td := key.TrafficDirection()
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
	firstVersion versioned.KeepVersion
	mutex        lock.Mutex
	changes      []MapChange
	synced       []MapChange
	version      *versioned.VersionHandle
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
			k.Identity = id
			mc.changes = append(mc.changes, MapChange{Add: true, Key: k, Value: value})
		}
	}
	for _, id := range deletes {
		for _, k := range keys {
			k.Identity = id
			mc.changes = append(mc.changes, MapChange{Add: false, Key: k, Value: value})
		}
	}
}

// SyncMapChanges moves the current batch of changes to 'synced' to be consumed as a unit
func (mc *MapChanges) SyncMapChanges(txn *versioned.Tx) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	if len(mc.changes) > 0 {
		// Only apply changes after the initial version
		if txn.After(mc.firstVersion) {
			mc.synced = append(mc.synced, mc.changes...)
			mc.version.Close()
			mc.version = txn.GetVersionHandle()
			log.WithFields(logrus.Fields{
				logfields.NewVersion: mc.version,
			}).Debug("SyncMapChanges: Got handle on the new version")
		} else {
			log.WithFields(logrus.Fields{
				logfields.Version:    mc.firstVersion,
				logfields.OldVersion: txn,
			}).Debug("SyncMapChanges: Discarding already applied changes")
		}
	}
	mc.changes = nil
}

// detach releases any version handle we may hold
func (mc *MapChanges) detach() {
	mc.mutex.Lock()
	mc.version.Close()
	mc.mutex.Unlock()
}

// consumeMapChanges transfers the incremental changes from MapChanges to the caller,
// while applying the changes to PolicyMapState.
func (mc *MapChanges) consumeMapChanges(p *EndpointPolicy, features policyFeatures) (*versioned.VersionHandle, ChangeState) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	changes := ChangeState{
		Adds:    make(Keys, len(mc.synced)),
		Deletes: make(Keys, len(mc.synced)),
		Old:     make(map[Key]MapStateEntry, len(mc.synced)),
	}

	var redirects map[string]uint16
	if p.PolicyOwner != nil {
		redirects = p.PolicyOwner.GetRealizedRedirects()
	}

	for i := range mc.synced {
		if mc.synced[i].Add {
			// Redirect entries for unrealized redirects come in with an invalid
			// redirect port (65535), replace it with the actual proxy port number.
			key := mc.synced[i].Key
			entry := mc.synced[i].Value
			if entry.ProxyPort == unrealizedRedirectPort {
				var exists bool
				proxyID := ProxyIDFromKey(uint16(p.PolicyOwner.GetID()), key, entry.Listener)
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
			p.policyMapState.denyPreferredInsertWithChanges(key, entry, features, changes)
		} else {
			// Delete the contribution of this cs to the key and collect incremental changes
			cs, _ := mc.synced[i].Value.owners.Get() // get the sole selector
			p.policyMapState.deleteKeyWithChanges(mc.synced[i].Key, cs, changes)
		}
	}

	// move version to the caller
	version := mc.version
	mc.version = nil

	mc.synced = nil

	return version, changes
}
