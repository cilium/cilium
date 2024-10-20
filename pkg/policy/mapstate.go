// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"iter"
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

// Map type for external use. Internally we have more detail in private 'mapSteteEntry' type,
// as well as more extensive indexing via tries.
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
)

var (
	LabelsAllowAnyIngress = labels.LabelArrayList{labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyIngress, labels.LabelSourceReserved)}}
	LabelsAllowAnyEgress = labels.LabelArrayList{labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved)}}
)

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
// that associates each identity with a mapStateEntry. This strategy
// greatly enhances the usefuleness of the Trie and improves lookup,
// deletion, and insertion times.
type mapStateMap struct {
	// entries is the map containing the MapStateEntries
	entries map[Key]mapStateEntry
	// trie is a Trie that indexes policy Keys without their identity
	// and stores the identities in an associated builtin map.
	trie bitlpm.Trie[bitlpm.Key[policyTypes.LPMKey], IDSet]
}

type IDSet map[identity.NumericIdentity]struct{}

func (msm *mapStateMap) Empty() bool {
	return len(msm.entries) == 0
}

func (msm *mapStateMap) Lookup(k Key) (mapStateEntry, bool) {
	v, ok := msm.entries[k]
	return v, ok
}

func (msm *mapStateMap) upsert(k Key, e mapStateEntry) {
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
		if !f(k, e.MapStateEntry) {
			return false
		}
	}
	return true
}

func (msm *mapStateMap) forEach(f func(Key, mapStateEntry) bool) bool {
	for k, e := range msm.entries {
		if !f(k, e) {
			return false
		}
	}
	return true
}

func (msm *mapStateMap) forKey(k Key, f func(Key, mapStateEntry) bool) bool {
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

// forDifferentKeys calls 'f' for each Key 'k' with identities in 'idSet', if different from 'key'.
func (msm *mapStateMap) forDifferentKeys(key, k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	for id := range idSet {
		k.Identity = id
		if key != k && !msm.forKey(k, f) {
			return false
		}
	}
	return true
}

// forSpecificIDs calls 'f' for each non-ANY ID in 'idSet' with port/proto from 'k'.
func (msm *mapStateMap) forSpecificIDs(k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	for id := range idSet {
		if id != 0 {
			k.Identity = id
			if !msm.forKey(k, f) {
				return false
			}
		}
	}
	return true
}

// forIDs calls 'f' for each ID in 'idSet' with port/proto from 'k'.
func (msm *mapStateMap) forIDs(k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	for id := range idSet {
		k.Identity = id
		if !msm.forKey(k, f) {
			return false
		}
	}
	return true
}

// forID calls 'f' for 'k' if 'k.Identity' exists in 'idSet'.
func (msm *mapStateMap) forID(k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	if _, exists := idSet[k.Identity]; exists {
		if !msm.forKey(k, f) {
			return false
		}
	}
	return true
}

// NarrowerKeysWithWildcardID iterates over ANY keys with narrower port/proto's in the trie.
// Equal port/protos are not included.
// New keys with the protocol/port of the iterated keys can be safely added during iteration as this
// operation does not change the trie, but only adds elements to the idSet that is not used after
// yielding.
func (msm *mapStateMap) NarrowerKeysWithWildcardID(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := msm.trie.DescendantIterator(key.PrefixLength(), key)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey.Value()}

			// Visit narrower ANY keys
			if !k.PortProtoIsEqual(key) && !msm.forID(k.WithIdentity(0), idSet, yield) {
				return
			}
		}
	}
}

// BroaderOrEqualKeys iterates over broader or equal (broader or equal port/proto and the same
// or wildcard ID) in the trie.
func (msm *mapStateMap) BroaderOrEqualKeys(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := msm.trie.AncestorIterator(key.PrefixLength(), key)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey.Value()}

			// ANY identity is broader or equal to all identities, visit it first if it exists
			if !msm.forID(k.WithIdentity(0), idSet, yield) {
				return
			}

			// Visit key with the same identity, if it exists.
			// ANY identity was already visited above.
			if key.Identity != 0 && !msm.forID(k.WithIdentity(key.Identity), idSet, yield) {
				return
			}
		}
	}
}

// NarrowerKeys iterates over narrower keys in the trie.
func (msm *mapStateMap) NarrowerKeys(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := msm.trie.DescendantIterator(key.PrefixLength(), key)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey.Value()}

			// All identities are narrower than ANY identity, visit different keys
			if key.Identity == 0 {
				if !msm.forDifferentKeys(key, k, idSet, yield) {
					return
				}
			} else { // key has a specific identity
				// Need to visit the key with the same identity, if PortProto is different,
				// and one exists.
				if !k.PortProtoIsEqual(key) && !msm.forID(k.WithIdentity(key.Identity), idSet, yield) {
					return
				}
			}
		}
	}
}

// NarrowerOrEqualKeys iterates over narrower or equal keys in the trie.
// Iterated keys can be safely deleted during iteration due to DescendantIterator holding enough
// state that allows iteration to be continued even if the current trie node is removed.
func (msm *mapStateMap) NarrowerOrEqualKeys(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := msm.trie.DescendantIterator(key.PrefixLength(), key)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey.Value()}

			// All identities are narrower or equal to ANY identity.
			if key.Identity == 0 {
				if !msm.forIDs(k, idSet, yield) {
					return
				}
			} else { // key has a specific identity
				// Need to visit the key with the same identity, if it exists.
				if !msm.forID(k.WithIdentity(key.Identity), idSet, yield) {
					return
				}
			}
		}
	}
}

// BroaderKeysWithSpecificID iterates over keys with broader proto/port and a specific
// identity in the trie.
// Equal port/protos or identities are not included.
func (msm *mapStateMap) BroaderKeysWithSpecificID(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := msm.trie.AncestorIterator(key.PrefixLength(), key)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey.Value()}

			// Visit different keys with specific IDs
			if !k.PortProtoIsEqual(key) && !msm.forSpecificIDs(k, idSet, yield) {
				return
			}
		}
	}
}

// CoveringKeys iterates over broader port/proto entries in the trie in LPM order,
// with most specific match being returned first.
func (msm *mapStateMap) CoveringKeys(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := msm.trie.AncestorLongestPrefixFirstIterator(key.PrefixLength(), key)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey.Value()}

			// Visit key with the same identity, if port/proto is different.
			// ANY identity is visited below.
			if key.Identity != 0 && !k.PortProtoIsEqual(key) {
				if !msm.forID(k.WithIdentity(key.Identity), idSet, yield) {
					return
				}
			}

			// ANY identity covers all non-ANY identities, visit them second.
			// Keys with ANY identity visit ANY keys only if port/proto is different.
			if key.Identity != 0 || !k.PortProtoIsEqual(key) {
				if !msm.forID(k.WithIdentity(0), idSet, yield) {
					return
				}
			}
		}
	}
}

// SubsetKeys iterates over narrower or equal port/proto entries in the trie in an LPM order
// (least specific match first).
func (msm *mapStateMap) SubsetKeys(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := msm.trie.DescendantShortestPrefixFirstIterator(key.PrefixLength(), key)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey.Value()}

			// For an ANY key, visit all different keys
			if key.Identity == 0 {
				if !msm.forDifferentKeys(key, k, idSet, yield) {
					return
				}
			} else { // key has a specific ID
				// Visit only keys with the ANY or the same ID, if they exist
				if !msm.forID(k.WithIdentity(0), idSet, yield) {
					return
				}
				// Else visit the different key with the same identity
				if !k.PortProtoIsEqual(key) && !msm.forID(k.WithIdentity(key.Identity), idSet, yield) {
					return
				}
			}
		}
	}
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

	// IsDeny is true when the policy should be denied.
	IsDeny bool

	// AuthType is non-zero when authentication is required for the traffic to be allowed.
	AuthType AuthType
}

// mapSteteEntry is the entry type with additional internal bookkeping of the relation between
// explicitly and implicitly added entries.
type mapStateEntry struct {
	MapStateEntry

	// priority is used to select the proxy port if multiple rules would apply different proxy
	// ports to a policy map entry. Lower numbers indicate higher priority. If left out, the
	// proxy port number (10000-20000) is used.
	priority uint16

	// hasAuthType is 'DefaultAuthType' when policy has no explicit AuthType set. In this case
	// the value of AuthType is derived from more generic entries covering this entry.
	hasAuthType HasAuthType

	// derivedFromRules tracks the policy rules this entry derives from.
	// In sorted order.
	derivedFromRules labels.LabelArrayList

	// owners collects the keys in the map and selectors in the policy that require this key to be present.
	// TODO: keep track which selector needed the entry to be deny, redirect, or just allow.
	owners set.Set[MapStateOwner]

	// dependents contains the keys for entries create based on this entry. These entries
	// will be deleted once all of the owners are deleted.
	dependents Keys
}

// newMapStateEntry creates a map state entry. If redirect is true, the
// caller is expected to replace the ProxyPort field before it is added to
// the actual BPF map.
// 'cs' is used to keep track of which policy selectors need this entry. If it is 'nil' this entry
// will become sticky and cannot be completely removed via incremental updates. Even in this case
// the entry may be overridden or removed by a deny entry.
func newMapStateEntry(cs MapStateOwner, derivedFrom labels.LabelArrayList, proxyPort uint16, priority uint16, deny bool, hasAuth HasAuthType, authType AuthType) mapStateEntry {
	if proxyPort == 0 {
		priority = 0
	} else if priority == 0 {
		priority = proxyPort // default for tie-breaking
	}
	return mapStateEntry{
		MapStateEntry: MapStateEntry{
			ProxyPort: proxyPort,
			IsDeny:    deny,
			AuthType:  authType,
		},
		priority:         priority,
		hasAuthType:      hasAuth,
		derivedFromRules: derivedFrom,
		owners:           set.NewSet(cs),
	}
}

// dependentOf returns a new mapStateEntry that is a copy of 'e', but has 'ownerKey' as the sole
// owner, and has no dependent keys.
func (e *mapStateEntry) dependentOf(ownerKey Key) mapStateEntry {
	return mapStateEntry{
		MapStateEntry:    e.MapStateEntry,
		priority:         e.priority,
		hasAuthType:      e.hasAuthType,
		derivedFromRules: slices.Clone(e.derivedFromRules),
		owners:           set.NewSet[MapStateOwner](ownerKey),
	}
}

// dependentFrom returns a new mapStateEntry that is a copy of 'e', but has 'ownerKey' as the sole
// owner, and has no dependent keys.
func (e mapStateEntry) authOverrideFrom(ownerKey Key, entry *mapStateEntry) mapStateEntry {
	lbls := slices.Clone(e.derivedFromRules)
	lbls.MergeSorted(entry.derivedFromRules)

	return mapStateEntry{
		MapStateEntry:    e.MapStateEntry.WithAuthType(entry.AuthType),
		priority:         e.priority,
		hasAuthType:      DefaultAuthType,
		derivedFromRules: lbls,
		owners:           set.NewSet[MapStateOwner](ownerKey),
	}
}

func (e MapStateEntry) toMapStateEntry(priority uint16, hasAuth HasAuthType, cs MapStateOwner, derivedFrom labels.LabelArrayList) mapStateEntry {
	if e.ProxyPort == 0 {
		priority = 0
	} else if priority == 0 {
		priority = e.ProxyPort // default for tie-breaking
	}
	return mapStateEntry{
		MapStateEntry:    e,
		priority:         priority,
		hasAuthType:      hasAuth,
		derivedFromRules: derivedFrom,
		owners:           set.NewSet(cs),
	}
}

func (e *mapStateEntry) GetRuleLabels() labels.LabelArrayList {
	return e.derivedFromRules
}

// AddDependent adds 'key' to the set of dependent keys.
func (e *mapStateEntry) AddDependent(key Key) {
	if e.dependents == nil {
		e.dependents = make(Keys, 1)
	}
	e.dependents[key] = struct{}{}
}

// RemoveDependent removes 'key' from the set of dependent keys.
func (e *mapStateEntry) RemoveDependent(key Key) {
	delete(e.dependents, key)
	// Nil the map when empty. This is mainly to make unit testing easier.
	if len(e.dependents) == 0 {
		e.dependents = nil
	}
}

// HasDependent returns true if the 'key' is contained
// within the set of dependent keys
func (e *mapStateEntry) HasDependent(key Key) bool {
	_, ok := e.dependents[key]
	return ok
}

func newMapStateMap() mapStateMap {
	return mapStateMap{
		entries: make(map[Key]mapStateEntry),
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
	v, ok := ms.get(k)
	if ok {
		return v.MapStateEntry, ok
	}
	return MapStateEntry{}, false
}

// Get the mapStateEntry that matches the Key.
func (ms *mapState) get(k Key) (mapStateEntry, bool) {
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
func (ms *mapState) insert(k Key, v mapStateEntry) {
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
func (ms *mapState) updateExisting(k Key, v mapStateEntry) {
	if v.IsDeny {
		ms.denies.entries[k] = v
	} else {
		ms.allows.entries[k] = v
	}
}

// deleteExisting removes the Key an related MapStateEntry.
func (ms *mapState) deleteExisting(k Key, v mapStateEntry) {
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

// Empty returns 'true' if there are no entries in the map
func (ms *mapState) Empty() bool {
	return ms.allows.Len() == 0 && ms.denies.Len() == 0
}

// forEach iterates over every Key MapStateEntry and stops when the function
// argument returns false. It returns false iff the iteration was cut short.
// Used for testing.
func (ms *mapState) forEach(f func(Key, mapStateEntry) (cont bool)) (complete bool) {
	return ms.allows.forEach(f) && ms.denies.forEach(f)
}

// Len returns the length of the map
func (ms *mapState) Len() int {
	return ms.allows.Len() + ms.denies.Len()
}

// equalsWithLabels determines if this mapState is equal to the
// argument MapState. Only compares the exported MapStateEntry and derivedFromLabels.
// Only used for testing.
func (msA *mapState) equalsWithLabels(msB *mapState) bool {
	if msA.Len() != msB.Len() {
		return false
	}
	return msA.forEach(func(kA Key, vA mapStateEntry) bool {
		vB, ok := msB.get(kA)
		return ok && (&vB).DatapathAndDerivedFromEqual(&vA)
	})
}

// Equals determines if this MapState is equal to the
// argument (exported) MapStateMap
// Only used for testing from other packages.
func (msA *mapState) Equals(msB MapStateMap) bool {
	if msA.Len() != len(msB) {
		return false
	}
	return msA.forEach(func(kA Key, vA mapStateEntry) bool {
		vB, ok := msB[kA]
		return ok && vB == vA.MapStateEntry
	})
}

// deepEquals determines if this MapState is equal to the argument MapState.
// Only used for testing.
func (msA *mapState) deepEquals(msB *mapState) bool {
	if msA.Len() != msB.Len() {
		return false
	}
	return msA.forEach(func(kA Key, vA mapStateEntry) bool {
		vB, ok := msB.get(kA)
		return ok && (&vB).deepEqual(&vA)
	})
}

// Diff returns the string of differences between 'obtained' and 'expected' prefixed with
// '+ ' or '- ' for obtaining something unexpected, or not obtaining the expected, respectively.
// For use in debugging from other packages.
func (obtained *mapState) Diff(expected MapStateMap) (res string) {
	res += "Missing (-), Unexpected (+):\n"
	for kE, vE := range expected {
		if vO, ok := obtained.get(kE); ok {
			if vO.MapStateEntry != vE {
				res += "- " + kE.String() + ": " + vE.String() + "\n"
				res += "+ " + kE.String() + ": " + vO.MapStateEntry.String() + "\n"
			}
		} else {
			res += "- " + kE.String() + ": " + vE.String() + "\n"
		}
	}
	obtained.ForEach(func(kO Key, vO MapStateEntry) bool {
		if _, ok := expected[kO]; !ok {
			res += "+ " + kO.String() + ": " + vO.String() + "\n"
		}
		return true
	})
	return res
}

// diff returns the string of differences between 'obtained' and 'expected' prefixed with
// '+ ' or '- ' for obtaining something unexpected, or not obtaining the expected, respectively.
// For use in debugging.
func (obtained *mapState) diff(expected *mapState) (res string) {
	res += "Missing (-), Unexpected (+):\n"
	expected.forEach(func(kE Key, vE mapStateEntry) bool {
		if vO, ok := obtained.get(kE); ok {
			if !(&vO).deepEqual(&vE) {
				res += "- " + kE.String() + ": " + vE.String() + "\n"
				res += "+ " + kE.String() + ": " + vO.String() + "\n"
			}
		} else {
			res += "- " + kE.String() + ": " + vE.String() + "\n"
		}
		return true
	})
	obtained.forEach(func(kO Key, vO mapStateEntry) bool {
		if _, ok := expected.get(kO); !ok {
			res += "+ " + kO.String() + ": " + vO.String() + "\n"
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

// addDependentOnEntry adds 'dependent' to the set of dependent keys of 'e', where 'e' already
// exists in 'ms'.
func (ms *mapState) addDependentOnEntry(owner Key, e mapStateEntry, dependent Key, changes ChangeState) {
	if _, exists := e.dependents[dependent]; !exists {
		changes.insertOldIfNotExists(owner, e)
		e.AddDependent(dependent)
		ms.updateExisting(owner, e)
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
func (e *mapStateEntry) merge(entry *mapStateEntry) {
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
	if len(entry.derivedFromRules) > 0 {
		e.derivedFromRules.MergeSorted(entry.derivedFromRules)
	}
}

// IsRedirectEntry returns true if the entry redirects to a proxy port
func (e *MapStateEntry) IsRedirectEntry() bool {
	return e.ProxyPort != 0
}

// DatapathAndDerivedFromEqual returns true of two entries are equal in the datapath's PoV,
// i.e., IsDeny, ProxyPort and AuthType are the same for both entries, and the DerivedFromRules
// fields are also equal.
// This is used for testing only via mapState.Equal and mapState.Diff.
func (e *mapStateEntry) DatapathAndDerivedFromEqual(o *mapStateEntry) bool {
	if e == nil || o == nil {
		return e == o
	}

	return e.MapStateEntry == o.MapStateEntry && e.derivedFromRules.DeepEqual(&o.derivedFromRules)
}

// DeepEqual is a manually generated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
// Defined manually due to deepequal-gen not supporting interface types.
func (e *mapStateEntry) deepEqual(o *mapStateEntry) bool {
	if e.MapStateEntry != o.MapStateEntry {
		return false
	}

	if e.priority != o.priority {
		return false
	}

	if !e.derivedFromRules.DeepEqual(&o.derivedFromRules) {
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

	return true
}

func (e MapStateEntry) WithAuthType(authType AuthType) MapStateEntry {
	e.AuthType = authType
	return e
}

// String returns a string representation of the MapStateEntry
func (e MapStateEntry) String() string {
	return "ProxyPort=" + strconv.FormatUint(uint64(e.ProxyPort), 10) +
		",IsDeny=" + strconv.FormatBool(e.IsDeny) +
		",AuthType=" + e.AuthType.String()
}

// String returns a string representation of the MapStateEntry
func (e mapStateEntry) String() string {
	return e.MapStateEntry.String() +
		",derivedFromRules=" + fmt.Sprintf("%v", e.derivedFromRules) +
		",priority=" + strconv.FormatUint(uint64(e.priority), 10) +
		",owners=" + e.owners.String() +
		",dependents=" + fmt.Sprintf("%v", e.dependents)
}

// addKeyWithChanges adds a 'key' with value 'entry' to 'keys' keeping track of incremental changes in 'adds' and 'deletes', and any changed or removed old values in 'old', if not nil.
func (ms *mapState) addKeyWithChanges(key Key, entry mapStateEntry, changes ChangeState) bool {
	// Keep all owners that need this entry so that it is deleted only if all the owners delete their contribution
	var datapathEqual bool
	oldEntry, exists := ms.get(key)
	// Only merge if both old and new are allows or denies
	if exists && (oldEntry.IsDeny == entry.IsDeny) {
		// Do nothing if entries are equal
		if entry.deepEqual(&oldEntry) {
			return false // nothing to do
		}

		// Save old value before any changes, if desired
		changes.insertOldIfNotExists(key, oldEntry)

		// Compare for datapath equalness before merging, as the old entry is updated in
		// place!
		datapathEqual = oldEntry.MapStateEntry == entry.MapStateEntry
		oldEntry.merge(&entry)
		ms.updateExisting(key, oldEntry)
	} else if !exists || entry.IsDeny {
		// Insert a new entry if one did not exist or a deny entry is overwriting an allow
		// entry.

		// Save old value before any changes, if any
		if exists {
			changes.insertOldIfNotExists(key, oldEntry)
		}

		// Callers already have cloned the containers, no need to do it again here
		ms.insert(key, entry)
	} else {
		// Do not record and incremental add if nothing was done
		return false
	}

	// Record an incremental Add if desired and entry is new or changed
	if changes.Adds != nil && (!exists || !datapathEqual) {
		changes.Adds[key] = struct{}{}
		// Key add overrides any previous delete of the same key
		if changes.Deletes != nil {
			delete(changes.Deletes, key)
		}
	}

	return true
}

// deleteKeyWithChanges deletes a 'key' from 'keys' keeping track of incremental changes in 'adds'
// and 'deletes'.
// The key is unconditionally deleted if 'owner' is nil, otherwise only the contribution of this
// 'owner' is removed.
func (ms *mapState) deleteKeyWithChanges(key Key, owner MapStateOwner, changes ChangeState) {
	if entry, exists := ms.get(key); exists {
		// Save old value before any changes, if desired
		oldAdded := changes.insertOldIfNotExists(key, entry)
		if owner != nil {
			if entry.owners.Has(owner) {
				// remove this owner from entry's owners
				changed := entry.owners.Remove(owner)
				// Remove the dependency from the owner Key
				if ownerKey, ok := owner.(Key); ok {
					ms.RemoveDependent(ownerKey, key, changes)
				}
				// key is not deleted if other owners still need it
				if entry.owners.Len() > 0 {
					if changed {
						// re-insert entry due to owner change
						ms.updateExisting(key, entry)
					}
					return
				}
			} else {
				// 'owner' was not found, do not change anything
				if oldAdded {
					delete(changes.old, key)
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
	for k, v := range changes.old {
		ms.insert(k, v)
	}
}

// insertDependentOfKey adds a dependent entry to 'k' with the more specific port/proto of 'newKey'
// to ensure 'v' takes precedence.
// Called only for 'k' with specific identity and with broader protocol/port than l4-only 'newKey'.
func (ms *mapState) insertDependentOfKey(k Key, v mapStateEntry, newKey Key, changes ChangeState) {
	// Compute narrower 'key' with identity of 'k'
	key := newKey.WithIdentity(k.Identity)
	if ms.addKeyWithChanges(key, v.dependentOf(k), changes) {
		ms.addDependentOnEntry(k, v, key, changes)
	}
}

// insertDependentOfNewKey adds a dependent entry to 'newKey' with the more specific port/proto of
// 'k' to ensure 'newEntry' takes precedence.
// Called only for L4-only 'k' with narrower protocol/port than 'newKey' with a specific identity.
func (ms *mapState) insertDependentOfNewKey(newKey Key, newEntry *mapStateEntry, k Key, changes ChangeState) {
	// Compute narrower 'key' with identity of 'newKey'
	key := k.WithIdentity(newKey.Identity)
	if ms.addKeyWithChanges(key, newEntry.dependentOf(newKey), changes) {
		newEntry.AddDependent(key)
	}
}

// insertAuthOverrideFromKey adds a dependent entry to 'k' with the more specific port/proto of
// 'newKey' and with override auth type from 'v' to ensure auth type of 'v' is used for identity of
// 'k' also when the traffic matches the L4-only 'newKey'.
// Called only for 'k' with specific identity and with broader protocol/port than L4-only 'newKey'.
func (ms *mapState) insertAuthOverrideFromKey(k Key, v mapStateEntry, newKey Key, newEntry mapStateEntry, changes ChangeState) {
	// Compute narrower 'key' with identity of 'k'
	key := newKey.WithIdentity(k.Identity)
	if ms.addKeyWithChanges(key, newEntry.authOverrideFrom(k, &v), changes) {
		ms.addDependentOnEntry(k, v, key, changes)
	}
}

// insertAuthOverrideKey adds a dependent entry to 'newKey' with the more specific port/proto of 'k'
// and with override auth type from 'newEntry' to ensure auth type of 'newEntry' is used for
// identity of 'newKey' also when the traffic matches the L4-only 'k'.
// Called only for L4-only 'k' with narrower protocol/port than 'newKey' with a specific identity.
func (ms *mapState) insertAuthOverrideFromNewKey(newKey Key, newEntry *mapStateEntry, k Key, v mapStateEntry, changes ChangeState) {
	// Compute narrower 'key' with identity of 'newKey'
	key := k.WithIdentity(newKey.Identity)
	if ms.addKeyWithChanges(key, v.authOverrideFrom(newKey, newEntry), changes) {
		newEntry.AddDependent(key)
	}
}

func (ms *mapState) insertWithChanges(key Key, entry mapStateEntry, features policyFeatures, changes ChangeState) {
	ms.denyPreferredInsertWithChanges(key, entry, features, changes)
}

// denyPreferredInsertWithChanges contains the most important business logic for policy
// insertions. It inserts a key and entry into the map by giving preference to deny entries, and
// L3-only deny entries over L3-L4 allows.
//
// Since bpf datapath denies by default, we only need to add deny entries to carve out more specific
// holes to less specific allow rules. But since we don't if allow entries will be added later
// (e.g., incrementally due to FQDN rules), we must generally add deny entries even if there are no
// allow entries yet.
//
// Note on bailed or deleted entries: In general, if we bail out due to being covered by an existing
// entry, or delete an entry due to being covered by the new one, we would want this action reversed
// if the existing entry or this new one is incremantally removed, respectively.
// Generally, whenever a deny entry covers an allow entry (i.e., covering key has broader or equal
// protocol/port, and the keys have the same identity, or the covering key has wildcard identity (ID
// == 0)).
// Secondly, only keys with a specific identity (ID != 0) can be incrementally added or deleted.
// Finally, due to the selector cache being transactional, when an identity is removed, all keys
// with that identity are incrementally deleted.
// Hence, if a covering key is incrementally deleted, it is a key with a specific identity, and all
// keys covered by it will be deleted as well, so there is no situation where this bailed-out or
// deleted key should be reinstated due to the covering key being incrementally deleted.
//
// Note on added dependent L3/4 entries: Since the datapath always gives precedence to the matching
// entry with the most specific L4 (narrower protocol/port), we need to add L3/4 entries e.g., when
// precedence would be given to a narrower allow entry with the wildcard identity (L4-only key),
// while precedence should be given to the deny entry with a specific identity and broader L4 when
// the given packet matches both of them. To force the datapath to give precedence to the deny entry
// we add a new dependent deny entry with the identity of the (broader) deny entry and the L4
// protocol and port of the (narrower) L4-only key. The added key is marked as a dependent entry of
// the key with a specific identity (rather than the l4-only key), so that the dependent added entry
// is also deleted when the identity of its owner key is (incrementally) removed.
//
// Incremental changes performed are recorded in 'changes'.
func (ms *mapState) denyPreferredInsertWithChanges(newKey Key, newEntry mapStateEntry, features policyFeatures, changes ChangeState) {
	// Bail if covered by a deny key
	if !ms.denies.Empty() {
		for k := range ms.denies.BroaderOrEqualKeys(newKey) {
			// Identical deny key needs to be added to merge their entries.
			if k != newKey || !newEntry.IsDeny {
				return
			}
		}
	}

	if newEntry.IsDeny {
		// Delete covered allow entries.
		for k := range ms.allows.NarrowerOrEqualKeys(newKey) {
			ms.deleteKeyWithChanges(k, nil, changes)
		}
		// Delete covered deny entries, except for identical keys that need to be merged.
		for k := range ms.denies.NarrowerKeys(newKey) {
			ms.deleteKeyWithChanges(k, nil, changes)
		}

		// Add L3/4 deny entry for each more specific allow key with the wildcard identity
		// as the more specific allow would otherwise take precedence in the datapath over
		// the less specific 'newKey' with a specific identity.
		//
		// Skip when 'newKey' has no port wildcarding, as then there can't be any narrower
		// keys.
		if newKey.Identity != 0 && newKey.HasPortWildcard() {
			for k := range ms.allows.NarrowerKeysWithWildcardID(newKey) {
				ms.insertDependentOfNewKey(newKey, &newEntry, k, changes)
			}
		}
	} else {
		// newEntry is an allow entry.
		// NOTE: We do not delete redundant allow entries.

		// Avoid allocs in this block if there are no deny enties
		if !ms.denies.Empty() {
			// Add L3/4 deny entries for broader deny keys with a specific identity as
			// the narrower L4-only allow would otherwise take precedence in the
			// datapath.
			if newKey.Identity == 0 && newKey.Nexthdr != 0 { // L4-only newKey
				for k, v := range ms.denies.BroaderKeysWithSpecificID(newKey) {
					ms.insertDependentOfKey(k, v, newKey, changes)
				}
			}
		}

		// Checking for auth feature here is faster than calling 'authPreferredInsert' and
		// checking for it there.
		if features.contains(authRules) {
			ms.authPreferredInsert(newKey, newEntry, changes)
			return
		}
	}

	ms.addKeyWithChanges(newKey, newEntry, changes)
}

// overrideAuthType sets the AuthType of 'v' to that of 'newKey', saving the old entry in 'changes'.
func (ms *mapState) overrideAuthType(newEntry mapStateEntry, k Key, v mapStateEntry, changes ChangeState) {
	// Save the old value first
	changes.insertOldIfNotExists(k, v)

	// Auth type can be changed in-place, trie is not affected
	v.AuthType = newEntry.AuthType
	ms.allows.entries[k] = v
}

// authPreferredInsert applies AuthType of a more generic entry to more specific entries, if not
// explicitly specified.
//
// This function is expected to be called for a map insertion after deny
// entry evaluation. If there is a map entry that is a superset of 'newKey'
// which denies traffic matching 'newKey', then this function should not be called.
func (ms *mapState) authPreferredInsert(newKey Key, newEntry mapStateEntry, changes ChangeState) {
	if newEntry.hasAuthType == DefaultAuthType {
		// New entry has a default auth type.

		// Fill in the AuthType from the most specific covering key with an explicit
		// auth type
		for _, v := range ms.allows.CoveringKeys(newKey) {
			if v.hasAuthType == ExplicitAuthType {
				// AuthType from the most specific covering key is applied to
				// 'newEntry'
				newEntry.AuthType = v.AuthType
				break
			}
		}

		// Override the AuthType for specific L3/4 keys, if the newKey is L4-only,
		// and there is a key with broader port/proto for a specific identity that
		// has an explicit auth type.
		if newKey.Identity == 0 && newKey.Nexthdr != 0 { // L4-only newKey
			for k, v := range ms.allows.BroaderKeysWithSpecificID(newKey) {
				if v.hasAuthType == ExplicitAuthType {
					ms.insertAuthOverrideFromKey(k, v, newKey, newEntry, changes)
				}
			}
		}
	} else { // New entry has an explicit auth type
		// Check if the new key is the most specific covering key of any other key
		// with the default auth type, and propagate the auth type from the new
		// entry to such entries.
		if newKey.Identity == 0 {
			// A key with a wildcard ID can be the most specific covering key
			// for keys with any ID. Hence we need to iterate narrower keys with
			// all IDs and:
			// - change all iterated keys with a default auth type
			//   to the auth type of the newKey.
			// - stop iteration for any given ID at first key with that ID that
			//   has an explicit auth type, as that is the most specific covering
			//   key for the remaining subset keys with that specific ID.
			seenIDs := make(IDSet)
			for k, v := range ms.allows.SubsetKeys(newKey) {
				// Skip if a subset entry has an explicit auth type
				if v.hasAuthType == ExplicitAuthType {
					// Keep track of IDs for which an explicit auth type
					// has been encountered.
					seenIDs[k.Identity] = struct{}{}
					continue
				}
				// Override entries for which an explicit auth type has not been
				// seen yet.
				if _, exists := seenIDs[k.Identity]; !exists {
					ms.overrideAuthType(newEntry, k, v, changes)
				}
			}
		} else {
			// A key with a specific ID can be the most specific covering key
			// only for keys with the same ID. However, a wildcard ID key can also be
			// the most specific covering key for those keys, if it has a more
			// specific proto/port than the newKey. Hence we need to iterate
			// narrower keys with the same or ANY ID and:
			// - change all iterated keys with the same ID and a default auth
			//   type to the auth type of the newKey
			// - stop iteration at first key with an explicit auth, as that is
			//   the most specific covering key for the remaining subset keys with
			//   the same ID.
			for k, v := range ms.allows.SubsetKeys(newKey) {
				// Stop if a subset entry has an explicit auth type, as that is more
				// specific for all remaining subset keys
				if v.hasAuthType == ExplicitAuthType {
					break
				}
				// auth only propagates from a key with specific ID
				// to keys with the same ID.
				if k.Identity != 0 {
					ms.overrideAuthType(newEntry, k, v, changes)
				}
			}

			// Override authtype for specific L3L4 keys if 'newKey' with a
			// specific ID has an explicit AuthType and an L4-only 'k' has a
			// default AuthType. In this case AuthType of 'newEntry' should only
			// override the AuthType for the L3 & L4 combination, not L4 in
			// general.
			//
			// Only (partially) wildcarded port can have narrower keys.
			if newKey.HasPortWildcard() {
				for k, v := range ms.allows.NarrowerKeysWithWildcardID(newKey) {
					if v.hasAuthType == DefaultAuthType {
						ms.insertAuthOverrideFromNewKey(newKey, &newEntry, k, v, changes)
					}
				}
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
func (changes *ChangeState) insertOldIfNotExists(key Key, entry mapStateEntry) bool {
	if changes == nil || changes.old == nil {
		return false
	}
	if _, exists := changes.old[key]; !exists {
		// Only insert the old entry if the entry was not first added on this round of
		// changes.
		if _, added := changes.Adds[key]; !added {
			// Clone to keep this entry separate from the one that may remain in 'keys'
			entry.derivedFromRules = slices.Clone(entry.derivedFromRules)
			entry.owners = entry.owners.Clone()
			entry.dependents = maps.Clone(entry.dependents)

			changes.old[key] = entry
			return true
		}
	}
	return false
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
		entry := newMapStateEntry(nil, derivedFrom, 0, 0, false, ExplicitAuthType, AuthTypeDisabled) // Authentication never required for local host ingress
		ms.insertWithChanges(localHostKey, entry, allFeatures, ChangeState{})
	}
}

// allowAllIdentities translates all identities in selectorCache to their
// corresponding Keys in the specified direction (ingress, egress) which allows
// all at L3.
// Note that this is used when policy is not enforced, so authentication is explicitly not required.
func (ms *mapState) allowAllIdentities(ingress, egress bool) {
	if ingress {
		ms.allows.upsert(allKey[trafficdirection.Ingress], newMapStateEntry(nil, LabelsAllowAnyIngress, 0, 0, false, ExplicitAuthType, AuthTypeDisabled))
	}
	if egress {
		ms.allows.upsert(allKey[trafficdirection.Egress], newMapStateEntry(nil, LabelsAllowAnyEgress, 0, 0, false, ExplicitAuthType, AuthTypeDisabled))
	}
}

// MapChanges collects updates to the endpoint policy on the
// granularity of individual mapstate key-value pairs for both adds
// and deletes. 'mutex' must be held for any access.
type MapChanges struct {
	firstVersion versioned.KeepVersion
	mutex        lock.Mutex
	changes      []mapChange
	synced       []mapChange
	version      *versioned.VersionHandle
}

type mapChange struct {
	Add   bool // false deletes
	Key   Key
	Value mapStateEntry
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
func (mc *MapChanges) AccumulateMapChanges(adds, deletes []identity.NumericIdentity, keys []Key, value mapStateEntry) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	for _, id := range adds {
		for _, k := range keys {
			k.Identity = id
			mc.changes = append(mc.changes, mapChange{
				Add:   true,
				Key:   k,
				Value: value,
			})
		}
	}
	for _, id := range deletes {
		for _, k := range keys {
			k.Identity = id
			mc.changes = append(mc.changes, mapChange{
				Add:   false,
				Key:   k,
				Value: value,
			})
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
		old:     make(map[Key]mapStateEntry, len(mc.synced)),
	}

	for i := range mc.synced {
		key := mc.synced[i].Key
		entry := mc.synced[i].Value

		if mc.synced[i].Add {
			// Insert the key to and collect the incremental changes to the overall
			// state in 'changes'
			p.policyMapState.insertWithChanges(key, entry, features, changes)
		} else {
			// Delete the contribution of this cs to the key and collect incremental
			// changes
			cs, _ := entry.owners.Get() // get the sole selector
			p.policyMapState.deleteKeyWithChanges(key, cs, changes)
		}
	}

	// move version to the caller
	version := mc.version
	mc.version = nil

	mc.synced = nil

	return version, changes
}
