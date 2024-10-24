// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"iter"
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
type MapStateOwner = CachedSelector

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

	// Using largest possible port value since it has the lowest priority
	unrealizedRedirectPort = uint16(65535)
)

var (
	LabelsAllowAnyIngress = labels.LabelArrayList{labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyIngress, labels.LabelSourceReserved)}}
	LabelsAllowAnyEgress = labels.LabelArrayList{labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved)}}
)

// mapState is an indexed container for policymap keys and entries.
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
type mapState struct {
	// entries is the map containing the MapStateEntries
	entries map[Key]mapStateEntry
	// trie is a Trie that indexes policy Keys without their identity
	// and stores the identities in an associated builtin map.
	trie bitlpm.Trie[bitlpm.Key[policyTypes.LPMKey], IDSet]
}

type IDSet map[identity.NumericIdentity]struct{}

// Valid returns true if the entries map has been initialized
func (msm *mapState) Valid() bool {
	return msm.entries != nil
}

func (msm *mapState) Empty() bool {
	return len(msm.entries) == 0
}

func (msm *mapState) Lookup(k Key) (mapStateEntry, bool) {
	v, ok := msm.entries[k]
	return v, ok
}

func (msm *mapState) upsert(k Key, e mapStateEntry) {
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

func (msm *mapState) delete(k Key) {
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

func (msm *mapState) ForEach(f func(Key, MapStateEntry) bool) bool {
	for k, e := range msm.entries {
		if !f(k, e.MapStateEntry) {
			return false
		}
	}
	return true
}

func (msm *mapState) forEach(f func(Key, mapStateEntry) bool) bool {
	for k, e := range msm.entries {
		if !f(k, e) {
			return false
		}
	}
	return true
}

func (msm *mapState) forKey(k Key, f func(Key, mapStateEntry) bool) bool {
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
func (msm *mapState) forDifferentKeys(key, k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	for id := range idSet {
		k.Identity = id
		if key != k && !msm.forKey(k, f) {
			return false
		}
	}
	return true
}

// forIDs calls 'f' for each ID in 'idSet' with port/proto from 'k'.
func (msm *mapState) forIDs(k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	for id := range idSet {
		k.Identity = id
		if !msm.forKey(k, f) {
			return false
		}
	}
	return true
}

// forID calls 'f' for 'k' if 'k.Identity' exists in 'idSet'.
func (msm *mapState) forID(k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	if _, exists := idSet[k.Identity]; exists {
		if !msm.forKey(k, f) {
			return false
		}
	}
	return true
}

// BroaderOrEqualKeys iterates over broader or equal (broader or equal port/proto and the same
// or wildcard ID) in the trie.
func (msm *mapState) BroaderOrEqualKeys(key Key) iter.Seq2[Key, mapStateEntry] {
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
// TODO: remove, not used
func (msm *mapState) NarrowerKeys(key Key) iter.Seq2[Key, mapStateEntry] {
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
func (msm *mapState) NarrowerOrEqualKeys(key Key) iter.Seq2[Key, mapStateEntry] {
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

// CoveringKeysWithSameID iterates over broader port/proto entries in the trie in LPM order,
// with most specific match with the same ID as in 'key' being returned first.
func (msm *mapState) CoveringKeysWithSameID(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := msm.trie.AncestorLongestPrefixFirstIterator(key.PrefixLength(), key)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey.Value()}

			// Visit key with the same identity, if port/proto is different.
			if !k.PortProtoIsEqual(key) && !msm.forID(k.WithIdentity(key.Identity), idSet, yield) {
				return
			}
		}
	}
}

// SubsetKeysWithSameID iterates over narrower or equal port/proto entries in the trie in an LPM
// order (least specific match first).
func (msm *mapState) SubsetKeysWithSameID(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := msm.trie.DescendantShortestPrefixFirstIterator(key.PrefixLength(), key)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey.Value()}

			// Visit key with the same identity, if port/proto is different.
			if !k.PortProtoIsEqual(key) && !msm.forID(k.WithIdentity(key.Identity), idSet, yield) {
				return
			}
		}
	}
}

func (msm *mapState) Len() int {
	return len(msm.entries)
}

// MapStateEntry is the configuration associated with a Key in a
// MapState. This is a minimized version of policymap.PolicyEntry.
type MapStateEntry struct {
	// Listener name for proxy redirection, if any
	Listener string

	// The proxy port, in host byte order.
	// If 0 (default), there is no proxy redirection for the corresponding
	// Key. Any other value signifies proxy redirection.
	ProxyPort uint16

	// IsDeny is true when the policy should be denied.
	IsDeny bool

	// HasAuthType is 'DefaultAuthType' when policy has no explicit AuthType set. In this case
	// the value of AuthType is derived from more generic entries covering this entry.
	HasAuthType HasAuthType

	// AuthType is non-zero when authentication is required for the traffic to be allowed.
	AuthType AuthType
}

// mapSteteEntry is the entry type with additional internal bookkeping of the relation between
// explicitly and implicitly added entries.
type mapStateEntry struct {
	MapStateEntry

	// priority is used to select the Listener if multiple rules would apply different listeners
	// to a policy map entry. Lower numbers indicate higher priority. If left out, the proxy
	// port number (10000-20000) is used.
	priority uint16

	// derivedFromRules tracks the policy rules this entry derives from.
	// In sorted order.
	derivedFromRules labels.LabelArrayList

	// owners collects the keys in the map and selectors in the policy that require this key to be present.
	// TODO: keep track which selector needed the entry to be deny, redirect, or just allow.
	owners set.Set[MapStateOwner]
}

// newMapStateEntry creates a map state entry. If redirect is true, the
// caller is expected to replace the ProxyPort field before it is added to
// the actual BPF map.
// 'cs' is used to keep track of which policy selectors need this entry. If it is 'nil' this entry
// will become sticky and cannot be completely removed via incremental updates. Even in this case
// the entry may be overridden or removed by a deny entry.
func newMapStateEntry(cs MapStateOwner, derivedFrom labels.LabelArrayList, proxyPort uint16, listener string, priority uint16, deny bool, hasAuth HasAuthType, authType AuthType) mapStateEntry {
	if proxyPort == 0 {
		listener = ""
		priority = 0
	} else if priority == 0 {
		priority = proxyPort // default for tie-breaking
	}
	return mapStateEntry{
		MapStateEntry: MapStateEntry{
			Listener:    listener,
			ProxyPort:   proxyPort,
			IsDeny:      deny,
			HasAuthType: hasAuth,
			AuthType:    authType,
		},
		priority:         priority,
		derivedFromRules: derivedFrom,
		owners:           set.NewSet(cs),
	}
}

func (e MapStateEntry) toMapStateEntry(priority uint16, cs MapStateOwner, derivedFrom labels.LabelArrayList) mapStateEntry {
	if e.ProxyPort == 0 {
		e.Listener = ""
		priority = 0
	} else if priority == 0 {
		priority = e.ProxyPort // default for tie-breaking
	}
	return mapStateEntry{
		MapStateEntry:    e,
		priority:         priority,
		derivedFromRules: derivedFrom,
		owners:           set.NewSet(cs),
	}
}

func (e *mapStateEntry) GetRuleLabels() labels.LabelArrayList {
	return e.derivedFromRules
}

func newMapState() mapState {
	return mapState{
		entries: make(map[Key]mapStateEntry),
		trie:    bitlpm.NewTrie[policyTypes.LPMKey, IDSet](policyTypes.MapStatePrefixLen),
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
	return ms.Lookup(k)
}

// insert the Key and MapStateEntry into the MapState
func (ms *mapState) insert(k Key, v mapStateEntry) {
	if k.DestPort == 0 && k.PortPrefixLen() > 0 {
		log.WithFields(logrus.Fields{
			logfields.Stacktrace: hclog.Stacktrace(),
			logfields.PolicyKey:  k,
		}).Errorf("mapState.insert: invalid port prefix length for wildcard port")
	}
	ms.upsert(k, v)
}

// updateExisting re-inserts an existing entry to its map, to be used to persist changes in the
// entry. Indices are not updated.
func (ms *mapState) updateExisting(k Key, v mapStateEntry) {
	ms.entries[k] = v
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
		return ok && (&vB).Equal(&vA.MapStateEntry)
	})
}

// Equal determines if this mapState is equal to the argument mapState.
// Only used for testing.
func (msA *mapState) Equal(msB *mapState) bool {
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
			if !(&vO.MapStateEntry).Equal(&vE) {
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

// merge adds owners, and DerivedFromRules from a new 'entry' to an existing
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
				e.Listener = entry.Listener
				e.priority = entry.priority
			}
		}

		// Explicit auth takes precedence over defaulted one.
		if entry.HasAuthType == ExplicitAuthType {
			if e.HasAuthType == ExplicitAuthType {
				// Numerically higher AuthType takes precedence when both are explicitly defined
				if entry.AuthType > e.AuthType {
					e.AuthType = entry.AuthType
				}
			} else {
				e.HasAuthType = ExplicitAuthType
				e.AuthType = entry.AuthType
			}
		} else if e.HasAuthType == DefaultAuthType {
			e.AuthType = entry.AuthType // new default takes precedence
		}
	}

	e.owners.Merge(entry.owners)

	// merge DerivedFromRules
	if len(entry.derivedFromRules) > 0 {
		e.derivedFromRules.MergeSorted(entry.derivedFromRules)
	}
}

// IsRedirectEntry returns true if the entry redirects to a proxy port
func (e *MapStateEntry) IsRedirectEntry() bool {
	return e.ProxyPort != 0
}

// Equal returns true of two entries are equal,
// i.e., IsDeny, ProxyPort and AuthType are the same for both entries.
func (e *MapStateEntry) Equal(o *MapStateEntry) bool {
	if e == nil || o == nil {
		return e == o
	}

	return e.IsDeny == o.IsDeny && e.ProxyPort == o.ProxyPort && e.AuthType == o.AuthType
}

// DatapathAndDerivedFromEqual returns true of two entries are equal in the datapath's PoV,
// i.e., IsDeny, ProxyPort and AuthType are the same for both entries, and the DerivedFromRules
// fields are also equal.
// This is used for testing only via mapState.Equal and mapState.Diff.
func (e *mapStateEntry) DatapathAndDerivedFromEqual(o *mapStateEntry) bool {
	if e == nil || o == nil {
		return e == o
	}

	return e.IsDeny == o.IsDeny && e.ProxyPort == o.ProxyPort && e.AuthType == o.AuthType &&
		e.derivedFromRules.DeepEqual(&o.derivedFromRules)
}

// DeepEqual is a manually generated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
// Defined manually due to deepequal-gen not supporting interface types.
func (e *mapStateEntry) deepEqual(o *mapStateEntry) bool {
	if !e.Equal(&o.MapStateEntry) {
		return false
	}

	if e.Listener != o.Listener || e.priority != o.priority {
		return false
	}

	if !e.derivedFromRules.DeepEqual(&o.derivedFromRules) {
		return false
	}

	if !e.owners.Equal(o.owners) {
		return false
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
		",Listener=" + e.Listener +
		",IsDeny=" + strconv.FormatBool(e.IsDeny) +
		",AuthType=" + e.AuthType.String()
}

// String returns a string representation of the MapStateEntry
func (e mapStateEntry) String() string {
	return e.MapStateEntry.String() +
		",derivedFromRules=" + fmt.Sprintf("%v", e.derivedFromRules) +
		",priority=" + strconv.FormatUint(uint64(e.priority), 10) +
		",owners=" + e.owners.String()
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
		datapathEqual = oldEntry.Equal(&entry.MapStateEntry)
		oldEntry.merge(&entry)
		ms.updateExisting(key, oldEntry)
	} else if !exists || entry.IsDeny {
		// Insert a new entry if one did not exist or a deny entry is overwriting an allow
		// entry.
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

		if changes.Deletes != nil {
			changes.Deletes[key] = struct{}{}
			// Remove a potential previously added key
			if changes.Adds != nil {
				delete(changes.Adds, key)
			}
		}

		ms.delete(key)
	}
}

// RevertChanges undoes changes to 'keys' as indicated by 'changes.adds' and 'changes.old' collected via
// denyPreferredInsertWithChanges().
func (ms *mapState) revertChanges(changes ChangeState) {
	for k := range changes.Adds {
		ms.delete(k)
	}
	// 'old' contains all the original values of both modified and deleted entries
	for k, v := range changes.old {
		ms.insert(k, v)
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
// Whenever the bpf datapath finds both L4-only and L3/L4 matching policy entries for a given
// packet, it uses the following logic to choose the policy entry:
// - L4-only entry is chosen if it is a deny or has more specific port/proto than the L3/L4 entry
// - otherwise the L3/L4 entry is chosen
//
// This gives precedence for deny entry, or if none is present, then the one with the more specific
// L4 is chosen. This means that it suffices to manage deny precedence among the keys with the same
// ID here, the datapath take care of the precedence between different IDs (that is, between a
// specific ID and the wildcard ID (==0)
//
// Note on bailed or deleted entries:
//
// It would seem like that when we bail out due to being covered by an existing
// entry, or delete an entry due to being covered by the new one, we would want this action reversed
// if the existing entry or this new one is incremantally removed, respectively.
//
// Consider these facts:
//  1. Whenever a deny entry covers an allow entry, the covering key has broader or equal
//     protocol/port, and the keys have the same identity, or the covering key has wildcard identity
//     (ID == 0).
//  2. Only keys with a specific identity (ID != 0) can be incrementally added or deleted.
//  3. Due to the selector cache being transactional, when an identity is removed, all keys
//     with that identity are incrementally deleted.
//
// Hence, if a covering key is incrementally deleted, it is a key with a specific identity (2), and
// all keys covered by it will be deleted as well (3), so there is no situation where this
// bailed-out or deleted key should be reinstated due to the covering key being incrementally
// deleted.
//
// Incremental changes performed are recorded in 'changes'.
func (ms *mapState) denyPreferredInsertWithChanges(newKey Key, newEntry mapStateEntry, features policyFeatures, changes ChangeState) {
	// Bail if covered by a deny key
	for k, v := range ms.BroaderOrEqualKeys(newKey) {
		// Identical deny key needs to be added to merge their entries.
		if v.IsDeny && !(newEntry.IsDeny && k == newKey) {
			return
		}
	}

	if newEntry.IsDeny {
		// Delete covered entries
		for k, v := range ms.NarrowerOrEqualKeys(newKey) {
			// Except for identical deny keys that need to be merged.
			if !(v.IsDeny && k == newKey) {
				ms.deleteKeyWithChanges(k, nil, changes)
			}
		}
	} else {
		// newEntry is an allow entry.
		// NOTE: We do not delete redundant allow entries.

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
	ms.entries[k] = v
}

// authPreferredInsert applies AuthType of a more generic entry to more specific entries, if not
// explicitly specified.
//
// This function is expected to be called for a map insertion after deny
// entry evaluation. If there is a covering map key for 'newKey'
// which denies traffic matching 'newKey', then this function should not be called.
func (ms *mapState) authPreferredInsert(newKey Key, newEntry mapStateEntry, changes ChangeState) {
	if newEntry.HasAuthType == DefaultAuthType {
		// New entry has a default auth type.

		// Fill in the AuthType from the most specific covering key with the same ID and an
		// explicit auth type
		for _, v := range ms.CoveringKeysWithSameID(newKey) {
			if v.IsDeny {
				panic("covering deny key should not exist")
			}
			if v.HasAuthType == ExplicitAuthType {
				// AuthType from the most specific covering key is applied to
				// 'newEntry'
				newEntry.AuthType = v.AuthType
				break
			}
		}
	} else { // New entry has an explicit auth type
		// Check if the new key is the most specific covering key of any other key
		// with the same ID and default auth type, and propagate the auth type from the new
		// entry to such entries.
		for k, v := range ms.SubsetKeysWithSameID(newKey) {
			if v.IsDeny || v.HasAuthType == ExplicitAuthType {
				// Stop if a subset entry is deny or has an explicit auth type, as
				// that is the more specific covering key for all remaining subset
				// keys
				break
			}
			ms.overrideAuthType(newEntry, k, v, changes)
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
		entry := newMapStateEntry(nil, derivedFrom, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled) // Authentication never required for local host ingress
		ms.insertWithChanges(localHostKey, entry, allFeatures, ChangeState{})
	}
}

// allowAllIdentities translates all identities in selectorCache to their
// corresponding Keys in the specified direction (ingress, egress) which allows
// all at L3.
// Note that this is used when policy is not enforced, so authentication is explicitly not required.
func (ms *mapState) allowAllIdentities(ingress, egress bool) {
	if ingress {
		ms.upsert(allKey[trafficdirection.Ingress], newMapStateEntry(nil, LabelsAllowAnyIngress, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled))
	}
	if egress {
		ms.upsert(allKey[trafficdirection.Egress], newMapStateEntry(nil, LabelsAllowAnyEgress, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled))
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
		if mc.synced[i].Add {
			// Redirect entries for unrealized redirects come in with an invalid
			// redirect port (65535), replace it with the actual proxy port number.
			key := mc.synced[i].Key
			entry := mc.synced[i].Value
			if entry.ProxyPort == unrealizedRedirectPort {
				var exists bool
				proxyID := ProxyIDFromKey(uint16(p.PolicyOwner.GetID()), key, entry.Listener)
				entry.ProxyPort, exists = p.Redirects[proxyID]
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
			p.policyMapState.insertWithChanges(key, entry, features, changes)
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
