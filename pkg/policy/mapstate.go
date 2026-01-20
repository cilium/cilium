// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"iter"
	"log/slog"
	"slices"
	"strconv"

	"github.com/hashicorp/go-hclog"

	"github.com/cilium/cilium/pkg/container/bitlpm"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
)

// Key and Keys are types used both internally and externally.
// The types have been lifted out, but an alias is being used
// so we don't have to change all the code everywhere.
//
// Do not use these types outside of pkg/policy or pkg/endpoint,
// lest ye find yourself with hundreds of unnecessary imports.
type Key = types.Key
type Keys = types.Keys
type LPMKeys = types.LPMKeys
type MapStateEntry = types.MapStateEntry
type MapStateMap = types.MapStateMap

const NoAuthRequirement = types.NoAuthRequirement

type mapStateMap map[Key]mapStateEntry

func EgressKey() types.Key {
	return types.EgressKey()
}

func IngressKey() types.Key {
	return types.IngressKey()
}

func KeyForDirection(direction trafficdirection.TrafficDirection) Key {
	return types.KeyForDirection(direction)
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
	LabelDenyAnyIngress        = "deny-any-ingress"
	LabelAllowAnyEgress        = "allow-any-egress"
	LabelDenyAnyEgress         = "deny-any-egress"
)

var (
	LabelsAllowAnyIngress = labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyIngress, labels.LabelSourceReserved)}
	LabelsDenyAnyIngress = labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelDenyAnyIngress, labels.LabelSourceReserved)}
	LabelsAllowAnyEgress = labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved)}
	LabelsDenyAnyEgress = labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelDenyAnyEgress, labels.LabelSourceReserved)}
	LabelsLocalHostIngress = labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowLocalHostIngress, labels.LabelSourceReserved)}
)

type L34Entry struct {
	key   Key
	entry mapStateEntry
}

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
	logger *slog.Logger
	// entries is the map containing the MapStateEntries
	entries mapStateMap
	// trie is a Trie that indexes policy Keys without their identity
	// and stores the identities in an associated builtin map.
	trie bitlpm.Trie[types.LPMKey, IDSet]
	// idIndex indexes entries by ID
	byId map[identity.NumericIdentity]LPMKeys
	// temp space for L3/4 entries to be added
	inserts []L34Entry
}

type IDSet map[identity.NumericIdentity]struct{}

// Valid returns true if the entries map has been initialized
func (ms *mapState) Valid() bool {
	return ms.entries != nil
}

func (ms *mapState) Empty() bool {
	return len(ms.entries) == 0
}

func (ms *mapState) upsert(k Key, e mapStateEntry) {
	_, exists := ms.entries[k]

	// upsert entry
	ms.entries[k] = e

	// Update indices if 'k' is a new key
	if !exists {
		// Update trie
		idSet, ok := ms.trie.ExactLookup(k.PrefixLength(), k.LPMKey)
		if !ok {
			idSet = make(IDSet)
			ms.trie.Upsert(k.PrefixLength(), k.LPMKey, idSet)
		}
		idSet[k.Identity] = struct{}{}

		// update byId if in use
		if ms.byId != nil {
			keys := ms.byId[k.Identity]
			if keys == nil {
				keys = make(LPMKeys)
				ms.byId[k.Identity] = keys
			}
			keys[k.LPMKey] = struct{}{}
		}
	}
}

func (ms *mapState) delete(k Key) {
	_, exists := ms.entries[k]
	if exists {
		delete(ms.entries, k)

		idSet, ok := ms.trie.ExactLookup(k.PrefixLength(), k.LPMKey)
		if ok {
			delete(idSet, k.Identity)
			if len(idSet) == 0 {
				ms.trie.Delete(k.PrefixLength(), k.LPMKey)
			}
		}

		if ms.byId != nil {
			keys := ms.byId[k.Identity]
			if keys != nil {
				delete(keys, k.LPMKey)
				if len(keys) == 0 {
					delete(ms.byId, k.Identity)
				}
			}
		}
	}
}

func (ms *mapState) ForEach(f func(Key, MapStateEntry) bool) bool {
	for k, e := range ms.entries {
		if !f(k, e.MapStateEntry) {
			return false
		}
	}
	return true
}

func (ms *mapState) forEach(f func(Key, mapStateEntry) bool) bool {
	for k, e := range ms.entries {
		if !f(k, e) {
			return false
		}
	}
	return true
}

func (ms *mapState) forKey(k Key, f func(Key, mapStateEntry) bool) bool {
	e, ok := ms.entries[k]
	if ok {
		return f(k, e)
	}
	ms.logger.Error(
		"Missing MapStateEntry",
		logfields.Stacktrace, hclog.Stacktrace(),
		logfields.PolicyKey, k,
	)
	return true
}

// forIDs calls 'f' for each ID in 'idSet' with port/proto from 'k'.
func (ms *mapState) forIDs(k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	for id := range idSet {
		k.Identity = id
		if !ms.forKey(k, f) {
			return false
		}
	}
	return true
}

// forID calls 'f' for 'k' if 'k.Identity' exists in 'idSet'.
func (ms *mapState) forID(k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	if _, exists := idSet[k.Identity]; exists {
		if !ms.forKey(k, f) {
			return false
		}
	}
	return true
}

// BroaderOrEqualKeys iterates over broader or equal (broader or equal port/proto and the same
// or wildcard ID) in the trie.
// If a key is a wildcard key then also keys with any specific IDs are returned!
func (ms *mapState) BroaderOrEqualKeys(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := ms.trie.AncestorIterator(key.PrefixLength(), key.LPMKey)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey}

			// Visit all identities for an ANY key
			if key.Identity == 0 {
				if !ms.forIDs(k, idSet, yield) {
					return
				}
				continue
			}

			// ANY identity is broader or equal to all identities, visit it first if it
			// exists
			if !ms.forID(k.WithIdentity(0), idSet, yield) {
				return
			}

			// Visit key with the same identity, if it exists.
			// ANY identity was already visited above.
			if key.Identity != 0 && !ms.forID(k.WithIdentity(key.Identity), idSet, yield) {
				return
			}
		}
	}
}

// NarrowerOrEqualKeys iterates over narrower or equal keys in the trie.
// Iterated keys can be safely deleted during iteration due to DescendantIterator holding enough
// state that allows iteration to be continued even if the current trie node is removed.
func (ms *mapState) NarrowerOrEqualKeys(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := ms.trie.DescendantIterator(key.PrefixLength(), key.LPMKey)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey}

			// All identities are narrower or equal to ANY identity.
			if key.Identity == 0 {
				if !ms.forIDs(k, idSet, yield) {
					return
				}
			} else { // key has a specific identity
				// Need to visit the key with the same identity, if it exists.
				if !ms.forID(k.WithIdentity(key.Identity), idSet, yield) {
					return
				}
			}
		}
	}
}

// CoveringKeysWithSameID iterates over broader or equal port/proto entries in the trie in LPM order,
// with most specific match with the same ID as in 'key' being returned first.
func (ms *mapState) CoveringKeysWithSameID(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := ms.trie.AncestorLongestPrefixFirstIterator(key.PrefixLength(), key.LPMKey)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey}

			// Visit key with the same identity
			if !ms.forID(k.WithIdentity(key.Identity), idSet, yield) {
				return
			}
		}
	}
}

// SubsetKeysWithSameID iterates over narrower or equal port/proto entries in the trie in an LPM
// order (least specific match first).
func (ms *mapState) SubsetKeysWithSameID(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := ms.trie.DescendantShortestPrefixFirstIterator(key.PrefixLength(), key.LPMKey)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey}

			// Visit key with the same identity
			if !ms.forID(k.WithIdentity(key.Identity), idSet, yield) {
				return
			}
		}
	}
}

// LPMAncestors iterates over broader or equal port/proto entries in the trie in LPM order,
// with most specific match with the same ID as in 'key' being returned first.
func (ms *mapState) LPMAncestors(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := ms.trie.AncestorLongestPrefixFirstIterator(key.PrefixLength(), key.LPMKey)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey}

			// Visit key with the same identity, if one exists.
			if !ms.forID(k.WithIdentity(key.Identity), idSet, yield) {
				return
			}
			// Then visit key with zero identity if not already done above and one
			// exists.
			if key.Identity != 0 && !ms.forID(k.WithIdentity(0), idSet, yield) {
				return
			}
		}
	}
}

// lookup finds the policy verdict applicable to the given 'key' using the same precedence logic
// between L3 and L4-only policies as the bpf datapath  when both match the given 'key'.
// To be used in testing in place of the bpf datapath when full integration testing is not desired.
// Returns the closest matching covering policy entry and 'true' if found.
// 'key' must not have a wildcard identity or port.
func (ms *mapState) lookup(key Key) (mapStateEntry, bool) {
	// Validate that the search key has no wildcards
	if key.Identity == 0 || key.Nexthdr == 0 || key.DestPort == 0 || key.EndPort() != key.DestPort {
		ms.logger.Error(
			"invalid key for Lookup",
			logfields.Stacktrace, hclog.Stacktrace(),
			logfields.PolicyKey, key,
		)
	}
	var l3key, l4key Key
	var l3entry, l4entry mapStateEntry
	var haveL3, haveL4 bool
	for k, v := range ms.LPMAncestors(key) {
		if !haveL3 && k.Identity != 0 {
			if v.IsValid() {
				l3key, l3entry = k, v
				haveL3 = true
			}
		}
		if !haveL4 && k.Identity == 0 {
			if v.IsValid() {
				l4key, l4entry = k, v
				haveL4 = true
			}
		}
		if haveL3 && haveL4 {
			break
		}
	}

	authOverride := func(entry, other mapStateEntry) mapStateEntry {
		// This logic needs to be the same as in authPreferredInsert() where the newEntry's
		// auth type may be overridden by a covering key.
		// This also needs to reflect the logic in bpf/lib/policy.h __account_and_check().
		if !entry.AuthRequirement.IsExplicit() &&
			other.AuthRequirement.AuthType() > entry.AuthRequirement.AuthType() &&
			other.AllowPrecedence() >= entry.AllowPrecedence() {
			entry.AuthRequirement = other.AuthRequirement.AsDerived()
		}
		return entry
	}

	// only one entry found
	if haveL3 != haveL4 {
		if haveL3 {
			return l3entry, true
		}
		return l4entry, true
	}

	// both L3 and L4 matches found
	if haveL3 && haveL4 {
		// Precedence rules of the bpf datapath between two policy entries:
		// 1. higher precedence level entry wins, but auth may need to be propagated.
		// 2. if Deny at same precedence level, no further processing is needed
		// 3. if both entries are allows at the same precedence level, the one with more
		//    specific L4 is selected
		// 4. If the two allows on the same precedence level have equal port/proto, then
		//    the policy for a specific L3 is selected (rather than the L4-only entry)
		//
		// If the selected entry has non-explicit auth type, it gets the auth type from the
		// other entry, if the other entry's auth type is numerically higher.

		// 1. Entry with higher precedence level is selected.
		//    Auth requirement does not propagate from a lower precedence rule to a
		//    higher precedence rule!
		if l3entry.Precedence > l4entry.Precedence {
			return l3entry, true
		}
		if l4entry.Precedence > l3entry.Precedence {
			return l4entry, true
		}

		// 2. Entries at the same precedence,
		// Check for the L3 deny first to match the datapath behavior
		if l3entry.IsDeny() {
			return l3entry, true
		}

		// 3. Two allow entries, select the one with more specific L4
		// L3-entry must be selected if prefix lengths are the same!
		if l4key.PrefixLength() > l3key.PrefixLength() {
			return authOverride(l4entry, l3entry), true
		}
		// 4. Two allow entries are equally specific port/proto or L3-entry is more specific
		return authOverride(l3entry, l4entry), true
	}

	// Deny by default if no matches are found
	return mapStateEntry{MapStateEntry: types.DenyEntry(), derivedFromRules: NilRuleOrigin}, false
}

func (ms *mapState) Len() int {
	return len(ms.entries)
}

// Skeleton returns a preallocated mapState, allocating map capacities for the new mapState from the
// map lengths of the current 'ms'.
func (ms *mapState) Skeleton() mapState {
	sk := mapState{
		logger:  ms.logger,
		entries: make(mapStateMap, len(ms.entries)),
		trie:    bitlpm.NewTrie[types.LPMKey, IDSet](types.MapStatePrefixLen),
	}
	if ms.byId != nil {
		sk.byId = make(map[identity.NumericIdentity]LPMKeys, len(ms.byId))

		// preallocate id index keysets to their current sizes
		for k, v := range ms.byId {
			sk.byId[k] = make(LPMKeys, len(v))
		}
	}
	return sk
}

type passMeta struct {
	// passPrecedence is the precedence of a PASS verdict on the key of this entry.
	// This is separate from the MapStateEntry.Precedence, as an allow or deny entry may
	// have the same key, and both need to be kept
	passPrecedence types.Precedence

	// nextTierPrecedence is the base precedence of the next tier.
	// This is used when bumping lower tier entry precedences due to a covering pass entry,
	// and to discern if a given new entry is on the same tier as the pass enrty.
	nextTierPrecedence types.Precedence
}

// mapStateEntry is the entry type with additional internal bookkeping of the relation between
// explicitly and implicitly added entries.
type mapStateEntry struct {
	MapStateEntry

	passMeta

	// derivedFromRules tracks the policy rules this entry derives from.
	// Must be initialized explicitly, zero-intialization does not work with unique.Handle[].
	derivedFromRules ruleOrigin
}

func (e mapStateEntry) IsPassEntry() bool {
	return e.passPrecedence != 0
}

// Precedence returns the precedence of the entry, which is the highest of the passPrecedence
// and MapStateEntry.Precedence if both are valid.
// Returns zero for for an invalid entry that is not a pass entry.
func (e mapStateEntry) GetPrecedence() types.Precedence {
	precedence := e.passPrecedence
	if e.IsValid() && e.Precedence > precedence {
		precedence = e.Precedence
	}
	return precedence
}

// PassEntry returns a MapStateEntry with maximum precedence for a pass entry
func PassEntry(priority, nextTierPriority types.Priority, derivedFrom ruleOrigin) mapStateEntry {
	return mapStateEntry{
		passMeta: passMeta{
			passPrecedence:     priority.ToPassPrecedence(),
			nextTierPrecedence: nextTierPriority.ToPassPrecedence(),
		},
		MapStateEntry:    types.InvalidEntry(),
		derivedFromRules: derivedFrom,
	}
}

// newMapStateEntry creates a map state entry.
func newMapStateEntry(
	priority types.Priority,
	nextTierPriority types.Priority,
	derivedFrom ruleOrigin,
	proxyPort uint16,
	listenerPriority ListenerPriority,
	verdict types.Verdict,
	authReq AuthRequirement,
) mapStateEntry {
	if verdict == types.Pass {
		return PassEntry(priority, nextTierPriority, derivedFrom)
	}
	return mapStateEntry{
		MapStateEntry:    types.NewMapStateEntry(priority, verdict == types.Deny, proxyPort, listenerPriority, authReq),
		derivedFromRules: derivedFrom,
	}
}

var invalidMapStateEntry = mapStateEntry{MapStateEntry: types.InvalidEntry()}

func makeInvalidEntry() mapStateEntry {
	return invalidMapStateEntry
}

// newAllowEntryWithLabels creates an allow entry with the specified labels.
// Used for adding allow-all entries when policy enforcement is not wanted.
func newAllowEntryWithLabels(lbls labels.LabelArray) mapStateEntry {
	return newMapStateEntry(0, types.MaxPriority, makeSingleRuleOrigin(lbls, ""), 0, 0, types.Allow, NoAuthRequirement)
}

func NewMapStateEntry(e MapStateEntry) mapStateEntry {
	return mapStateEntry{
		MapStateEntry:    e,
		derivedFromRules: NilRuleOrigin,
	}
}

func emptyMapState(logger *slog.Logger) mapState {
	return newMapState(logger, mapState{}, 0)
}

func newMapState(logger *slog.Logger, ms mapState, features policyFeatures) mapState {
	// replace skeleton if entries map is nil
	if ms.entries == nil {
		ms = mapState{
			logger:  logger,
			entries: make(mapStateMap),
			trie:    bitlpm.NewTrie[types.LPMKey, IDSet](types.MapStatePrefixLen),
		}
	}

	// initialize byId index if needed for pass verdict processing
	if features&passRules != 0 {
		ms.byId = make(map[identity.NumericIdentity]LPMKeys)
	}
	return ms
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
		ms.logger.Error(
			"mapState.Get: invalid port prefix length for wildcard port",
			logfields.Stacktrace, hclog.Stacktrace(),
			logfields.PolicyKey, k,
		)
	}

	v, ok := ms.entries[k]
	return v, ok
}

// insert the Key and MapStateEntry into the MapState
func (ms *mapState) insert(k Key, v mapStateEntry) {
	if k.DestPort == 0 && k.PortPrefixLen() > 0 {
		ms.logger.Error(
			"mapState.insert: invalid port prefix length for wildcard port",
			logfields.Stacktrace, hclog.Stacktrace(),
			logfields.PolicyKey, k,
		)
	}
	ms.upsert(k, v)
}

// updateExisting re-inserts an existing entry to its map, to be used to persist changes in the
// entry. Indices are not updated.
func (ms *mapState) updateExisting(k Key, v mapStateEntry) {
	ms.entries[k] = v
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

// Equal determines if this mapState is equal to the argument mapState.
// Only used for testing.
func (msA *mapState) Equal(msB *mapState) bool {
	if msA.Len() != msB.Len() {
		return false
	}
	return msA.forEach(func(kA Key, vA mapStateEntry) bool {
		vB, ok := msB.get(kA)
		return ok && (&vB).Equal(&vA)
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
			if !(&vO).Equal(&vE) {
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

func (ms mapState) String() (res string) {
	ms.forEach(func(kO Key, vO mapStateEntry) bool {
		res += kO.String() + ": " + vO.String() + "\n"
		return true
	})
	return res
}

// Equal returns true of two entries are equal.
// This is used for testing only via mapState.Equal and mapState.Diff.
func (e *mapStateEntry) Equal(o *mapStateEntry) bool {
	if e == nil || o == nil {
		return e == o
	}

	return *e == *o
}

// String returns a string representation of the MapStateEntry
func (e mapStateEntry) String() string {
	var pass string
	if e.passPrecedence != 0 {
		pass = ",pass=" + strconv.FormatUint(uint64(e.passPrecedence.Priority()), 10) +
			",nextTier=" + strconv.FormatUint(uint64(e.nextTierPrecedence.Priority()), 10)
	}
	var nilRuleOrigin ruleOrigin
	var labelText string
	if e.derivedFromRules != nilRuleOrigin {
		labelText = ",derivedFromRules=" + string(e.derivedFromRules.LabelsString()) +
			",log=" + e.derivedFromRules.LogString()
	}
	return e.MapStateEntry.String() + labelText + pass
}

// addKeyWithChanges adds a 'key' with value 'entry' to 'keys' keeping track of incremental changes in 'adds' and 'deletes', and any changed or removed old values in 'old', if not nil.
func (ms *mapState) addKeyWithChanges(key Key, entry mapStateEntry, changes ChangeState) bool {
	var datapathEqual bool
	oldEntry, exists := ms.get(key)

	// Only merge if both old and new have the same precedence
	// (ignoring any difference in the proxy port precedence)
	// Pass entries are always overridden without merging the MapStateEntries,
	if exists {
		// Do nothing if entries are equal
		if entry.Equal(&oldEntry) {
			return false // nothing to do
		}

		// Save old value before any changes, if desired
		changes.insertOldIfNotExists(key, oldEntry)

		// Compare for datapath equalness before merging, as the old entry is updated in
		// place!
		datapathEqual = oldEntry.MapStateEntry == entry.MapStateEntry

		// keep the highest pass precedence (0 == not a pass entry)
		if entry.passPrecedence > oldEntry.passPrecedence {
			oldEntry.passPrecedence = entry.passPrecedence
			oldEntry.nextTierPrecedence = entry.nextTierPrecedence
		}

		// Figure out which MapStateEntry to keep
		if !oldEntry.IsValid() {
			oldEntry.MapStateEntry = entry.MapStateEntry
			oldEntry.derivedFromRules = entry.derivedFromRules
		} else if entry.IsValid() {
			// both are valid
			if oldEntry.Precedence.ProxyPortPrecedenceMayDiffer(entry.Precedence) {
				// entries on same priority level are merged
				oldEntry.MapStateEntry.Merge(entry.MapStateEntry)
				oldEntry.derivedFromRules = oldEntry.derivedFromRules.Merge(entry.derivedFromRules)
			} else if oldEntry.Precedence < entry.Precedence {
				// higher precedence entry takes over
				oldEntry.MapStateEntry = entry.MapStateEntry
				oldEntry.derivedFromRules = entry.derivedFromRules
			} else if oldEntry.passPrecedence >= entry.passPrecedence {
				// Do not record and incremental add if nothing was done
				return false
			}
		}

		ms.updateExisting(key, oldEntry)
	} else {
		// Callers already have cloned the containers, no need to do it again here
		ms.insert(key, entry)
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

// deleteExistingWithChanges deletes an existing 'key'/'entry' from 'ms' keeping track of incremental
// changes in 'changes'
func (ms *mapState) deleteExistingWithChanges(key Key, entry mapStateEntry, changes ChangeState) {
	// Only record as a delete if the entry was not added on the same round of changes
	if changes.insertOldIfNotExists(key, entry) && changes.Deletes != nil {
		changes.Deletes[key] = struct{}{}
	}
	// Remove a potential previously added key
	if changes.Adds != nil {
		delete(changes.Adds, key)
	}

	ms.delete(key)
}

// deleteKeyWithChanges deletes a 'key' from 'ms' keeping track of incremental changes in 'changes'
func (ms *mapState) deleteKeyWithChanges(key Key, changes ChangeState) {
	if entry, exists := ms.get(key); exists {
		ms.deleteExistingWithChanges(key, entry, changes)
	}
}

// deleteIdWithChanges deletes a 'key' from 'ms' keeping track of incremental changes in 'changes'
func (ms *mapState) deleteIdWithChanges(id identity.NumericIdentity, changes ChangeState) {
	if lpmKeys, exists := ms.byId[id]; exists {
		key := Key{Identity: id}
		for lpmKey := range lpmKeys {
			key.LPMKey = lpmKey
			ms.deleteKeyWithChanges(key, changes)
		}
	}
}

// RevertChanges undoes changes to 'keys' as indicated by 'changes.adds' and 'changes.old' collected
// via insertWithChanges().
func (ms *mapState) revertChanges(changes ChangeState) {
	for k := range changes.Adds {
		ms.delete(k)
	}
	// 'old' contains all the original values of both modified and deleted entries
	for k, v := range changes.old {
		ms.insert(k, v)
	}
}

// InheritPassPrecedence bumps the precedence of the given entry to follow the given
// 'passPrecedence', retaining the lowest bits for deny and proxy port precedence.
// The given passPrecedence is also stored in e.passPrecedence so this entry can safely overwrite
// the pass entry with the same key.
func (e mapStateEntry) InheritPassPrecedence(passMeta passMeta, sameKey bool) mapStateEntry {
	// Both passPrecedence and nextTierPrcedence have the low 8 bits all set, so those bits
	// cancel out and the deny and proxy port precedence bits are retained intact.
	e.Precedence -= passMeta.nextTierPrecedence
	e.Precedence += passMeta.passPrecedence
	// passed to entries are on priority level lower than the pass entry itself
	e.Precedence -= 0x100

	// Mark pass metadata on the entry to retain them if the pass entry key is overwritten by
	// any passed-to entry.
	if sameKey {
		e.passPrecedence = passMeta.passPrecedence
		e.nextTierPrecedence = passMeta.nextTierPrecedence
	}

	return e
}

// insertIfNotCovered the given entry, unless covered by a higher precedence key
func (ms *mapState) insertIfNotCovered(key Key, entry mapStateEntry, changes ChangeState) {
	// bail out if covered by a higher precedence (non-pass) entry
	for _, v2 := range ms.CoveringKeysWithSameID(key) {
		if v2.IsValid() && v2.Precedence > entry.Precedence {
			return
		}
	}
	ms.logger.Error("QUEUING PASS ENTRY",
		"key", key.String(),
		"entry", entry.String())
	ms.inserts = append(ms.inserts, L34Entry{key: key, entry: entry})
}

func (ms *mapState) addInserts(changes ChangeState) {
	for _, kv := range ms.inserts {
		ms.logger.Error("INSERTING QUEUED ENTRY",
			"key", kv.key.String(),
			"entry", kv.entry.String())
		ms.addKeyWithChanges(kv.key, kv.entry, changes)
	}
	// reslice to clear without releasing capacity
	ms.inserts = ms.inserts[:0]
}

// maybeBailEntry iterates over the LPM ancestors of the given key and returns true if the entry
// must not be inserted to the mapState.
// While iterating it makes note of any pass metadata and:
//   - for covering entries elevates the precedence of the new entry to follow that of the pass
//     entry.
//   - for non-covering pass entries, where the new key has a wildcard identity and the pass key
//     has a specific identity, a new key is added with the ID from the pass key and the more
//     specific L4 key from the new key, with precedence elevated to follow the pass entry.
func (ms *mapState) maybeBailEntry(tierPrecedence types.Precedence, key Key, entry *mapStateEntry, changes ChangeState) bool {
	var bailPrecedence types.Precedence
	var passKey Key
	var passMeta passMeta

	// Find the highest precedence covering pass and bail entries and pass if the found
	// passPrecedence is higher than the bailPrecedence, else bail if any bail was found.
	// On any found pass, add new L3/4 entries for non-covering keys.
	//
	// Note that BroaderOrEqualKeys iterates in random order, we can not assume entries to be
	// iterated in any LPM order or in the order of precedence.
	for k, v := range ms.BroaderOrEqualKeys(key) {
		isCoveringKey := key.Identity != 0 || k.Identity == 0
		// Bump precedence if covered by a higher tier PASS verdict.
		if v.IsPassEntry() && v.passPrecedence > entry.Precedence {
			// pass by any higher tier?
			if v.passPrecedence > tierPrecedence {
				// a synthetic entry may need to be inserted for
				// each non-covering pass key
				if !isCoveringKey {
					ms.insertIfNotCovered(
						key.WithIdentity(k.Identity),
						entry.InheritPassPrecedence(v.passMeta, false),
						changes)
					continue
				}
				// else keep the highest precedence covering pass key
				if v.passPrecedence > passMeta.passPrecedence {
					passKey = k
					passMeta = v.passMeta
				}
			} else if isCoveringKey {
				// higher precedence covering pass entry, but not on
				// higher tier, so it must be on the same tier. Bail
				// the new allow/deny entry immediately.
				return true
			}
		}
		// Bail if covered by an allow/deny key of higher precedence.
		if isCoveringKey && v.IsValid() &&
			(v.Precedence > entry.Precedence ||
				// New deny entry is also bailed due to different covering deny key
				// of the same precedence, equal keys need to be merged
				entry.IsDeny() && v.Precedence == entry.Precedence && k != key) {
			if v.Precedence > bailPrecedence {
				bailPrecedence = v.Precedence
			}
		}
	}
	if passMeta.passPrecedence > 0 && passMeta.passPrecedence > bailPrecedence {
		// This entry is covered by a higher tier rule with a PASS verdict.
		*entry = entry.InheritPassPrecedence(passMeta, passKey == key)
		ms.logger.Error("PASSED TO",
			"key", key.String(),
			"entry", entry.String(),
			"bail", bailPrecedence > 0)
		return false
	}

	return bailPrecedence > 0
}

// pruneNarrower iterates over all LPM descendants of the given key and removes any lower precedence
// entries, unless the new entry is to be bailed out. Even if bailed, it can be due to an entry on a
// higher tier, so we apply any higher tier passes even if the entry is to be bailed out.
func (ms *mapState) pruneNarrower(bail bool, tierPrecedence types.Precedence, key Key, entry *mapStateEntry, changes ChangeState) {
	// Delete covered entries of lower precedence, and
	// same precedence deny entries if the keys are different
	//
	// Process higher precedence more specific pass entries
	for k, v := range ms.NarrowerOrEqualKeys(key) {
		if !bail {
			// Should the pass metadata be deleted?
			deletePassEntry := !v.IsPassEntry() || v.passPrecedence < entry.Precedence

			// Should the allow/deny verdict be deleted?
			// Equal precedence entries [[[deny implied]]] are to be merged
			deleteEntry := !v.IsValid() ||
				(v.Precedence < entry.Precedence ||
					v.IsDeny() && v.Precedence == entry.Precedence && k != key)

			// Delete entry if no pass metadata and no allow/deny
			if deletePassEntry && deleteEntry {
				ms.deleteExistingWithChanges(k, v, changes)
				continue
			}
			if deletePassEntry || deleteEntry {
				// else have to keep the entry for either pass or allow/deny
				if deletePassEntry {
					v.passPrecedence = 0
					v.nextTierPrecedence = 0
				}
				if deleteEntry {
					v.Invalidate()
				}
				ms.updateExisting(k, v)
			}
		}

		ms.logger.Error("DENY/ALLOW-LOOK",
			"key", k.String(),
			"entry", v.String())

		// higher precedence pass entry on a higher tier?
		if key.Identity == 0 &&
			v.IsPassEntry() && v.passPrecedence > entry.Precedence &&
			v.passPrecedence > tierPrecedence {
			ms.logger.Error("DENY/ALLOW-MAYBEPASS",
				"key", k.String(),
				"entry", entry.InheritPassPrecedence(v.passMeta, k == key).String())
			ms.insertIfNotCovered(k, entry.InheritPassPrecedence(v.passMeta, k == key), changes)
		}
	}
}

// insertWithChanges contains the most important business logic for policy insertions. It inserts a
// key and entry into the map only if not covered by an entry of a higher precedence. This allows
// the datapath to perform a longest-prefix-match lookup which always results into the highest
// precedence match for the given L4 fields (protocol and port). Two lookups are necessary to find
// if both a wildcard ID and specific ID matches exist, in which case the precedence values in the
// found entries are used to determine the final verdict.
//
// A higher precedence PASS verdict is managed as metadata alongside the MapStateEntry and does not
// stop inserting covered entries of lower precedence. The PASS entries are not inserted into the
// datapath so the invariant described above is not violated.
//
// PASS metadata for wildcard ID entries is always inserted in the tiered order, higher precedence
// tiers first, starting from tier 0. Incremental updates are only ever done due to newly added or
// deleted identities while wildcard ID entries are always added during the initial full mapstate
// generation. This means that when adding non-wildcard ID pass entries lower-precedence PASS
// entries with the wildcard ID may already exist. In both cases, already existing entries (PASS
// included) may have more or less specific L4 match (i.e., can appear up or down in the LPM trie).
//
// Whenever the bpf datapath finds both L4-only and L3/L4 matching policy entries for a given
// packet, it uses the following logic to choose the policy entry:
//  1. Entry with higher precedence value is selected
//  2. When at the same precedence, the entry with more specific port/proto is chosen
//  3. When both entries have the same port/proto, the L3/L4 entry is chosen.
//
// This selects the higher precedence rule either by the numerical precedence value, or by the more
// specific L4, and the L3/L4 entry when the L4 is the same. This means that it suffices to manage
// explicit and deny precedence among the keys with the same ID here, the datapath take care of the
// precedence between different IDs (that is, between a specific ID and the wildcard ID (==0)).
//
// Note on bailed or deleted entries:
//
// It would seem like that when we bail out due to being covered by an existing entry, or delete an
// entry due to being covered by the new one, we would want this action reversed if the existing
// entry or this new one is incremantally removed, respectively. But consider these facts:
//  1. Whenever a key covers an another, the covering key has broader or equal
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
// Inserted entry may be a Pass entry, and while mapState can merge pass entries with allow/deny,
// the new entry passed in is never such a combination.
//
// Incremental changes performed are recorded in 'changes'.
func (ms *mapState) insertWithChanges(tierPrecedence types.Precedence, newKey Key, newEntry mapStateEntry, features policyFeatures, changes ChangeState) {
	if tierPrecedence&0xff != 0 {
		ms.logger.Error(
			"invalid tierPrecedence",
			logfields.Stacktrace, hclog.Stacktrace(),
			logfields.PolicyKey, newKey,
			logfields.PolicyEntry, newEntry,
			logfields.PolicyPrecedence, tierPrecedence,
		)
	}
	bail := false
	if newEntry.IsPassEntry() {
		ms.logger.Error("PASS",
			"key", newKey.String(),
			"entry", newEntry.String())

		// Bail if covered by a key of a higher precedence (pass or not)
		for k, v := range ms.BroaderOrEqualKeys(newKey) {
			// skip non-covering keys
			if newKey.Identity == 0 && k.Identity != 0 {
				continue
			}
			// bail if covered by a higher precedence PASS entry on the same tier,
			// or a higher precedence allow/deny on any tier.
			if v.IsPassEntry() && v.passPrecedence > newEntry.passPrecedence &&
				v.nextTierPrecedence == newEntry.nextTierPrecedence {
				return
			}
			if v.IsValid() && v.Precedence > newEntry.passPrecedence {
				return
			}
		}
		// Delete covered entries of lower precedence levels.
		// Covered pass entries are only deleted if at the same tier.
		for k, v := range ms.NarrowerOrEqualKeys(newKey) {
			// Should the pass metadata be deleted?
			deletePassEntry := !v.IsPassEntry() || v.passPrecedence < newEntry.passPrecedence
			// Should the allow/deny verdict be deleted?
			deleteEntry := !v.IsValid() || v.Precedence < newEntry.passPrecedence

			// Delete entry if no pass metadata and no allow/deny
			if deletePassEntry && deleteEntry {
				ms.deleteExistingWithChanges(k, v, changes)
			} else if deletePassEntry || deleteEntry {
				// else have to keep the entry for either pass or allow/deny
				if deletePassEntry {
					v.passPrecedence = 0
					v.nextTierPrecedence = 0
				}
				if deleteEntry {
					v.Invalidate()
				}
				ms.updateExisting(k, v)
			}
		}
	} else if newEntry.IsDeny() {
		ms.logger.Error("DENY",
			"key", newKey.String(),
			"entry", newEntry.String())

		bail = ms.maybeBailEntry(tierPrecedence, newKey, &newEntry, changes)
		ms.pruneNarrower(bail, tierPrecedence, newKey, &newEntry, changes)
	} else {
		// authPreferredInsert takes care for precedence and auth
		if features.contains(authRules) {
			ms.logger.Error("ALLOW-AUTH",
				"key", newKey.String(),
				"entry", newEntry.String())
			ms.authPreferredInsert(newKey, newEntry, features, changes)
			ms.addInserts(changes)
			return
		}

		ms.logger.Error("ALLOW",
			"key", newKey.String(),
			"entry", newEntry.String())

		// No pruning of allow rules if all rules have the same precedence level.
		if features.contains(precedenceFeatures) {
			// must observe pass entries before bailing out
			bail = ms.maybeBailEntry(tierPrecedence, newKey, &newEntry, changes)
			ms.pruneNarrower(bail, tierPrecedence, newKey, &newEntry, changes)
		}
	}
	if !bail {
		ms.addKeyWithChanges(newKey, newEntry, changes)
	}
	ms.addInserts(changes)
}

// overrideProxyPortForAuth sets the proxy port and priority of 'v' to that of 'newKey', saving the
// old entry in 'changes'.
// Returns 'true' if changes were made.
func (ms *mapState) overrideProxyPortForAuth(newEntry mapStateEntry, k Key, v mapStateEntry, changes ChangeState) bool {
	if v.AuthRequirement.IsExplicit() {
		// Save the old value first
		changes.insertOldIfNotExists(k, v)

		// Proxy port can be changed in-place, trie is not affected
		v.ProxyPort = newEntry.ProxyPort
		v.Precedence = newEntry.Precedence

		ms.entries[k] = v
		return true
	}
	return false
}

// overrideAuthRequirement sets the AuthRequirement of 'v' to that of 'newKey', saving the old entry
// in 'changes'.
func (ms *mapState) overrideAuthRequirement(newEntry mapStateEntry, k Key, v mapStateEntry, changes ChangeState) {
	if v.AuthRequirement.AuthType() != newEntry.AuthRequirement.AuthType() {
		// Save the old value first
		changes.insertOldIfNotExists(k, v)

		// Auth type can be changed in-place, trie is not affected
		// Only derived auth type is ever overridden, so the explicit flag is not copied
		v.AuthRequirement = newEntry.AuthRequirement.AsDerived()
		ms.entries[k] = v
	}
}

// authPreferredInsert applies AuthRequirement of a more generic entry to more specific entries, if
// not explicitly specified.
//
// This function is expected to be called for a map insertion after deny
// entry evaluation. If there is a covering map key for 'newKey'
// which denies traffic matching 'newKey', then this function should not be called.
func (ms *mapState) authPreferredInsert(newKey Key, newEntry mapStateEntry, features policyFeatures, changes ChangeState) {
	// Bail if covered by a key with a higher precedence and current
	// entry has no explicit auth.
	var derived bool
	newEntryHasExplicitAuth := newEntry.AuthRequirement.IsExplicit()

	for k, v := range ms.CoveringKeysWithSameID(newKey) {
		if v.Precedence > newEntry.Precedence {
			if v.IsDeny() || !newEntryHasExplicitAuth {
				// Covering entry has higher precedence and newEntry has a default
				// auth type => MUST bail out
				return
			}

			// newEnry has (a different) explicit auth requirement, must propagate
			// proxy port and precedence and keep it
			newEntry.ProxyPort = v.ProxyPort
			newEntry.Precedence = v.Precedence

			// Can break out:
			// - if there were covering denies the allow 'v' would
			//   not have existed, and
			// - since the new entry has explicit auth it does not need to be
			//   derived.
			break
		}
		// Fill in the AuthType from the most specific covering key with the same ID and an
		// explicit auth type, ignoring any difference in proxy port precedence
		if !derived && !newEntryHasExplicitAuth &&
			!k.PortProtoIsEqual(newKey) &&
			v.AuthRequirement.IsExplicit() &&
			v.AllowPrecedence() >= newEntry.AllowPrecedence() {
			// AuthType from the most specific covering key is applied to 'newEntry' as
			// derived auth type.
			newEntry.AuthRequirement = v.AuthRequirement.AsDerived()
			derived = true
		}
	}

	// Delete covered allow entries with lower precedence, but keep
	// entries with different "auth" and propagate proxy port and priority to them.
	//
	// Check if the new key is the most specific covering key of any other key
	// with the same ID and default auth type, and propagate the auth type from the new
	// entry to such entries.
	var propagated bool
	for k, v := range ms.SubsetKeysWithSameID(newKey) {
		if v.Precedence < newEntry.Precedence {
			if !ms.overrideProxyPortForAuth(newEntry, k, v, changes) {
				ms.deleteExistingWithChanges(k, v, changes)
				continue
			}
		}
		if !propagated && newEntryHasExplicitAuth && !k.PortProtoIsEqual(newKey) {
			// New entry has an explicit auth type
			if v.IsDeny() || v.AuthRequirement.IsExplicit() {
				// Stop if a subset entry is deny or also has an explicit auth type, as
				// that is the more specific covering key for all remaining subset
				// keys
				propagated = true
				continue
			}
			ms.overrideAuthRequirement(newEntry, k, v, changes)
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
		entry := newAllowEntryWithLabels(LabelsLocalHostIngress)
		ms.insertWithChanges(types.Priority(0).ToPassPrecedence(), localHostKey, entry, allFeatures, ChangeState{})
	}
}

// allowAllIdentities translates all identities in selectorCache to their
// corresponding Keys in the specified direction (ingress, egress) which allows
// all at L3.
// Note that this is used when policy is not enforced, so authentication is explicitly not required,
// and priority is left at 0.
func (ms *mapState) allowAllIdentities(ingress, egress bool) {
	if ingress {
		ms.upsert(allKey[trafficdirection.Ingress], newAllowEntryWithLabels(LabelsAllowAnyIngress))
	}
	if egress {
		ms.upsert(allKey[trafficdirection.Egress], newAllowEntryWithLabels(LabelsAllowAnyEgress))
	}
}

// MapChanges collects updates to the endpoint policy on the
// granularity of individual mapstate key-value pairs for both adds
// and deletes. 'mutex' must be held for any access.
type MapChanges struct {
	logger    *slog.Logger
	firstRev  types.SelectorRevision
	mutex     lock.Mutex
	changes   []mapChange
	synced    []mapChange
	selectors SelectorSnapshot
}

type mapChange struct {
	Add            bool // false deletes
	Tier           types.Tier
	BasePrecedence types.Precedence
	Key            Key
	Value          mapStateEntry
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
//
// If an identity is present in 'adds' or 'deletes', then the caller must make sure all keys that
// need to be added/deleted for that identity are accumulated before 'SyncMapChanges' is called, so
// that when the changes are applied, all keys for that identity are applied at the same time.
func (mc *MapChanges) AccumulateMapChanges(tier types.Tier, basePriority types.Priority, adds, deletes []identity.NumericIdentity, keys []Key, value mapStateEntry) {
	basePrecedence := basePriority.ToPassPrecedence()
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	for _, id := range adds {
		for _, k := range keys {
			k.Identity = id
			mc.changes = append(mc.changes, mapChange{
				Add:            true,
				Tier:           tier,
				BasePrecedence: basePrecedence,
				Key:            k,
				Value:          value,
			})
		}
	}
	for _, id := range deletes {
		for _, k := range keys {
			k.Identity = id
			mc.changes = append(mc.changes, mapChange{
				Add:            false,
				Tier:           tier,
				BasePrecedence: basePrecedence,
				Key:            k,
				Value:          value,
			})
		}
	}
}

// SyncMapChanges moves the current batch of changes to 'synced' to be consumed as a unit
func (mc *MapChanges) SyncMapChanges(selectors SelectorSnapshot) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	if len(mc.changes) > 0 {
		// Only apply changes after the initial version

		if selectors.After(mc.firstRev) {
			mc.synced = append(mc.synced, mc.changes...)
			mc.selectors = selectors
			mc.logger.Debug(
				"SyncMapChanges: Got handle on the new version",
				logfields.NewVersion, mc.selectors,
			)
		} else {
			mc.logger.Debug(
				"SyncMapChanges: Discarding already applied changes",
				logfields.Version, mc.firstRev,
				logfields.OldVersion, selectors,
			)
		}
	}
	mc.changes = nil
}

// detach releases any version handle we may hold
func (mc *MapChanges) detach() {
	mc.mutex.Lock()
	mc.selectors.Invalidate()
	mc.mutex.Unlock()
}

// consumeMapChanges transfers the incremental changes from MapChanges to the caller,
// while applying the changes to PolicyMapState.
func (mc *MapChanges) consumeMapChanges(p *EndpointPolicy, features policyFeatures) (SelectorSnapshot, ChangeState) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	changes := ChangeState{
		Adds:    make(Keys, len(mc.synced)),
		Deletes: make(Keys, len(mc.synced)),
		old:     make(mapStateMap, len(mc.synced)),
	}

	// sort changes in mc.synced so that we will insert higher tier rules first.
	slices.SortFunc(mc.synced, func(a, b mapChange) int {
		// lower tier values come first
		return int(a.Tier - b.Tier)
	})

	for i := range mc.synced {
		key := mc.synced[i].Key
		entry := mc.synced[i].Value
		basePrecedence := mc.synced[i].BasePrecedence

		if mc.synced[i].Add {
			// Insert the key to and collect the incremental changes to the overall
			// state in 'changes'
			p.policyMapState.insertWithChanges(basePrecedence, key, entry, features, changes)
		} else {
			// Delete the contribution of this cs to the key and collect incremental
			// changes
			if p.policyMapState.byId != nil {
				// incremental delete only happens when an identity is deleted,
				// delete all keys for this identity if we have the id index
				p.policyMapState.deleteIdWithChanges(key.Identity, changes)
			} else {
				p.policyMapState.deleteKeyWithChanges(key, changes)
			}
		}
	}

	// move selector snapshot to the caller
	version := mc.selectors
	mc.selectors.Invalidate()

	mc.synced = nil

	return version, changes
}
