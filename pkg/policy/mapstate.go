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

// forIDs calls 'f' for each non-wildcard ID in 'idSet' with port/proto from 'k'.
func (ms *mapState) forNonWildcardIDs(k Key, idSet IDSet, f func(Key, mapStateEntry) bool) bool {
	for id := range idSet {
		if id != 0 {
			k.Identity = id
			if !ms.forKey(k, f) {
				return false
			}
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

// CoveringBroaderOrEqualKeys iterates over broader or equal (broader or equal port/proto and the
// same or wildcard ID) in the trie.
func (ms *mapState) CoveringBroaderOrEqualKeys(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := ms.trie.AncestorIterator(key.PrefixLength(), key.LPMKey)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey}

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

// BroaderOrEqualKeys iterates over broader or equal (broader or equal port/proto and the same
// or wildcard ID) in the trie.
// If a key is a wildcard key then also keys with any specific IDs are iterated!
func (ms *mapState) BroaderOrEqualKeys(key Key) iter.Seq2[Key, mapStateEntry] {
	return func(yield func(Key, mapStateEntry) bool) {
		iter := ms.trie.AncestorIterator(key.PrefixLength(), key.LPMKey)
		for ok, lpmKey, idSet := iter.Next(); ok; ok, lpmKey, idSet = iter.Next() {
			k := Key{LPMKey: lpmKey}

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

			// Last, Visit all identities for an ANY key
			if key.Identity == 0 {
				if !ms.forNonWildcardIDs(k, idSet, yield) {
					return
				}
			}
		}
	}
}

// CoveredNarrowerOrEqualKeys iterates over narrower or equal keys in the trie.
// Iterated keys can be safely deleted during iteration due to DescendantIterator holding enough
// state that allows iteration to be continued even if the current trie node is removed.
func (ms *mapState) CoveredNarrowerOrEqualKeys(key Key) iter.Seq2[Key, mapStateEntry] {
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

// NarrowerOrEqualKeys iterates over narrower or equal keys in the trie.
// Iterated keys can be safely deleted during iteration due to DescendantIterator holding enough
// state that allows iteration to be continued even if the current trie node is removed.
// If a key is a non-wildcard key then also the wildcard key is iterated!
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

			// Last, Visit ANY identity for a specific identity
			if key.Identity != 0 {
				if !ms.forID(k.WithIdentity(0), idSet, yield) {
					return
				}
			}
		}
	}
}

// CoveringKeysWithSameID iterates over broader or equal port/proto entries in the trie in LPM
// order, with most specific match with the same ID as in 'key' being returned first.
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

// Pass verdict related metadata can not be fully resolved at the L4Filter level due to named port
// mapping not existing at that level.
type passMeta struct {
	// precedence is the precedence of a PASS verdict on the key of this entry.
	// This is separate from the MapStateEntry.Precedence, as an allow or deny entry may
	// have the same key, and both need to be kept
	precedence types.Precedence

	// tierMinPrecedence is the last precedence on this tier.
	// This is used when bumping lower tier entry precedences due to a covering pass entry,
	// and to discern if a given new entry is on the same tier as the pass entry.
	tierMaxPrecedence, tierMinPrecedence types.Precedence
}

func (pm passMeta) String() string {
	return strconv.FormatUint(uint64(pm.precedence.Priority()), 10) + "/" +
		strconv.FormatUint(uint64(pm.tierMaxPrecedence.Priority()), 10) + ":" +
		strconv.FormatUint(uint64(pm.tierMinPrecedence.Priority()), 10)
}

// passMetas is a slice of pass metadata, where there may be at most one entry for each tier (as
// identified by 'tierMinPrecedence'), ordered by increasing precedence.
type passMetas []passMeta

// Collect adds the given pass metadata to its place in ascending tier order, unless there already
// is metadata for the same tier. In that case the higher precedence pass metadata is retained.
func (pm *passMetas) Collect(pass passMeta) {
	if pass.precedence == 0 || pass.precedence < pass.tierMinPrecedence || pass.precedence > pass.tierMaxPrecedence {
		return
	}

	var i int
	for i = 0; i < len(*pm); i++ {
		m := (*pm)[i]
		if m.tierMinPrecedence > pass.tierMinPrecedence {
			break
		}
		if m.tierMinPrecedence == pass.tierMinPrecedence {
			if pass.precedence > m.precedence {
				(*pm)[i] = pass
			}
			return
		}
	}
	// empty slice (i == 0) or only lower tiers before index 'i'
	*pm = slices.Insert(*pm, i, pass)
}

// isDifferentTierOrHigherPrecedence returns true if 'pass' if of a different tier or higher
// precedence than the given 'precedence'.
func (pass passMeta) isDifferentTierOrHigherPrecedence(precedence types.Precedence) bool {
	sameTier := pass.tierMinPrecedence <= precedence &&
		precedence <= pass.tierMaxPrecedence
	return !sameTier || pass.precedence > precedence
}

// Delete returns a new slice with lower precedence entries in the same tier removed
func (old passMetas) Delete(precedence types.Precedence) passMetas {
	new := make(passMetas, 0, len(old))
	for i := range old {
		if old[i].isDifferentTierOrHigherPrecedence(precedence) {
			new = append(new, old[i])
		}
	}
	return new
}

// Merge combines pass metadata from 'old' and 'other', reusing the 'old' slice.
func (old passMetas) Merge(other passMetas) passMetas {
	// Merge pass metadata keeping only the highest precedence entry at each tier.
	// Each passMeta slice has at most one entry on each tier.
	// Elements are sorted in the order if increasing precedence.
	var i, j int
	for ; j < len(other); j++ {
		// keep old[i] if lower tier
		for ; i < len(old) && old[i].tierMinPrecedence < other[j].tierMinPrecedence; i++ {
		}
		if i == len(old) {
			break
		}
		// old[i] is now equal or higher tier than other[j]
		if old[i].tierMinPrecedence > other[j].tierMinPrecedence {
			// 'j' is lower tier, insert
			old = slices.Insert(old, i, other[j])
		} else if old[i].precedence < other[j].precedence {
			// same tier, 'j' if higher precedence, keep 'j'
			old[i] = other[j]
		}
	}
	if i == len(old) && j < len(other) {
		return append(old, other[j:]...)
	}
	return old
}

// MergeClone returns either 'old' or 'other' unmodified, or clones the slice '*old' and returns
// a pointer to the newly merged slice of pass metadata.
func (old *passMetas) MergeClone(other *passMetas) *passMetas {
	if old == nil || len(*old) == 0 {
		return other
	}
	if other == nil || len(*other) == 0 {
		return old
	}
	if slices.Equal(*old, *other) {
		return old
	}

	new := slices.Clone(*old).Merge(*other)
	return &new
}

// mapStateEntry is the entry type with additional internal bookkeping of the relation between
// explicitly and implicitly added entries.
type mapStateEntry struct {
	MapStateEntry

	// pass metadata is stored via a pointer to limit the overhead on entries without any pass
	// metadata.
	passes *passMetas

	// derivedFromRules tracks the policy rules this entry derives from.
	// Must be initialized explicitly, zero-intialization does not work with unique.Handle[].
	derivedFromRules ruleOrigin
}

func (e mapStateEntry) IsPassEntry() bool {
	return e.passes != nil
}

// Passes iterates over the pass metadata in the entry.
func (e mapStateEntry) Passes() iter.Seq[passMeta] {
	return func(yield func(passMeta) bool) {
		if e.passes != nil {
			for _, meta := range *e.passes {
				if !yield(meta) {
					return
				}
			}
		}
	}
}

// PassEntry returns a pass entry with a single pass metadata initialized from the parameter values.
func PassEntry(priority, tierPriority, nextTierPriority types.Priority, derivedFrom ruleOrigin) mapStateEntry {
	return mapStateEntry{
		passes: &passMetas{{
			precedence:        priority.ToPassPrecedence(),
			tierMaxPrecedence: tierPriority.ToTierMaxPrecedence(),
			tierMinPrecedence: nextTierPriority.ToPassPrecedence() + 0x100,
		}},
		MapStateEntry:    types.InvalidEntry(),
		derivedFromRules: derivedFrom,
	}
}

// newMapStateEntry creates a map state entry.
func newMapStateEntry(
	priority types.Priority,
	tierPriority types.Priority,
	nextTierPriority types.Priority,
	derivedFrom ruleOrigin,
	proxyPort uint16,
	listenerPriority ListenerPriority,
	verdict types.Verdict,
	authReq AuthRequirement,
) mapStateEntry {
	if verdict == types.Pass {
		return PassEntry(priority, tierPriority, nextTierPriority, derivedFrom)
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
	return newMapStateEntry(0, types.HighestPriority, types.LowestPriority, makeSingleRuleOrigin(lbls, ""), 0, 0, types.Allow, NoAuthRequirement)
}

func NewMapStateEntry(e MapStateEntry) mapStateEntry {
	return mapStateEntry{
		MapStateEntry:    e,
		derivedFromRules: NilRuleOrigin,
	}
}

func emptyMapState(logger *slog.Logger) mapState {
	return newMapState(logger, nil, 0)
}

// newMapState returns a new mapState with capacities from the given old mapState (if non-nil),
// according to the given policy features.
func newMapState(logger *slog.Logger, old *mapState, features policyFeatures) mapState {
	var nEntries int

	if old != nil {
		nEntries = len(old.entries)
	}

	ms := mapState{
		logger:  logger,
		entries: make(mapStateMap, nEntries),
		trie:    bitlpm.NewTrie[types.LPMKey, IDSet](types.MapStatePrefixLen),
	}

	if features&passRules != 0 {
		if old == nil {
			ms.byId = make(map[identity.NumericIdentity]LPMKeys)
		} else {
			ms.byId = make(map[identity.NumericIdentity]LPMKeys, len(old.byId))
			// preallocate id index keysets to their current sizes, if any
			for k, v := range old.byId {
				ms.byId[k] = make(LPMKeys, len(v))
			}
		}
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
		return ok && vB.Equal(vA)
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
			if !vO.Equal(vE) {
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
func (e mapStateEntry) Equal(o mapStateEntry) bool {
	return e.MapStateEntry == o.MapStateEntry && e.derivedFromRules == o.derivedFromRules &&
		(e.passes == o.passes || (e.passes != nil && o.passes != nil &&
			slices.Equal(*e.passes, *o.passes)))
}

// String returns a string representation of the MapStateEntry
func (e mapStateEntry) String() string {
	var pass string
	if e.passes != nil {
		pass += ",pass=["
		for _, passMeta := range *e.passes {
			if len(pass) > 7 {
				pass += ","
			}
			pass += passMeta.String()
		}
		pass += "]"
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
		if entry.Equal(oldEntry) {
			return false // nothing to do
		}

		// Save old value before any changes, if desired
		changes.insertOldIfNotExists(key, oldEntry)

		// Compare for datapath equalness before merging, as the old entry is updated in
		// place!
		datapathEqual = oldEntry.MapStateEntry == entry.MapStateEntry

		oldPass := oldEntry.passes
		oldEntry.passes = oldEntry.passes.MergeClone(entry.passes)
		passUpdated := oldEntry.passes != oldPass

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
			} else if !passUpdated {
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

func (e *mapStateEntry) InheritPassPrecedence(passes passMetas) types.Precedence {
	precedence := e.Precedence
	for _, pass := range passes {
		// Both pass.precedence and tierMinPrcedence have the low 8 bits zeroed, so
		// those bits cancel out and the deny and proxy port precedence bits are
		// retained intact.
		precedence -= pass.tierMinPrecedence
		precedence += pass.precedence
	}
	return precedence
}

// pruneCoveredNarrowerKey deletes all or part of the entry 'v' depending on the given covering key
// 'k' and precedence.
func (ms *mapState) pruneCoveredNarrowerKey(k Key, v mapStateEntry, key Key, precedence types.Precedence, changes ChangeState) {
	// Delete lower precedence pass metadata on the same tier
	deletePassMeta := true
	deletePassEntry := false
	for pass := range v.Passes() {
		if pass.isDifferentTierOrHigherPrecedence(precedence) {
			// a pass must be kept, so the whole can not be deleted
			deletePassMeta = false
		} else {
			// a pass must be deleted
			deletePassEntry = true
		}
	}

	// Delete lower precedence allow/deny verdict.
	// Equal precedence entries [[[deny implied]]] are to be merged
	deleteEntry := !v.IsValid() ||
		(v.Precedence < precedence ||
			v.IsDeny() && v.Precedence == precedence && k != key)

	// Delete whole entry?
	if deletePassMeta && deleteEntry {
		ms.deleteExistingWithChanges(k, v, changes)
	} else if deletePassMeta || deletePassEntry || deleteEntry {
		// Have to keep the entry for either pass or allow/deny
		if deletePassMeta {
			v.passes = nil
		} else if deletePassEntry {
			// *v.passes may be shared, must create a new slice
			passes := v.passes.Delete(precedence)
			v.passes = &passes
		}
		if deleteEntry {
			v.Invalidate()
		}
		ms.updateExisting(k, v)
	}
}

type keySlice []Key

func (sp *keySlice) addNewKey(key Key, doneKeys *Keys) {
	if !doneKeys.Has(key) {
		*sp = append(*sp, key)
		doneKeys.Insert(key) // mark as added
	}
}

func (sp *keySlice) addNewKeys(l34Keys, doneKeys *Keys) {
	for k := range *l34Keys {
		sp.addNewKey(k, doneKeys)
	}
}

// collectNarrowerPasses adds the narrower key 'k' (with identity from 'key' if narrower) to 'm' if
// 'v' has a higher precedence pass.
func (sp *keySlice) collectNarrowerPasses(tierMaxPrecedence types.Precedence, k Key, v mapStateEntry, key Key, doneKeys *Keys) {
	// k has narrower L4, but the narrower identity may be on 'key'
	if k.Identity == 0 {
		k.Identity = key.Identity
	}
	if k != key {
		// Narrower higher precedence pass entry on a higher tier?
		for pass := range v.Passes() {
			if pass.precedence > tierMaxPrecedence {
				sp.addNewKey(k, doneKeys)
				break // skip remaining passes of higher tiers
			}
		}
	}
}

// All iterates over the keys in '*sp', allowing the iteration body (yield) to push new keys to it.
func (sp *keySlice) All() iter.Seq[Key] {
	return func(yield func(Key) bool) {
		for len(*sp) > 0 {
			// get the first key
			key := (*sp)[0]
			// shrink the slice to not iterate this key again
			*sp = (*sp)[1:]
			// reset empty slice to reuse the data from the beginning, if new keys are
			// pushed while yielding
			if len(*sp) == 0 {
				*sp = (*sp)[:0]
			}
			if !yield(key) {
				return
			}
		}
	}
}

// insertWithPasses contains the most important business logic for pass policy insertions. It
// inserts a key and entry into the map only if not covered by an entry of a higher precedence. This
// allows the datapath to perform a longest-prefix-match lookup which always results into the
// highest precedence match for the given L4 fields (protocol and port). Two lookups are necessary
// to find if both a wildcard ID and specific ID matches exist, in which case the precedence values
// in the found entries are used to determine the final verdict.
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
// Inserted entry may be a Pass entry, and while mapState can merge pass entries with allow/deny,
// the new entry passed in is never such a combination.
//
// Incremental changes performed are recorded in 'changes'.
func (ms *mapState) insertWithPasses(tierMaxPrecedence types.Precedence, key Key, entry mapStateEntry, changes ChangeState) {
	if tierMaxPrecedence&0xff != 0xff || entry.IsValid() && entry.Precedence > tierMaxPrecedence {
		ms.logger.Error(
			"invalid tierMaxPrecedence",
			logfields.PolicyPrecedence, tierMaxPrecedence,
			logfields.PolicyKey, key,
			logfields.PolicyEntry, entry,
			logfields.Stacktrace, hclog.Stacktrace(),
		)
		return
	}

	// Add a new pass entry?
	if entry.IsPassEntry() {
		// Newly inserted pass entry has exactly one pass entry
		if len(*entry.passes) != 1 || (*entry.passes)[0].precedence > tierMaxPrecedence {
			ms.logger.Error(
				"invalid new pass entry",
				logfields.PolicyPrecedence, tierMaxPrecedence,
				logfields.PolicyKey, key,
				logfields.PolicyEntry, entry,
				logfields.Stacktrace, hclog.Stacktrace(),
			)
			return
		}
		newPass := (*entry.passes)[0]

		// Bail if covered by a higher or equal precedence pass/allow/deny on the same tier
		for _, v := range ms.CoveringBroaderOrEqualKeys(key) {
			// bail if covered by a higher precedence allow/deny on the same tier
			if v.IsValid() && tierMaxPrecedence >= v.Precedence && v.Precedence > newPass.precedence {
				return
			}
			// bail if covered by a higher or equal precedence PASS entry on the same
			// tier
			for pass := range v.Passes() {
				if pass.tierMinPrecedence == newPass.tierMinPrecedence &&
					pass.precedence >= newPass.precedence {
					return
				}
			}
		}
		// Delete covered entries of lower or same precedence levels at the same tier.
		// Note that this pass entry is always added before any possibly passed-to lower
		// tier entries, so we are not accidentallly deleting any already passed to entries
		// here.
		for k, v := range ms.CoveredNarrowerOrEqualKeys(key) {
			ms.pruneCoveredNarrowerKey(k, v, key, newPass.precedence, changes)
		}
		ms.addKeyWithChanges(key, entry, changes)
		return
	}

	// Allow/Deny entry, iterate over the LPM ancestors of the given key, and add the possibly
	// updated ("passed-to") entry to the mapState, unless bailed.
	//
	// While iterating make note of any pass metadata:
	//   - for covering pass entries elevates the precedence of the new entry to follow that of
	//     the pass entry.
	//   - for non-covering pass entries, where the new key has a wildcard identity and the pass
	//     key has a specific identity, a new key is added with the ID from the pass key and the
	//     more specific L4 key from the new key, with precedence elevated to follow the pass
	//     entry.
	//
	// Additional subset keys may need to be added due to higher tier pass entries:
	//   - for key.Identity == 0, additional keys with specific IDs from pass entries must be
	//     added
	//   - narrower L3/L4 pass entries must be added for all higher tier pass entries with
	//     narrower L4 match.
	//
	// In many cases the given key is actually not added (is "bailed out"), and only those
	// additional L3/4 entries remain.

	var passes passMetas
	var l34Keys, doneKeys Keys
	var bailPrecedence types.Precedence
	var keys keySlice

	// Find the covering pass and bail entries and pass if the found
	// passPrecedence is higher than the bailPrecedence, else bail if found.
	//
	// On any found pass, add new L3/4 entries for non-covering keys.
	//
	// Note that BroaderOrEqualKeys iterates in random order, we can not assume entries to be
	// iterated in any LPM order or in the order of precedence.
	for k, v := range ms.BroaderOrEqualKeys(key) {
		isCoveringKey := key.Identity != 0 || k.Identity == 0
		// Bump precedence if covered by a higher tier PASS verdict.
		for pass := range v.Passes() {
			// is the pass from a higher tier?
			if pass.tierMinPrecedence > entry.Precedence {
				// A new L3/4 entry may need to be inserted non-covering
				// pass key. Collect them.
				if !isCoveringKey {
					l34Keys.Insert(key.WithIdentity(k.Identity))
					break // skip remaining passes of higher tiers
				}
				// else keep the highest precedence covering pass key for each tier
				passes.Collect(pass)
			} else if isCoveringKey && pass.precedence > entry.Precedence {
				// higher precedence covering pass entry, but not on
				// higher tier, so it must be on the same tier. Bail
				// the new allow/deny entry immediately.
				return
			}
		}
		// Bail if covered by an allow/deny key of higher precedence.
		if v.IsValid() && (v.Precedence > entry.Precedence ||
			// New deny entry is also bailed due to different covering deny key
			// of the same precedence, equal keys need to be merged
			entry.IsDeny() && v.Precedence == entry.Precedence && k != key) {
			if isCoveringKey {
				// bail immediately for a covering key on the same tier
				if v.Precedence <= tierMaxPrecedence {
					return
				}
				// store the highest bail precedence for higher tier
				// covering keys
				if v.Precedence > bailPrecedence {
					bailPrecedence = v.Precedence
				}
			} else if v.Precedence <= tierMaxPrecedence {
				// non-covering bail on the same tier, prevents processing
				// this narrower key
				doneKeys.Insert(key.WithIdentity(k.Identity))
			}
		}
	}

	// Add new L34 keys to 'keys', unless done or bailed
	keys.addNewKeys(&l34Keys, &doneKeys)

	bail := bailPrecedence > 0 // bailed unless passed

	// Iterate over all LPM descendants of the key and remove all lower precedence
	// entries, unless the new entry is to be bailed out. Even if bailed, there may be a
	// higher tier narrower pass to be considered.
	for k, v := range ms.NarrowerOrEqualKeys(key) {
		isCoveringKey := key.Identity == 0 || k.Identity == key.Identity
		if !bail && isCoveringKey {
			ms.pruneCoveredNarrowerKey(k, v, key, entry.Precedence, changes)
		}
		keys.collectNarrowerPasses(tierMaxPrecedence, k, v, key, &doneKeys)
	}

	// Pass to a higher tier?
	if len(passes) > 0 {
		// This entry is covered by one or more higher tier rules with a PASS verdict.
		// All covering passes are processed at once.
		precedence := entry.InheritPassPrecedence(passes)
		if precedence > bailPrecedence {
			// 'entry' must be kept unmodified
			passed := entry
			passed.Precedence = precedence

			// Iterate over all LPM descendants of the key and remove all lower
			// precedence entries.
			for k, v := range ms.CoveredNarrowerOrEqualKeys(key) {
				ms.pruneCoveredNarrowerKey(k, v, key, precedence, changes)
			}
			ms.addKeyWithChanges(key, passed, changes)
			bail = true
		}
	}
	if !bail {
		ms.addKeyWithChanges(key, entry, changes)
	}

	// Loop over covered keys added due applicable passes found on the main key above.  All
	// these subset keys would be trivially bailed due to the main key just added above, so we
	// don't even try adding them here, only adding the applicable passes if not bailed.
	for key := range keys.All() {
		// clear temporary storage for the processing of the subkey
		bailPrecedence = 0
		passes = passes[:0]
		clear(l34Keys)

		// Find the applicable pass entries, and the highest precedence bailing entry.
		// Note that since 'key' here is narrower than the parameter 'key', it is possible
		// we find additional entries to the ones found earlier.
		for k, v := range ms.BroaderOrEqualKeys(key) {
			isCoveringKey := key.Identity != 0 || k.Identity == 0
			// Bump precedence if covered by a higher tier PASS verdict.
			for pass := range v.Passes() {
				// is the pass from a higher tier?
				if pass.tierMinPrecedence > entry.Precedence {
					// A new L3/4 entry may need to be inserted non-covering
					// pass key. Collect them.
					if !isCoveringKey {
						l34Keys.Insert(key.WithIdentity(k.Identity))
						break // skip remaining passes of higher tiers
					}
					// else keep the highest precedence covering pass key for
					// each tier
					passes.Collect(pass)
				}
			}
			// Bail if covered by an allow/deny key of higher precedence on a higher
			// tier.
			if v.IsValid() && (v.Precedence > entry.Precedence ||
				// New deny entry is also bailed due to different covering deny key
				// of the same precedence, equal keys need to be merged
				entry.IsDeny() && v.Precedence == entry.Precedence && k != key) {
				if isCoveringKey {
					// store the highest bail precedence for higher tier
					// covering keys
					if v.Precedence > tierMaxPrecedence && v.Precedence > bailPrecedence {
						bailPrecedence = v.Precedence
					}
				} else if v.Precedence <= tierMaxPrecedence {
					// non-covering bail on the same tier, prevents insertion of
					// l3Passes on the narrower key
					doneKeys.Insert(key.WithIdentity(k.Identity))
				}
			}
		}

		// Add new L34 keys to 'keys', unless done or bailed
		keys.addNewKeys(&l34Keys, &doneKeys)

		// This entry is covered by one or more higher tier rules with a PASS verdict.
		// All covering passes are processed at once.
		precedence := entry.InheritPassPrecedence(passes)
		if precedence > bailPrecedence {
			// 'entry' must be kept unmodified
			passed := entry
			passed.Precedence = precedence

			// Iterate over all LPM descendants of the key and remove all lower
			// precedence entries.
			for k, v := range ms.CoveredNarrowerOrEqualKeys(key) {
				ms.pruneCoveredNarrowerKey(k, v, key, precedence, changes)
			}
			ms.addKeyWithChanges(key, passed, changes)
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
func (ms *mapState) insertWithChanges(tierMaxPrecedence types.Precedence, newKey Key, newEntry mapStateEntry, features policyFeatures, changes ChangeState) {
	if features.contains(passRules) {
		if features.contains(authRules) {
			ms.logger.Error("Pass rules are not supported with auth rules")
		}
		ms.insertWithPasses(tierMaxPrecedence, newKey, newEntry, changes)
		return
	}

	if newEntry.IsDeny() {
		for k, v := range ms.CoveringBroaderOrEqualKeys(newKey) {
			// Bail if covered by an allow/deny key of higher precedence
			if v.IsValid() && (v.Precedence > newEntry.Precedence ||
				// New deny entry is also bailed due to different covering deny key
				// of the same precedence, equal keys need to be merged
				v.Precedence == newEntry.Precedence && k != newKey) {
				return
			}
		}

		// Delete covered entries of lower precedence, and
		// same precedence deny entries if the keys are different
		for k, v := range ms.CoveredNarrowerOrEqualKeys(newKey) {
			if v.Precedence < newEntry.Precedence ||
				v.Precedence == newEntry.Precedence && k != newKey {
				ms.deleteExistingWithChanges(k, v, changes)
			}
		}
	} else {
		// authPreferredInsert takes care for precedence and auth
		if features.contains(authRules) {
			ms.authPreferredInsert(newKey, newEntry, features, changes)
			return
		}

		// No pruning of allow rules if all rules have the same precedence level.
		if features.contains(precedenceFeatures) {
			for _, v := range ms.CoveringBroaderOrEqualKeys(newKey) {
				// Bail if covered by an allow/deny key of higher precedence
				if v.IsValid() && v.Precedence > newEntry.Precedence {
					return
				}
			}

			// Delete covered entries of lower precedence, and
			// same precedence deny entries if the keys are different
			for k, v := range ms.CoveredNarrowerOrEqualKeys(newKey) {
				if v.Precedence < newEntry.Precedence {
					ms.deleteExistingWithChanges(k, v, changes)
				}
			}
		}
	}
	ms.addKeyWithChanges(newKey, newEntry, changes)
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
func (ms *mapState) determineAllowLocalhostIngress(features policyFeatures) {
	if option.Config.AlwaysAllowLocalhost() {
		entry := newAllowEntryWithLabels(LabelsLocalHostIngress)
		ms.insertWithChanges(types.Priority(0).ToTierMaxPrecedence(), localHostKey, entry, features, ChangeState{})
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
	Add               bool // false deletes
	Tier              types.Tier
	TierMaxPrecedence types.Precedence
	Key               Key
	Value             mapStateEntry
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
	tierMaxPrecedence := basePriority.ToTierMaxPrecedence()
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	for _, id := range adds {
		for _, k := range keys {
			k.Identity = id
			mc.changes = append(mc.changes, mapChange{
				Add:               true,
				Tier:              tier,
				TierMaxPrecedence: tierMaxPrecedence,
				Key:               k,
				Value:             value,
			})
		}
	}
	for _, id := range deletes {
		for _, k := range keys {
			k.Identity = id
			mc.changes = append(mc.changes, mapChange{
				Add:               false,
				Tier:              tier,
				TierMaxPrecedence: tierMaxPrecedence,
				Key:               k,
				Value:             value,
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
		tierMaxPrecedence := mc.synced[i].TierMaxPrecedence

		if mc.synced[i].Add {
			// Insert the key to and collect the incremental changes to the overall
			// state in 'changes'
			p.policyMapState.insertWithChanges(tierMaxPrecedence, key, entry, features, changes)
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
