// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"

	"github.com/cespare/xxhash/v2"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

const (
	// MaxRuleSets is the maximum number of unique rule sets.
	// Sized as ~2x the maximum endpoints per node (4095) to accommodate
	// concurrent hitless transitions during rolling policy updates.
	MaxRuleSets = 8192
)

// ruleSetKey represents the hash of a set of rules.
type ruleSetKey string

// SharedRule pairs a SharedPolicyKey with its PolicyEntry value.
type SharedRule struct {
	Key   SharedPolicyKey
	Entry PolicyEntry
}

// ruleKeyWithoutRuleSetID represents a rule's key fields excluding RuleSetID.
type ruleKeyWithoutRuleSetID struct {
	Identity  uint32
	Egress    uint8
	Protocol  uint8
	DPort     uint16
	PrefixLen uint8
}

// RuleSetAllocator manages the assignment of unique RuleSetIDs to sets of policy rules.
type RuleSetAllocator struct {
	mu            lock.Mutex
	rulesets      map[ruleSetKey]uint32   // hash -> rule_set_id
	idToHash      map[uint32]ruleSetKey   // rule_set_id -> hash
	idToRules     map[uint32][]SharedRule // rule_set_id -> rules (for cleanup and incremental updates)
	refcount      map[uint32]int          // rule_set_id -> refcount
	nextRuleSetID uint32                  // Next available rule_set_id
	freeIDs       []uint32                // Recycled rule_set_ids available for reuse
	epToRuleSetID map[uint16]uint32       // endpoint ID -> current rule_set_id
	maxRuleSets   uint32
}

// Option is a functional option for configuring RuleSetAllocator.
type Option func(*RuleSetAllocator)

// WithMaxRuleSets sets the maximum number of unique rule sets.
func WithMaxRuleSets(max uint32) Option {
	return func(a *RuleSetAllocator) {
		if max > 0 {
			a.maxRuleSets = max
		}
	}
}

// NewRuleSetAllocator creates a new allocator.
func NewRuleSetAllocator(opts ...Option) *RuleSetAllocator {
	a := &RuleSetAllocator{
		rulesets:      make(map[ruleSetKey]uint32),
		idToHash:      make(map[uint32]ruleSetKey),
		idToRules:     make(map[uint32][]SharedRule),
		refcount:      make(map[uint32]int),
		nextRuleSetID: 1, // Start from 1 (0 is reserved for "no rule set")
		epToRuleSetID: make(map[uint16]uint32),
		maxRuleSets:   MaxRuleSets,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *RuleSetAllocator) nextIDLocked() (uint32, error) {
	if n := len(a.freeIDs); n > 0 {
		id := a.freeIDs[n-1]
		a.freeIDs = a.freeIDs[:n-1]
		return id, nil
	}
	if a.nextRuleSetID >= a.maxRuleSets {
		return 0, fmt.Errorf("max rule sets reached: %d", a.maxRuleSets)
	}
	id := a.nextRuleSetID
	a.nextRuleSetID++
	return id, nil
}

// ArenaRuleWithEntry combines a policy key with its entry for allocation input.
type ArenaRuleWithEntry struct {
	Key   policyTypes.Key
	Entry policyTypes.MapStateEntry
}

// GetOrAllocate returns the rule_set_id for the given rules.
func (a *RuleSetAllocator) GetOrAllocate(rules []ArenaRuleWithEntry) (uint32, error) {
	ruleSetHash := ComputeRuleSetHashFromEntries(rules)

	a.mu.Lock()
	defer a.mu.Unlock()

	if id, exists := a.rulesets[ruleSetHash]; exists {
		a.refcount[id]++
		return id, nil
	}

	ruleSetID, err := a.nextIDLocked()
	if err != nil {
		return 0, err
	}

	EnsureSharedMapsOpen()
	m := GetSharedPolicyMap()
	sharedRules := make([]SharedRule, len(rules))
	for i, r := range rules {
		key := NewSharedKey(ruleSetID, r.Key)
		entry := NewSharedEntry(key, r.Entry)

		if err := m.Update(&key, &entry); err != nil {
			for j := range i {
				_ = m.Delete(&sharedRules[j].Key)
			}
			a.freeIDs = append(a.freeIDs, ruleSetID)
			return 0, fmt.Errorf("failed to update shared policy map: %w", err)
		}
		sharedRules[i] = SharedRule{Key: key, Entry: entry}
	}

	a.rulesets[ruleSetHash] = ruleSetID
	a.idToHash[ruleSetID] = ruleSetHash
	a.idToRules[ruleSetID] = sharedRules
	a.refcount[ruleSetID] = 1

	return ruleSetID, nil
}

// UpdateEndpointRules performs incremental updates when possible.
func (a *RuleSetAllocator) UpdateEndpointRules(epID uint16, rules []ArenaRuleWithEntry) (uint32, bool, error) {
	newHash := ComputeRuleSetHashFromEntries(rules)

	a.mu.Lock()
	defer a.mu.Unlock()

	oldRuleSetID, hadOld := a.epToRuleSetID[epID]

	// Case 1: Exact hash match exists
	if existingID, ok := a.rulesets[newHash]; ok {
		if existingID == oldRuleSetID {
			return existingID, false, nil
		}
		a.refcount[existingID]++
		a.epToRuleSetID[epID] = existingID
		if hadOld {
			a.releaseRuleSetLocked(oldRuleSetID)
		}
		return existingID, false, nil
	}

	// Case 2: Check if we can update in-place (sole owner)
	if hadOld && a.refcount[oldRuleSetID] == 1 {
		oldRules := a.idToRules[oldRuleSetID]
		if oldRules != nil {
			newSharedRules := a.convertToSharedRules(oldRuleSetID, rules)

			added, removed, modified := diffSharedRules(oldRules, newSharedRules)

			if len(added) > 0 || len(removed) > 0 || len(modified) > 0 {
				if err := a.applyIncrementalUpdate(oldRuleSetID, added, removed, modified); err != nil {
					return a.allocateNewRuleSetLocked(epID, rules, newHash, hadOld, oldRuleSetID)
				}

				a.idToRules[oldRuleSetID] = newSharedRules
				delete(a.rulesets, a.idToHash[oldRuleSetID])
				a.rulesets[newHash] = oldRuleSetID
				a.idToHash[oldRuleSetID] = newHash

				return oldRuleSetID, true, nil
			}
			return oldRuleSetID, false, nil
		}
	}

	// Case 3: Fallback - allocate new rule set
	return a.allocateNewRuleSetLocked(epID, rules, newHash, hadOld, oldRuleSetID)
}

func (a *RuleSetAllocator) allocateNewRuleSetLocked(epID uint16, rules []ArenaRuleWithEntry, hash ruleSetKey, hadOld bool, oldRuleSetID uint32) (uint32, bool, error) {
	ruleSetID, err := a.nextIDLocked()
	if err != nil {
		return 0, false, err
	}

	sharedRules := a.convertToSharedRules(ruleSetID, rules)

	EnsureSharedMapsOpen()
	m := GetSharedPolicyMap()
	for i, r := range sharedRules {
		if err := m.Update(&r.Key, &r.Entry); err != nil {
			for j := range i {
				_ = m.Delete(&sharedRules[j].Key)
			}
			a.freeIDs = append(a.freeIDs, ruleSetID)
			return 0, false, fmt.Errorf("failed to write shared rules: %w", err)
		}
	}

	a.rulesets[hash] = ruleSetID
	a.idToHash[ruleSetID] = hash
	a.idToRules[ruleSetID] = sharedRules
	a.refcount[ruleSetID] = 1
	a.epToRuleSetID[epID] = ruleSetID

	if hadOld {
		a.releaseRuleSetLocked(oldRuleSetID)
	}

	return ruleSetID, false, nil
}

func (a *RuleSetAllocator) convertToSharedRules(ruleSetID uint32, rules []ArenaRuleWithEntry) []SharedRule {
	sharedRules := make([]SharedRule, len(rules))
	for i, r := range rules {
		key := NewSharedKey(ruleSetID, r.Key)
		entry := NewSharedEntry(key, r.Entry)
		sharedRules[i] = SharedRule{Key: key, Entry: entry}
	}
	return sharedRules
}

func (a *RuleSetAllocator) releaseRuleSetLocked(id uint32) {
	if a.refcount[id] == 0 {
		return
	}

	a.refcount[id]--
	if a.refcount[id] == 0 {
		if hash, exists := a.idToHash[id]; exists {
			delete(a.rulesets, hash)
			delete(a.idToHash, id)
		}

		if rules, exists := a.idToRules[id]; exists {
			a.deleteRuleSetLocked(id, rules)
			delete(a.idToRules, id)
		} else {
			a.deleteRuleSetLocked(id, nil)
		}

		delete(a.refcount, id)
		a.freeIDs = append(a.freeIDs, id)
	}
}

func (a *RuleSetAllocator) deleteRuleSetLocked(id uint32, rules []SharedRule) {
	m := GetSharedPolicyMap()
	if len(rules) > 0 {
		for _, r := range rules {
			_ = m.Delete(&r.Key)
		}
	} else {
		// Fallback: iterate shared policy map and remove any entries matching id
		var toDelete []bpf.MapKey
		_ = m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
			if key, ok := k.(*SharedPolicyKey); ok && key.RuleSetID == id {
				toDelete = append(toDelete, key)
			}
		})
		for _, key := range toDelete {
			_ = m.Delete(key)
		}
	}
}

func diffSharedRules(old, new []SharedRule) (added, removed []SharedRule, modified []modifiedRule) {
	oldMap := make(map[ruleKeyWithoutRuleSetID]SharedRule, len(old))
	for _, r := range old {
		key := ruleKeyWithoutRuleSetID{
			Identity:  r.Key.Identity,
			Egress:    r.Key.TrafficDirection,
			Protocol:  r.Key.Nexthdr,
			DPort:     r.Key.DestPortNetwork,
			PrefixLen: r.Key.GetPrefixLen(),
		}
		oldMap[key] = r
	}

	for _, r := range new {
		key := ruleKeyWithoutRuleSetID{
			Identity:  r.Key.Identity,
			Egress:    r.Key.TrafficDirection,
			Protocol:  r.Key.Nexthdr,
			DPort:     r.Key.DestPortNetwork,
			PrefixLen: r.Key.GetPrefixLen(),
		}
		if oldRule, exists := oldMap[key]; exists {
			if !sharedRulesEqual(oldRule.Entry, r.Entry) {
				modified = append(modified, modifiedRule{old: oldRule, new: r})
			}
			delete(oldMap, key)
		} else {
			added = append(added, r)
		}
	}

	for _, r := range oldMap {
		removed = append(removed, r)
	}

	return
}

type modifiedRule struct {
	old SharedRule
	new SharedRule
}

func sharedRulesEqual(a, b PolicyEntry) bool {
	return a.ProxyPortNetwork == b.ProxyPortNetwork &&
		a.Flags == b.Flags &&
		a.AuthRequirement == b.AuthRequirement &&
		a.Precedence == b.Precedence &&
		a.Cookie == b.Cookie
}

func (a *RuleSetAllocator) applyIncrementalUpdate(ruleSetID uint32, added, removed []SharedRule, modified []modifiedRule) error {
	EnsureSharedMapsOpen()
	m := GetSharedPolicyMap()
	for _, r := range removed {
		_ = m.Delete(&r.Key)
	}

	for _, mod := range modified {
		if err := m.Update(&mod.new.Key, &mod.new.Entry); err != nil {
			return fmt.Errorf("failed to update modified rule: %w", err)
		}
	}

	for _, r := range added {
		if err := m.Update(&r.Key, &r.Entry); err != nil {
			return fmt.Errorf("failed to insert new rule: %w", err)
		}
	}

	return nil
}

// RemoveEndpoint removes endpoint tracking from the allocator.
func (a *RuleSetAllocator) RemoveEndpoint(epID uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ruleSetID, ok := a.epToRuleSetID[epID]; ok {
		a.releaseRuleSetLocked(ruleSetID)
		delete(a.epToRuleSetID, epID)
	}
}

// RestoreRuleSet recovers ruleset state during agent startup.
func (a *RuleSetAllocator) RestoreRuleSet(id uint32) error {
	if id == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.idToHash[id]; exists {
		return nil
	}

	placeholderHash := ruleSetKey(fmt.Sprintf("restored:%d", id))
	a.rulesets[placeholderHash] = id
	a.idToHash[id] = placeholderHash
	a.refcount[id] = 0

	if id >= a.nextRuleSetID {
		a.nextRuleSetID = id + 1
	}

	return nil
}

// RestoreRuleSetWithRules recovers a rule set and its rules during agent startup.
func (a *RuleSetAllocator) RestoreRuleSetWithRules(id uint32, rules []SharedRule) error {
	if id == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	ruleSetHash := ComputeRuleSetHashFromSharedRules(rules)
	a.rulesets[ruleSetHash] = id
	a.idToHash[id] = ruleSetHash
	a.idToRules[id] = rules
	a.refcount[id] = 0 // will be populated when LinkEndpoint is called

	if id >= a.nextRuleSetID {
		a.nextRuleSetID = id + 1
	}

	return nil
}

// PurgeOrphanedRuleSets removes rulesets that have no endpoints referencing them.
func (a *RuleSetAllocator) PurgeOrphanedRuleSets() {
	a.mu.Lock()
	defer a.mu.Unlock()

	var orphaned []uint32
	for id, ref := range a.refcount {
		if ref == 0 {
			orphaned = append(orphaned, id)
		}
	}

	for _, id := range orphaned {
		if hash, exists := a.idToHash[id]; exists {
			delete(a.rulesets, hash)
			delete(a.idToHash, id)
		}
		if rules, exists := a.idToRules[id]; exists {
			a.deleteRuleSetLocked(id, rules)
			delete(a.idToRules, id)
		} else {
			a.deleteRuleSetLocked(id, nil)
		}
		delete(a.refcount, id)
		a.freeIDs = append(a.freeIDs, id)
	}
}

// LinkEndpoint explicitly tracks which rule set an endpoint is using.
func (a *RuleSetAllocator) LinkEndpoint(epID uint16, ruleSetID uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if oldID, hadOld := a.epToRuleSetID[epID]; hadOld {
		if oldID == ruleSetID {
			return
		}
		if a.refcount[oldID] > 0 {
			a.releaseRuleSetLocked(oldID)
		}
	}

	if _, exists := a.idToHash[ruleSetID]; !exists {
		placeholderHash := ruleSetKey(fmt.Sprintf("restored:%d", ruleSetID))
		a.rulesets[placeholderHash] = ruleSetID
		a.idToHash[ruleSetID] = placeholderHash
		a.refcount[ruleSetID] = 0
	}

	if ruleSetID >= a.nextRuleSetID {
		a.nextRuleSetID = ruleSetID + 1
	}

	a.epToRuleSetID[epID] = ruleSetID
	a.refcount[ruleSetID]++
}

// ReleaseByID releases a reference to the rule set.
func (a *RuleSetAllocator) ReleaseByID(id uint32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.refcount[id] == 0 {
		return false
	}

	a.releaseRuleSetLocked(id)
	return a.refcount[id] == 0
}

func getPortPrefixLen(pk policyTypes.Key) uint8 {
	if pk.Nexthdr != 0 || pk.DestPort != 0 {
		prefixLen := uint8(LPMProtoPrefixBits)
		if pk.DestPort != 0 {
			prefixLen += pk.PortPrefixLen()
		}
		return prefixLen
	}
	return 0
}

// ComputeRuleSetHashFromEntries calculates a deterministic hash for a set of rules.
func ComputeRuleSetHashFromEntries(rules []ArenaRuleWithEntry) ruleSetKey {
	sorted := make([]ArenaRuleWithEntry, len(rules))
	copy(sorted, rules)

	slices.SortFunc(sorted, func(a, b ArenaRuleWithEntry) int {
		if v := cmp.Compare(a.Key.Identity, b.Key.Identity); v != 0 {
			return v
		}
		if v := cmp.Compare(a.Key.TrafficDirection(), b.Key.TrafficDirection()); v != 0 {
			return v
		}
		if v := cmp.Compare(a.Key.Nexthdr, b.Key.Nexthdr); v != 0 {
			return v
		}
		if v := cmp.Compare(a.Key.DestPort, b.Key.DestPort); v != 0 {
			return v
		}
		return cmp.Compare(getPortPrefixLen(a.Key), getPortPrefixLen(b.Key))
	})

	d := xxhash.New()
	buf := make([]byte, 23)
	for _, r := range sorted {
		binary.LittleEndian.PutUint32(buf[0:], uint32(r.Key.Identity))
		buf[4] = uint8(r.Key.TrafficDirection())
		buf[5] = uint8(r.Key.Nexthdr)
		binary.LittleEndian.PutUint16(buf[6:], r.Key.DestPort)
		buf[8] = getPortPrefixLen(r.Key)
		binary.LittleEndian.PutUint16(buf[9:], r.Entry.ProxyPort)
		buf[11] = uint8(r.Entry.AuthRequirement.AuthType())
		if r.Entry.IsDeny() {
			buf[12] = 1
		} else {
			buf[12] = 0
		}
		binary.LittleEndian.PutUint32(buf[13:], uint32(r.Entry.Precedence))
		binary.LittleEndian.PutUint32(buf[17:], r.Entry.Cookie)
		buf[21] = '|'
		buf[22] = 0
		d.Write(buf)
	}

	return ruleSetKey(strconv.FormatUint(d.Sum64(), 36))
}

// ComputeRuleSetHashFromSharedRules calculates a deterministic hash for a set of SharedRules.
func ComputeRuleSetHashFromSharedRules(rules []SharedRule) ruleSetKey {
	sorted := make([]SharedRule, len(rules))
	copy(sorted, rules)

	slices.SortFunc(sorted, func(a, b SharedRule) int {
		if v := cmp.Compare(a.Key.Identity, b.Key.Identity); v != 0 {
			return v
		}
		if v := cmp.Compare(a.Key.TrafficDirection, b.Key.TrafficDirection); v != 0 {
			return v
		}
		if v := cmp.Compare(a.Key.Nexthdr, b.Key.Nexthdr); v != 0 {
			return v
		}
		if v := cmp.Compare(a.Key.GetDestPort(), b.Key.GetDestPort()); v != 0 {
			return v
		}
		return cmp.Compare(a.Key.GetPrefixLen(), b.Key.GetPrefixLen())
	})

	d := xxhash.New()
	buf := make([]byte, 23)
	for _, r := range sorted {
		binary.LittleEndian.PutUint32(buf[0:], r.Key.Identity)
		buf[4] = r.Key.TrafficDirection
		buf[5] = r.Key.Nexthdr
		binary.LittleEndian.PutUint16(buf[6:], r.Key.GetDestPort())
		buf[8] = r.Key.GetPrefixLen()
		binary.LittleEndian.PutUint16(buf[9:], r.Entry.GetProxyPort())
		buf[11] = uint8(r.Entry.AuthRequirement.AuthType())
		if r.Entry.IsDeny() {
			buf[12] = 1
		} else {
			buf[12] = 0
		}
		binary.LittleEndian.PutUint32(buf[13:], uint32(r.Entry.Precedence))
		binary.LittleEndian.PutUint32(buf[17:], r.Entry.Cookie)
		buf[21] = '|'
		buf[22] = 0
		d.Write(buf)
	}

	return ruleSetKey(strconv.FormatUint(d.Sum64(), 36))
}
