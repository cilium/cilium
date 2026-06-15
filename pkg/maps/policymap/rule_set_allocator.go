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

	"github.com/cilium/cilium/pkg/lock"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

const (
	// MaxRuleSets is the maximum number of unique rule sets.
	MaxRuleSets = 4096
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
	epToRuleSetID map[uint16]uint32       // endpoint ID -> current rule_set_id
	maxRuleSets   uint32
}

// NewRuleSetAllocator creates a new allocator.
func NewRuleSetAllocator(maxRuleSets ...uint32) *RuleSetAllocator {
	maxVal := uint32(MaxRuleSets)
	if len(maxRuleSets) > 0 && maxRuleSets[0] > 0 {
		maxVal = maxRuleSets[0]
	}
	return &RuleSetAllocator{
		rulesets:      make(map[ruleSetKey]uint32),
		idToHash:      make(map[uint32]ruleSetKey),
		idToRules:     make(map[uint32][]SharedRule),
		refcount:      make(map[uint32]int),
		nextRuleSetID: 1, // Start from 1 (0 is reserved for "no rule set")
		epToRuleSetID: make(map[uint16]uint32),
		maxRuleSets:   maxVal,
	}
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

	if a.nextRuleSetID >= a.maxRuleSets {
		return 0, fmt.Errorf("max rule sets reached: %d", a.maxRuleSets)
	}

	ruleSetID := a.nextRuleSetID
	a.nextRuleSetID++

	sharedRules := make([]SharedRule, len(rules))
	for i, r := range rules {
		key := NewSharedKey(ruleSetID, r.Key)
		entry := NewSharedEntry(key, r.Entry)

		if err := SharedPolicyMap.Update(&key, &entry); err != nil {
			for j := range i {
				_ = SharedPolicyMap.Delete(&sharedRules[j].Key)
			}
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
	if a.nextRuleSetID >= a.maxRuleSets {
		return 0, false, fmt.Errorf("max rule sets reached: %d", a.maxRuleSets)
	}

	ruleSetID := a.nextRuleSetID
	a.nextRuleSetID++

	sharedRules := a.convertToSharedRules(ruleSetID, rules)

	EnsureSharedMapsOpen()
	for i, r := range sharedRules {
		if err := SharedPolicyMap.Update(&r.Key, &r.Entry); err != nil {
			for j := range i {
				_ = SharedPolicyMap.Delete(&sharedRules[j].Key)
			}
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
		}

		delete(a.refcount, id)
	}
}

func (a *RuleSetAllocator) deleteRuleSetLocked(id uint32, rules []SharedRule) {
	for _, r := range rules {
		_ = SharedPolicyMap.Delete(&r.Key)
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
	for _, r := range removed {
		_ = SharedPolicyMap.Delete(&r.Key)
	}

	for _, m := range modified {
		if err := SharedPolicyMap.Update(&m.new.Key, &m.new.Entry); err != nil {
			return fmt.Errorf("failed to update modified rule: %w", err)
		}
	}

	for _, r := range added {
		if err := SharedPolicyMap.Update(&r.Key, &r.Entry); err != nil {
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
		a.refcount[id]++
		return nil
	}

	placeholderHash := ruleSetKey(fmt.Sprintf("restored:%d", id))
	a.rulesets[placeholderHash] = id
	a.idToHash[id] = placeholderHash
	a.refcount[id] = 1

	if id >= a.nextRuleSetID {
		a.nextRuleSetID = id + 1
	}

	return nil
}

// LinkEndpoint explicitly tracks which rule set an endpoint is using.
func (a *RuleSetAllocator) LinkEndpoint(epID uint16, ruleSetID uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.epToRuleSetID[epID] = ruleSetID
}

// ReleaseByID releases a reference to the rule set.
func (a *RuleSetAllocator) ReleaseByID(id uint32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.refcount[id] == 0 {
		return false
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
		}

		delete(a.refcount, id)
		return true
	}
	return false
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
		return cmp.Compare(a.Key.DestPort, b.Key.DestPort)
	})

	d := xxhash.New()
	buf := make([]byte, 22)
	for _, r := range sorted {
		binary.LittleEndian.PutUint32(buf[0:], uint32(r.Key.Identity))
		buf[4] = uint8(r.Key.TrafficDirection())
		buf[5] = uint8(r.Key.Nexthdr)
		binary.LittleEndian.PutUint16(buf[6:], r.Key.DestPort)
		binary.LittleEndian.PutUint16(buf[8:], r.Entry.ProxyPort)
		buf[10] = uint8(r.Entry.AuthRequirement.AuthType())
		if r.Entry.IsDeny() {
			buf[11] = 1
		} else {
			buf[11] = 0
		}
		binary.LittleEndian.PutUint32(buf[12:], uint32(r.Entry.Precedence))
		binary.LittleEndian.PutUint32(buf[16:], r.Entry.Cookie)
		buf[20] = '|'
		buf[21] = 0
		d.Write(buf)
	}

	return ruleSetKey(strconv.FormatUint(d.Sum64(), 36))
}
