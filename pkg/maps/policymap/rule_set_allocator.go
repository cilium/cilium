// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
	"strconv"

	"github.com/cespare/xxhash/v2"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/lock"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

// ruleSetKey represents the hash of a set of rules.
type ruleSetKey string

// ruleKeyWithoutRuleSetID represents a rule's key fields excluding RuleSetID.
// Used for diffing rules within a rule set.
type ruleKeyWithoutRuleSetID struct {
	Identity  uint32
	Egress    uint8
	Protocol  uint8
	DPort     uint16
	PrefixLen uint8
}

// RuleSetAllocator manages the assignment of unique GroupIDs to sets of policy rules.
// In Phase 4: Uses shared LPM trie for kernel-handled prefix matching + arena for data dedup.
type RuleSetAllocator struct {
	mu            lock.Mutex
	rulesets      map[ruleSetKey]uint32      // hash -> rule_set_id
	idToHash      map[uint32]ruleSetKey      // rule_set_id -> hash
	idToRules     map[uint32][]SharedLPMRule // rule_set_id -> rules (for cleanup and incremental updates)
	refcount      map[uint32]int             // rule_set_id -> refcount
	nextRuleSetID uint32                     // Next available rule_set_id
	arenaAlloc    *ArenaAllocator            // Arena for rule data storage
	epToRuleSetID map[uint16]uint32          // endpoint ID -> current rule_set_id (for incremental updates)
}

// NewRuleSetAllocator creates a new allocator.
// maxGroups: Max unique rule sets (controls memory usage).
func NewRuleSetAllocator(maxGroups int, arena *ArenaAllocator) *RuleSetAllocator {
	return &RuleSetAllocator{
		rulesets:      make(map[ruleSetKey]uint32),
		idToHash:      make(map[uint32]ruleSetKey),
		idToRules:     make(map[uint32][]SharedLPMRule),
		refcount:      make(map[uint32]int),
		nextRuleSetID: 1, // Start from 1 (0 is reserved for "no rule set")
		arenaAlloc:    arena,
		epToRuleSetID: make(map[uint16]uint32),
	}
}

// ArenaRuleWithEntry combines a SharedPolicyKey with its associated MapStateEntry
// for storage in the arena.
type ArenaRuleWithEntry struct {
	Key   policyTypes.Key
	Entry policyTypes.MapStateEntry
}

// GetOrAllocate returns the rule_set_id for the given rules with full entry data.
func (a *RuleSetAllocator) GetOrAllocate(rules []ArenaRuleWithEntry) (uint32, error) {
	// 1. Compute Hash (from key+entry fields for deduplication)
	ruleSetHash := ComputeRuleSetHashFromEntries(rules)

	a.mu.Lock()
	defer a.mu.Unlock()

	// 2. Check Cache - if same rules exist, reuse rule_set_id
	if id, exists := a.rulesets[ruleSetHash]; exists {
		a.refcount[id]++
		return id, nil
	}

	// 3. Allocate New rule_set_id
	if a.arenaAlloc == nil {
		return 0, fmt.Errorf("arena allocator not initialized")
	}

	// Check limits
	if len(rules) > 65535 {
		return 0, fmt.Errorf("too many rules in set: %d (max 65535)", len(rules))
	}

	if a.nextRuleSetID >= MaxRuleSets {
		return 0, fmt.Errorf("max rule sets reached: %d", MaxRuleSets)
	}

	// Allocate new rule_set_id
	ruleSetID := a.nextRuleSetID
	a.nextRuleSetID++

	// 4. Convert to SharedLPMRule format
	sharedRules := make([]SharedLPMRule, len(rules))
	for i, r := range rules {
		// Convert Go direction to BPF direction
		egress := uint8(0)
		if r.Key.TrafficDirection() == 1 { // Egress in Go
			egress = 1
		}

		portPrefixLen := r.Key.PortPrefixLen()
		var prefixLen uint8
		if r.Key.Nexthdr == 0 {
			// L3-only: any protocol implies any port
			prefixLen = 0
		} else if portPrefixLen == 0 {
			// Specific protocol, but any port
			prefixLen = 8
		} else {
			// Specific protocol + port (range)
			prefixLen = 8 + portPrefixLen
		}

		sharedRules[i] = SharedLPMRule{
			// Key fields
			RuleSetID: ruleSetID,
			Identity:  uint32(r.Key.Identity),
			Egress:    egress,
			Protocol:  uint8(r.Key.Nexthdr),
			DPort:     r.Key.DestPort, // Host byte order
			PrefixLen: prefixLen,

			// Value fields
			ProxyPort:   r.Entry.ProxyPort,
			Deny:        r.Entry.IsDeny(),
			AuthType:    uint8(r.Entry.AuthRequirement.AuthType()),
			HasExplicit: r.Entry.AuthRequirement.IsExplicit(),
			Precedence:  uint32(r.Entry.Precedence),
			Cookie:      r.Entry.Cookie,
		}
	}

	// 5. Write to shared LPM trie + arena
	if err := a.arenaAlloc.WriteRulesToSharedLPM(sharedRules); err != nil {
		return 0, fmt.Errorf("write to shared LPM failed: %w", err)
	}

	// 6. Update Cache
	a.rulesets[ruleSetHash] = ruleSetID
	a.idToHash[ruleSetID] = ruleSetHash
	a.idToRules[ruleSetID] = sharedRules // Store for cleanup
	a.refcount[ruleSetID] = 1

	return ruleSetID, nil
}

// UpdateEndpointRules performs incremental updates when possible.
func (a *RuleSetAllocator) UpdateEndpointRules(epID uint16, rules []ArenaRuleWithEntry) (uint32, bool, error) {
	if a.arenaAlloc == nil {
		return 0, false, fmt.Errorf("arena allocator not initialized")
	}

	// Compute hash of new rules
	newHash := ComputeRuleSetHashFromEntries(rules)

	a.mu.Lock()
	defer a.mu.Unlock()

	// Get current state for this endpoint
	oldRuleSetID, hadOld := a.epToRuleSetID[epID]

	// Case 1: Exact hash match exists (cross-endpoint deduplication)
	if existingID, ok := a.rulesets[newHash]; ok {
		if existingID == oldRuleSetID {
			// No change - same rules, same RuleSetID
			return existingID, false, nil
		}
		// Switch to existing shared rule set
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
			// Convert new rules to SharedLPMRule format
			newSharedRules := a.convertToSharedLPMRules(oldRuleSetID, rules)

			// Compute diff
			added, removed, modified := diffSharedLPMRules(oldRules, newSharedRules)

			// If there are changes, apply incrementally
			if len(added) > 0 || len(removed) > 0 || len(modified) > 0 {
				if err := a.applyIncrementalUpdate(oldRuleSetID, added, removed, modified); err != nil {
					// Fallback to full rebuild on error
					return a.allocateNewRuleSetLocked(epID, rules, newHash, hadOld, oldRuleSetID)
				}

				// Update tracking
				a.idToRules[oldRuleSetID] = newSharedRules
				delete(a.rulesets, a.idToHash[oldRuleSetID])
				a.rulesets[newHash] = oldRuleSetID
				a.idToHash[oldRuleSetID] = newHash

				return oldRuleSetID, true, nil
			}
			// No changes - same rules
			return oldRuleSetID, false, nil
		}
	}

	// Case 3: Fallback - allocate new rule set
	return a.allocateNewRuleSetLocked(epID, rules, newHash, hadOld, oldRuleSetID)
}

// allocateNewRuleSetLocked allocates a new RuleSetID and writes all rules.
// Must be called with a.mu held.
func (a *RuleSetAllocator) allocateNewRuleSetLocked(epID uint16, rules []ArenaRuleWithEntry, hash ruleSetKey, hadOld bool, oldRuleSetID uint32) (uint32, bool, error) {
	if len(rules) > 65535 {
		return 0, false, fmt.Errorf("too many rules in set: %d (max 65535)", len(rules))
	}

	if a.nextRuleSetID >= MaxRuleSets {
		return 0, false, fmt.Errorf("max rule sets reached: %d", MaxRuleSets)
	}

	// Allocate new rule_set_id
	ruleSetID := a.nextRuleSetID
	a.nextRuleSetID++

	// Convert and write rules
	sharedRules := a.convertToSharedLPMRules(ruleSetID, rules)

	if err := a.arenaAlloc.WriteRulesToSharedLPM(sharedRules); err != nil {
		return 0, false, fmt.Errorf("write to shared LPM failed: %w", err)
	}

	// Update cache
	a.rulesets[hash] = ruleSetID
	a.idToHash[ruleSetID] = hash
	a.idToRules[ruleSetID] = sharedRules
	a.refcount[ruleSetID] = 1
	a.epToRuleSetID[epID] = ruleSetID

	// Release old rule set
	if hadOld {
		a.releaseRuleSetLocked(oldRuleSetID)
	}

	return ruleSetID, false, nil
}

// convertToSharedLPMRules converts ArenaRuleWithEntry slice to SharedLPMRule slice.
func (a *RuleSetAllocator) convertToSharedLPMRules(ruleSetID uint32, rules []ArenaRuleWithEntry) []SharedLPMRule {
	sharedRules := make([]SharedLPMRule, len(rules))
	for i, r := range rules {
		egress := uint8(0)
		if r.Key.TrafficDirection() == 1 {
			egress = 1
		}

		portPrefixLen := r.Key.PortPrefixLen()
		var prefixLen uint8
		if r.Key.Nexthdr == 0 {
			prefixLen = 0
		} else if portPrefixLen == 0 {
			prefixLen = 8
		} else {
			prefixLen = 8 + portPrefixLen
		}

		sharedRules[i] = SharedLPMRule{
			RuleSetID:   ruleSetID,
			Identity:    uint32(r.Key.Identity),
			Egress:      egress,
			Protocol:    uint8(r.Key.Nexthdr),
			DPort:       r.Key.DestPort,
			PrefixLen:   prefixLen,
			ProxyPort:   r.Entry.ProxyPort,
			Deny:        r.Entry.IsDeny(),
			AuthType:    uint8(r.Entry.AuthRequirement.AuthType()),
			HasExplicit: r.Entry.AuthRequirement.IsExplicit(),
			Precedence:  uint32(r.Entry.Precedence),
			Cookie:      r.Entry.Cookie,
		}
	}
	return sharedRules
}

// releaseRuleSetLocked decrements refcount and cleans up if zero.
// Must be called with a.mu held.
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
			if a.arenaAlloc != nil {
				_ = a.arenaAlloc.DeleteRuleSetFromSharedLPM(id, rules)
			}
			delete(a.idToRules, id)
		}

		delete(a.refcount, id)
	}
}

// diffSharedLPMRules computes the difference between old and new rule sets.
// Returns slices of added, removed, and modified rules.
// Uses pre-allocated maps with capacity hints for efficiency.
func diffSharedLPMRules(old, new []SharedLPMRule) (added, removed []SharedLPMRule, modified []modifiedRule) {
	// Build map of old rules by key (excluding RuleSetID) with capacity hint
	oldMap := make(map[ruleKeyWithoutRuleSetID]SharedLPMRule, len(old))
	for _, r := range old {
		key := ruleKeyWithoutRuleSetID{
			Identity:  r.Identity,
			Egress:    r.Egress,
			Protocol:  r.Protocol,
			DPort:     r.DPort,
			PrefixLen: r.PrefixLen,
		}
		oldMap[key] = r
	}

	// Find added and modified (single pass over new rules, no second map needed)
	for _, r := range new {
		key := ruleKeyWithoutRuleSetID{
			Identity:  r.Identity,
			Egress:    r.Egress,
			Protocol:  r.Protocol,
			DPort:     r.DPort,
			PrefixLen: r.PrefixLen,
		}
		if oldRule, exists := oldMap[key]; exists {
			// Same key - check if value changed
			if !sharedLPMRulesEqual(oldRule, r) {
				modified = append(modified, modifiedRule{old: oldRule, new: r})
			}
			delete(oldMap, key) // Mark as processed
		} else {
			added = append(added, r)
		}
	}

	// Remaining in oldMap are removed
	for _, r := range oldMap {
		removed = append(removed, r)
	}

	return
}

// modifiedRule represents a rule that changed value but kept the same key.
type modifiedRule struct {
	old SharedLPMRule
	new SharedLPMRule
}

// sharedLPMRulesEqual checks if two rules have the same value fields.
func sharedLPMRulesEqual(a, b SharedLPMRule) bool {
	return a.ProxyPort == b.ProxyPort &&
		a.Deny == b.Deny &&
		a.AuthType == b.AuthType &&
		a.HasExplicit == b.HasExplicit &&
		a.Precedence == b.Precedence &&
		a.Cookie == b.Cookie
}

// applyIncrementalUpdate applies only the changed rules to the LPM trie.
func (a *RuleSetAllocator) applyIncrementalUpdate(ruleSetID uint32, added, removed []SharedLPMRule, modified []modifiedRule) error {
	// Delete removed rules
	if len(removed) > 0 {
		if err := a.arenaAlloc.DeleteRuleSetFromSharedLPM(ruleSetID, removed); err != nil {
			return fmt.Errorf("failed to delete removed rules: %w", err)
		}
	}

	// Handle modified rules: delete old, add new
	for _, m := range modified {
		// Delete old entry
		if err := a.arenaAlloc.DeleteRuleSetFromSharedLPM(ruleSetID, []SharedLPMRule{m.old}); err != nil {
			// Log but continue - may not exist
		}
	}

	// Collect all rules to add (new rules + modified new versions)
	toAdd := make([]SharedLPMRule, 0, len(added)+len(modified))
	toAdd = append(toAdd, added...)
	for _, m := range modified {
		toAdd = append(toAdd, m.new)
	}

	// Write new rules
	if len(toAdd) > 0 {
		if err := a.arenaAlloc.WriteRulesToSharedLPM(toAdd); err != nil {
			return fmt.Errorf("failed to write new rules: %w", err)
		}
	}

	return nil
}

// RemoveEndpoint removes endpoint tracking from the allocator.
// This should be called when an endpoint is deleted.
func (a *RuleSetAllocator) RemoveEndpoint(epID uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ruleSetID, ok := a.epToRuleSetID[epID]; ok {
		a.releaseRuleSetLocked(ruleSetID)
		delete(a.epToRuleSetID, epID)
	}
}

// RestoreRuleSet re-registers an existing RuleSet into the allocator's cache
// and increments its refcount. This is used during agent startup to recover state.
//
// Phase 4: rule_set_id is an incrementing counter, not an arena offset.
// The shared LPM trie and arena are pinned kernel maps that persist across restarts.
// We just need to track refcounts - the actual rule data remains in the kernel maps.
func (a *RuleSetAllocator) RestoreRuleSet(id uint32) error {
	if id == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// 1. If already tracked, just increment refcount
	if _, exists := a.idToHash[id]; exists {
		a.refcount[id]++
		return nil
	}

	// 2. Track this rule_set_id
	// Generate a placeholder hash based on the ID
	// (actual rules persist in the kernel LPM trie)
	placeholderHash := ruleSetKey(fmt.Sprintf("restored:%d", id))

	a.rulesets[placeholderHash] = id
	a.idToHash[id] = placeholderHash
	a.refcount[id] = 1

	// Update nextRuleSetID if needed to avoid collisions
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
// When refcount reaches 0, removes entries from the shared LPM trie.
func (a *RuleSetAllocator) ReleaseByID(id uint32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.refcount[id] == 0 {
		return false // Double free?
	}

	a.refcount[id]--
	if a.refcount[id] == 0 {
		// Garbage Collect from caches
		if hash, exists := a.idToHash[id]; exists {
			delete(a.rulesets, hash)
			delete(a.idToHash, id)
		}

		// Delete entries from shared LPM trie
		if rules, exists := a.idToRules[id]; exists {
			if a.arenaAlloc != nil {
				// DeleteRuleSetFromSharedLPM handles its own error logging
				_ = a.arenaAlloc.DeleteRuleSetFromSharedLPM(id, rules)
			}
			delete(a.idToRules, id)
		}

		delete(a.refcount, id)
		return true
	}
	return false
}

// ComputeRuleSetHash calculates a deterministic hash for a set of rules.
// Uses xxhash for fast, non-cryptographic hashing with binary encoding
// to avoid expensive string formatting and SHA256.
func ComputeRuleSetHash(keys []SharedPolicyKey) ruleSetKey {
	// Create a copy to sort
	sorted := make([]SharedPolicyKey, len(keys))
	copy(sorted, keys)

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Identity != sorted[j].Identity {
			return sorted[i].Identity < sorted[j].Identity
		}
		if sorted[i].Direction != sorted[j].Direction {
			return sorted[i].Direction < sorted[j].Direction
		}
		if sorted[i].Nexthdr != sorted[j].Nexthdr {
			return sorted[i].Nexthdr < sorted[j].Nexthdr
		}
		// Sort by Network Byte Order to match BPF's view.
		portI := sorted[i].DestPortNetwork
		portJ := sorted[j].DestPortNetwork
		if portI != portJ {
			return portI < portJ
		}
		pportI := byteorder.HostToNetwork16(sorted[i].ProxyPort)
		pportJ := byteorder.HostToNetwork16(sorted[j].ProxyPort)
		if pportI != pportJ {
			return pportI < pportJ
		}
		if sorted[i].PrefixLen != sorted[j].PrefixLen {
			return sorted[i].PrefixLen < sorted[j].PrefixLen
		}
		if sorted[i].AuthType != sorted[j].AuthType {
			return sorted[i].AuthType < sorted[j].AuthType
		}
		if sorted[i].Precedence != sorted[j].Precedence {
			return sorted[i].Precedence < sorted[j].Precedence
		}
		if sorted[i].Deny != sorted[j].Deny {
			return sorted[i].Deny < sorted[j].Deny
		}
		return sorted[i].Cookie < sorted[j].Cookie
	})

	// Use streaming xxhash with binary encoding instead of string formatting + SHA256.
	// Each rule contributes 22 bytes (4+1+1+2+1+2+1+1+4+4+1 = 22) to the hash.
	d := xxhash.New()
	buf := make([]byte, 22)
	for _, k := range sorted {
		binary.LittleEndian.PutUint32(buf[0:], uint32(k.Identity))
		buf[4] = uint8(k.Direction)
		buf[5] = uint8(k.Nexthdr)
		binary.LittleEndian.PutUint16(buf[6:], k.DestPortNetwork)
		buf[8] = k.PrefixLen
		binary.LittleEndian.PutUint16(buf[9:], k.ProxyPort)
		buf[11] = k.AuthType
		buf[12] = k.Deny
		binary.LittleEndian.PutUint32(buf[13:], uint32(k.Precedence))
		binary.LittleEndian.PutUint32(buf[17:], k.Cookie)
		buf[21] = '|' // separator
		d.Write(buf)
	}

	return ruleSetKey(strconv.FormatUint(d.Sum64(), 36))
}

// ComputeRuleSetHashFromEntries calculates a deterministic hash for a set of rules with entries.
// Uses xxhash with binary encoding for fast hashing. Includes both key and entry fields
// for full deduplication.
func ComputeRuleSetHashFromEntries(rules []ArenaRuleWithEntry) ruleSetKey {
	// Create a copy to sort
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

	// Use streaming xxhash with binary encoding instead of string formatting + SHA256.
	// Each rule contributes 22 bytes to the hash:
	//   identity(4) + direction(1) + nexthdr(1) + destport(2) +
	//   proxyport(2) + authtype(1) + deny(1) + precedence(4) + cookie(4) + sep(1) + pad(1) = 22
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
		buf[20] = '|' // separator
		buf[21] = 0   // padding
		d.Write(buf)
	}

	return ruleSetKey(strconv.FormatUint(d.Sum64(), 36))
}
