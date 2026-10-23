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

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

const (
	// MaxRuleSets is the maximum number of unique rule sets.
	// Sized as 2x the maximum endpoints per node to accommodate
	// concurrent hitless transitions during rolling policy updates.
	MaxRuleSets = 2 * defaults.MaxEndpointID
)

// ruleSetKey represents the hash of a set of rules.
type ruleSetKey string

// sharedRule pairs a SharedPolicyKey with its PolicyEntry value.
type sharedRule struct {
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

// ruleSetEntry holds metadata and rules for an allocated rule_set_id.
type ruleSetEntry struct {
	hash     ruleSetKey
	rules    []sharedRule
	refcount int
}

// RuleSetAllocator manages the assignment of unique RuleSetIDs to sets of policy rules.
type RuleSetAllocator struct {
	mu            lock.Mutex
	rulesets      map[ruleSetKey]uint32    // hash -> rule_set_id
	byID          map[uint32]*ruleSetEntry // rule_set_id -> entry (hash, rules, refcount)
	nextRuleSetID uint32                   // Next available rule_set_id
	freeIDs       []uint32                 // Recycled rule_set_ids available for reuse
	epToRuleSetID map[uint16]uint32        // endpoint ID -> current rule_set_id
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
		byID:          make(map[uint32]*ruleSetEntry),
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

// ruleWithEntry combines a policy key with its entry for allocation input.
type ruleWithEntry struct {
	Key   policyTypes.Key
	Entry policyTypes.MapStateEntry
}

func convertToSharedRules(ruleSetID uint32, rules []ruleWithEntry) []sharedRule {
	sharedRules := make([]sharedRule, len(rules))
	for i, r := range rules {
		key := NewSharedKey(ruleSetID, r.Key)
		entry := NewSharedEntry(key, r.Entry)
		sharedRules[i] = sharedRule{Key: key, Entry: entry}
	}
	return sharedRules
}

func diffSharedRules(old, new []sharedRule) (added, removed []sharedRule, modified []modifiedRule) {
	oldMap := make(map[ruleKeyWithoutRuleSetID]sharedRule, len(old))
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
	old sharedRule
	new sharedRule
}

func sharedRulesEqual(a, b PolicyEntry) bool {
	return a.ProxyPortNetwork == b.ProxyPortNetwork &&
		a.Flags == b.Flags &&
		a.Precedence == b.Precedence &&
		a.Cookie == b.Cookie
}

// restoreRuleSetWithRules recovers a rule set and its rules during agent startup.
func (a *RuleSetAllocator) restoreRuleSetWithRules(id uint32, rules []sharedRule) {
	if id == 0 {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	ruleSetHash := computeRuleSetHashFromSharedRules(rules)
	a.rulesets[ruleSetHash] = id
	a.byID[id] = &ruleSetEntry{
		hash:     ruleSetHash,
		rules:    rules,
		refcount: 0, // will be populated when linkEndpoint is called
	}

	if id >= a.nextRuleSetID {
		a.nextRuleSetID = id + 1
	}
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

// computeRuleSetHashFromEntries calculates a deterministic hash for a set of rules.
func computeRuleSetHashFromEntries(rules []ruleWithEntry) ruleSetKey {
	sorted := make([]ruleWithEntry, len(rules))
	copy(sorted, rules)

	slices.SortFunc(sorted, func(a, b ruleWithEntry) int {
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
		buf[11] = 0 // reserved (formerly auth type)
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

// computeRuleSetHashFromSharedRules calculates a deterministic hash for a set of sharedRules.
func computeRuleSetHashFromSharedRules(rules []sharedRule) ruleSetKey {
	sorted := make([]sharedRule, len(rules))
	copy(sorted, rules)

	slices.SortFunc(sorted, func(a, b sharedRule) int {
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
		buf[11] = 0 // reserved (formerly auth type)
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
