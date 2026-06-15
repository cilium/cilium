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

	// lockdownRuleSetID is never allocated, so the shared policy map has no entries for it
	// and the datapath denies all traffic of an endpoint whose overlay entry points to it.
	lockdownRuleSetID = 0
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
	hash ruleSetKey
	// rules are the entries of the rule set in the shared policy map. If a map update
	// fails, they also include the entries left in the map, so that they are always known
	// and a later update can fix or delete them.
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
	// pendingDelete are unused rule sets with entries that could not be deleted yet. Their
	// IDs are not reused until the entries are deleted.
	pendingDelete map[uint32]struct{}
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
		nextRuleSetID: lockdownRuleSetID + 1,
		epToRuleSetID: make(map[uint16]uint32),
		maxRuleSets:   MaxRuleSets,
		pendingDelete: make(map[uint32]struct{}),
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

// setRulesLocked records the entries a rule set has in the shared policy map and their
// hash. Other endpoints find the rule set by the hash of its actual entries, so they only
// share it when it holds exactly their rules.
func (a *RuleSetAllocator) setRulesLocked(id uint32, entry *ruleSetEntry, rules []sharedRule, hash ruleSetKey) {
	if a.rulesets[entry.hash] == id {
		delete(a.rulesets, entry.hash)
	}
	entry.rules, entry.hash = rules, hash
	if _, taken := a.rulesets[hash]; !taken {
		a.rulesets[hash] = id
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
