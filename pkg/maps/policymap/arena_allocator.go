package policymap

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"unsafe"

	ciliumebpf "github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// batchSupportChecked indicates if we've already checked batch support.
var (
	batchSupportOnce   sync.Once
	batchUpdateSupport bool
)

// ArenaHeader resides at Offset 0 of the Arena memory.
// It persists the allocator state across agent restarts.
type ArenaHeader struct {
	Magic      uint64 // Magic number to check validity (0xDEADBEEFCAFEB222)
	FreeOffset uint64 // Pointer to the next free byte for bump allocation
}

const (
	ArenaMagic = 0xDEADBEEFCAFEB222 // V2 Magic
	HeaderSize = uint64(unsafe.Sizeof(ArenaHeader{}))
)

// ArenaMapBackend defines the interface required by ArenaAllocator.
type ArenaMapBackend interface {
	FD() int
	MaxEntries() uint32
}

// rulePoolEntry tracks a globally deduplicated rule in arena.
type rulePoolEntry struct {
	arenaOffset uint32 // Offset in arena where rule data is stored
	refcount    int    // Number of rule sets referencing this rule
}

// ArenaAllocator manages a BPF Arena map for storing variable-sized policy rule sets.
// It uses a Segregated Fit (Power-of-Two) allocator.
type ArenaAllocator struct {
	mapFD     int
	data      []byte
	size      int
	maxOffset uint64
	logger    *slog.Logger
	header    *ArenaHeader // Pointer to the memory-mapped header

	// Global per-rule deduplication pool
	// Key: hash of rule data (verdict fields only)
	// Value: arena offset + refcount
	rulePool map[uint64]rulePoolEntry
}

// NewArenaAllocator creates a new ArenaAllocator backed by the given map (or mock).
func NewArenaAllocator(logger *slog.Logger, m ArenaMapBackend) (*ArenaAllocator, error) {
	if m == nil {
		return nil, fmt.Errorf("arena map is nil")
	}

	fd := m.FD()
	pageSize := os.Getpagesize()
	maxPages := int(m.MaxEntries())
	size := maxPages * pageSize

	logger.Info("Attempting to mmap Arena V2",
		"fd", fd,
		"maxEntries", maxPages,
		"pageSize", pageSize,
		"totalSize", size,
	)

	// We do NOT mmap again. We use the address mmapped by InitUniversalMaps.
	// This avoids double-mmap issues (EINVAL) on some kernels/configs.
	// We read the global arenaBaseAddr populated by InitUniversalMaps.
	addr := arenaBaseAddr

	if addr != 0 {
		logger.Info("Recovered Arena Address from memory", "address", addr)
	}

	if addr == 0 {
		return nil, fmt.Errorf("arena address is 0 (not initialized)")
	}

	return newArenaAllocatorWithAddr(logger, m, addr)
}

// NewArenaAllocatorForTest creates a new ArenaAllocator with a specific address.
func NewArenaAllocatorForTest(logger *slog.Logger, m ArenaMapBackend, addr uint64) (*ArenaAllocator, error) {
	return newArenaAllocatorWithAddr(logger, m, addr)
}

func newArenaAllocatorWithAddr(logger *slog.Logger, m ArenaMapBackend, addr uint64) (*ArenaAllocator, error) {
	if m == nil {
		return nil, fmt.Errorf("arena map is nil")
	}
	fd := m.FD()
	pageSize := os.Getpagesize()
	maxPages := int(m.MaxEntries())
	size := maxPages * pageSize

	// Create slice from pointer (without new mmap)
	var b []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	hdr.Data = uintptr(addr)
	hdr.Len = size
	hdr.Cap = size

	alloc := &ArenaAllocator{
		mapFD:     fd,
		data:      b,
		size:      size,
		maxOffset: uint64(size),
		logger:    logger,
		header:    (*ArenaHeader)(unsafe.Pointer(&b[0])),
		rulePool:  make(map[uint64]rulePoolEntry),
	}

	// Check for Persistence / Initialization
	if alloc.header.Magic == ArenaMagic {
		logger.Info("Recovered Arena Allocator V2 state",
			"freeOffset", alloc.header.FreeOffset)
		// We trust the persisted state.
	} else {
		logger.Info("Initializing new Arena Allocator V2 header (Resetting)")
		// Initialize Header
		alloc.Reset()
	}

	alloc.updateMetrics()
	return alloc, nil
}

func (a *ArenaAllocator) updateMetrics() {
	pageSize := os.Getpagesize()
	usedPages := (int(a.header.FreeOffset) + pageSize - 1) / pageSize
	if option.Config.PolicySharedMapMetrics {
		metrics.PolicySharedMapArenaPages.WithLabelValues("used").Set(float64(usedPages))
	}
}

// Reset clears the allocator. Use cautiously!
func (a *ArenaAllocator) Reset() {
	a.header.Magic = ArenaMagic
	// Align to 64 bytes initially
	a.header.FreeOffset = (HeaderSize + 63) &^ 63
}

func (a *ArenaAllocator) Close() error {
	// We do not unmap the memory here because we didn't create the mapping.
	// It is owned by the BPF loader or the ebpf.Map object (via InitUniversalMaps).
	a.data = nil
	return nil
}

// SharedLPMRule represents a rule to be written to the shared LPM trie.
// It includes both the key fields and the full policy entry data.
type SharedLPMRule struct {
	// Key fields
	RuleSetID uint32 // Which rule set this belongs to
	Identity  uint32 // Remote identity (0 for L4-only)
	Egress    uint8  // 0=ingress, 1=egress
	Protocol  uint8  // L4 protocol (0 = any)
	DPort     uint16 // Destination port (host byte order, 0 = any)
	PrefixLen uint8  // LPM prefix length for proto+port (0-24)

	// Value fields (full policy entry)
	ProxyPort   uint16
	Deny        bool
	AuthType    uint8
	HasExplicit bool
	Precedence  uint32
	Cookie      uint32
}

// WriteRulesToSharedLPM writes rules to the shared LPM trie and arena.
// Returns error if write fails.
func (a *ArenaAllocator) WriteRulesToSharedLPM(rules []SharedLPMRule) error {
	if len(rules) == 0 {
		return nil
	}

	// Get the shared LPM map
	lpmMap := SharedLPMMap()
	if lpmMap == nil {
		return fmt.Errorf("shared LPM map not initialized")
	}

	var newArenaEntries int
	var deduplicatedEntries int

	// Phase 1: Process arena allocation and collect keys/values
	keys := make([]SharedLPMKey, len(rules))
	values := make([]SharedLPMValue, len(rules))

	for i, rule := range rules {
		// Compute hash of rule DATA (verdict fields only, not key fields)
		// This enables per-rule deduplication across different rule sets
		ruleHash := computeRuleHash(rule)

		var arenaOffset uint32

		// Check global rule pool for existing rule with same verdict
		if existing, ok := a.rulePool[ruleHash]; ok {
			// GLOBAL DEDUPLICATION: Reuse existing arena offset
			arenaOffset = existing.arenaOffset
			// Increment refcount for this rule
			a.rulePool[ruleHash] = rulePoolEntry{
				arenaOffset: existing.arenaOffset,
				refcount:    existing.refcount + 1,
			}
			deduplicatedEntries++
		} else {
			// New unique rule - allocate in arena (use persisted FreeOffset)
			currentOff := uint32(a.header.FreeOffset)
			if int(currentOff)+ArenaPolicyEntrySize > len(a.data) {
				return fmt.Errorf("arena exhausted: need offset %d + %d bytes, have %d",
					currentOff, ArenaPolicyEntrySize, len(a.data))
			}

			// Write ArenaPolicyEntry to arena
			offset := int(currentOff)
			binary.LittleEndian.PutUint16(a.data[offset:], rule.ProxyPort)

			// Flags: deny(1) | reserved(2) | lpm_prefix_length(5)
			flags := rule.PrefixLen << 3
			if rule.Deny {
				flags |= 0x1
			}
			a.data[offset+2] = flags

			// AuthType: auth_type(7) | has_explicit_auth_type(1)
			authType := rule.AuthType & 0x7f
			if rule.HasExplicit {
				authType |= 0x80
			}
			a.data[offset+3] = authType

			binary.LittleEndian.PutUint32(a.data[offset+4:], rule.Precedence)
			binary.LittleEndian.PutUint32(a.data[offset+8:], rule.Cookie)

			arenaOffset = currentOff

			// Add to global rule pool with refcount=1
			a.rulePool[ruleHash] = rulePoolEntry{
				arenaOffset: arenaOffset,
				refcount:    1,
			}

			// Advance offset (align to 4 bytes)
			currentOff += ArenaPolicyEntrySize
			currentOff = (currentOff + 3) &^ 3
			a.header.FreeOffset = uint64(currentOff)

			newArenaEntries++
		}

		// Compute LPM prefix length for the key
		// Base: rule_set_id(32) + identity(32) + egress(8) = 72 bits
		// Add proto+port prefix (0-24 bits)
		keyPrefixLen := uint32(SharedPolicyBasePrefix) + uint32(rule.PrefixLen)

		// Build LPM key
		keys[i] = SharedLPMKey{
			PrefixLen: keyPrefixLen,
			RuleSetID: rule.RuleSetID,
			SecLabel:  rule.Identity,
			Egress:    rule.Egress,
			Protocol:  rule.Protocol,
			DPort:     htons(rule.DPort), // Convert to network byte order
		}

		// Build LPM value
		// Flags: deny(1) | reserved(2) | lpm_prefix_length(5)
		valueFlags := rule.PrefixLen << 3
		if rule.Deny {
			valueFlags |= 0x1
		}

		// AuthType: auth_type(7) | has_explicit_auth_type(1)
		valueAuthType := rule.AuthType & 0x7f
		if rule.HasExplicit {
			valueAuthType |= 0x80
		}

		values[i] = SharedLPMValue{
			ArenaOffset: arenaOffset,
			Flags:       valueFlags,
			AuthType:    valueAuthType,
			ProxyPort:   htons(rule.ProxyPort),
		}
	}

	// Phase 2: Write to LPM trie using batch operations when available
	var batchUsed bool
	if len(keys) > 1 && hasBatchUpdateSupport(lpmMap) {
		// Try batch update (more efficient for multiple entries)
		_, err := lpmMap.BatchUpdate(keys, values, &ciliumebpf.BatchOptions{
			ElemFlags: uint64(ciliumebpf.UpdateAny),
		})
		if err == nil {
			batchUsed = true
		} else {
			// Batch failed, fall back to individual updates
			a.logger.Debug("Batch update failed, falling back to individual updates",
				"error", err,
				"ruleCount", len(keys),
			)
		}
	}

	// Fall back to individual updates if batch not used
	if !batchUsed {
		for i := range keys {
			if err := lpmMap.Update(keys[i], values[i], 0); err != nil {
				return fmt.Errorf("failed to update shared LPM for rule_set=%d identity=%d: %w",
					rules[i].RuleSetID, rules[i].Identity, err)
			}
		}
	}

	a.logger.Debug("Wrote rules to shared LPM trie",
		"totalRules", len(rules),
		"newArenaEntries", newArenaEntries,
		"deduplicatedArenaEntries", deduplicatedEntries,
		"arenaUsedBytes", a.header.FreeOffset,
		"globalPoolSize", len(a.rulePool),
		"batchUsed", batchUsed,
	)

	return nil
}

// hasBatchUpdateSupport checks if the kernel supports batch update operations for LPM trie maps.
// This is cached after the first check.
func hasBatchUpdateSupport(m *ebpf.Map) bool {
	batchSupportOnce.Do(func() {
		// Batch operations for LPM trie require kernel 5.12+
		batchUpdateSupport = true // Assume support, will be set to false on first failure
	})
	return batchUpdateSupport
}

// hasBatchDeleteSupport checks if the kernel supports batch delete operations for LPM trie maps.
// Batch delete has the same kernel requirements as batch update.
func hasBatchDeleteSupport(m *ebpf.Map) bool {
	// Batch delete uses the same kernel support as batch update
	return hasBatchUpdateSupport(m)
}

// computeRuleHash computes a hash of rule data for deduplication.
func computeRuleHash(rule SharedLPMRule) uint64 {
	// Simple hash combining all rule data fields
	h := uint64(rule.ProxyPort)
	h = h*31 + uint64(rule.Precedence)
	h = h*31 + uint64(rule.Cookie)
	h = h*31 + uint64(rule.AuthType)
	if rule.Deny {
		h = h*31 + 1
	}
	if rule.HasExplicit {
		h = h*31 + 2
	}
	h = h*31 + uint64(rule.PrefixLen)
	return h
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

// DeleteRuleSetFromSharedLPM removes all entries for a rule set from the shared LPM trie.
// This is used when a rule set is no longer referenced by any endpoint.
func (a *ArenaAllocator) DeleteRuleSetFromSharedLPM(ruleSetID uint32, rules []SharedLPMRule) error {
	if len(rules) == 0 {
		return nil
	}

	lpmMap := SharedLPMMap()
	if lpmMap == nil {
		return fmt.Errorf("shared LPM map not initialized")
	}

	var deleted int
	var freedArenaEntries int

	// Phase 1: Collect all keys for deletion
	keys := make([]SharedLPMKey, len(rules))
	for i, rule := range rules {
		keyPrefixLen := uint32(SharedPolicyBasePrefix) + uint32(rule.PrefixLen)
		keys[i] = SharedLPMKey{
			PrefixLen: keyPrefixLen,
			RuleSetID: ruleSetID,
			SecLabel:  rule.Identity,
			Egress:    rule.Egress,
			Protocol:  rule.Protocol,
			DPort:     htons(rule.DPort),
		}
	}

	// Phase 2: Delete from LPM trie using batch operations when available
	var batchUsed bool
	if len(keys) > 1 && hasBatchDeleteSupport(lpmMap) {
		// Try batch delete (more efficient for multiple entries)
		count, err := lpmMap.BatchDelete(keys, nil)
		if err == nil {
			deleted = count
			batchUsed = true
		} else {
			// Batch failed, fall back to individual deletes
			a.logger.Debug("Batch delete failed, falling back to individual deletes",
				"error", err,
				"ruleCount", len(keys),
			)
		}
	}

	// Fall back to individual deletes if batch not used
	if !batchUsed {
		for _, key := range keys {
			if err := lpmMap.Delete(key); err != nil {
				// Ignore not-found errors
				a.logger.Debug("Failed to delete LPM entry (may not exist)",
					"ruleSetID", ruleSetID,
					"identity", key.SecLabel,
					"error", err,
				)
			} else {
				deleted++
			}
		}
	}

	// Phase 3: Update rule pool refcounts (always done regardless of batch/individual)
	for _, rule := range rules {
		ruleHash := computeRuleHash(rule)
		if existing, ok := a.rulePool[ruleHash]; ok {
			if existing.refcount <= 1 {
				// Last reference - remove from pool
				delete(a.rulePool, ruleHash)
				freedArenaEntries++
				// Note: Arena memory is not reclaimed (bump allocator)
				// Space will be reused after agent restart
			} else {
				// Decrement refcount
				a.rulePool[ruleHash] = rulePoolEntry{
					arenaOffset: existing.arenaOffset,
					refcount:    existing.refcount - 1,
				}
			}
		}
	}

	a.logger.Debug("Deleted rule set from shared LPM (per-rule dedup)",
		"ruleSetID", ruleSetID,
		"deletedLPMEntries", deleted,
		"freedArenaEntries", freedArenaEntries,
		"globalPoolSize", len(a.rulePool),
		"batchUsed", batchUsed,
	)

	return nil
}
