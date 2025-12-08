package policymap

import (
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"

	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	ciliumebpf "github.com/cilium/ebpf"
)

const (
	ArenaMapName     = "cilium_policy_a"
	SharedLPMMapName = "cilium_policy_s"

	// Configurable limits - must match BPF side
	SharedLPMMaxEntries = 131072
	ArenaMaxRuleData    = 65536
	MaxRuleSets         = 4096

	// Prefix length constants
	SharedPolicyFullPrefix = 96 // Full prefix for exact match
	SharedPolicyBasePrefix = 72 // Base prefix (rule_set_id + identity + direction)
	LPMProtoPrefixBits     = 8  // Protocol prefix bits
	LPMFullPrefixBits      = 24 // Protocol + port prefix bits
)

var (
	arenaMap      *ebpf.Map
	sharedLPMMap  *ebpf.Map
	arenaBaseAddr uint64
)

// SharedLPMKey is the key for the shared LPM trie.
// Includes rule_set_id to enable sharing across endpoints.
// Must match struct shared_lpm_key in BPF.
//
// Key layout for LPM matching:
//
//	Bytes 0-3:   PrefixLen (always full prefix for lookup)
//	Bytes 4-7:   RuleSetID (32 bits, always exact match)
//	Bytes 8-11:  SecLabel/identity (32 bits, always exact match)
//	Byte  12:    Egress flag (1 bit) + pad (7 bits)
//	Byte  13:    Protocol (8 bits, LPM matched)
//	Bytes 14-15: DPort (16 bits, LPM matched)
type SharedLPMKey struct {
	PrefixLen uint32 // LPM prefix length
	RuleSetID uint32 // Identifies the rule set (for sharing)
	SecLabel  uint32 // Remote identity (0 for L4-only)
	Egress    uint8  // Direction: 0=ingress, 1=egress (uses only 1 bit)
	Protocol  uint8  // L4 protocol
	DPort     uint16 // Destination port (network byte order)
}

// SharedLPMValue is the value for the shared LPM trie.
// Points to full rule data in arena memory.
// Must match struct shared_policy_value in BPF.
type SharedLPMValue struct {
	ArenaOffset uint32 // Offset in arena to policy_entry data
	Flags       uint8  // deny:1, reserved:2, lpm_prefix_length:5
	AuthType    uint8  // auth_type:7, has_explicit_auth_type:1
	ProxyPort   uint16 // Proxy redirect port (network byte order)
}

// ArenaPolicyEntry is the full policy entry data stored in arena.
// Multiple LPM entries can point to the same arena offset.
// Must match struct arena_policy_entry in BPF.
type ArenaPolicyEntry struct {
	ProxyPort  uint16 // Network byte order
	Flags      uint8  // deny:1, reserved:2, lpm_prefix_length:5
	AuthType   uint8  // auth_type:7, has_explicit_auth_type:1
	Precedence uint32
	Cookie     uint32
}

// ArenaPolicyEntrySize is the size of ArenaPolicyEntry in bytes.
const ArenaPolicyEntrySize = 12

func universalPolicyLogger() *slog.Logger {
	return logging.DefaultSlogLogger.With(logfields.LogSubsys, "policymap-universal")
}

// PolicyRule is the on-the-wire BPF struct for a rule.
type PolicyRule struct {
	Identity        uint32 // NumericIdentity
	Direction       uint8  // TrafficDirection
	Nexthdr         uint8  // U8proto
	DestPortNetwork uint16
}

// RuleNode is the on-the-wire BPF struct for a list node.
type RuleNode struct {
	RuleID     uint32
	NextNodeID uint32
}

// InitUniversalMaps initializes the Phase 4 BPF Maps with the given limits.
func InitUniversalMaps() error {
	universalPolicyLogger().Info("InitUniversalMaps started")
	if !SharedManagerEnabled() {
		universalPolicyLogger().Info("InitUniversalMaps: SharedManager not enabled")
		return nil
	}

	// Arena Map (if enabled)
	if option.Config.EnablePolicySharedMapArena {

		// Use 4096 pages (16MB)
		maxPages := 4096

		spec := &ebpf.MapSpec{
			Name:       ArenaMapName,
			Type:       ciliumebpf.MapType(33), // BPF_MAP_TYPE_ARENA
			MaxEntries: uint32(maxPages),
			MapExtra:   0x10000000000, // Explicit address (shifted to avoid collision)
			Flags:      1 << 10,       // BPF_F_MMAPABLE
			KeySize:    0,
			ValueSize:  0,
			Pinning:    ebpf.PinByName,
		}

		pageSize := os.Getpagesize()
		size := int(maxPages) * pageSize

		// Check if map exists first
		var err error
		arenaMap, err = ebpf.LoadRegisterMap(universalPolicyLogger(), ArenaMapName)
		if err != nil {
			arenaMap = ebpf.NewMap(universalPolicyLogger(), spec)
			if err := arenaMap.OpenOrCreate(); err != nil {
				return fmt.Errorf("failed to create arena map: %w", err)
			}
		}

		// Shared LPM Trie Map - global LPM trie with rule_set_id for sharing
		// Key: (prefix_len, rule_set_id, identity, direction, proto, port)
		// Value: (arena_offset, flags, auth_type, proxy_port)
		sharedLPMSpec := &ebpf.MapSpec{
			Name:       SharedLPMMapName,
			Type:       ebpf.LPMTrie,
			KeySize:    16, // sizeof(SharedLPMKey)
			ValueSize:  8,  // sizeof(SharedLPMValue)
			MaxEntries: SharedLPMMaxEntries,
			Pinning:    ebpf.PinByName,
			Flags:      unix.BPF_F_NO_PREALLOC,
		}

		sharedLPMMap, err = ebpf.LoadRegisterMap(universalPolicyLogger(), SharedLPMMapName)
		if err != nil {
			sharedLPMMap = ebpf.NewMap(universalPolicyLogger(), sharedLPMSpec)
			if err := sharedLPMMap.OpenOrCreate(); err != nil {
				return fmt.Errorf("failed to create shared LPM map: %w", err)
			}
		}

		universalPolicyLogger().Info("Shared LPM trie initialized",
			"maxEntries", SharedLPMMaxEntries,
			"keySize", 16,
			"valueSize", 8,
		)

		// Always perform mmap to ensure user-space access is set up.
		performMmap := func(m *ebpf.Map) error {
			fd := m.FD()

			// Must use explicit address if MapExtra is set
			addr := uintptr(0x10000000000)

			r, _, errno := unix.Syscall6(unix.SYS_MMAP,
				addr,
				uintptr(size),
				uintptr(unix.PROT_READ|unix.PROT_WRITE),
				uintptr(unix.MAP_SHARED|unix.MAP_FIXED),
				uintptr(fd),
				0,
			)
			if errno != 0 {
				// If mmap fails, cleanup
				pinPath := bpf.MapPath(universalPolicyLogger(), ArenaMapName)
				os.Remove(pinPath)
				return errno
			}

			// Record the address for the ArenaAllocator
			arenaBaseAddr = uint64(r)

			// Touch the memory to ensure it's allocated in kernel.
			// BPF datapath cannot call sleepable allocation helpers.
			// By writing from Go, we trigger a page fault and kernel allocates the page.
			ptr := (*uint16)(unsafe.Pointer(r))
			*ptr = 0

			return nil
		}

		if err := performMmap(arenaMap); err != nil {
			return fmt.Errorf("failed to mmap arena map: %w", err)
		}
	}

	return nil
}

func ArenaMap() *ebpf.Map {
	return arenaMap
}

func SharedLPMMap() *ebpf.Map {
	return sharedLPMMap
}
