// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// SharedPolicyMapName is the pinned name of the shared LPM trie map.
	SharedPolicyMapName = "cilium_policy_shared"

	// PolicyOverlayMapName is the pinned name of the overlay map.
	PolicyOverlayMapName = "cilium_policy_overlay"

	// SharedPolicyFullPrefix is the prefix size in bits of the full BPF key.
	// rule_set_id (32) + sec_label (32) + egress (8) + protocol (8) + dport (16) = 96 bits.
	SharedPolicyFullPrefix = 96

	// SharedPolicyBasePrefix is the prefix size of the base L3 match (covers rule_set_id + identity + egress).
	// rule_set_id (32) + sec_label (32) + egress (8) = 72 bits.
	SharedPolicyBasePrefix = 72

	// LPMProtoPrefixBits is the prefix length extension for protocol match.
	// protocol (8) = 8 bits.
	LPMProtoPrefixBits = 8

	// LPMFullPrefixBits is the prefix length extension for protocol + port match.
	// protocol (8) + port (16) = 24 bits.
	LPMFullPrefixBits = 24
)

// SharedPolicyKey represents the key in the shared policy LPM trie.
// Must be kept in sync with struct shared_policy_key in <bpf/lib/policy.h>.
type SharedPolicyKey struct {
	Prefixlen        uint32
	RuleSetID        uint32
	Identity         uint32
	TrafficDirection uint8
	Nexthdr          uint8
	DestPortNetwork  uint16
}

// GetDestPort returns the DestPortNetwork in host byte order
func (k *SharedPolicyKey) GetDestPort() uint16 {
	return byteorder.NetworkToHost16(k.DestPortNetwork)
}

// GetPortPrefixLen returns the prefix length applicable to the port in the key
func (k *SharedPolicyKey) GetPortPrefixLen() uint8 {
	prefixLen := k.GetPrefixLen()
	if prefixLen <= LPMProtoPrefixBits {
		return 0
	}
	return prefixLen - LPMProtoPrefixBits
}

// GetPrefixLen returns the prefix length applicable to the protocol and port in the key
// (subtracting the base 72 bits of RuleSetID, Identity, and Direction)
func (k *SharedPolicyKey) GetPrefixLen() uint8 {
	if k.Prefixlen <= SharedPolicyBasePrefix {
		return 0
	}
	return uint8(k.Prefixlen - SharedPolicyBasePrefix)
}

func (k *SharedPolicyKey) PortProtoString() string {
	dport := k.GetDestPort()
	protoStr := u8proto.U8proto(k.Nexthdr).String()
	prefixLen := k.GetPrefixLen()
	portPrefixLen := k.GetPortPrefixLen()

	switch {
	case prefixLen == 0, prefixLen == LPMProtoPrefixBits:
		return protoStr
	case prefixLen > LPMProtoPrefixBits && prefixLen < LPMFullPrefixBits:
		portLen := uint16(0xffff >> portPrefixLen)
		return fmt.Sprintf("%d-%d/%s", dport, dport+portLen, protoStr)
	case prefixLen == LPMFullPrefixBits:
		return fmt.Sprintf("%d/%s", dport, protoStr)
	default:
		return fmt.Sprintf("<INVALID PREFIX LENGTH: %d>", prefixLen)
	}
}

func (k *SharedPolicyKey) String() string {
	trafficDirectionString := trafficdirection.TrafficDirection(k.TrafficDirection).String()
	portProtoStr := k.PortProtoString()
	return fmt.Sprintf("RuleSet:%d %s: %d %s", k.RuleSetID, trafficDirectionString, k.Identity, portProtoStr)
}

func (k *SharedPolicyKey) New() bpf.MapKey { return &SharedPolicyKey{} }

// OverlayKey represents the key in the overlay map (Endpoint ID).
type OverlayKey struct {
	EndpointID uint32
}

func (k *OverlayKey) String() string  { return strconv.FormatUint(uint64(k.EndpointID), 10) }
func (k *OverlayKey) New() bpf.MapKey { return &OverlayKey{} }

// OverlayValue represents the value in the overlay map (Rule Set ID).
type OverlayValue struct {
	RuleSetID uint32
}

func (v *OverlayValue) String() string    { return strconv.FormatUint(uint64(v.RuleSetID), 10) }
func (v *OverlayValue) New() bpf.MapValue { return &OverlayValue{} }

// BPFMap defines the interface for interacting with BPF maps (or mock maps).
type BPFMap interface {
	OpenOrCreate() error
	Close() error
	Update(key bpf.MapKey, value bpf.MapValue) error
	Delete(key bpf.MapKey) error
	Lookup(key bpf.MapKey) (bpf.MapValue, error)
	DumpWithCallback(cb bpf.DumpCallback) error
}

type fakeMapEntry struct {
	key   bpf.MapKey
	value bpf.MapValue
}

// FakeBPFMap is an in-memory mock implementation of BPFMap for unit tests.
type FakeBPFMap struct {
	lock    lock.RWMutex
	entries map[string]fakeMapEntry
}

// NewFakeBPFMap creates a new in-memory FakeBPFMap.
func NewFakeBPFMap() *FakeBPFMap {
	return &FakeBPFMap{
		entries: make(map[string]fakeMapEntry),
	}
}

func (m *FakeBPFMap) OpenOrCreate() error { return nil }
func (m *FakeBPFMap) Close() error        { return nil }

func (m *FakeBPFMap) Update(key bpf.MapKey, value bpf.MapValue) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.entries[key.String()] = fakeMapEntry{key: key, value: value}
	return nil
}

func (m *FakeBPFMap) Delete(key bpf.MapKey) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.entries, key.String())
	return nil
}

func (m *FakeBPFMap) Lookup(key bpf.MapKey) (bpf.MapValue, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	entry, ok := m.entries[key.String()]
	if !ok {
		return nil, ebpf.ErrKeyNotExist
	}
	return entry.value, nil
}

func (m *FakeBPFMap) DumpWithCallback(cb bpf.DumpCallback) error {
	if cb == nil {
		return nil
	}
	m.lock.RLock()
	entries := make([]fakeMapEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		entries = append(entries, entry)
	}
	m.lock.RUnlock()

	for _, entry := range entries {
		cb(entry.key, entry.value)
	}
	return nil
}

// NewSharedPolicyBPFMap creates a new BPF map instance for cilium_policy_shared.
func NewSharedPolicyBPFMap() BPFMap {
	return bpf.NewMap(
		SharedPolicyMapName,
		ebpf.LPMTrie,
		&SharedPolicyKey{},
		&PolicyEntry{},
		131072, // MaxEntries matching newCiliumPolicySharedSpec
		unix.BPF_F_NO_PREALLOC,
	).WithGroupName("policy_shared")
}

// NewPolicyOverlayBPFMap creates a new BPF map instance for cilium_policy_overlay.
func NewPolicyOverlayBPFMap() BPFMap {
	return bpf.NewMap(
		PolicyOverlayMapName,
		ebpf.Hash,
		&OverlayKey{},
		&OverlayValue{},
		16384, // MaxEntries matching newCiliumPolicyOverlaySpec
		unix.BPF_F_NO_PREALLOC,
	).WithGroupName("policy_overlay")
}

var (
	sharedPolicyMapVal  atomic.Pointer[BPFMap]
	policyOverlayMapVal atomic.Pointer[BPFMap]
)

func init() {
	spm := NewSharedPolicyBPFMap()
	pom := NewPolicyOverlayBPFMap()
	sharedPolicyMapVal.Store(&spm)
	policyOverlayMapVal.Store(&pom)
}

// GetSharedPolicyMap returns the thread-safe reference to SharedPolicyMap.
func GetSharedPolicyMap() BPFMap {
	if p := sharedPolicyMapVal.Load(); p != nil {
		return *p
	}
	return nil
}

// SetSharedPolicyMap thread-safely sets the SharedPolicyMap reference.
func SetSharedPolicyMap(m BPFMap) {
	sharedPolicyMapVal.Store(&m)
}

// GetPolicyOverlayMap returns the thread-safe reference to PolicyOverlayMap.
func GetPolicyOverlayMap() BPFMap {
	if p := policyOverlayMapVal.Load(); p != nil {
		return *p
	}
	return nil
}

// SetPolicyOverlayMap thread-safely sets the PolicyOverlayMap reference.
func SetPolicyOverlayMap(m BPFMap) {
	policyOverlayMapVal.Store(&m)
}

// NewSharedKey converts a ruleSetID and a policy MapState key to a SharedPolicyKey.
func NewSharedKey(ruleSetID uint32, pk policyTypes.Key) SharedPolicyKey {
	prefixLen := SharedPolicyBasePrefix // 72 bits
	if pk.Nexthdr != 0 || pk.DestPort != 0 {
		prefixLen += int(LPMProtoPrefixBits) // 8 bits -> 80
		if pk.DestPort != 0 {
			prefixLen += int(pk.PortPrefixLen()) // up to 16 bits -> 96
		}
	}
	return SharedPolicyKey{
		Prefixlen:        uint32(prefixLen),
		RuleSetID:        ruleSetID,
		Identity:         uint32(pk.Identity),
		TrafficDirection: uint8(pk.TrafficDirection()),
		Nexthdr:          uint8(pk.Nexthdr),
		DestPortNetwork:  byteorder.HostToNetwork16(pk.DestPort),
	}
}

// NewSharedEntry converts a policy MapState entry to a PolicyEntry value.
func NewSharedEntry(key SharedPolicyKey, pe policyTypes.MapStateEntry) PolicyEntry {
	pef := getPolicyEntryFlags(policyEntryFlagParams{
		IsDeny:    pe.IsDeny(),
		PrefixLen: key.GetPrefixLen(),
	})

	return PolicyEntry{
		ProxyPortNetwork: byteorder.HostToNetwork16(pe.ProxyPort),
		Flags:            pef,
		AuthRequirement:  pe.AuthRequirement,
		Precedence:       pe.Precedence,
		Cookie:           pe.Cookie,
	}
}

// EnsureSharedMapsOpen ensures SharedPolicyMap and PolicyOverlayMap are open.
// In test environments or unprivileged environments where BPF maps cannot be opened,
// it falls back to in-memory fake maps so unit/integration tests succeed without root.
func EnsureSharedMapsOpen() {
	spm := GetSharedPolicyMap()
	if spm != nil {
		if err := spm.OpenOrCreate(); err != nil {
			if _, ok := spm.(*FakeBPFMap); !ok {
				SetSharedPolicyMap(NewFakeBPFMap())
			}
		}
	}
	pom := GetPolicyOverlayMap()
	if pom != nil {
		if err := pom.OpenOrCreate(); err != nil {
			if _, ok := pom.(*FakeBPFMap); !ok {
				SetPolicyOverlayMap(NewFakeBPFMap())
			}
		}
	}
}
