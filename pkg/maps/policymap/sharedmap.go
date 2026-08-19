// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"strconv"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
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

var (
	// SharedPolicyMap is the node-scoped shared policy LPM trie map.
	SharedPolicyMap = bpf.NewMap(
		SharedPolicyMapName,
		ebpf.LPMTrie,
		&SharedPolicyKey{},
		&PolicyEntry{},
		131072, // MaxEntries matching newCiliumPolicySharedSpec
		unix.BPF_F_NO_PREALLOC,
	).WithGroupName("policy_shared")

	// PolicyOverlayMap is the overlay map mapping Endpoint ID -> Rule Set ID.
	PolicyOverlayMap = bpf.NewMap(
		PolicyOverlayMapName,
		ebpf.Hash,
		&OverlayKey{},
		&OverlayValue{},
		16384, // MaxEntries matching newCiliumPolicyOverlaySpec
		unix.BPF_F_NO_PREALLOC,
	).WithGroupName("policy_overlay")
)

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

// EnsureSharedMapsOpen reopens SharedPolicyMap and PolicyOverlayMap from bpffs.
func EnsureSharedMapsOpen() {
	SharedPolicyMap.Close()
	_ = SharedPolicyMap.OpenOrCreate()
	PolicyOverlayMap.Close()
	_ = PolicyOverlayMap.OpenOrCreate()
}
