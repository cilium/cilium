// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package srv6map

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName4   = "cilium_srv6_v4"
	MapName6   = "cilium_srv6_v6"
	MaxEntries = 16384
)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key4 struct {
	// PrefixLen is full 32 bits of SourceIP + DestCIDR's mask bits
	PrefixLen uint32

	SourceIP types.IPv4
	DestCIDR types.IPv4
}

func (k *Key4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Key4) NewValue() bpf.MapValue    { return &Value{} }
func (k *Key4) String() string {
	return fmt.Sprintf("%s %s/%d", k.SourceIP, k.DestCIDR, k.PrefixLen-getStaticPrefixBits4())
}

func getStaticPrefixBits4() uint32 {
	staticMatchSize := unsafe.Sizeof(Key4{})
	staticMatchSize -= unsafe.Sizeof(Key4{}.PrefixLen)
	staticMatchSize -= unsafe.Sizeof(Key4{}.DestCIDR)
	return uint32(staticMatchSize) * 8
}

// NewKey4 returns a new Key4 instance
func NewKey4(src, dst net.IP, mask net.IPMask) Key4 {
	result := Key4{}

	ones, _ := mask.Size()

	copy(result.SourceIP[:], src.To4())
	copy(result.DestCIDR[:], dst.To4())
	result.PrefixLen = getStaticPrefixBits4() + uint32(ones)

	return result
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key6 struct {
	// PrefixLen is full 32 bits of SourceIP + DestCIDR's mask bits
	PrefixLen uint32

	SourceIP types.IPv6
	DestCIDR types.IPv6
}

func (k *Key6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Key6) NewValue() bpf.MapValue    { return &Value{} }
func (k *Key6) String() string {
	return fmt.Sprintf("%s %s/%d", k.SourceIP, k.DestCIDR, k.PrefixLen-getStaticPrefixBits6())
}

func getStaticPrefixBits6() uint32 {
	staticMatchSize := unsafe.Sizeof(Key6{})
	staticMatchSize -= unsafe.Sizeof(Key6{}.PrefixLen)
	staticMatchSize -= unsafe.Sizeof(Key6{}.DestCIDR)
	return uint32(staticMatchSize) * 8
}

// NewKey6 returns a new Key6 instance
func NewKey6(src, dst net.IP, mask net.IPMask) Key6 {
	result := Key6{}

	ones, _ := mask.Size()

	copy(result.SourceIP[:], src.To16())
	copy(result.DestCIDR[:], dst.To16())
	result.PrefixLen = getStaticPrefixBits6() + uint32(ones)

	return result
}

// Value implements the bpf.MapValue interface. It contains the
// SID for SRv6 encapsulation.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Value struct {
	SID types.IPv6 `align:"sid"`
}

// String pretty print the SID.
func (v *Value) String() string {
	return fmt.Sprintf("%s", v.SID)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// SRv6Map initiates a Map
var SRv6Map4 = bpf.NewMap(
	MapName4,
	bpf.MapTypeLPMTrie,
	&Key4{}, int(unsafe.Sizeof(Key4{})),
	&Value{}, int(unsafe.Sizeof(Value{})),
	MaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()

// SRv6Map initiates a Map
var SRv6Map6 = bpf.NewMap(
	MapName6,
	bpf.MapTypeLPMTrie,
	&Key6{}, int(unsafe.Sizeof(Key6{})),
	&Value{}, int(unsafe.Sizeof(Value{})),
	MaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()
