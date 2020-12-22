// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lbmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/types"
)

const (
	SourceRange4MapName = "cilium_lb4_source_range"
	SourceRange6MapName = "cilium_lb6_source_range"
	lpmPrefixLen4       = 16 + 16 // sizeof(SourceRangeKey4.RevNATID)+sizeof(SourceRangeKey4.Pad)
	lpmPrefixLen6       = 16 + 16 // sizeof(SourceRangeKey6.RevNATID)+sizeof(SourceRangeKey6.Pad)
)

type SourceRangeKey interface {
	GetCIDR() *cidr.CIDR
	GetRevNATID() uint16

	// Convert fields to network byte order.
	ToNetwork() SourceRangeKey

	// ToHost converts fields to host byte order.
	ToHost() SourceRangeKey
}

// The compile-time check for whether the structs implement the interface
var _ SourceRangeKey = (*SourceRangeKey4)(nil)
var _ SourceRangeKey = (*SourceRangeKey6)(nil)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type SourceRangeKey4 struct {
	PrefixLen uint32     `align:"lpm_key"`
	RevNATID  uint16     `align:"rev_nat_id"`
	Pad       uint16     `align:"pad"`
	Address   types.IPv4 `align:"addr"`
}

func (k *SourceRangeKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *SourceRangeKey4) NewValue() bpf.MapValue    { return &SourceRangeValue{} }
func (k *SourceRangeKey4) String() string            { return fmt.Sprintf("%s", k.Address) }
func (k *SourceRangeKey4) ToNetwork() SourceRangeKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNATID = byteorder.HostToNetwork(n.RevNATID).(uint16)
	return &n
}

// ToHost returns the key in the host byte order
func (k *SourceRangeKey4) ToHost() SourceRangeKey {
	h := *k
	h.RevNATID = byteorder.NetworkToHost(h.RevNATID).(uint16)
	return &h
}

func (k *SourceRangeKey4) GetCIDR() *cidr.CIDR {
	var (
		c  net.IPNet
		ip types.IPv4
	)
	c.Mask = net.CIDRMask(int(k.PrefixLen)-lpmPrefixLen4, 32)
	k.Address.DeepCopyInto(&ip)
	c.IP = ip.IP()
	return cidr.NewCIDR(&c)
}
func (k *SourceRangeKey4) GetRevNATID() uint16 {
	return k.RevNATID
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type SourceRangeKey6 struct {
	PrefixLen uint32     `align:"lpm_key"`
	RevNATID  uint16     `align:"rev_nat_id"`
	Pad       uint16     `align:"pad"`
	Address   types.IPv6 `align:"addr"`
}

func (k *SourceRangeKey6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *SourceRangeKey6) NewValue() bpf.MapValue    { return &SourceRangeValue{} }
func (k *SourceRangeKey6) String() string            { return fmt.Sprintf("%s", k.Address) }
func (k *SourceRangeKey6) ToNetwork() SourceRangeKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNATID = byteorder.HostToNetwork(n.RevNATID).(uint16)
	return &n
}

// ToHost returns the key in the host byte order
func (k *SourceRangeKey6) ToHost() SourceRangeKey {
	h := *k
	h.RevNATID = byteorder.NetworkToHost(h.RevNATID).(uint16)
	return &h
}

func (k *SourceRangeKey6) GetCIDR() *cidr.CIDR {
	var (
		c  net.IPNet
		ip types.IPv6
	)
	c.Mask = net.CIDRMask(int(k.PrefixLen)-lpmPrefixLen6, 128)
	k.Address.DeepCopyInto(&ip)
	c.IP = ip.IP()
	return cidr.NewCIDR(&c)
}
func (k *SourceRangeKey6) GetRevNATID() uint16 {
	return k.RevNATID
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type SourceRangeValue struct {
	Pad uint8 // not used
}

func (v *SourceRangeValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *SourceRangeValue) String() string              { return "" }

var SourceRange4Map = bpf.NewMap(
	SourceRange4MapName,
	bpf.MapTypeLPMTrie,
	&SourceRangeKey4{}, int(unsafe.Sizeof(SourceRangeKey4{})),
	&SourceRangeValue{}, int(unsafe.Sizeof(SourceRangeValue{})),
	MaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()

var SourceRange6Map = bpf.NewMap(
	SourceRange6MapName,
	bpf.MapTypeLPMTrie,
	&SourceRangeKey6{}, int(unsafe.Sizeof(SourceRangeKey6{})),
	&SourceRangeValue{}, int(unsafe.Sizeof(SourceRangeValue{})),
	MaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()

func srcRangeKey(cidr *cidr.CIDR, revNATID uint16, ipv6 bool) bpf.MapKey {
	ones, _ := cidr.Mask.Size()
	id := byteorder.HostToNetwork(revNATID).(uint16)
	if ipv6 {
		key := &SourceRangeKey6{PrefixLen: uint32(ones) + lpmPrefixLen6, RevNATID: id}
		copy(key.Address[:], cidr.IP.To16())
		return key
	} else {
		key := &SourceRangeKey4{PrefixLen: uint32(ones) + lpmPrefixLen4, RevNATID: id}
		copy(key.Address[:], cidr.IP.To4())
		return key
	}
}
