// Copyright 2021 Authors of Cilium
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

package egressmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName    = "cilium_egress_v4"
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
func (k *Key4) NewValue() bpf.MapValue    { return &EgressInfo4{} }
func (k *Key4) String() string {
	return fmt.Sprintf("%s %s/%d", k.SourceIP, k.DestCIDR, k.PrefixLen-getStaticPrefixBits())
}

func getStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(Key4{})
	staticMatchSize -= unsafe.Sizeof(Key4{}.PrefixLen)
	staticMatchSize -= unsafe.Sizeof(Key4{}.DestCIDR)
	return uint32(staticMatchSize) * 8
}

// NewKey returns a new Key4 instance
func NewKey(src, dst net.IP, mask net.IPMask) Key4 {
	result := Key4{}

	ones, _ := mask.Size()

	copy(result.SourceIP[:], src.To4())
	copy(result.DestCIDR[:], dst.To4())
	result.PrefixLen = getStaticPrefixBits() + uint32(ones)

	return result
}

// EgressInfo4 implements the bpf.MapValue interface. It contains the
// information about egress gateway and egress IP address for masquerading.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type EgressInfo4 struct {
	EgressIP       types.IPv4 `align:"egress_ip"`
	TunnelEndpoint types.IPv4 `align:"tunnel_endpoint"`
}

// String pretty print the egress information.
func (v *EgressInfo4) String() string {
	return fmt.Sprintf("%s %s", v.TunnelEndpoint, v.EgressIP)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *EgressInfo4) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// EgressMap initiates a Map
var EgressMap = bpf.NewMap(
	MapName,
	bpf.MapTypeLPMTrie,
	&Key4{}, int(unsafe.Sizeof(Key4{})),
	&EgressInfo4{}, int(unsafe.Sizeof(EgressInfo4{})),
	MaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()
