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

package ipmasq

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName    = "cilium_ipmasq_v4"
	MaxEntries = 16384
)

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key4 struct {
	PrefixLen uint32
	Address   types.IPv4
}

func (k *Key4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *Key4) NewValue() bpf.MapValue    { return &Value{} }
func (k *Key4) String() string            { return fmt.Sprintf("%s", k.Address) }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Value struct {
	Pad uint8 // not used
}

func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *Value) String() string              { return "" }

var IPMasq4Map = bpf.NewMap(
	MapName,
	bpf.MapTypeLPMTrie,
	&Key4{}, int(unsafe.Sizeof(Key4{})),
	&Value{}, int(unsafe.Sizeof(Value{})),
	MaxEntries,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()

type IPMasqBPFMap struct{}

func (*IPMasqBPFMap) Update(cidr net.IPNet) error {
	return IPMasq4Map.Update(key(cidr), &Value{})
}

func (*IPMasqBPFMap) Delete(cidr net.IPNet) error {
	return IPMasq4Map.Delete(key(cidr))
}

func (*IPMasqBPFMap) Dump() ([]net.IPNet, error) {
	cidrs := []net.IPNet{}
	if err := IPMasq4Map.DumpWithCallback(
		func(key bpf.MapKey, value bpf.MapValue) {
			cidrs = append(cidrs, keyToIPNet(key.(*Key4)))
		}); err != nil {
		return nil, err
	}
	return cidrs, nil
}

func key(cidr net.IPNet) *Key4 {
	ones, _ := cidr.Mask.Size()
	key := &Key4{PrefixLen: uint32(ones)}
	copy(key.Address[:], cidr.IP.To4())
	return key
}

func keyToIPNet(key *Key4) net.IPNet {
	var (
		cidr net.IPNet
		ip   types.IPv4
	)

	cidr.Mask = net.CIDRMask(int(key.PrefixLen), 32)
	key.Address.DeepCopyInto(&ip)
	cidr.IP = ip.IP()

	return cidr
}
