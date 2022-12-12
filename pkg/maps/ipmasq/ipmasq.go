// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
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

var (
	ipMasq4Map *bpf.Map
	once       sync.Once
)

func IPMasq4Map() *bpf.Map {
	once.Do(func() {
		ipMasq4Map = bpf.NewMap(
			MapName,
			bpf.MapTypeLPMTrie,
			&Key4{}, int(unsafe.Sizeof(Key4{})),
			&Value{}, int(unsafe.Sizeof(Value{})),
			MaxEntries,
			bpf.BPF_F_NO_PREALLOC,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapName))
	})
	return ipMasq4Map
}

type IPMasqBPFMap struct{}

func (*IPMasqBPFMap) Update(cidr net.IPNet) error {
	return IPMasq4Map().Update(key(cidr), &Value{})
}

func (*IPMasqBPFMap) Delete(cidr net.IPNet) error {
	return IPMasq4Map().Delete(key(cidr))
}

func (*IPMasqBPFMap) Dump() ([]net.IPNet, error) {
	cidrs := []net.IPNet{}
	if err := IPMasq4Map().DumpWithCallback(
		func(key bpf.MapKey, _ bpf.MapValue) {
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
