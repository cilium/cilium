// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName    = "cilium_ipmasq_v4"
	MaxEntries = 16384
)

type Key4 struct {
	PrefixLen uint32
	Address   types.IPv4
}

func (k *Key4) String() string             { return fmt.Sprintf("%s", k.Address) }
func (k *Key4) DeepCopyMapKey() bpf.MapKey { return &Key4{} }

type Value struct {
	Pad uint8 // not used
}

func (v *Value) String() string                 { return "" }
func (v *Value) DeepCopyMapValue() bpf.MapValue { return &Value{} }

var (
	ipMasq4Map *bpf.Map
	once       sync.Once
)

func IPMasq4Map() *bpf.Map {
	once.Do(func() {
		ipMasq4Map = bpf.NewMap(
			MapName,
			ebpf.LPMTrie,
			&Key4{},
			&Value{},
			MaxEntries,
			bpf.BPF_F_NO_PREALLOC,
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
