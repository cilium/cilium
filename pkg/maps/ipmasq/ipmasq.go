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
	MapNameIPv4    = "cilium_ipmasq_v4"
	MaxEntriesIPv4 = 16384
)

type Key4 struct {
	PrefixLen uint32
	Address   types.IPv4
}

func (k *Key4) String() string  { return fmt.Sprintf("%s", k.Address) }
func (k *Key4) New() bpf.MapKey { return &Key4{} }

type Value struct {
	Pad uint8 // not used
}

func (v *Value) String() string    { return "" }
func (v *Value) New() bpf.MapValue { return &Value{} }

var (
	ipMasq4Map *bpf.Map
	onceIPv4   sync.Once
)

func IPMasq4Map() *bpf.Map {
	onceIPv4.Do(func() {
		ipMasq4Map = bpf.NewMap(
			MapNameIPv4,
			ebpf.LPMTrie,
			&Key4{},
			&Value{},
			MaxEntriesIPv4,
			bpf.BPF_F_NO_PREALLOC,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapNameIPv4))
	})
	return ipMasq4Map
}

type IPMasqBPFMap struct{}

func (*IPMasqBPFMap) Update(cidr net.IPNet) error {
	return IPMasq4Map().Update(keyIPv4(cidr), &Value{})
}

func (*IPMasqBPFMap) Delete(cidr net.IPNet) error {
	return IPMasq4Map().Delete(keyIPv4(cidr))
}

func (*IPMasqBPFMap) Dump() ([]net.IPNet, error) {
	cidrs := []net.IPNet{}
	if err := IPMasq4Map().DumpWithCallback(
		func(keyIPv4 bpf.MapKey, _ bpf.MapValue) {
			cidrs = append(cidrs, keyToIPNetIPv4(keyIPv4.(*Key4)))
		}); err != nil {
		return nil, err
	}
	return cidrs, nil
}

func keyIPv4(cidr net.IPNet) *Key4 {
	ones, _ := cidr.Mask.Size()
	key := &Key4{PrefixLen: uint32(ones)}
	copy(key.Address[:], cidr.IP.To4())
	return key
}

func keyToIPNetIPv4(key *Key4) net.IPNet {
	var (
		cidr net.IPNet
		ip   types.IPv4
	)

	cidr.Mask = net.CIDRMask(int(key.PrefixLen), 32)
	key.Address.DeepCopyInto(&ip)
	cidr.IP = ip.IP()

	return cidr
}
