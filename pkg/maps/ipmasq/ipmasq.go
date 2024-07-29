// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"net/netip"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapNameIPv4    = "cilium_ipmasq_v4"
	MaxEntriesIPv4 = 16384
	MapNameIPv6    = "cilium_ipmasq_v6"
	MaxEntriesIPv6 = 16384
)

type Key4 struct {
	PrefixLen uint32
	Address   types.IPv4
}

func (k *Key4) String() string  { return k.Address.String() }
func (k *Key4) New() bpf.MapKey { return &Key4{} }

type Key6 struct {
	PrefixLen uint32
	Address   types.IPv6
}

func (k *Key6) String() string  { return k.Address.String() }
func (k *Key6) New() bpf.MapKey { return &Key6{} }

type Value struct {
	Pad uint8 // not used
}

func (v *Value) String() string    { return "" }
func (v *Value) New() bpf.MapValue { return &Value{} }

var (
	ipMasq4Map *bpf.Map
	onceIPv4   sync.Once
	ipMasq6Map *bpf.Map
	onceIPv6   sync.Once
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

func IPMasq6Map() *bpf.Map {
	onceIPv6.Do(func() {
		ipMasq6Map = bpf.NewMap(
			MapNameIPv6,
			ebpf.LPMTrie,
			&Key6{},
			&Value{},
			MaxEntriesIPv6,
			bpf.BPF_F_NO_PREALLOC,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapNameIPv6))
	})
	return ipMasq6Map
}

type IPMasqBPFMap struct{}

func (*IPMasqBPFMap) Update(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		if option.Config.EnableIPv4Masquerade {
			return IPMasq4Map().Update(keyIPv4(cidr), &Value{})
		}
	} else {
		if option.Config.EnableIPv6Masquerade {
			return IPMasq6Map().Update(keyIPv6(cidr), &Value{})
		}
	}
	return nil
}

func (*IPMasqBPFMap) Delete(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		if option.Config.EnableIPv4Masquerade {
			return IPMasq4Map().Delete(keyIPv4(cidr))
		}
	} else {
		if option.Config.EnableIPv6Masquerade {
			return IPMasq6Map().Delete(keyIPv6(cidr))
		}
	}
	return nil
}

// DumpForProtocols dumps the contents of the ip-masq-agent maps for IPv4
// and/or IPv6, as requested by the caller.
// Given that the package does not expose the maps directly, it's necessary to
// specify which protocol we need when ipMasq4Map/ipMasq6Map, or config
// options, have not been set, as is the case when calling from the CLI, for
// example.
func (*IPMasqBPFMap) DumpForProtocols(ipv4Needed, ipv6Needed bool) ([]netip.Prefix, error) {
	cidrs := []netip.Prefix{}
	if ipv4Needed {
		if err := IPMasq4Map().DumpWithCallback(
			func(keyIPv4 bpf.MapKey, _ bpf.MapValue) {
				cidrs = append(cidrs, keyToIPNetIPv4(keyIPv4.(*Key4)))
			}); err != nil {
			return nil, err
		}
	}
	if ipv6Needed {
		if err := IPMasq6Map().DumpWithCallback(
			func(keyIPv6 bpf.MapKey, _ bpf.MapValue) {
				cidrs = append(cidrs, keyToIPNetIPv6(keyIPv6.(*Key6)))
			}); err != nil {
			return nil, err
		}
	}
	return cidrs, nil
}

// Dump dumps the contents of the ip-masq-agent maps for IPv4 and/or IPv6, as
// required based on configuration options.
func (*IPMasqBPFMap) Dump() ([]netip.Prefix, error) {
	return (&IPMasqBPFMap{}).DumpForProtocols(option.Config.EnableIPv4Masquerade, option.Config.EnableIPv6Masquerade)
}

func keyIPv4(cidr netip.Prefix) *Key4 {
	ones := cidr.Bits()
	key := &Key4{PrefixLen: uint32(ones)}
	copy(key.Address[:], cidr.Masked().Addr().AsSlice())
	return key
}

func keyToIPNetIPv4(key *Key4) netip.Prefix {
	return netip.PrefixFrom(key.Address.Addr(), int(key.PrefixLen))
}

func keyIPv6(cidr netip.Prefix) *Key6 {
	ones := cidr.Bits()
	key := &Key6{PrefixLen: uint32(ones)}
	copy(key.Address[:], cidr.Masked().Addr().AsSlice())
	return key
}

func keyToIPNetIPv6(key *Key6) netip.Prefix {
	return netip.PrefixFrom(key.Address.Addr(), int(key.PrefixLen))
}
