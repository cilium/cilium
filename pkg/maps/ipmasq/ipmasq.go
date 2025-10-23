// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"

	"github.com/cilium/cilium/pkg/bpf"
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

type IPMasqBPFMap struct {
	ipMasq4Map *bpf.Map
	ipMasq6Map *bpf.Map
}

func OpenIPMasqBPFMap(logger *slog.Logger) (*IPMasqBPFMap, error) {
	m := &IPMasqBPFMap{}
	var err error

	m.ipMasq4Map, err = bpf.OpenMap(bpf.MapPath(logger, MapNameIPv4), &Key4{}, &Value{})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	m.ipMasq6Map, err = bpf.OpenMap(bpf.MapPath(logger, MapNameIPv6), &Key6{}, &Value{})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	return m, nil
}

func (m *IPMasqBPFMap) Update(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		if m.ipMasq4Map != nil {
			return m.ipMasq4Map.Update(keyIPv4(cidr), &Value{})
		}
	} else {
		if m.ipMasq6Map != nil {
			return m.ipMasq6Map.Update(keyIPv6(cidr), &Value{})
		}
	}
	return nil
}

func (m *IPMasqBPFMap) Delete(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		if m.ipMasq4Map != nil {
			return m.ipMasq4Map.Delete(keyIPv4(cidr))
		}
	} else {
		if m.ipMasq6Map != nil {
			return m.ipMasq6Map.Delete(keyIPv6(cidr))
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
func (m *IPMasqBPFMap) DumpForProtocols(ipv4Needed, ipv6Needed bool) ([]netip.Prefix, error) {
	cidrs := []netip.Prefix{}
	if ipv4Needed && m.ipMasq4Map != nil {
		if err := m.ipMasq4Map.DumpWithCallback(
			func(keyIPv4 bpf.MapKey, _ bpf.MapValue) {
				cidrs = append(cidrs, keyToIPNetIPv4(keyIPv4.(*Key4)))
			}); err != nil {
			return nil, err
		}
	}
	if ipv6Needed && m.ipMasq6Map != nil {
		if err := m.ipMasq6Map.DumpWithCallback(
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
func (m *IPMasqBPFMap) Dump() ([]netip.Prefix, error) {
	return m.DumpForProtocols(m.ipMasq4Map != nil, m.ipMasq6Map != nil)
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
