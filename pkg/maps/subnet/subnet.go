// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MapName is the name of the subnet map.
	MapName = "cilium_subnet_map"

	// MaxEntries is the maximum number of keys that can be present in the
	// subnet map.
	MaxEntries = 1024

	SubnetKeyIPv4 uint8 = 1
	SubnetKeyIPv6 uint8 = 2
)

// SubnetMapKey implements the bpf.MapKey interface.
// Must be in sync with struct subnet_key in <bpf/lib/subnet.h>
type SubnetMapKey struct {
	Prefixlen uint32     `align:"lpm_key"`
	Pad0      uint16     `align:"pad0"`
	Pad1      uint8      `align:"pad1"`
	Family    uint8      `align:"family"`
	IP        types.IPv6 `align:"$union0"`
}

// getStaticPrefixBits returns the number of bits in the Prefixlen field
// that are not part of the actual subnet prefix, i.e., the bits used for
// static fields in the SubnetMapKey struct.
func getStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(SubnetMapKey{})
	staticMatchSize -= unsafe.Sizeof(SubnetMapKey{}.Prefixlen)
	staticMatchSize -= unsafe.Sizeof(SubnetMapKey{}.IP)
	return uint32(staticMatchSize) * 8
}

func (k SubnetMapKey) String() string {
	var (
		addr netip.Addr
		ok   bool
	)

	switch k.Family {
	case SubnetKeyIPv4:
		addr, ok = netip.AddrFromSlice(k.IP[:net.IPv4len])
		if !ok {
			return "<unknown>"
		}
	case SubnetKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	default:
		return "<unknown>"
	}

	prefixLen := int(k.Prefixlen - getStaticPrefixBits())
	return netip.PrefixFrom(addr, prefixLen).String()
}

func (k *SubnetMapKey) New() bpf.MapKey { return &SubnetMapKey{} }

func (k SubnetMapKey) Prefix() netip.Prefix {
	var addr netip.Addr
	prefixLen := int(k.Prefixlen - getStaticPrefixBits())
	switch k.Family {
	case SubnetKeyIPv4:
		addr = netip.AddrFrom4(*(*[4]byte)(k.IP[:4]))
	case SubnetKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	}
	return netip.PrefixFrom(addr, prefixLen)
}

// getPrefixLen determines the length that should be set inside the Key so that
// the lookup prefix is correct in the BPF map key. The specified 'prefixBits'
// indicates the number of bits in the IP that must match to match the entry in
// the BPF subnet map.
func getPrefixLen(prefixBits int) uint32 {
	return getStaticPrefixBits() + uint32(prefixBits)
}

// SubnetMapValue implements the bpf.MapValue interface.
// Must be in sync with struct subnet_value in <bpf/lib/subnet.h>
type SubnetMapValue struct {
	Identity uint32 `align:"identity"`
}

func (v *SubnetMapValue) String() string {
	return fmt.Sprintf("identity=%d", v.Identity)
}

func (v *SubnetMapValue) New() bpf.MapValue { return &SubnetMapValue{} }

// NewValue returns a Value based on the provided identity.
func NewValue(identity uint32) SubnetMapValue {
	return SubnetMapValue{
		Identity: identity,
	}
}

type subnetMap struct {
	*bpf.Map
}

// SubnetMap constructs the cilium_subnet_map. Direct use of this
// outside of this package is solely for cilium-dbg.
func SubnetMap() *bpf.Map {
	return bpf.NewMap(
		MapName,
		ebpf.LPMTrie,
		&SubnetMapKey{},
		&SubnetMapValue{},
		MaxEntries,
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG,
	)
}

func newSubnetMap(cfg *option.DaemonConfig, lc cell.Lifecycle) (out bpf.MapOut[subnetMap]) {
	m := subnetMap{SubnetMap()}
	if cfg.RoutingMode == option.RoutingModeHybrid {
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				// We want to recreate the map in case schema has changed.
				return m.Recreate()
			},
			OnStop: func(cell.HookContext) error {
				return m.Close()
			},
		})
	}
	return bpf.NewMapOut(m)
}
