// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	vrfMapName4   = "cilium_srv6_vrf_v4"
	vrfMapName6   = "cilium_srv6_vrf_v6"
	maxVRFEntries = 16384

	// vrf4StaticPrefixBits represents the size in bits of the static
	// prefix part of an vrf key (i.e. the VRF ID).
	vrf4StaticPrefixBits = uint32(unsafe.Sizeof(types.IPv4{}) * 8)

	// vrf6StaticPrefixBits represents the size in bits of the static
	// prefix part of an vrf key (i.e. the VRF ID).
	vrf6StaticPrefixBits = uint32(unsafe.Sizeof(types.IPv6{}) * 8)
)

// VRFKey4 is a key for the VRFMap4. Implements bpf.MapKey.
type VRFKey4 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32     `align:"lpm"`
	SourceIP  types.IPv4 `align:"src_ip"`
	DestCIDR  types.IPv4 `align:"dst_cidr"`
}

func (v *VRFKey4) New() bpf.MapKey {
	return &VRFKey4{}
}

func (v *VRFKey4) String() string {
	return fmt.Sprintf("srcip=%s, destCIDR=%s", v.SourceIP, v.getDestCIDR())
}

func (k *VRFKey4) getDestCIDR() netip.Prefix {
	return netip.PrefixFrom(
		k.DestCIDR.Addr(),
		int(k.PrefixLen-vrf4StaticPrefixBits),
	)
}

// VRFKey6 is a key for the VRFMap6. Implements bpf.MapKey.
type VRFKey6 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32     `align:"lpm"`
	SourceIP  types.IPv6 `align:"src_ip"`
	DestCIDR  types.IPv6 `align:"dst_cidr"`
}

func (v *VRFKey6) New() bpf.MapKey {
	return &VRFKey6{}
}

func (v *VRFKey6) String() string {
	return fmt.Sprintf("srcip=%s, destCIDR=%s", v.SourceIP, v.getDestCIDR())
}

func (k *VRFKey6) getDestCIDR() netip.Prefix {
	return netip.PrefixFrom(
		k.DestCIDR.Addr(),
		int(k.PrefixLen-vrf6StaticPrefixBits),
	)
}

// VRFKey abstracts away the differences between VRFKey4 and VRFKey6.
type VRFKey struct {
	SourceIP netip.Addr
	DestCIDR netip.Prefix
}

// VRFValue is a value for the VRFMap4/6. Implements bpf.MapValue.
type VRFValue struct {
	ID uint32
}

func (v *VRFValue) New() bpf.MapValue {
	return &VRFValue{}
}

func (v *VRFValue) String() string {
	return fmt.Sprintf("vrfid=%d", v.ID)
}

// SRv6VRFIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of policy maps.
type SRv6VRFIterateCallback func(*VRFKey, *VRFValue)

// Define different types for IPv4 and IPv6 maps for DI
type VRFMap4 srv6VRFMap
type VRFMap6 srv6VRFMap

// IterateWithCallback iterates through the IPv4 keys/values of a VRF mapping
// map, passing each key/value pair to the cb callback.
func (m *VRFMap4) IterateWithCallback(cb SRv6VRFIterateCallback) error {
	return m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		k4 := k.(*VRFKey4)
		key := &VRFKey{
			SourceIP: k4.SourceIP.Addr(),
			DestCIDR: k4.getDestCIDR(),
		}
		value := v.(*VRFValue)
		cb(key, value)
	})
}

// IterateWithCallback iterates through the IPv6 keys/values of a VRF mapping
// map, passing each key/value pair to the cb callback.
func (m *VRFMap6) IterateWithCallback(cb SRv6VRFIterateCallback) error {
	return m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		k6 := k.(*VRFKey6)
		key := &VRFKey{
			SourceIP: k6.SourceIP.Addr(),
			DestCIDR: k6.getDestCIDR(),
		}
		value := v.(*VRFValue)
		cb(key, value)
	})
}

// srv6VRFMap is the internal representation of an SRv6 VRF mapping map.
type srv6VRFMap struct {
	*bpf.Map
}

func newVRFMaps(dc *option.DaemonConfig, lc cell.Lifecycle) (bpf.MapOut[*VRFMap4], bpf.MapOut[*VRFMap6], defines.NodeOut) {
	if !dc.EnableSRv6 {
		return bpf.MapOut[*VRFMap4]{}, bpf.MapOut[*VRFMap6]{}, defines.NodeOut{}
	}

	m4 := bpf.NewMap(
		vrfMapName4,
		ebpf.LPMTrie,
		&VRFKey4{},
		&VRFValue{},
		maxVRFEntries,
		bpf.BPF_F_NO_PREALLOC,
	)

	m6 := bpf.NewMap(
		vrfMapName6,
		ebpf.LPMTrie,
		&VRFKey6{},
		&VRFValue{},
		maxVRFEntries,
		bpf.BPF_F_NO_PREALLOC,
	)

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if err := m4.OpenOrCreate(); err != nil {
				return err
			}
			if err := m6.OpenOrCreate(); err != nil {
				return err
			}
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			m4.Close()
			m6.Close()
			return nil
		},
	})

	nodeOut := defines.NodeOut{
		NodeDefines: defines.Map{
			"SRV6_VRF_MAP_SIZE": strconv.FormatUint(maxVRFEntries, 10),
		},
	}

	return bpf.NewMapOut(&VRFMap4{m4}), bpf.NewMapOut(&VRFMap6{m6}), nodeOut
}

// OpenVRFMaps opens the SRv6 VRF maps on bpffs
func OpenVRFMaps(logger *slog.Logger) (*VRFMap4, *VRFMap6, error) {
	m4, err := bpf.OpenMap(bpf.MapPath(logger, vrfMapName4), &VRFKey4{}, &VRFValue{})
	if err != nil {
		return nil, nil, err
	}

	m6, err := bpf.OpenMap(bpf.MapPath(logger, vrfMapName6), &VRFKey6{}, &VRFValue{})
	if err != nil {
		return nil, nil, err
	}

	return &VRFMap4{m4}, &VRFMap6{m6}, nil
}
