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
	policyMapName4   = "cilium_srv6_policy_v4"
	policyMapName6   = "cilium_srv6_policy_v6"
	maxPolicyEntries = 16384

	// policyStaticPrefixBits represents the size in bits of the static
	// prefix part of an policy key (i.e. the VRF ID).
	policyStaticPrefixBits = uint32(unsafe.Sizeof(uint32(0)) * 8)
)

// PolicyKey4 is a key for the PolicyMap4. Implements bpf.MapKey.
type PolicyKey4 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32     `align:"lpm"`
	VRFID     uint32     `align:"vrf_id"`
	DestCIDR  types.IPv4 `align:"dst_cidr"`
}

func (k *PolicyKey4) New() bpf.MapKey {
	return &PolicyKey4{}
}

func (k *PolicyKey4) String() string {
	return fmt.Sprintf("vrfid=%d, destCIDR=%s", k.VRFID, k.getDestCIDR())
}

func (k *PolicyKey4) getDestCIDR() netip.Prefix {
	return netip.PrefixFrom(
		k.DestCIDR.Addr(),
		int(k.PrefixLen-policyStaticPrefixBits),
	)
}

// PolicyKey6 is a key for the PolicyMap6. Implements bpf.MapKey.
type PolicyKey6 struct {
	// PrefixLen is full 32 bits of VRF ID + DestCIDR's mask bits
	PrefixLen uint32     `align:"lpm"`
	VRFID     uint32     `align:"vrf_id"`
	DestCIDR  types.IPv6 `align:"dst_cidr"`
}

func (k *PolicyKey6) New() bpf.MapKey {
	return &PolicyKey6{}
}

func (k *PolicyKey6) String() string {
	return fmt.Sprintf("vrfid=%d, destCIDR=%s", k.VRFID, k.getDestCIDR())
}

func (k *PolicyKey6) getDestCIDR() netip.Prefix {
	return netip.PrefixFrom(
		k.DestCIDR.Addr(),
		int(k.PrefixLen-policyStaticPrefixBits),
	)
}

// PolicyKey abstracts away the differences between PolicyKey4 and PolicyKey6.
type PolicyKey struct {
	VRFID    uint32
	DestCIDR netip.Prefix
}

// PolicyValue is a value for the PolicyMap4/6. Implements bpf.MapValue.
type PolicyValue struct {
	SID types.IPv6
}

func (k *PolicyValue) New() bpf.MapValue {
	return &PolicyValue{}
}

func (v *PolicyValue) String() string {
	return fmt.Sprintf("sid=%s", v.SID.String())
}

// SRv6PolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an SRv6 policy map.
type SRv6PolicyIterateCallback func(*PolicyKey, *PolicyValue)

// Define different types for IPv4 and IPv6 maps for DI
type PolicyMap4 srv6PolicyMap
type PolicyMap6 srv6PolicyMap

// IterateWithCallback4 iterates through the IPv4 keys/values of an egress
// policy map, passing each key/value pair to the cb callback.
func (m *PolicyMap4) IterateWithCallback(cb SRv6PolicyIterateCallback) error {
	return m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		k4 := k.(*PolicyKey4)
		key := &PolicyKey{
			VRFID:    k4.VRFID,
			DestCIDR: k4.getDestCIDR(),
		}
		value := v.(*PolicyValue)
		cb(key, value)
	})
}

// IterateWithCallback iterates through the IPv6 keys/values of an egress
// policy map, passing each key/value pair to the cb callback.
func (m *PolicyMap6) IterateWithCallback(cb SRv6PolicyIterateCallback) error {
	return m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		k6 := k.(*PolicyKey6)
		key := &PolicyKey{
			VRFID:    k6.VRFID,
			DestCIDR: k6.getDestCIDR(),
		}
		value := v.(*PolicyValue)
		cb(key, value)
	})
}

// srv6PolicyMap is the internal representation of an SRv6 policy map.
type srv6PolicyMap struct {
	*bpf.Map
}

func newPolicyMaps(dc *option.DaemonConfig, lc cell.Lifecycle) (bpf.MapOut[*PolicyMap4], bpf.MapOut[*PolicyMap6], defines.NodeOut) {
	if !dc.EnableSRv6 {
		return bpf.MapOut[*PolicyMap4]{}, bpf.MapOut[*PolicyMap6]{}, defines.NodeOut{}
	}

	m4 := bpf.NewMap(
		policyMapName4,
		ebpf.LPMTrie,
		&PolicyKey4{},
		&PolicyValue{},
		maxPolicyEntries,
		bpf.BPF_F_NO_PREALLOC,
	)

	m6 := bpf.NewMap(
		policyMapName6,
		ebpf.LPMTrie,
		&PolicyKey6{},
		&PolicyValue{},
		maxPolicyEntries,
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
			"SRV6_POLICY_MAP_SIZE": strconv.FormatUint(maxPolicyEntries, 10),
		},
	}

	return bpf.NewMapOut(&PolicyMap4{m4}), bpf.NewMapOut(&PolicyMap6{m6}), nodeOut
}

// OpenPolicyMaps opens the SRv6 policy maps on bpffs
func OpenPolicyMaps(logger *slog.Logger) (*PolicyMap4, *PolicyMap6, error) {
	m4, err := bpf.OpenMap(bpf.MapPath(logger, policyMapName4), &PolicyKey4{}, &PolicyValue{})
	if err != nil {
		return nil, nil, err
	}
	m6, err := bpf.OpenMap(bpf.MapPath(logger, policyMapName6), &PolicyKey6{}, &PolicyValue{})
	if err != nil {
		return nil, nil, err
	}
	return &PolicyMap4{m4}, &PolicyMap6{m6}, nil
}
