// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep_policy

import (
	"fmt"
	"net/netip"

	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/hive/cell"
)

const (
	MaxEntries = 16384
	// Name is the canonical name for the VTEP map on the filesystem.
	VtepPolicyMapName = "cilium_vtep_policy_map"
)

// Must be in sync with struct vtep_key in <bpf/lib/vtep.h>
type VtepPolicyKey struct {
	PrefixLen uint32     `align:"prefixlen"`
	SourceIP  types.IPv4 `align:"src_ip"`
	DestCIDR  types.IPv4 `align:"dst_ip"`
}

func (k VtepPolicyKey) String() string {
	return fmt.Sprintf("%s.%s/%d", k.SourceIP, k.DestCIDR, k.PrefixLen)
}

func (k *VtepPolicyKey) New() bpf.MapKey { return &VtepPolicyKey{} }

// NewKey returns an Key based on the provided source IP address and destination CIDR
func NewKey(srcIP netip.Addr, dstCIDR netip.Prefix) VtepPolicyKey {
	result := VtepPolicyKey{}

	ip4 := srcIP.As4()
	copy(result.SourceIP[:], ip4[:])

	cidr := dstCIDR.Addr().As4()
	copy(result.DestCIDR[:], cidr[:])

	result.PrefixLen = 32 + uint32(dstCIDR.Bits())

	return result
}

// VtepPolicyVal implements the bpf.MapValue interface. It contains the
// VTEP endpoint MAC and IP
type VtepPolicyVal struct {
	Mac    mac.Uint64MAC `align:"vtep_mac"`
	VtepIp types.IPv4    `align:"tunnel_endpoint"`
	_      [4]byte
}

func (v *VtepPolicyVal) String() string {
	return fmt.Sprintf("vtepmac=%s tunnelendpoint=%s",
		v.Mac, v.VtepIp)
}

func (v *VtepPolicyVal) New() bpf.MapValue { return &VtepPolicyVal{} }

// Map represents an VTEP BPF map.
type VtepPolicyMap struct {
	m *bpf.Map
}

func createPolicyMapFromDaemonConfig(lifecycle cell.Lifecycle, cfg *option.DaemonConfig, metricsRegistry *metrics.Registry) bpf.MapOut[*VtepPolicyMap] {
	if !cfg.EnableVTEP || !cfg.EnableIPv4 {
		return bpf.NewMapOut[*VtepPolicyMap](nil)
	}

	return bpf.NewMapOut(newVtepPolicyMap(lifecycle, metricsRegistry, ebpf.PinByName))
}

// CreatePrivatePolicyMap4 creates an unpinned IPv4 policy map.
//
// Useful for testing.
func CreatePrivatePolicyMap(lc cell.Lifecycle, registry *metrics.Registry) *VtepPolicyMap {
	return newVtepPolicyMap(lc, registry, ebpf.PinNone)
}

func newVtepPolicyMap(lc cell.Lifecycle, registry *metrics.Registry, pinning ebpf.PinType) *VtepPolicyMap {
	m := bpf.NewMap(
		VtepPolicyMapName,
		ebpf.LPMTrie,
		&VtepPolicyKey{},
		&VtepPolicyVal{},
		defaults.MaxVtepPolicyEntries,
		0,
	).WithCache().WithPressureMetric(registry).
		WithEvents(option.Config.GetEventBufferConfig(VtepPolicyMapName))

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			switch pinning {
			case ebpf.PinNone:
				return m.CreateUnpinned()
			case ebpf.PinByName:
				return m.OpenOrCreate()
			}
			return fmt.Errorf("received unexpected pin type: %d", pinning)
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	return &VtepPolicyMap{m}
}

func NewVal(newTunnelEndpoint netip.Addr, vtepMAC mac.MAC) VtepPolicyVal {
	mac, _ := vtepMAC.Uint64()

	value := VtepPolicyVal{
		Mac: mac,
	}

	ip4 := newTunnelEndpoint.As4()
	copy(value.VtepIp[:], ip4[:])

	return value
}

// OpenPinnedVtepPolicyMap opens an existing pinned IPv4 policy map.
func OpenPinnedVtepPolicyMap(logger *slog.Logger) (*VtepPolicyMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, VtepPolicyMapName), &VtepPolicyKey{}, &VtepPolicyVal{})
	if err != nil {
		return nil, err
	}

	return &VtepPolicyMap{m}, nil
}

// Function to update vtep map with VTEP CIDR
func (m *VtepPolicyMap) UpdateVtepPolicyMapping(srcIP netip.Addr, dstCIDR netip.Prefix, newTunnelEndpoint netip.Addr, vtepMAC mac.MAC) error {
	key := NewKey(srcIP, dstCIDR)
	value := NewVal(newTunnelEndpoint, vtepMAC)

	return m.m.Update(&key, &value)
}

func (m *VtepPolicyMap) RemoveVtepPolicyMapping(srcIP netip.Addr, dstCIDR netip.Prefix) error {
	key := NewKey(srcIP, dstCIDR)
	return m.m.Delete(&key)
}

func (m *VtepPolicyMap) Delete(key *VtepPolicyKey) error {
	return m.m.Delete(key)
}

func (m *VtepPolicyMap) Lookup(key *VtepPolicyKey) (*VtepPolicyVal, error) {
	ret, err := m.m.Lookup(key)
	if err != nil {
		return nil, err
	}
	return ret.(*VtepPolicyVal), err
}

// VtepPolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an vtep policy map.
type VtepPolicyIterateCallback func(*VtepPolicyKey, *VtepPolicyVal)

// IterateWithCallback iterates through all the keys/values of an vtep policy
// map, passing each key/value pair to the cb callback.
func (m *VtepPolicyMap) IterateWithCallback(cb VtepPolicyIterateCallback) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*VtepPolicyKey)
		value := v.(*VtepPolicyVal)

		cb(key, value)
	})
}

func (k *VtepPolicyKey) Match(ip netip.Addr, destCIDR netip.Prefix) bool {
	nkey := NewKey(ip, destCIDR)
	return nkey == *k
}

func (v *VtepPolicyVal) Match(vtepIP netip.Addr, rmac mac.MAC) bool {
	nval := NewVal(vtepIP, rmac)
	return nval == *v
}
