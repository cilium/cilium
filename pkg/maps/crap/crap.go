// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package crap

import (
	"fmt"
	"net/netip"

	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/hive/cell"
)

const (
	MaxEntries  = 8192
	CrapMapName = "cilium_crap_map"
)

// Must be in sync with struct crap_key in <bpf/lib/crap.h>
type CrapKey struct {
	DestIP types.IPv4 `align:"dst_ip"`
}

func (k CrapKey) String() string {
	return fmt.Sprintf("%s", k.DestIP)
}

func (k *CrapKey) New() bpf.MapKey { return &CrapKey{} }

// NewKey returns an Key based on the provided source IP address and destination CIDR
func NewKey(dstIP netip.Addr) CrapKey {
	result := CrapKey{}

	ip4 := dstIP.As4()
	copy(result.DestIP[:], ip4[:])

	return result
}

// CrapVal implements the bpf.MapValue interface. It contains the
type CrapVal struct {
	PodIp types.IPv4 `align:"pod_ip"`
}

func (v *CrapVal) String() string {
	return fmt.Sprintf("pod_ip=%s", v.PodIp)
}

func (v *CrapVal) New() bpf.MapValue { return &CrapVal{} }

// Map represents an CRAP BPF map.
type CrapMap struct {
	m *bpf.Map
}

func createPolicyMapFromDaemonConfig(lifecycle cell.Lifecycle, cfg *option.DaemonConfig, metricsRegistry *metrics.Registry) bpf.MapOut[*CrapMap] {
	if !cfg.EnableIPv4 {
		return bpf.NewMapOut[*CrapMap](nil)
	}

	return bpf.NewMapOut(newCrapMap(lifecycle, metricsRegistry, ebpf.PinByName))
}

// CreatePrivatePolicyMap4 creates an unpinned IPv4 policy map.
//
// Useful for testing.
func CreatePrivatePolicyMap(lc cell.Lifecycle, registry *metrics.Registry) *CrapMap {
	return newCrapMap(lc, registry, ebpf.PinNone)
}

func newCrapMap(lc cell.Lifecycle, registry *metrics.Registry, pinning ebpf.PinType) *CrapMap {
	m := bpf.NewMap(
		CrapMapName,
		ebpf.Hash,
		&CrapKey{},
		&CrapVal{},
		8192,
		0,
	).WithCache().WithPressureMetric(registry).
		WithEvents(option.Config.GetEventBufferConfig(CrapMapName))

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

	return &CrapMap{m}
}

func NewVal(newTunnelEndpoint netip.Addr) CrapVal {
	value := CrapVal{}

	ip4 := newTunnelEndpoint.As4()
	copy(value.PodIp[:], ip4[:])

	return value
}

// OpenPinnedCrapMap opens an existing pinned IPv4 policy map.
func OpenPinnedCrapMap(logger *slog.Logger) (*CrapMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, CrapMapName), &CrapKey{}, &CrapVal{})
	if err != nil {
		return nil, err
	}

	return &CrapMap{m}, nil
}

func (m *CrapMap) UpdateCrapMapping(dstIP netip.Addr, podIp netip.Addr) error {
	key := NewKey(dstIP)
	value := NewVal(podIp)

	return m.m.Update(&key, &value)
}

func (m *CrapMap) Update(key CrapKey, value CrapVal) error {
	return m.m.Update(&key, &value)
}

func (m *CrapMap) RemoveCrapMapping(dstIP netip.Addr) error {
	key := NewKey(dstIP)
	return m.m.Delete(&key)
}

func (m *CrapMap) Delete(key *CrapKey) error {
	return m.m.Delete(key)
}

func (m *CrapMap) Lookup(key *CrapKey) (*CrapVal, error) {
	ret, err := m.m.Lookup(key)
	if err != nil {
		return nil, err
	}
	return ret.(*CrapVal), err
}

// CrapIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an crap bpf map.
type CrapIterateCallback func(*CrapKey, *CrapVal)

// IterateWithCallback iterates through all the keys/values of crap rules
// map, passing each key/value pair to the cb callback.
func (m *CrapMap) IterateWithCallback(cb CrapIterateCallback) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*CrapKey)
		value := v.(*CrapVal)

		cb(key, value)
	})
}

func (k *CrapKey) Match(dst_ip netip.Addr) bool {
	nkey := NewKey(dst_ip)
	return nkey == *k
}

func (v *CrapVal) Match(podIP netip.Addr) bool {
	nval := NewVal(podIP)
	return nval == *v
}
