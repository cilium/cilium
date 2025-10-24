// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MapNameIPv4 is the name of the map used to retrieve L4 ports
	// associated to the datagram to which an IPv4 belongs.
	MapNameIPv4 = "cilium_ipv4_frag_datagrams"

	// MapNameIPv6 is the name of the map used to retrieve L4 ports
	// associated to the datagram to which an IPv6 belongs.
	MapNameIPv6 = "cilium_ipv6_frag_datagrams"
)

// FragmentKey4 must match 'struct ipv4_frag_id' in "bpf/lib/ipv4.h".
type FragmentKey4 struct {
	DestAddr   types.IPv4 `align:"daddr"`
	SourceAddr types.IPv4 `align:"saddr"`
	ID         uint16     `align:"id"`
	Proto      uint8      `align:"proto"`
	_          uint8
}

// FragmentValue4 must match 'struct ipv4_frag_l4ports' in "bpf/lib/ipv4.h".
type FragmentValue4 struct {
	SourcePort uint16 `align:"sport"`
	DestPort   uint16 `align:"dport"`
}

// String converts the key into a human-readable string format.
func (k *FragmentKey4) String() string {
	return fmt.Sprintf("%s --> %s, %d, %d", k.SourceAddr, k.DestAddr, k.Proto, k.NativeID())
}

func (k *FragmentKey4) New() bpf.MapKey { return &FragmentKey4{} }

func (k *FragmentKey4) NativeID() uint16 { return byteorder.NetworkToHost16(k.ID) }

// String converts the value into a human-readable string format.
func (v *FragmentValue4) String() string {
	return fmt.Sprintf("%d, %d", v.DestPort, v.SourcePort)
}

func (v *FragmentValue4) New() bpf.MapValue { return &FragmentValue4{} }

type FragMap4 struct {
	*bpf.Map
}

func NewFragMap4(
	lifecycle cell.Lifecycle,
	registry *metrics.Registry,
	mapSpecRegistry *registry.MapSpecRegistry,
	cfg *option.DaemonConfig,
) (bpf.MapOut[*FragMap4], error) {
	fragMap := &FragMap4{}

	mapSpecRegistry.ModifyMapSpec(MapNameIPv4, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(cfg.FragmentsMapEntries)
		return nil
	})

	if !cfg.EnableIPv4FragmentsTracking {
		return bpf.NewMapOut(fragMap), nil
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			spec, err := mapSpecRegistry.Get(MapNameIPv4)
			if err != nil {
				return fmt.Errorf("failed to get map spec for %s: %w", MapNameIPv4, err)
			}

			fragMap.Map = bpf.NewMap(spec,
				&FragmentKey4{},
				&FragmentValue4{}).
				WithEvents(cfg.GetEventBufferConfig(MapNameIPv4)).
				WithPressureMetric(registry)

			return fragMap.OpenOrCreate()
		},
		OnStop: func(hc cell.HookContext) error {
			return fragMap.Map.Close()
		},
	})

	return bpf.NewMapOut(fragMap), nil
}

// OpenMap4 opens the pre-initialized IPv4 fragments map for access.
func OpenMap4(logger *slog.Logger) (*bpf.Map, error) {
	return bpf.OpenMap(bpf.MapPath(logger, MapNameIPv4), &FragmentKey4{}, &FragmentValue4{})
}

// FragmentKey6 must match 'struct ipv6_frag_id' in "bpf/lib/ipv6.h".
type FragmentKey6 struct {
	ID         uint32     `align:"id"`
	Proto      uint8      `align:"proto"`
	_          [3]uint8   `align:"pad"`
	SourceAddr types.IPv6 `align:"saddr"`
	DestAddr   types.IPv6 `align:"daddr"`
}

// FragmentValue6 must match 'struct ipv6_frag_l4ports' in "bpf/lib/ipv4.h".
type FragmentValue6 struct {
	SourcePort uint16 `align:"sport"`
	DestPort   uint16 `align:"dport"`
}

// String converts the key into a human-readable string format.
func (k *FragmentKey6) String() string {
	return fmt.Sprintf("%s --> %s, %d, %d", k.SourceAddr, k.DestAddr, k.Proto, k.NativeID())
}

func (k *FragmentKey6) New() bpf.MapKey { return &FragmentKey6{} }

func (k *FragmentKey6) NativeID() uint32 { return byteorder.NetworkToHost32(k.ID) }

// String converts the value into a human-readable string format.
func (v *FragmentValue6) String() string {
	return fmt.Sprintf("%d, %d", v.DestPort, v.SourcePort)
}

func (v *FragmentValue6) New() bpf.MapValue { return &FragmentValue6{} }

type FragMap6 struct {
	*bpf.Map
}

func NewFragMap6(
	lifecycle cell.Lifecycle,
	registry *metrics.Registry,
	mapSpecRegistry *registry.MapSpecRegistry,
	cfg *option.DaemonConfig,
) (bpf.MapOut[*FragMap6], error) {
	fragMap := &FragMap6{}

	mapSpecRegistry.ModifyMapSpec(MapNameIPv6, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(cfg.FragmentsMapEntries)
		return nil
	})

	if !cfg.EnableIPv6FragmentsTracking {
		return bpf.NewMapOut(fragMap), nil
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			spec, err := mapSpecRegistry.Get(MapNameIPv6)
			if err != nil {
				return fmt.Errorf("failed to get map spec for %s: %w", MapNameIPv6, err)
			}

			fragMap.Map = bpf.NewMap(spec,
				&FragmentKey6{},
				&FragmentValue6{}).
				WithEvents(cfg.GetEventBufferConfig(MapNameIPv6)).
				WithPressureMetric(registry)

			return fragMap.OpenOrCreate()
		},
		OnStop: func(hc cell.HookContext) error {
			return fragMap.Map.Close()
		},
	})

	return bpf.NewMapOut(fragMap), nil
}

// OpenMap6 opens the pre-initialized IPv6 fragments map for access.
func OpenMap6(logger *slog.Logger) (*bpf.Map, error) {
	return bpf.OpenMap(bpf.MapPath(logger, MapNameIPv6), &FragmentKey6{}, &FragmentValue6{})
}
