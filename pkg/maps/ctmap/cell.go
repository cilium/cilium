// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"fmt"
	"slices"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the ctmap.Map which contains the connection tracking state.
var Cell = cell.Module(
	"ct-map",
	"eBPF map which manages connection tracking",

	cell.Provide(newCTMaps),
)

func newCTMaps(lifecycle cell.Lifecycle, daemonConfig *option.DaemonConfig, registry *metrics.Registry, natMap4 nat.NatMap4, natMap6 nat.NatMap6) bpf.MapOut[CTMaps] {
	InitMapInfo(natMap4, natMap6)

	ctMaps := &ctMaps{}

	if daemonConfig.IPv4Enabled() {
		ctMaps.v4AnyMap = newMap(MapNameAny4Global, mapTypeIPv4AnyGlobal, WithRegistry(registry))
		ctMaps.v4TCPMap = newMap(MapNameTCP4Global, mapTypeIPv4TCPGlobal, WithRegistry(registry))
	}

	if daemonConfig.IPv6Enabled() {
		ctMaps.v6AnyMap = newMap(MapNameAny6Global, mapTypeIPv6AnyGlobal, WithRegistry(registry))
		ctMaps.v6TCPMap = newMap(MapNameTCP6Global, mapTypeIPv6TCPGlobal, WithRegistry(registry))
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return ctMaps.init()
		},
		OnStop: func(context cell.HookContext) error {
			return ctMaps.close()
		},
	})

	return bpf.NewMapOut(CTMaps(ctMaps))
}

// CTMaps provides access to the active connection tracking BPF maps.
type CTMaps interface {
	// ActiveMaps returns a slice of global CT maps that are used, depending
	// on whether IPv4 and/or IPv6 is configured.
	ActiveMaps() []*Map
}

type ctMaps struct {
	v4AnyMap *Map
	v4TCPMap *Map
	v6AnyMap *Map
	v6TCPMap *Map
}

var _ CTMaps = (*ctMaps)(nil)

func (r *ctMaps) ActiveMaps() []*Map {
	return slices.DeleteFunc([]*Map{r.v4AnyMap, r.v4TCPMap, r.v6AnyMap, r.v6TCPMap}, func(m *Map) bool { return m == nil })
}

func (r *ctMaps) init() error {
	for _, m := range r.ActiveMaps() {
		if err := m.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open and create %s map: %w", m.Name(), err)
		}
	}

	return nil
}

func (r *ctMaps) close() error {
	for _, m := range r.ActiveMaps() {
		if err := m.Close(); err != nil {
			return fmt.Errorf("failed to close %s map: %w", m.Name(), err)
		}
	}

	return nil
}
