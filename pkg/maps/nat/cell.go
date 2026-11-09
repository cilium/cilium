// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/kpr"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
)

// Cell exposes global nat maps via Hive.
var Cell = cell.Module(
	"nat-maps",
	"NAT Maps",
	cell.Provide(provideGlobalNATMaps),
	cell.Invoke(configureGlobalNATMaps),
	cell.Provide(provideNATRetriesMap),
)

// NatMap4 describes ipv4 nat map behaviors, used for providing map
// to hive.
type NatMap4 interface {
	NatMap
	DumpBatch4(func(*tuple.TupleKey4, *NatEntry4)) (count int, err error)
}

// NatMap6 describes ipv6 nat map behaviors, used for providing map
// to hive.
type NatMap6 interface {
	NatMap
	DumpBatch6(func(*tuple.TupleKey6, *NatEntry6)) (count int, err error)
}

func provideGlobalNATMaps(lc cell.Lifecycle, mapRegistry *mapregistry.MapRegistry,
	metricsRegistry *metrics.Registry, cfg *option.DaemonConfig,
	kprCfg kpr.KPRConfig) (bpf.MapOut[NatMap4], bpf.MapOut[NatMap6]) {
	var out4 bpf.MapOut[NatMap4]
	var out6 bpf.MapOut[NatMap6]
	ipv4NatMap := &Map{family: IPv4}
	ipv6NatMap := &Map{family: IPv6}

	if !kprCfg.KubeProxyReplacement && !cfg.EnableBPFMasquerade {
		return out4, out6
	}

	if cfg.EnableIPv4 {
		out4 = bpf.NewMapOut[NatMap4](ipv4NatMap)
	}
	if cfg.EnableIPv6 {
		out6 = bpf.NewMapOut[NatMap6](ipv6NatMap)
	}

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			var err error
			if cfg.EnableIPv4 {
				if ipv4NatMap.Map, err = bpf.NewMapFromRegistry(mapRegistry, MapNameSnat4Global,
					&NatKey4{}, &NatEntry4{}); err != nil {
					return fmt.Errorf("create IPv4 nat map from registry: %w", err)
				}
				ipv4NatMap.Map.WithCache().
					WithEvents(cfg.GetEventBufferConfig(MapNameSnat4Global)).
					WithPressureMetric(metricsRegistry)
				if err := ipv4NatMap.OpenOrCreate(); err != nil {
					return fmt.Errorf("open IPv4 nat map: %w", err)
				}
			}
			if cfg.EnableIPv6 {
				if ipv6NatMap.Map, err = bpf.NewMapFromRegistry(mapRegistry, MapNameSnat6Global,
					&NatKey6{}, &NatEntry6{}); err != nil {
					return fmt.Errorf("create IPv6 nat map from registry: %w", err)
				}
				ipv6NatMap.Map.WithCache().
					WithEvents(cfg.GetEventBufferConfig(MapNameSnat6Global)).
					WithPressureMetric(metricsRegistry)
				if err := ipv6NatMap.OpenOrCreate(); err != nil {
					return fmt.Errorf("open IPv6 nat map: %w", err)
				}
			}
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			if m := ipv4NatMap.Map; m != nil {
				if err := m.Close(); err != nil {
					return err
				}
			}
			if m := ipv6NatMap.Map; m != nil {
				if err := m.Close(); err != nil {
					return err
				}
			}
			return nil
		},
	})

	return out4, out6
}

func configureGlobalNATMaps(reg *mapregistry.MapRegistry) error {
	var flags uint32
	if option.Config.BPFDistributedLRU {
		flags |= unix.BPF_F_NO_COMMON_LRU
	}
	maxEntries := uint32(maxEntries())
	if err := configureNATMap(reg, MapNameSnat4Global, flags, maxEntries); err != nil {
		return err
	}
	if err := configureNATMap(reg, MapNameSnat6Global, flags, maxEntries); err != nil {
		return err
	}
	if err := configurePerClusterNATMap(reg, perClusterIPv4OuterMap, flags,
		maxEntries); err != nil {
		return err
	}
	if err := configurePerClusterNATMap(reg, perClusterIPv6OuterMap, flags,
		maxEntries); err != nil {
		return err
	}
	return nil
}

func configureNATMap(reg *mapregistry.MapRegistry, mapName string, flags, maxEntries uint32) error {
	if err := reg.Modify(mapName, func(patch *mapregistry.MapSpecPatch) {
		patch.Flags = flags
		patch.MaxEntries = maxEntries
	}); err != nil {
		return fmt.Errorf("error setting %s map flags and max entries: %w", mapName, err)
	}
	return nil
}

func configurePerClusterNATMap(reg *mapregistry.MapRegistry, mapName string, innerFlags,
	innerMaxEntries uint32) error {
	if err := reg.Modify(mapName, func(patch *mapregistry.MapSpecPatch) {
		patch.InnerMap.Flags = innerFlags
		patch.InnerMap.MaxEntries = innerMaxEntries
	}); err != nil {
		return fmt.Errorf("error setting %s inner map flags and max entries: %w", mapName,
			err)
	}
	return nil
}

// NATRetriesMap is a marker interface for the NAT retries map.
// It doesn't provide any functionality to the Cilium Agent because
// the bpf map is only created by the Cilium Agent for the datapath.
// It's still provided to be picked up as dependency by the Loader
// and initialized at startup.
type NATRetriesMap any

func provideNATRetriesMap(lifecycle cell.Lifecycle, daemonConfig *option.DaemonConfig, kprConfig kpr.KPRConfig) bpf.MapOut[NATRetriesMap] {
	if !kprConfig.KubeProxyReplacement && !option.Config.EnableBPFMasquerade {
		return bpf.NewMapOut(NATRetriesMap(nil))
	}

	natRetriesMap := newNATRetriesMap(daemonConfig.IPv4Enabled(), daemonConfig.IPv6Enabled())

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return natRetriesMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			// no need to close because the maps are only created for datapath (Create)
			return nil
		},
	})

	return bpf.NewMapOut(NATRetriesMap(natRetriesMap))
}
