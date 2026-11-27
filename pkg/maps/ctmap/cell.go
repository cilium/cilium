// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/nat"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

const conntrackScrubBPFIteratorName = "conntrack-scrub-bpf-iterator"

// Config contains configuration for the connection tracking BPF maps.
type Config struct {
	ConntrackScrubBPFIterator bool `mapstructure:"conntrack-scrub-bpf-iterator"`
}

// Flags registers the CLI and ConfigMap flags for [Config].
func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(conntrackScrubBPFIteratorName, def.ConntrackScrubBPFIterator,
		"Enable in-kernel eBPF map iterator for IPv4 endpoint connection tracking scrubbing")
	_ = flags.MarkHidden(conntrackScrubBPFIteratorName)
}

var defaultConfig = Config{
	ConntrackScrubBPFIterator: true,
}

// Cell provides the ctmap.Map which contains the connection tracking state.
var Cell = cell.Module(
	"ct-map",
	"eBPF map which manages connection tracking",

	cell.Config(defaultConfig),
	cell.Provide(newCTMaps),
	cell.Invoke(configure),
)

func newCTMapFromRegistry(
	reg *mapregistry.MapRegistry,
	mapName string,
	m mapType,
	metrics *metrics.Registry,
	opts ...MapOption,
) (*Map, error) {
	bpfMap, err := bpf.NewMapFromRegistry(reg, mapName, m.key(), m.value())
	if err != nil {
		return nil, fmt.Errorf("create CT map %s from registry: %w", mapName, err)
	}
	bpfMap.WithPressureMetric(metrics)

	result := &Map{Map: bpfMap, mapType: m}
	for _, opt := range opts {
		opt(result)
	}
	return result, nil
}

func newCTMaps(
	logger *slog.Logger,
	lifecycle cell.Lifecycle,
	cfg Config,
	daemonConfig *option.DaemonConfig,
	metrics *metrics.Registry,
	reg *mapregistry.MapRegistry,
	natMap4 nat.NatMap4,
	natMap6 nat.NatMap6,
) bpf.MapOut[CTMaps] {
	InitMapInfo(natMap4, natMap6)

	ctMaps := &ctMaps{}
	if daemonConfig.IPv4Enabled() && cfg.ConntrackScrubBPFIterator {
		ctMaps.ctIter = newCTIterator(logger)
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			if daemonConfig.IPv4Enabled() {
				var err error
				ctMaps.v4AnyMap, err = newCTMapFromRegistry(reg, maps.CiliumCTAny4Global, mapTypeIPv4AnyGlobal, metrics, withCTIterator(ctMaps.ctIter))
				if err != nil {
					return err
				}
				ctMaps.v4TCPMap, err = newCTMapFromRegistry(reg, maps.CiliumCT4Global, mapTypeIPv4TCPGlobal, metrics, withCTIterator(ctMaps.ctIter))
				if err != nil {
					return err
				}
			}

			if daemonConfig.IPv6Enabled() {
				var err error
				ctMaps.v6AnyMap, err = newCTMapFromRegistry(reg, maps.CiliumCTAny6Global, mapTypeIPv6AnyGlobal, metrics)
				if err != nil {
					return err
				}
				ctMaps.v6TCPMap, err = newCTMapFromRegistry(reg, maps.CiliumCT6Global, mapTypeIPv6TCPGlobal, metrics)
				if err != nil {
					return err
				}
			}
			return ctMaps.init()
		},
		OnStop: func(context cell.HookContext) error {
			return ctMaps.close()
		},
	})

	return bpf.NewMapOut(CTMaps(ctMaps))
}

func configure(daemonConfig *option.DaemonConfig, reg *mapregistry.MapRegistry) error {
	tcpMapSize := option.CTMapEntriesGlobalTCPDefault
	if daemonConfig.CTMapEntriesGlobalTCP != 0 {
		tcpMapSize = daemonConfig.CTMapEntriesGlobalTCP
	}
	anyMapSize := option.CTMapEntriesGlobalAnyDefault
	if daemonConfig.CTMapEntriesGlobalAny != 0 {
		anyMapSize = daemonConfig.CTMapEntriesGlobalAny
	}

	for _, patch := range []struct {
		name       string
		maxEntries int
	}{
		{name: maps.CiliumCTAny4Global, maxEntries: anyMapSize},
		{name: maps.CiliumCTAny6Global, maxEntries: anyMapSize},
		{name: maps.CiliumCT4Global, maxEntries: tcpMapSize},
		{name: maps.CiliumCT6Global, maxEntries: tcpMapSize},
	} {
		if err := reg.Modify(patch.name, func(m *mapregistry.MapSpecPatch) {
			m.MaxEntries = uint32(patch.maxEntries)
			m.Flags = bpf.GetMapMemoryFlags(ebpf.LRUHash)
		}); err != nil {
			return fmt.Errorf("configure %s inner map: %w", patch.name, err)
		}
	}
	return nil
}

// CTMaps provides access to the active connection tracking BPF maps.
type CTMaps interface {
	// ActiveMaps returns a slice of global CT maps that are used, depending
	// on whether IPv4 and/or IPv6 is configured.
	ActiveMaps() []*Map
}

type ctMaps struct {
	ctIter   *ctIterator
	v4AnyMap *Map
	v4TCPMap *Map
	v6AnyMap *Map
	v6TCPMap *Map
}

var _ CTMaps = (*ctMaps)(nil)

func (r *ctMaps) ActiveMaps() []*Map {
	return slices.DeleteFunc([]*Map{r.v4TCPMap, r.v4AnyMap, r.v6TCPMap, r.v6AnyMap}, func(m *Map) bool { return m == nil })
}

func (r *ctMaps) init() error {
	for _, m := range r.ActiveMaps() {
		if err := m.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open and create %s map: %w", m.Name(), err)
		}
	}
	if r.ctIter != nil {
		// Iterator unavailability logs and falls back to batch scrub; never fail agent startup.
		_ = r.ctIter.init()
	}

	return nil
}

func (r *ctMaps) close() error {
	var errs []error
	// Close the iterator before closing maps so any in-flight iterator scan
	// drains while maps are still open, avoiding ErrMapNotOpened and breaker
	// trips during shutdown.
	if r.ctIter != nil {
		if err := r.ctIter.close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close CT iterator: %w", err))
		}
	}
	for _, m := range r.ActiveMaps() {
		if err := m.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close %s map: %w", m.Name(), err))
		}
	}

	return errors.Join(errs...)
}
