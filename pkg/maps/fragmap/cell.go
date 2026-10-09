// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the fragmap.Map used to associate datagram
// fragments to the L4 ports of the datagram they belong to, in order to
// retrieve the full 5-tuple necessary to do L4-based lookups.
var Cell = cell.Module(
	"fragments-map",
	"Initializes fragments bpf map",

	// Provided to init at startup (The Loader depends on all maps via bpf.Mapout)
	cell.Provide(newFragMap),
	cell.Invoke(configure),
)

func configure(reg *registry.MapRegistry, daemonConfig *option.DaemonConfig) error {
	if err := reg.Modify(mapNameIPv4, func(m *registry.MapSpecPatch) {
		m.MaxEntries = uint32(daemonConfig.FragmentsMapEntries)
	}); err != nil {
		return fmt.Errorf("configure %s: %w", mapNameIPv4, err)
	}

	if err := reg.Modify(mapNameIPv6, func(m *registry.MapSpecPatch) {
		m.MaxEntries = uint32(daemonConfig.FragmentsMapEntries)
	}); err != nil {
		return fmt.Errorf("configure %s: %w", mapNameIPv6, err)
	}

	return nil
}

func newFragMap(lifecycle cell.Lifecycle, reg *registry.MapRegistry, metricsReg *metrics.Registry, daemonConfig *option.DaemonConfig) bpf.MapOut[Map] {
	fragMap := &fragMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return fragMap.init(reg, metricsReg, daemonConfig.GetEventBufferConfig)
		},
		OnStop: func(cell.HookContext) error {
			// no need to close because the maps are only created for datapath (Create)
			return nil
		},
	})

	return bpf.NewMapOut(Map(fragMap))
}
