// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the lxc.Map which contains the local endpoints.
var Cell = cell.Module(
	"lxc-map",
	"eBPF map which manages all local endpoints",

	cell.Provide(newLXCMap),
	cell.Invoke(configure),
)

func newLXCMap(
	lifecycle cell.Lifecycle,
	metrics *metrics.Registry,
	reg *mapregistry.MapRegistry,
) bpf.MapOut[Map] {
	lxcMap := &lxcMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			var err error
			lxcMap.bpfMap, err = bpf.NewMapFromRegistry(reg, mapName, &EndpointKey{}, &EndpointInfo{})
			if err != nil {
				return fmt.Errorf("create LXC map from registry: %w", err)
			}
			lxcMap.bpfMap.WithCache().WithPressureMetric(metrics).
				WithEvents(option.Config.GetEventBufferConfig(mapName))

			if err := lxcMap.init(); err != nil {
				return fmt.Errorf("failed to init lxc map: %w", err)
			}

			if !option.Config.RestoreState {
				// If we are not restoring state, all endpoints can be
				// deleted. Entries will be re-populated.
				if err := lxcMap.bpfMap.DeleteAll(); err != nil {
					return fmt.Errorf("failed to delete all entries in lxc map: %w", err)
				}
			}

			return nil
		},
		OnStop: func(context cell.HookContext) error {
			return lxcMap.close()
		},
	})

	return bpf.NewMapOut(Map(lxcMap))
}

func configure(reg *mapregistry.MapRegistry) error {
	flags := uint32(unix.BPF_F_RDONLY_PROG)
	if !option.Config.PreAllocateMaps {
		flags |= unix.BPF_F_NO_PREALLOC
	}

	return reg.Modify(mapName, func(m *mapregistry.MapSpecPatch) {
		m.Flags = flags
		m.MaxEntries = uint32(MaxEntries)
	})
}
