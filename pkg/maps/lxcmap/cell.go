// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the lxc.Map which contains the local endpoints.
var Cell = cell.Module(
	"lxc-map",
	"eBPF map which manages all local endpoints",

	cell.Provide(newLXCMap),
)

func newLXCMap(lifecycle cell.Lifecycle, registry *metrics.Registry) bpf.MapOut[Map] {
	lxcMap := newMap(registry)

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
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
