// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configmap

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
)

// Cell initializes and manages the config map.
var Cell = cell.Module(
	"config-map",
	"eBPF map config contains runtime configuration state for the Cilium datapath",

	cell.Provide(provide),
)

func provide(lifecycle cell.Lifecycle, reg *registry.MapRegistry) bpf.MapOut[Map] {
	configMap := &configMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) (err error) {
			var index Index
			var value Value
			configMap.m, err = bpf.NewMapFromRegistry(reg, MapName, &index, &value)
			if err != nil {
				return fmt.Errorf("create config map: %w", err)
			}

			return configMap.m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return configMap.m.Close()
		},
	})

	return bpf.NewMapOut(Map(configMap))
}
