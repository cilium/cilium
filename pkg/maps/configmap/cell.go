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

	cell.Provide(newMap),
)

func newMap(lifecycle cell.Lifecycle, reg *registry.MapRegistry) bpf.MapOut[Map] {
	configMap := &configMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			var (
				index Index
				value Value
			)

			spec, err := reg.Get(MapName)
			if err != nil {
				return fmt.Errorf("getting MapSpec: %w", err)
			}
			configMap.bpfMap = bpf.NewMapFromSpec(spec, &index, &value)

			return configMap.bpfMap.OpenOrCreate()
		},
		OnStop: func(stopCtx cell.HookContext) error {
			return configMap.bpfMap.Close()
		},
	})

	return bpf.NewMapOut(Map(configMap))
}
