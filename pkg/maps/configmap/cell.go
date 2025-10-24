// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configmap

import (
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

func newMap(lifecycle cell.Lifecycle, specReg *registry.MapSpecRegistry) bpf.MapOut[Map] {
	configMap := &configMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			spec, err := specReg.Get(MapName)
			if err != nil {
				return nil
			}

			var index Index
			var value Value

			configMap.bpfMap = bpf.NewMap(spec, &index, &value)

			return configMap.bpfMap.OpenOrCreate()
		},
		OnStop: func(stopCtx cell.HookContext) error {
			return configMap.bpfMap.Close()
		},
	})

	return bpf.NewMapOut(Map(configMap))
}
