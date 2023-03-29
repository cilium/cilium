// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configmap

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell initializes and manages the config map.
var Cell = cell.Module(
	"config-map",
	"eBPF map config contains runtime configuration state for the Cilium datapath",

	cell.Provide(newMap),
	cell.Invoke(func(Map) {}),
)

func newMap(lifecycle hive.Lifecycle) Map {
	configmap := newConfigMap()

	lifecycle.Append(hive.Hook{
		OnStart: func(startCtx hive.HookContext) error {
			return configmap.init()
		},
		OnStop: func(stopCtx hive.HookContext) error {
			return configmap.close()
		},
	})

	return configmap
}
