// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighborsmap

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the neighborsmap.Map that stores IP to mac address
// mappings for NodePort clients. It is primarily managed from the
// datapath; Cilium side is used to create the map only.
var Cell = cell.Module(
	"neighbors-map",
	"Initializes neighbors bpf map",

	// Provided to init at startup (The Loader depends on all maps via bpf.Mapout)
	cell.Provide(newNeighborsMap),
)

func newNeighborsMap(lifecycle cell.Lifecycle, daemonConfig *option.DaemonConfig, kprConfig kpr.KPRConfig) bpf.MapOut[Map] {
	if !kprConfig.KubeProxyReplacement {
		return bpf.NewMapOut(Map(nil))
	}

	neighborsMap := newMap(daemonConfig.NeighMapEntriesGlobal, daemonConfig.IPv4Enabled(), daemonConfig.IPv6Enabled())

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return neighborsMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			// no need to close because the maps are only created for datapath (Create)
			return nil
		},
	})

	return bpf.NewMapOut(Map(neighborsMap))
}
