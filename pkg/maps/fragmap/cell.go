// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
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
)

func newFragMap(lifecycle cell.Lifecycle, registry *metrics.Registry, daemonConfig *option.DaemonConfig) bpf.MapOut[Map] {
	fragMap := newMap(registry, daemonConfig.FragmentsMapEntries, daemonConfig.GetEventBufferConfig)

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return fragMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			// no need to close because the maps are only created for datapath (Create)
			return nil
		},
	})

	return bpf.NewMapOut(Map(fragMap))
}
