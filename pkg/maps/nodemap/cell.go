// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell provides the nodemap.Map which contains information about node IDs and their IP addresses.
var Cell = cell.Module(
	"node-map",
	"eBPF map which contains information about node IDs and their IP addresses",

	cell.Provide(newNodeMap),
)

func newNodeMap(lifecycle cell.Lifecycle) bpf.MapOut[Map] {
	nodeMap := newMap(MapName)

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return nodeMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			return nodeMap.close()
		},
	})

	return bpf.NewMapOut(Map(nodeMap))
}
