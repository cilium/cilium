// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell provides the nodemap.Map which contains information about node IDs and their IP addresses.
var Cell = cell.Module(
	"node-map",
	"eBPF map which contains information about node IDs and their IP addresses",

	cell.Provide(newNodeMap),
)

func newNodeMap(lifecycle hive.Lifecycle) bpf.MapOut[Map] {
	nodeMap := newMap()

	lifecycle.Append(hive.Hook{
		OnStart: func(context hive.HookContext) error {
			return nodeMap.init()
		},
		OnStop: func(context hive.HookContext) error {
			return nodeMap.close()
		},
	})

	return bpf.NewMapOut(Map(nodeMap))
}
