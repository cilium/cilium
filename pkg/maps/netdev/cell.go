// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netdev

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
)

// Cell initializes and manages the network devices map.
var Cell = cell.Module(
	"netdev-map",
	"eBPF map contains information about network devices for Cilium datapath",

	cell.Provide(newMap),

	// Synchronizes selected network devices into the cilium_devices BPF map.
	NetDevMapSyncCell,
)

func newMap(lifecycle cell.Lifecycle) bpf.MapOut[Map] {
	netDevMap := newNetDevMap()

	lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			return netDevMap.init()
		},
		OnStop: func(stopCtx cell.HookContext) error {
			return netDevMap.close()
		},
	})

	return bpf.NewMapOut(Map(netDevMap))
}
