// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell manages subnet routing information for hybrid routing mode.
//
// This cell provides:
//   - A BPF map that stores subnet-to-identity mappings
//   - A StateDB table for tracking subnet configurations from users
//   - A reconciler that syncs the table to the BPF map
//
// The BPF map is used by the datapath to look up subnets and determine
// whether to use tunnel (encapsulation) or native (direct) routing for
// packets sent to those subnets. This enables different subnets to use
// different routing modes in the same cluster.
// The cell is only active when routing mode is set to hybrid.
var Cell = cell.Module(
	"subnet-map",
	"Manages the subnet to identity BPF map",

	cell.Provide(
		newSubnetMap,        // eBPF map
		newSubnetEntryTable, // StateDB table
		statedb.RWTable[SubnetTableEntry].ToTable,

		scriptCommands, // Script commands
	),
	cell.Invoke(
		registerReconciler,
		bpf.RegisterTablePressureMetricsJob[SubnetTableEntry, subnetMap],
	),
)

func registerReconciler(cfg *option.DaemonConfig, params reconciler.Params, st statedb.RWTable[SubnetTableEntry], m subnetMap) error {
	if cfg.RoutingMode != option.RoutingModeHybrid {
		params.Log.Debug("Routing mode is not hybrid, skipping subnet map reconciler registration")
		return nil
	}
	params.Log = params.Log.With(
		logfields.BPFMapName, MapName,
		logfields.Table, TableName,
	)

	ops := bpf.NewMapOps[SubnetTableEntry](m.Map)
	_, err := reconciler.Register(
		params,
		st,
		SubnetTableEntry.clone,
		SubnetTableEntry.setStatus,
		SubnetTableEntry.getStatus,
		ops, // Reconciliation operations.
		nil, // No batch ops defined.
	)
	params.Log.Info("Registered reconciler")
	return err
}
