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

// Cell manages the cilium_subnet_map BPF map for implementing subnet-based
// identity routing in hybrid mode.
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
		params.Log.Info("Routing mode is not hybrid, skipping subnet map reconciler registration")
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
		func(s SubnetTableEntry) SubnetTableEntry { return s }, // Clone function.
		func(s SubnetTableEntry, status reconciler.Status) SubnetTableEntry { // Set status function.
			s.Status = status
			return s
		},
		func(s SubnetTableEntry) reconciler.Status { // Get status function.
			return s.Status
		},
		ops, // Reconciliation operations.
		nil, // No batch ops defined.
	)
	params.Log.Info("Registered reconciler")
	return err
}
