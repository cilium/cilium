// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/time"
)

// Cell manages the cilium_throttle BPF map for implementing per-endpoint
// bandwidth management. The cell provides RWTable[Edt] to which per
// endpoint bandwidth limits can be inserted. Use [NewEdt] to create the
// object. The table can be inspected with "cilium-dbg statedb bandwidth-edts".
// A reconciler is registered that reconciles the table with the cilium_throttle
// map.
var Cell = cell.Module(
	"bwmap",
	"Manages the endpoint bandwidth limit BPF map",

	cell.Provide(
		NewEdtTable,
		statedb.RWTable[Edt].ToTable,
		newThrottleMap,
	),
	cell.ProvidePrivate(
		edtReconcilerConfig,
	),
	cell.Invoke(
		statedb.RegisterTable[Edt],
		registerReconciler,
		bpf.RegisterTablePressureMetricsJob[Edt, throttleMap],
	),
)

func registerReconciler(cfg types.BandwidthConfig, rcfg reconciler.Config[Edt], params reconciler.Params) error {
	if cfg.EnableBandwidthManager {
		return reconciler.Register(rcfg, params)
	}
	return nil
}

func edtReconcilerConfig(m throttleMap, edts statedb.RWTable[Edt]) reconciler.Config[Edt] {
	ops := bpf.NewMapOps[Edt](m.Map)

	return reconciler.Config[Edt]{
		Table:                     edts,
		FullReconcilationInterval: time.Hour,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   time.Minute,
		IncrementalRoundSize:      100,
		GetObjectStatus: func(e Edt) reconciler.Status {
			return e.Status
		},
		SetObjectStatus: func(e Edt, s reconciler.Status) Edt {
			e.Status = s
			return e
		},
		CloneObject:     func(e Edt) Edt { return e },
		RateLimiter:     nil,
		Operations:      ops,
		BatchOperations: nil,
	}
}
