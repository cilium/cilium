// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ibwmap

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
)

// Cell manages the cilium_ingress_throttle BPF map for implementing per-endpoint
// bandwidth management. The cell provides RWTable[Throttle] to which per
// endpoint bandwidth limits can be inserted. Use [NewIngressThrottle] to create the
// object. The table can be inspected with "cilium-dbg statedb bandwidth-ingress".
// A reconciler is registered that reconciles the table with the cilium_ingress_throttle
// map.
var Cell = cell.Module(
	"ibwmap",
	"Manages the endpoint bandwidth limit BPF map",

	cell.Provide(
		NewIngressThrottleTable,
		statedb.RWTable[Throttle].ToTable,
		newThrottleMap,
	),
	cell.Invoke(
		statedb.RegisterTable[Throttle],
		registerReconciler,
		bpf.RegisterTablePressureMetricsJob[Throttle, throttleMap],
	),
)

func registerReconciler(cfg types.BandwidthConfig, m throttleMap, edts statedb.RWTable[Throttle], params reconciler.Params) error {
	if cfg.EnableBandwidthManager {
		ops := bpf.NewMapOps[Throttle](m.Map)
		_, err := reconciler.Register(
			params,
			edts,
			func(e Throttle) Throttle { return e },
			func(e Throttle, s reconciler.Status) Throttle {
				e.Status = s
				return e
			},
			func(e Throttle) reconciler.Status {
				return e.Status
			},
			ops,
			nil,
		)
		return err
	}
	return nil
}
