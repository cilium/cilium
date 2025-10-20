// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/registry"
)

// Cell manages the cilium_throttle BPF map for implementing per-endpoint
// bandwidth management. The cell provides RWTable[Edt] to which per
// endpoint bandwidth limits can be inserted. Use [NewEdt] to create the
// object. The table can be inspected with "cilium-dbg shell -- db/show bandwidth-edts".
// A reconciler is registered that reconciles the table with the cilium_throttle
// map.
var Cell = cell.Module(
	"bwmap",
	"Manages the endpoint bandwidth limit BPF map",

	cell.Provide(
		NewEdtTable,
		statedb.RWTable[Edt].ToTable,
		provide,
	),
	cell.Invoke(
		bpf.RegisterTablePressureMetricsJob[Edt, *throttleMap],
	),
)

// provide provides a throttleMap to the Hive and configures its MapSpec in the
// MapRegistry.
func provide(lc cell.Lifecycle, reg *registry.MapRegistry, log *slog.Logger,
	cfg types.BandwidthConfig, edts statedb.RWTable[Edt], params reconciler.Params) (out bpf.MapOut[*throttleMap], err error) {
	if err := reg.Modify(MapName, func(m *registry.MapSpecPatch) {
		m.MaxEntries = uint32(MapSize)
	}); err != nil {
		return bpf.MapOut[*throttleMap]{}, err
	}

	if !cfg.EnableBandwidthManager {
		// Remove map pin if the map is disabled.
		bpf.Remove(bpf.MapPath(log, MapName))

		return bpf.MapOut[*throttleMap]{}, nil
	}

	tm := &throttleMap{}
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) (err error) {
			tm.m, err = bpf.NewMapFromRegistry(reg, MapName, &EdtId{}, &EdtInfo{})
			if err != nil {
				return fmt.Errorf("create bandwidth map: %w", err)
			}

			registerReconciler(tm.m, edts, params)

			return tm.m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return tm.m.Close()
		},
	})

	return bpf.NewMapOut(tm), nil
}

// registerReconciler registers the reconciler for the bandwidth map.
func registerReconciler(m *bpf.Map, edts statedb.RWTable[Edt], params reconciler.Params) error {
	ops := bpf.NewMapOps[Edt](m)
	if _, err := reconciler.Register(
		params,
		edts,
		func(e Edt) Edt { return e },
		func(e Edt, s reconciler.Status) Edt {
			e.Status = s
			return e
		},
		func(e Edt) reconciler.Status {
			return e.Status
		},
		ops,
		nil,
	); err != nil {
		return fmt.Errorf("registering bandwidth edt reconciler: %w", err)
	}

	return nil
}
