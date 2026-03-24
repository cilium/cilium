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
	bandwidth "github.com/cilium/cilium/pkg/datapath/linux/bandwidth/types"
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
		configure,
		start,
		bpf.MaybeTablePressureMetrics[Edt, *throttleMap],
	),
)

// provide provides a throttleMap to the Hive and configures its MapSpec in the
// MapRegistry.
func provide(lc cell.Lifecycle, reg *registry.MapRegistry, log *slog.Logger,
	cfg bandwidth.Config, edts statedb.RWTable[Edt], params reconciler.Params) (
	out bpf.MaybeMapOut[*throttleMap], err error) {
	if !cfg.EnableBandwidthManager {
		// Remove map pin if the map is disabled.
		bpf.Remove(bpf.MapPath(log, MapName))

		return bpf.NoneMap[*throttleMap](), nil
	}

	return bpf.SomeMap(&throttleMap{}), nil
}

// configure configures the MapSpec for the throttle map in the MapRegistry.
// Must be executed regardless of the map being enabled or not.
func configure(reg *registry.MapRegistry) error {
	return reg.Modify(MapName, func(m *registry.MapSpecPatch) {
		m.MaxEntries = uint32(MapSize)
	})
}

// start opens the bandwidth map and schedules the reconciler if the map has
// been enabled.
//
// The map registry can only be read from an OnStart hook, so open the map and
// start the reconciler together.
func start(lc cell.Lifecycle, reg *registry.MapRegistry,
	mi bpf.MaybeMap[*throttleMap], edts statedb.RWTable[Edt], params reconciler.Params) {
	tm, ok := mi.Get()
	if !ok {
		return
	}

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) (err error) {
			m, err := bpf.NewMapFromRegistry(reg, MapName, &EdtId{}, &EdtInfo{})
			if err != nil {
				return fmt.Errorf("create bandwidth map: %w", err)
			}

			if err := startReconciler(m, edts, params); err != nil {
				return fmt.Errorf("start bandwidth map reconciler: %w", err)
			}

			if err := m.OpenOrCreate(); err != nil {
				return fmt.Errorf("open bandwidth map: %w", err)
			}

			tm.m = m

			return nil
		},
		OnStop: func(cell.HookContext) error {
			return tm.m.Close()
		},
	})
}

// startReconciler starts the reconciler for the bandwidth map.
func startReconciler(m *bpf.Map, edts statedb.RWTable[Edt], params reconciler.Params) error {
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
