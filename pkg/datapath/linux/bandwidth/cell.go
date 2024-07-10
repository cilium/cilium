// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// NOTE: We can only build on linux because we import bwmap which in turn imports pkg/ebpf and pkg/bpf
//       which throw build errors when building on non-linux platforms.

package bandwidth

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"bandwidth-manager",
	"Linux Bandwidth Manager for EDT-based pacing",

	cell.Config(types.DefaultBandwidthConfig),
	cell.Provide(newBandwidthManager),

	cell.ProvidePrivate(
		tables.NewBandwidthQDiscTable, // RWTable[*BandwidthQDisc]
	),
	cell.Invoke(registerReconciler),
)

type registerParams struct {
	cell.In

	Log              *slog.Logger
	Table            statedb.RWTable[*tables.BandwidthQDisc]
	BWM              types.BandwidthManager
	Config           types.BandwidthConfig
	DeriveParams     statedb.DeriveParams[*tables.Device, *tables.BandwidthQDisc]
	ReconcilerParams reconciler.Params
}

func registerReconciler(p registerParams) error {
	if !p.Config.EnableBandwidthManager {
		return nil
	}

	// Start deriving Table[*BandwidthQDisc] from Table[*Device]
	statedb.Derive("derive-desired-qdiscs", deviceToBandwidthQDisc)(
		p.DeriveParams,
	)

	_, err := reconciler.Register(
		p.ReconcilerParams,
		p.Table,

		(*tables.BandwidthQDisc).Clone,
		(*tables.BandwidthQDisc).SetStatus,
		(*tables.BandwidthQDisc).GetStatus,
		newOps(p.Log, p.BWM),
		nil,
	)
	return err
}

func newBandwidthManager(lc cell.Lifecycle, p bandwidthManagerParams) (types.BandwidthManager, defines.NodeFnOut) {
	m := &manager{params: p}

	if !option.Config.DryMode {
		lc.Append(m)
	}

	return m, defines.NewNodeFnOut(m.defines)
}

func (m *manager) Start(cell.HookContext) error {
	err := m.probe()
	if err != nil {
		return err
	} else if !m.enabled {
		return nil
	}

	return m.init()
}

func (*manager) Stop(cell.HookContext) error {
	return nil
}

type bandwidthManagerParams struct {
	cell.In

	Log          *slog.Logger
	Config       types.BandwidthConfig
	DaemonConfig *option.DaemonConfig
	Sysctl       sysctl.Sysctl
	DB           *statedb.DB
	EdtTable     statedb.RWTable[bwmap.Edt]
}

func deviceToBandwidthQDisc(device *tables.Device, deleted bool) (*tables.BandwidthQDisc, statedb.DeriveResult) {
	if deleted || !device.Selected {
		return &tables.BandwidthQDisc{
			LinkIndex: device.Index,
			LinkName:  device.Name,
		}, statedb.DeriveDelete
	}
	return &tables.BandwidthQDisc{
		LinkIndex: device.Index,
		LinkName:  device.Name,
		FqHorizon: FqDefaultHorizon,
		FqBuckets: FqDefaultBuckets,
		Status:    reconciler.StatusPending(),
	}, statedb.DeriveInsert
}
