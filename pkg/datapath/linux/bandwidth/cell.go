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
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"bandwidth-manager",
	"Linux Bandwidth Manager for EDT-based pacing",

	cell.Config(types.DefaultBandwidthConfig),
	cell.Provide(newBandwidthManager),

	cell.ProvidePrivate(
		tables.NewBandwidthQDiscTable, // RWTable[*BandwidthQDisc]
		newReconcilerConfig,           // reconciler.Config[*BandwidthQDisc]
	),
	cell.Invoke(registerReconciler),
)

func newReconcilerConfig(log *slog.Logger, tbl statedb.RWTable[*tables.BandwidthQDisc], bwm types.BandwidthManager) reconciler.Config[*tables.BandwidthQDisc] {
	return reconciler.Config[*tables.BandwidthQDisc]{
		Table:                     tbl,
		FullReconcilationInterval: 10 * time.Minute,
		RetryBackoffMinDuration:   time.Second,
		RetryBackoffMaxDuration:   time.Minute,
		IncrementalRoundSize:      1000,
		GetObjectStatus:           (*tables.BandwidthQDisc).GetStatus,
		SetObjectStatus:           (*tables.BandwidthQDisc).SetStatus,
		CloneObject:               (*tables.BandwidthQDisc).Clone,
		Operations:                newOps(log, bwm),
	}
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

func registerReconciler(
	cfg types.BandwidthConfig,
	deriveParams statedb.DeriveParams[*tables.Device, *tables.BandwidthQDisc],
	config reconciler.Config[*tables.BandwidthQDisc],
	reconcilerParams reconciler.Params,
) error {
	if !cfg.EnableBandwidthManager {
		return nil
	}

	// Start deriving Table[*BandwidthQDisc] from Table[*Device]
	statedb.Derive("derive-desired-qdiscs", deviceToBandwidthQDisc)(
		deriveParams,
	)

	// Create and register a reconciler for 'Table[*BandwidthQDisc]' that
	// reconciles using '*ops'.
	return reconciler.Register(config, reconcilerParams)
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
