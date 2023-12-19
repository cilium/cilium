// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// NOTE: We can only build on linux because we import bwmap which in turn imports pkg/ebpf and pkg/bpf
//       which throw build errors when building on non-linux platforms.

package bandwidth

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"bandwidth-manager",
	"Linux Bandwidth Manager for EDT-based pacing",

	cell.Config(Config{false, false}),
	cell.Provide(newBandwidthManager),

	cell.ProvidePrivate(
		tables.NewBandwidthQDiscTable, // RWTable[*BandwidthQDisc]
		newReconcilerConfig,           // reconciler.Config[*BandwidthQDisc]
	),
	cell.Invoke(registerReconciler),
)

type Config struct {
	// EnableBandwidthManager enables EDT-based pacing
	EnableBandwidthManager bool

	// EnableBBR enables BBR TCP congestion control for the node including Pods
	EnableBBR bool
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-bandwidth-manager", def.EnableBandwidthManager, "Enable BPF bandwidth manager")
	flags.Bool(EnableBBR, def.EnableBBR, "Enable BBR for the bandwidth manager")
}

func newReconcilerConfig(log logrus.FieldLogger, bwm types.BandwidthManager) reconciler.Config[*tables.BandwidthQDisc] {
	return reconciler.Config[*tables.BandwidthQDisc]{
		FullReconcilationInterval: 10 * time.Minute,
		RetryBackoffMinDuration:   time.Second,
		RetryBackoffMaxDuration:   time.Minute,
		IncrementalRoundSize:      1000,
		GetObjectStatus:           (*tables.BandwidthQDisc).GetStatus,
		WithObjectStatus:          (*tables.BandwidthQDisc).WithStatus,
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

	Log          logrus.FieldLogger
	Config       Config
	DaemonConfig *option.DaemonConfig
	Sysctl       sysctl.Sysctl
}

func registerReconciler(
	cfg Config,
	deriveParams statedb.DeriveParams[*tables.Device, *tables.BandwidthQDisc],
	reconcilerParams reconciler.Params[*tables.BandwidthQDisc],
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
	return reconciler.Register(reconcilerParams)
}

func deviceToBandwidthQDisc(device *tables.Device, deleted bool) (*tables.BandwidthQDisc, statedb.DeriveResult) {
	if deleted || !device.Selected {
		return &tables.BandwidthQDisc{
			LinkIndex: device.Index,
			LinkName:  device.Name,
			Status:    reconciler.StatusPendingDelete(),
		}, statedb.DeriveUpdate
	}
	return &tables.BandwidthQDisc{
		LinkIndex: device.Index,
		LinkName:  device.Name,
		FqHorizon: FqDefaultHorizon,
		FqBuckets: FqDefaultBuckets,
		Status:    reconciler.StatusPending(),
	}, statedb.DeriveInsert
}
