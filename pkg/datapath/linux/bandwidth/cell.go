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
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

var Cell = cell.Module(
	"bandwidth-manager",
	"Linux Bandwidth Manager for EDT-based pacing",

	cell.Config(Config{false, false}),
	cell.Provide(newBandwidthManager),
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

func newBandwidthManager(lc cell.Lifecycle, p bandwidthManagerParams) (datapath.BandwidthManager, defines.NodeFnOut) {
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
	DB           *statedb.DB
	Devices      statedb.Table[*tables.Device]
}
