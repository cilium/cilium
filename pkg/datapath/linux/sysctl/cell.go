// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysctl

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/afero"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"sysctl",
	"Manages sysctl settings",

	cell.Config(Config{}),

	cell.Provide(
		newReconcilingSysctl,
	),
	cell.ProvidePrivate(
		tables.NewSysctlTable,

		reconciler.New[*tables.Sysctl],
		newReconcilerConfig,
		newOps,
	),
	cell.ProvidePrivate(
		func() afero.Fs {
			return afero.NewOsFs()
		},
	),
)

type Config struct {
	ProcFs string `mapstructure:"procfs"`
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.String("procfs", "/proc", "Path to the host's proc filesystem mount")
}

func newReconcilerConfig(
	ops reconciler.Operations[*tables.Sysctl],
	tbl statedb.RWTable[*tables.Sysctl],
) reconciler.Config[*tables.Sysctl] {
	return reconciler.Config[*tables.Sysctl]{
		Table:                     tbl,
		FullReconcilationInterval: 10 * time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   5 * time.Second,
		IncrementalRoundSize:      100,
		GetObjectStatus:           (*tables.Sysctl).GetStatus,
		SetObjectStatus:           (*tables.Sysctl).SetStatus,
		CloneObject:               (*tables.Sysctl).Clone,
		Operations:                ops,
	}
}
