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

	cell.Config(defaultConfig),

	cell.Provide(
		newReconcilingSysctl,
	),
	cell.ProvidePrivate(
		tables.NewSysctlTable,

		newReconciler,
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
	flags.String("procfs", cfg.ProcFs, "Path to the host's proc filesystem mount")
}

var defaultConfig = Config{
	ProcFs: "/proc",
}

func newReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*tables.Sysctl],
	tbl statedb.RWTable[*tables.Sysctl],
) (reconciler.Reconciler[*tables.Sysctl], error) {
	return reconciler.Register(
		params,
		tbl,
		(*tables.Sysctl).Clone,
		(*tables.Sysctl).SetStatus,
		(*tables.Sysctl).GetStatus,
		ops,
		nil,

		reconciler.WithoutPruning(),
		reconciler.WithRefreshing(
			10*time.Minute,
			nil,
		),
	)
}
