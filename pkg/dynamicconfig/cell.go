// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
)

// Cell provides a reflector of cilium configs to DynamicConfigMap table.
// It provides read-only Table[DynamicConfig] and Get/Watch for config keys.
//
// Usage:
// cell.Module(
//
//		...
//	 cell.Invoke(
//			func(t statedb.Table[DynamicConfig], db *statedb.DB) {
//				c, f := dynamicconfig.GetKey(db.ReadTxn(), t, "KEY")
//
//				c, f, w := dynamicconfig.WatchKey(db.ReadTxn(), t, "KEY")
//			},
//		),
//		...
//
// )
var Cell = cell.Module(
	"cilium-agent-dynamic-config",
	"Reflects Cilium configuration to the DynamicConfig table",
	cell.ProvidePrivate(
		NewConfigTable,
		NewConfigMapReflector,
	),
	cell.Provide(
		statedb.RWTable[DynamicConfig].ToTable,
	),
	cell.Invoke(
		RegisterConfigMapReflector,
	),
	cell.Config(defaultConfig),
)

var defaultConfig = config{
	EnableDynamicConfig: false,
}

type config struct {
	EnableDynamicConfig bool
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-dynamic-config", c.EnableDynamicConfig, "Enables support for dynamic agent config")
}
