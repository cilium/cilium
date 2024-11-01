// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option/resolver"
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

var defaultConfig = Config{
	EnableDynamicConfig:    false,
	ConfigSources:          `[{"kind":"config-map","namespace":"kube-system","name":"cilium-config"}]`, // See pkg/option/resolver.go for the JSON definition
	ConfigSourcesOverrides: `{"allowConfigKeys":null,"denyConfigKeys":null}`,
}

type Config struct {
	EnableDynamicConfig    bool
	ConfigSources          string
	ConfigSourcesOverrides string
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-dynamic-config", c.EnableDynamicConfig, "Enables support for dynamic agent config")
	flags.String(resolver.ConfigSources, c.ConfigSources, "Ordered list of configuration sources")
	flags.MarkHidden(resolver.ConfigSources)
	flags.String(resolver.ConfigSourcesOverrides, c.ConfigSourcesOverrides, "List of configuration keys that are allowed and not allowed to be overridden. Allowed config keys takes precedence over deny config keys.")
	flags.MarkHidden(resolver.ConfigSourcesOverrides)
}
