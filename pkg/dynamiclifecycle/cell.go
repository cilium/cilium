// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamiclifecycle

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
)

// Cell registers a manager that manages the lifecycle of dynamic features.
// It allows to add new DynamicFeatureName, Append cell.HookInterface, and Start/Stop lifecycles.
// A dynamic feature is a group of cell hooks that are grouped together and their
// lifecycles are managed by the feature manager.
// The manager uses the DynamicConfig table as the source of truth for enablement.
// The manager delegates the responsibility of enablement to DynamicFeature StateDB reconciler.
var Cell = cell.Module(
	"dynamic-lifecycle-manager",
	"Groups dynamic feature lifecycles and allows to start and stop dynamically",

	cell.ProvidePrivate(
		newDynamicFeatureTable,
		newOps,
	),

	cell.Provide(
		statedb.RWTable[*DynamicFeature].ToTable,
	),

	cell.Invoke(
		registerWatcher,
		registerReconciler,
	),

	cell.Config(defaultConfig),
)

const ConfigKey = "dynamic-lifecycle-config"

var defaultConfig = config{
	EnableDynamicLifecycleManager: false,
	DynamicLifecycleConfig:        `[]`, // See manager.go for the JSON definition
}

type config struct {
	EnableDynamicLifecycleManager bool
	DynamicLifecycleConfig        string
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-dynamic-lifecycle-manager", c.EnableDynamicLifecycleManager, "Enables support for dynamic lifecycle management")
	flags.String(ConfigKey, c.DynamicLifecycleConfig, "List of dynamic lifecycle features and their configuration including the dependencies")
}
