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
	"dynamic-feature-manager",
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

const DynamicFeaturesConfigKey = "dynamic-feature-config"

var defaultConfig = config{
	EnableDynamicFeatureManager: false,
	DynamicFeatureConfig:        `[]`, // See manager.go for the JSON definition
}

type config struct {
	EnableDynamicFeatureManager bool
	DynamicFeatureConfig        string
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-dynamic-feature-manager", c.EnableDynamicFeatureManager, "Enables support for dynamic feature management")
	flags.String(DynamicFeaturesConfigKey, c.DynamicFeatureConfig, "List of dynamic features and their configuration including the dependencies")
}
