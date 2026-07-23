// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"

	"github.com/cilium/hive/cell"
)

var Cell = cell.Group(

	cell.Config(defaultNetworkDriverConfig),

	cell.ProvidePrivate(
		clusterConfigResource,

		newDriverClusterConfigTable,
		newDriverClusterConfigOps,

		newDriverNodeConfigTable,
		newDriverNodeConfigOps,
	),
	cell.Invoke(
		registerDriverClusterConfigReconciler,
		registerDriverNodeConfigReconciler,

		registerConfigManager,
	),
)

type NetworkDriverConfig struct {
	Enabled bool `mapstructure:"enable-network-driver"`
}

func (cfg NetworkDriverConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(
		"enable-network-driver",
		cfg.Enabled,
		"enable network driver to assign interfaces via Dynamic Resource Allocation",
	)
}

var defaultNetworkDriverConfig = NetworkDriverConfig{
	Enabled: false,
}
