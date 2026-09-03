// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/cilium/hive/cell"
)

var Cell = cell.Group(
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
