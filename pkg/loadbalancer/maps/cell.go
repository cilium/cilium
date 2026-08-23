// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"github.com/cilium/hive/cell"
)

// Provides [LBMap] a wrapper around the load-balancing BPF maps
var Cell = cell.Module(
	"loadbalancer-maps",
	"Load-balancing BPF maps",

	// Provide [lbmaps], abstraction for the load-balancing BPF map access.
	cell.Provide(newLBMaps),

	// Provide the map of the services that opted into scale-to-zero. It is
	// reconciled alongside the load-balancing maps, so it follows them in
	// being faked when the load balancer runs without a datapath.
	cell.Provide(newScaleToZeroMap),

	// Provide the 'lb/' script commands for debugging and testing.
	cell.Provide(scriptCommands),

	// Register a periodic job to update the BPF map pressure metrics.
	cell.Invoke(registerPressureMetricsReporter),
)
