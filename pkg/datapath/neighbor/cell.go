// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"neighbor",
	"Neighbor subsystem",

	ForwardableIPCell,

	// Config for the neighbor subsystem, shared by multiple components.
	cell.Config(neighborConfig{EnableL2NeighDiscovery: false}),
	cell.ProvidePrivate(newCommonConfig),

	// Desired neighbor table is an internal table, generated from the forwardable IPs,
	// devices, and routes.
	cell.ProvidePrivate(newDesiredNeighborTable),
	cell.Provide(statedb.RWTable[*DesiredNeighbor].ToTable),

	// An internal abstraction of netlink functions.
	// This cell provides a netlink handle in the current namespace.
	cell.ProvidePrivate(newNetlinkFuncsGetter),

	// The desired neighbor calculator is responsible for calculating the desired
	// neighbors based on the forwardable IPs, devices, and routes.
	cell.Invoke(newDesiredNeighborCalculator),

	// The individual operations called by the reconciler, decoupled from the
	// reconciler itself so that they can be tested in isolation.
	cell.ProvidePrivate(newOps),
	// The fully configured and hooked up reconciler, takes the desired neighbor
	// table and calls the operations to manage the neighbors in the kernel.
	cell.Invoke(newNeighborReconciler),
	// The neighbor refresher subscribes to the neighbor table to see when
	// neighbor entries go stale, tells the reconciler to refresh them.
	// This logic is only need on kernels which are incapable of refreshing
	// neighbors themselves.
	cell.Invoke(newNeighborRefresher),

	// Metrics about the neighbor subsystem. Mostly for debugging and
	// performance analysis.
	metrics.Metric(NewNeighborMetrics),
)

// This is a separate cell so it can be included independently in tests
// to assert against the contents of the forwardable IP table without
// having to include the entire neighbor subsystem.
var ForwardableIPCell = cell.Group(
	// Forwardable IP table contains all IPs to which we expect to forward packets.
	// Contents of the table are managed via [ForwardableIPManager] which is also
	// provided in this cell.
	cell.Provide(newForwardableIPTable),
)
