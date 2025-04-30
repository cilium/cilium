// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// Cell provides the [Writer] API for configuring load-balancing and the
// Table[*Service], Table[*Frontend] and Table[*Backend] for read-only access
// to load-balancing state.
var Cell = cell.Module(
	"loadbalancer-writer",
	"Tables and Writer API for manipulating load-balancing state",

	// Provide the RWTable[Service] and RWTable[Backend] privately to this
	// module so that the tables are only modified via the Services API.
	cell.ProvidePrivate(
		loadbalancer.NewServicesTable,
		loadbalancer.NewFrontendsTable,
		loadbalancer.NewBackendsTable,
	),

	cell.Provide(
		// Provide the [Writer] API for modifying the tables.
		NewWriter,

		// Provide direct read-only access to the tables.
		statedb.RWTable[*loadbalancer.Service].ToTable,
		statedb.RWTable[*loadbalancer.Frontend].ToTable,
		statedb.RWTable[*loadbalancer.Backend].ToTable,
	),

	// Register a background job to watch for node zone label changes.
	cell.Invoke(registerNodeZoneWatcher),

	// Register a background job to re-reconcile NodePort and HostPort frontends when
	// the node addresses change.
	cell.Invoke(registerNodePortAddressReconciler),
)
