// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

var Cell = cell.Module(
	"loadbalancer-experimental",
	"Experimental load-balancing control-plane",

	cell.Config(DefaultConfig),

	// Provides [Writer] API and the load-balancing tables.
	TablesCell,

	// Reflects Kubernetes services and endpoints to the load-balancing tables
	// using the [Writer].
	ReflectorCell,
)

// TablesCell provides the [Writer] API for configuring load-balancing and the
// Table[*Service], Table[*Frontend] and Table[*Backend] for read-only access
// to load-balancing state.
var TablesCell = cell.Module(
	"tables",
	"Experimental load-balancing control-plane",

	// Provide the RWTable[Service] and RWTable[Backend] privately to this
	// module so that the tables are only modified via the Services API.
	cell.ProvidePrivate(
		NewServicesTable,
		NewFrontendsTable,
		NewBackendsTable,
	),

	cell.Provide(
		// Provide the [Writer] API for modifying the tables.
		NewWriter,

		// Provide direct read-only access to the tables.
		statedb.RWTable[*Service].ToTable,
		statedb.RWTable[*Frontend].ToTable,
		statedb.RWTable[*Backend].ToTable,
	),
)
