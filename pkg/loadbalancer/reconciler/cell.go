// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// Load-balancing tables to BPF map reconciliation.
//
// Reconciles changes in Table[*Frontend] to the BPF maps.
var Cell = cell.Module(
	"loadbalancer-reconciler",
	"Load-balancing BPF map reconciliation",

	cell.Provide(
		newBPFOps,
		newBPFReconciler,
	),
	cell.Invoke(
		// Force the registration even if none uses Reconciler[*Frontend].
		func(reconciler.Reconciler[*loadbalancer.Frontend]) {},
	),

	// Provide the 'lb/' script commands for debugging and testing.
	cell.Provide(scriptCommands),

	// Terminate sockets connected to backends that have been removed.
	SocketTerminationCell,
)
