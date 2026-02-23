// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/promise"
)

// Load-balancing tables to BPF map reconciliation.
//
// Reconciles changes in Table[*Frontend] to the BPF maps.
var Cell = cell.Module(
	"loadbalancer-reconciler",
	"Load-balancing BPF map reconciliation",

	cell.Provide(
		// Provide [BPFOps] for reconciling a changed frontend.
		// Publicly provided only because this is used by pkg/loadbalancer/benchmark.
		newBPFOps,

		// Provide the 'lb/' script commands for debugging and testing.
		scriptCommands,
	),

	cell.ProvidePrivate(
		newBPFReconciler,
	),

	cell.Invoke(
		// Force the registration even if none uses Reconciler[*Frontend].
		func(promise.Promise[reconciler.Reconciler[*loadbalancer.Frontend]]) {},
	),

	// Terminate sockets connected to backends that have been removed.
	SocketTerminationCell,
)
