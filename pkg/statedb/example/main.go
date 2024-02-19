// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/statedb"
)

var Hive = hive.New(
	// job provides management for background workers and timers.
	job.Cell,

	// StateDB provides a transactional database to access and modify tables.
	statedb.Cell,

	// The backends table stores the desired state of the backends.
	cell.Provide(NewBackendTable),

	// Control-plane simulation for the backends table to provide the
	// desired state.
	controlCell,

	// Datapath simulation to reconcile the desired state to the datapath.
	reconcilerCell,
)

func main() {
	if err := Hive.Run(); err != nil {
		logging.DefaultLogger.Fatalf("Run failed: %s", err)
	}
}
