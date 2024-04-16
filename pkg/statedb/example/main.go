// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"log/slog"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/statedb"
)

var Hive = hive.New(
	cell.Provide(func() (logrus.FieldLogger, cell.Health) {
		h, _ := cell.NewSimpleHealth()
		return logrus.New(), h
	}),

	// job provides management for background workers and timers.
	job.Cell,

	// StateDB provides a transactional database to access and modify tables.
	statedb.Cell,

	// The backends table stores the desired state of the backends.
	cell.Provide(NewBackendTable),
	cell.Invoke(statedb.RegisterTable[Backend]),

	// Control-plane simulation for the backends table to provide the
	// desired state.
	controlCell,

	// Datapath simulation to reconcile the desired state to the datapath.
	reconcilerCell,
)

func main() {
	l := slog.Default()
	if err := Hive.Run(l); err != nil {
		l.Error("Run failed", "error", err)
		panic(err)
	}
}
