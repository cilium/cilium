// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
)

var Hive = hive.New(
	// job provides management for background workers and timers.
	job.Cell,

	// StateDB provides a transactional database to access and modify tables.
	statedb.Cell,

	// The backends table stores the desired state of the backends.
	BackendTableCell,

	// Control-plane simulation for the backends table to provide the
	// desired state.
	controlCell,

	// Datapath simulation to reconcile the desired state to the datapath.
	reconcilerCell,

	// Report the health status to stdout once a second.
	cell.Invoke(reportHealth),
)

func main() {
	if err := Hive.Run(); err != nil {
		logging.DefaultLogger.Fatalf("Run failed: %s", err)
	}
}

func reportHealth(health cell.Health, log logrus.FieldLogger, scope cell.Scope, jobs job.Registry, lc hive.Lifecycle) {
	g := jobs.NewGroup(scope)
	reportHealth := func(ctx context.Context) error {
		for _, status := range health.All() {
			log.Info(status.String())
		}
		return nil
	}
	g.Add(job.Timer("health-reporter", reportHealth, time.Second))
	lc.Append(g)
}
