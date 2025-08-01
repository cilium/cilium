// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"log/slog"
	"runtime/pprof"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

// LeaderLifecycle is the inner lifecycle of the kvstoremesh that is started when this
// instance is elected leader. It implements cell.Lifecycle allowing cells to use it.
type LeaderLifecycle struct {
	cell.DefaultLifecycle
}

func WithLeaderLifecycle(cells ...cell.Cell) cell.Cell {
	return cell.Module(
		"leader-lifecycle",
		"KVStoreMesh Leader Lifecycle",

		cell.Provide(
			func() *LeaderLifecycle { return &LeaderLifecycle{} },
		),
		cell.Decorate(
			func(reg job.Registry, h cell.Health, logger *slog.Logger, llc *LeaderLifecycle, mid cell.ModuleID) (cell.Lifecycle, job.Group) {
				return llc, reg.NewGroup(h, llc,
					job.WithLogger(logger),
					job.WithPprofLabels(pprof.Labels("cell", string(mid))))
			},
			cells...,
		),
	)
}
