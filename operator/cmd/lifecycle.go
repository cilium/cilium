// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

// LeaderLifecycle is the inner lifecycle of the operator that is started when this
// operator instance is elected leader. It implements cell.Lifecycle allowing cells
// to use it.
type LeaderLifecycle struct {
	cell.DefaultLifecycle
}

func WithLeaderLifecycle(cells ...cell.Cell) cell.Cell {
	return cell.Module(
		"leader-lifecycle",
		"Operator Leader Lifecycle",

		cell.Provide(
			func() *LeaderLifecycle { return &LeaderLifecycle{} },
		),
		cell.Decorate(
			func(lc *LeaderLifecycle, r job.Registry) (cell.Lifecycle, job.Registry) {
				return lc, r.WithLifecycle(lc)
			},
			cells...,
		),
	)
}
