// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/hive/cell"
)

// LeaderLifecycle is the inner lifecycle of the kvstoremesh that is started when this
// instance is elected leader. It implements cell.Lifecycle allowing cells to use it.
type LeaderLifecycle struct {
	cell.DefaultLifecycle
}

func WithLeaderLifecycle(cells ...cell.Cell) cell.Cell {
	return cell.Module(
		"leader-lifecycle",
		"Kvstoremesh Leader Lifecycle",

		cell.Provide(
			func() *LeaderLifecycle { return &LeaderLifecycle{} },
		),
		cell.Decorate(
			func(lc *LeaderLifecycle) cell.Lifecycle {
				return lc
			},
			cells...,
		),
	)
}
