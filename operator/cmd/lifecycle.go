// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/hive/cell"
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
			func(lc *LeaderLifecycle) cell.Lifecycle {
				return lc
			},
			cells...,
		),
	)

}
