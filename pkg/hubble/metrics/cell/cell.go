// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"hubble-metrics",
	"Provides metrics for Hubble",

	cell.Invoke(newHubbleMetrics),
)

type params struct {
	cell.In

	Lifecycle cell.Lifecycle
}

func newHubbleMetrics(p params) {
	s := &metricsServer{}
	p.Lifecycle.Append(s)
}
