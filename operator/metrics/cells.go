// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"operator-metrics",
	"Operator Metrics",
	cell.Metric(NewLegacyMetrics),
	cell.Invoke(registerDefaultMetrics),
	cell.Config(defaultOperatorRegistryConfig),
	cell.Provide(func(c OperatorRegistryConfig) metrics.RegistryConfig {
		return c
	}),
)
