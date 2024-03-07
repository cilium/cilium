// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module("metrics", "Metrics",
	// Provide registry to hive, but also invoke if case no cells decide to use as dependency
	cell.Provide(NewRegistry),
	cell.Metric(NewLegacyMetrics),
	cell.Config(defaultRegistryConfig),
	cell.Invoke(func(_ *Registry) {
		// This is a hack to ensure that errors/warnings collected in the pre hive initialization
		// phase are emitted as metrics.
		FlushLoggingMetrics()
	}),
)
