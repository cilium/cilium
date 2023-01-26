// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"metrics",
	"Metrics",

	cell.Config(defaultRegistryConfig),
	cell.Metric(NewLegacyMetrics),
	cell.Provide(NewRegistry),

	cell.Metric(NewLoggingHookMetrics),
	cell.Provide(NewLoggingHook),

	cell.Metric(NewMapPressureMetric),

	cell.Invoke(func(legacyMetrics *LegacyMetrics, daemonConfig *option.DaemonConfig) {
		// TODO move this to agent logic somewhere
		if daemonConfig.DNSProxyConcurrencyLimit > 0 {
			legacyMetrics.FQDNSemaphoreRejectedTotal.SetEnabled(true)
		}
	}),
)
