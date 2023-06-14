// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import "github.com/cilium/cilium/pkg/hive/cell"

var RegistryCell = cell.Module("metrics-registry", "Metrics Registry",
	cell.Provide(NewRegistry),
	cell.Config(defaultRegistryConfig),
)

var AgentMetrics = cell.Group(
	cell.Metric(NewLegacyMetrics),
	cell.Metric(NewBPFMapMetrics),
	cell.Invoke(newDefaultAgentMetrics),
)
