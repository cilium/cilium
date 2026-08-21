// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cel

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"cel",
	"CEL - Common Expression Language",

	// Provide config for the CEL module.
	cell.Config(DefaultConfig),

	// Register and provide Prometheus metrics.
	metrics.Metric(NewCELMetrics),

	// Initialize CEL environments.
	cell.Provide(NewEnvironment),
	cell.Invoke(registerGlobalEnv),
)
