// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package driftchecker

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	DriftCheckerConfigDelta metric.Gauge
}

func MetricsProvider() Metrics {
	return Metrics{
		DriftCheckerConfigDelta: metric.NewGauge(metric.GaugeOpts{
			Name:      "drift_checker_config_delta",
			Namespace: metrics.Namespace,
			Help:      "Total number of deltas found to mismatch between agent settings and remote sources.",
		}),
	}
}
