// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

var Cell = cell.Metric(newHealthMetrics)

type HealthMetrics struct {
	HealthStatusGauge metric.Vec[metric.Gauge]
}

func newHealthMetrics() *HealthMetrics {
	return &HealthMetrics{
		HealthStatusGauge: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: "hive_health_status_levels",
			Namespace:  "cilium",
			Subsystem:  "hive",
			Name:       "status",
			Help:       "Counts of health status levels of Hive components",
		}, []string{"status"}),
	}
}
