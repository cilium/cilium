// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// TotalGlobalServices tracks the total number of global services.
	TotalGlobalServices metric.Vec[metric.Gauge]
}

func NewMetrics() Metrics {
	return Metrics{
		TotalGlobalServices: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "global_services",
			Help:      "The total number of global services in the cluster mesh",
		}, []string{metrics.LabelSourceCluster}),
	}
}
