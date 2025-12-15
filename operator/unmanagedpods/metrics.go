// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package unmanagedpods

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// Metrics holds the metrics for the unmanaged pods controller.
type Metrics struct {
	// UnmanagedPods records the pods that are unmanaged by Cilium.
	// This includes Running pods not using hostNetwork, which do not have a corresponding CiliumEndpoint object.
	UnmanagedPods metric.Gauge
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		UnmanagedPods: metric.NewGauge(
			metric.GaugeOpts{
				Namespace: metrics.CiliumOperatorNamespace,
				Name:      "unmanaged_pods",
				Help:      "The total number of pods observed to be unmanaged by Cilium operator",
			},
		),
	}
}
