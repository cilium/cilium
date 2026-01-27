// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// Subsystem is the metrics subsystem for ztunnel
	subsystem = "ztunnel"

	// Label names
	labelStatus = "status"
)

// Metrics holds the 3 core ztunnel metrics
type Metrics struct {
	// EnrollmentFailures tracks endpoint enrollment failures to Z-tunnel
	// Status values: success, netns_failed, iptables_failed, send_failed
	EnrollmentFailures metric.Vec[metric.Counter]

	// ConnectionActive tracks whether Z-tunnel is connected (1) or not (0)
	ConnectionActive metric.Gauge
}

// NewMetrics creates a new Metrics instance with the 3 core ztunnel metrics
func NewMetrics() *Metrics {
	return &Metrics{
		EnrollmentFailures: metric.NewCounterVec(
			metric.CounterOpts{
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "enrollment_failures_total",
				Help:      "Total number of endpoint enrollment failures to ztunnel by status (success, netns_failed, iptables_failed, send_failed)",
			},
			[]string{labelStatus},
		),

		ConnectionActive: metric.NewGauge(
			metric.GaugeOpts{
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "connection_active",
				Help:      "Whether ztunnel connection is active (1) or not (0)",
			},
		),
	}
}

// getNamespace safely extracts namespace from endpoint, returns "unknown" if not available
func getNamespace(ep *endpoint.Endpoint) string {
	if ep == nil {
		return "unknown"
	}
	ns := ep.GetK8sNamespace()
	if ns == "" {
		return "unknown"
	}
	return ns
}
