// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// subsystem is the metrics subsystem for ztunnel XDS
	subsystem = "ztunnel_xds"

	// Label names
	labelStatus = "status"
)

// Metrics holds XDS-related metrics for ztunnel workload discovery
type Metrics struct {
	// EnrollmentFailures tracks workload enrollment failures to Z-tunnel via XDS
	// Status values: send_failed, nack_received
	EnrollmentFailures metric.Vec[metric.Counter]
}

// NewMetrics creates a new Metrics instance for XDS enrollment failures
func NewMetrics() *Metrics {
	return &Metrics{
		EnrollmentFailures: metric.NewCounterVec(
			metric.CounterOpts{
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "enrollment_failures_total",
				Help:      "Total number of workload enrollment failures to ztunnel via XDS by status (send_failed, nack_received)",
			},
			[]string{labelStatus},
		),
	}
}
