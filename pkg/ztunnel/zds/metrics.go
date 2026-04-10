// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// Subsystem is the metrics subsystem for ztunnel
	subsystem = "ztunnel_zds"

	// Label names
	labelStatus = "status"
)

// Metrics holds the core ztunnel metrics
type Metrics struct {
	// EnrollmentTotal tracks the total number of endpoint enrollment attempts to ztunnel
	EnrollmentTotal metric.Counter

	// EnrollmentFailures tracks endpoint enrollment failures to ztunnel
	// Status values: netns_failed, iptables_failed, send_failed, conversion_failed
	EnrollmentFailures metric.Vec[metric.Counter]

	// ConnectionActive tracks whether ztunnel is connected (1) or not (0)
	ConnectionActive metric.Gauge
}

// NewMetrics creates a new Metrics instance with the core ztunnel metrics
func NewMetrics() *Metrics {
	return &Metrics{
		EnrollmentTotal: metric.NewCounter(
			metric.CounterOpts{
				Disabled:  true,
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "enrollment_total",
				Help:      "Total number of endpoint enrollment attempts to ztunnel",
			},
		),

		EnrollmentFailures: metric.NewCounterVec(
			metric.CounterOpts{
				Disabled:  true,
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "enrollment_failures_total",
				Help:      "Total number of endpoint enrollment failures to ztunnel by status (netns_failed, iptables_failed, send_failed, conversion_failed)",
			},
			[]string{labelStatus},
		),

		ConnectionActive: metric.NewGauge(
			metric.GaugeOpts{
				Disabled:  true,
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "connection_active",
				Help:      "Whether ztunnel connection is active (1) or not (0)",
			},
		),
	}
}

// Enable enables ZDS metrics for Prometheus scraping.
func (m *Metrics) Enable() {
	if m == nil {
		return
	}
	m.EnrollmentTotal.SetEnabled(true)
	m.EnrollmentFailures.SetEnabled(true)
	m.ConnectionActive.SetEnabled(true)
}
