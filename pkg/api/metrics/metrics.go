// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"time"

	ciliumMetrics "github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// Metrics holds the Prometheus metrics for external cloud API usage.
type Metrics struct {
	APIDuration metric.Vec[metric.Observer]
	RateLimit   metric.Vec[metric.Observer]
}

// New returns a new Metrics for the given cloud API subsystem (e.g. "ec2", "azure").
func New(subsystem string) *Metrics {
	return &Metrics{
		APIDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: ciliumMetrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "api_duration_seconds",
			Help:      "Duration of interactions with API",
			Buckets: []float64{0.005, 0.025, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3,
				4, 5, 6, 8, 10, 15, 20, 30, 45, 60},
		}, []string{"operation", "response_code"}),

		RateLimit: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: ciliumMetrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "api_rate_limit_duration_seconds",
			Help:      "Duration of client-side rate limiter blocking",
		}, []string{"operation"}),
	}
}

// ObserveAPICall records the duration of an API call with the given operation name and response code.
func (m *Metrics) ObserveAPICall(operation, status string, duration float64) {
	m.APIDuration.WithLabelValues(operation, status).Observe(duration)
}

// ObserveRateLimit records a rate-limiter blocking event for the given operation.
func (m *Metrics) ObserveRateLimit(operation string, delay time.Duration) {
	m.RateLimit.WithLabelValues(operation).Observe(delay.Seconds())
}
