// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/operator/metrics"
)

// PrometheusMetrics is an implementation of Prometheus metrics for external
// API usage
type PrometheusMetrics struct {
	registry    metrics.RegisterGatherer
	APIDuration *prometheus.HistogramVec
	RateLimit   *prometheus.HistogramVec
}

// NewPrometheusMetrics returns a new metrics tracking implementation to cover
// external API usage.
func NewPrometheusMetrics(namespace, subsystem string, registry metrics.RegisterGatherer) *PrometheusMetrics {
	m := &PrometheusMetrics{registry: registry}

	m.APIDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "api_duration_seconds",
		Help:      "Duration of interactions with API",
	}, []string{"operation", "response_code"})

	m.RateLimit = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "api_rate_limit_duration_seconds",
		Help:      "Duration of client-side rate limiter blocking",
	}, []string{"operation"})

	registry.MustRegister(m.APIDuration)
	registry.MustRegister(m.RateLimit)

	return m
}

// ObserveAPICall must be called on every API call made with the operation
// performed, the status code received and the duration of the call
func (p *PrometheusMetrics) ObserveAPICall(operation, status string, duration float64) {
	p.APIDuration.WithLabelValues(operation, status).Observe(duration)
}

// ObserveRateLimit must be called in case an API call was subject to rate limiting
func (p *PrometheusMetrics) ObserveRateLimit(operation string, delay time.Duration) {
	p.RateLimit.WithLabelValues(operation).Observe(delay.Seconds())
}

// NoOpMetrics is a no-op implementation
type NoOpMetrics struct{}

// ObserveAPICall must be called on every API call made with the operation
// performed, the status code received and the duration of the call. This No-op
// implementation will perform no metrics accounting in return.
func (m *NoOpMetrics) ObserveAPICall(call, status string, duration float64) {}

// ObserveRateLimit must be called in case an API call was subject to rate
// limiting. This No-op implementation will perform no metrics accounting in
// return.
func (m *NoOpMetrics) ObserveRateLimit(operation string, duration time.Duration) {}
