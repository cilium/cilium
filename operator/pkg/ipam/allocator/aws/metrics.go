// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package aws

import (
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"
)

// Metrics holds the metrics for the AWS EC2 API client.
type Metrics struct {
	APIDuration metric.Vec[metric.Observer]
	RateLimit   metric.Vec[metric.Observer]
}

// NewMetrics returns the metrics for the AWS EC2 API client.
func NewMetrics() *Metrics {
	m := apiMetrics.New("ec2")
	return &Metrics{
		APIDuration: m.APIDuration,
		RateLimit:   m.RateLimit,
	}
}

// ObserveAPICall records the duration of an API call.
func (m *Metrics) ObserveAPICall(operation, status string, duration float64) {
	m.APIDuration.WithLabelValues(operation, status).Observe(duration)
}

// ObserveRateLimit records a rate-limiter blocking event.
func (m *Metrics) ObserveRateLimit(operation string, delay time.Duration) {
	m.RateLimit.WithLabelValues(operation).Observe(delay.Seconds())
}
