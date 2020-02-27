// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const eniSubsystem = "eni"

type prometheusMetrics struct {
	registry       *prometheus.Registry
	EC2ApiDuration *prometheus.HistogramVec
	EC2RateLimit   *prometheus.HistogramVec
}

// NewPrometheusMetrics returns a new ENI metrics implementation backed by
// Prometheus metrics.
func NewPrometheusMetrics(namespace string, registry *prometheus.Registry) *prometheusMetrics {
	m := &prometheusMetrics{
		registry: registry,
	}

	m.EC2ApiDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "aws_api_duration_seconds",
		Help:      "Duration of interactions with AWS API",
	}, []string{"operation", "responseCode"})

	m.EC2RateLimit = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "ec2_rate_limit_duration_seconds",
		Help:      "Duration of EC2 client-side rate limiter blocking",
	}, []string{"operation"})

	registry.MustRegister(m.EC2ApiDuration)
	registry.MustRegister(m.EC2RateLimit)

	return m
}

func (p *prometheusMetrics) ObserveEC2APICall(operation, status string, duration float64) {
	p.EC2ApiDuration.WithLabelValues(operation, status).Observe(duration)
}

func (p *prometheusMetrics) ObserveEC2RateLimit(operation string, delay time.Duration) {
	p.EC2RateLimit.WithLabelValues(operation).Observe(delay.Seconds())
}
