// Copyright 2020 Authors of Cilium
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

const azureSubsystem = "azure"

type prometheusMetrics struct {
	registry         *prometheus.Registry
	AzureApiDuration *prometheus.HistogramVec
	AzureRateLimit   *prometheus.HistogramVec
}

// NewPrometheusMetrics returns a new azure metrics implementation backed by
// Prometheus metrics.
func NewPrometheusMetrics(namespace string, registry *prometheus.Registry) *prometheusMetrics {
	m := &prometheusMetrics{
		registry: registry,
	}

	m.AzureApiDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: azureSubsystem,
		Name:      "api_duration_seconds",
		Help:      "Duration of interactions with Azure API",
	}, []string{"operation", "responseCode"})

	m.AzureRateLimit = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: azureSubsystem,
		Name:      "rate_limit_duration_seconds",
		Help:      "Duration of Azure client-side rate limiter blocking",
	}, []string{"operation"})

	registry.MustRegister(m.AzureApiDuration)
	registry.MustRegister(m.AzureRateLimit)

	return m
}

func (p *prometheusMetrics) ObserveAzureAPICall(operation, status string, duration float64) {
	p.AzureApiDuration.WithLabelValues(operation, status).Observe(duration)
}

func (p *prometheusMetrics) ObserveAzureRateLimit(operation string, delay time.Duration) {
	p.AzureRateLimit.WithLabelValues(operation).Observe(delay.Seconds())
}
