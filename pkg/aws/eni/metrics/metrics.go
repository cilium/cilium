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
	registry        *prometheus.Registry
	AllocateEniOps  *prometheus.CounterVec
	AllocateIpOps   *prometheus.CounterVec
	IPsAllocated    *prometheus.GaugeVec
	Available       prometheus.Gauge
	NodesAtCapacity prometheus.Gauge
	Resync          prometheus.Counter
	EC2ApiDuration  *prometheus.HistogramVec
	EC2RateLimit    *prometheus.HistogramVec
}

// NewPrometheusMetrics returns a new ENI metrics implementation backed by
// Prometheus metrics.
func NewPrometheusMetrics(namespace string, registry *prometheus.Registry) *prometheusMetrics {
	m := &prometheusMetrics{
		registry: registry,
	}

	m.IPsAllocated = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "ips",
		Help:      "Number of IPs allocated",
	}, []string{"type"})

	m.AllocateIpOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "allocation_ops",
		Help:      "Number of IP allocation operations",
	}, []string{"subnetId"})

	m.AllocateEniOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "interface_creation_ops",
		Help:      "Number of ENIs allocated",
	}, []string{"subnetId", "status"})

	m.Available = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "available",
		Help:      "Number of ENIs with addresses available",
	})

	m.NodesAtCapacity = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "nodes_at_capacity",
		Help:      "Number of nodes unable to allocate more addresses",
	})

	m.EC2ApiDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "aws_api_duration_seconds",
		Help:      "Duration of interactions with AWS API",
	}, []string{"operation", "responseCode"})

	m.Resync = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "resync_total",
		Help:      "Number of resync operations to synchronize AWS EC2 metadata",
	})

	m.EC2RateLimit = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "ec2_rate_limit_duration_seconds",
		Help:      "Duration of EC2 client-side rate limiter blocking",
	}, []string{"operation"})

	registry.MustRegister(m.IPsAllocated)
	registry.MustRegister(m.AllocateIpOps)
	registry.MustRegister(m.AllocateEniOps)
	registry.MustRegister(m.Available)
	registry.MustRegister(m.NodesAtCapacity)
	registry.MustRegister(m.Resync)
	registry.MustRegister(m.EC2ApiDuration)
	registry.MustRegister(m.EC2RateLimit)

	return m
}

func (p *prometheusMetrics) IncENIAllocationAttempt(status, subnetID string) {
	p.AllocateEniOps.WithLabelValues(subnetID, status).Inc()
}

func (p *prometheusMetrics) AddIPAllocation(subnetID string, allocated int64) {
	p.AllocateIpOps.WithLabelValues(subnetID).Add(float64(allocated))
}

func (p *prometheusMetrics) SetAllocatedIPs(typ string, allocated int) {
	p.IPsAllocated.WithLabelValues(typ).Set(float64(allocated))
}

func (p *prometheusMetrics) SetAvailableENIs(available int) {
	p.Available.Set(float64(available))
}

func (p *prometheusMetrics) SetNodesAtCapacity(nodes int) {
	p.NodesAtCapacity.Set(float64(nodes))
}

func (p *prometheusMetrics) ObserveEC2APICall(operation, status string, duration float64) {
	p.EC2ApiDuration.WithLabelValues(operation, status).Observe(duration)
}

func (p *prometheusMetrics) ObserveEC2RateLimit(operation string, delay time.Duration) {
	p.EC2RateLimit.WithLabelValues(operation).Observe(delay.Seconds())
}

func (p *prometheusMetrics) IncResyncCount() {
	p.Resync.Inc()
}
