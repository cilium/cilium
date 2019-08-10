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

	"github.com/cilium/cilium/pkg/trigger"

	"github.com/prometheus/client_golang/prometheus"
)

const eniSubsystem = "eni"

type prometheusMetrics struct {
	registry              *prometheus.Registry
	AllocateEniOps        *prometheus.CounterVec
	AllocateIpOps         *prometheus.CounterVec
	IPsAllocated          *prometheus.GaugeVec
	AvailableENIs         prometheus.Gauge
	AvailableIPsPerSubnet *prometheus.GaugeVec
	Nodes                 *prometheus.GaugeVec
	Resync                prometheus.Counter
	EC2ApiDuration        *prometheus.HistogramVec
	EC2RateLimit          *prometheus.HistogramVec
	deficitResolver       *triggerMetrics
	k8sSync               *triggerMetrics
	resync                *triggerMetrics
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

	m.AvailableENIs = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "available",
		Help:      "Number of ENIs with addresses available",
	})

	m.AvailableIPsPerSubnet = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "available_ips_per_subnet",
		Help:      "Number of available IPs per subnet ID",
	}, []string{"subnetId", "availabilityZone"})

	m.Nodes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "nodes",
		Help:      "Number of nodes by category { total | in-deficit | at-capacity }",
	}, []string{"category"})

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

	m.deficitResolver = newTriggerMetrics(namespace, "deficit_resolver")
	m.k8sSync = newTriggerMetrics(namespace, "k8s_sync")
	m.resync = newTriggerMetrics(namespace, "ec2_resync")

	registry.MustRegister(m.IPsAllocated)
	registry.MustRegister(m.AllocateIpOps)
	registry.MustRegister(m.AllocateEniOps)
	registry.MustRegister(m.AvailableENIs)
	registry.MustRegister(m.AvailableIPsPerSubnet)
	registry.MustRegister(m.Nodes)
	registry.MustRegister(m.Resync)
	registry.MustRegister(m.EC2ApiDuration)
	registry.MustRegister(m.EC2RateLimit)
	m.deficitResolver.register(registry)
	m.k8sSync.register(registry)
	m.resync.register(registry)

	return m
}

func (p *prometheusMetrics) DeficitResolverTrigger() trigger.MetricsObserver {
	return p.deficitResolver
}

func (p *prometheusMetrics) K8sSyncTrigger() trigger.MetricsObserver {
	return p.k8sSync
}

func (p *prometheusMetrics) ResyncTrigger() trigger.MetricsObserver {
	return p.resync
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
	p.AvailableENIs.Set(float64(available))
}

func (p *prometheusMetrics) SetAvailableIPsPerSubnet(subnetID string, availabilityZone string, available int) {
	p.AvailableIPsPerSubnet.WithLabelValues(subnetID, availabilityZone).Set(float64(available))
}

func (p *prometheusMetrics) SetNodes(label string, nodes int) {
	p.Nodes.WithLabelValues(label).Set(float64(nodes))
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

type triggerMetrics struct {
	total        prometheus.Counter
	folds        prometheus.Gauge
	callDuration prometheus.Histogram
	latency      prometheus.Histogram
}

func newTriggerMetrics(namespace, name string) *triggerMetrics {
	return &triggerMetrics{
		total: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: eniSubsystem,
			Name:      name + "_queued_total",
			Help:      "Number of queued triggers",
		}),
		folds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: eniSubsystem,
			Name:      name + "_folds",
			Help:      "Current level of folding",
		}),
		callDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: eniSubsystem,
			Name:      name + "_duration_seconds",
			Help:      "Duration of trigger runs",
		}),
		latency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: eniSubsystem,
			Name:      name + "_latency_seconds",
			Help:      "Latency between queue and trigger run",
		}),
	}
}

func (t *triggerMetrics) register(registry *prometheus.Registry) {
	registry.MustRegister(t.total)
	registry.MustRegister(t.folds)
	registry.MustRegister(t.callDuration)
	registry.MustRegister(t.latency)
}

func (t *triggerMetrics) QueueEvent(reason string) {
	t.total.Inc()
}

func (t *triggerMetrics) PostRun(duration, latency time.Duration, folds int) {
	t.callDuration.Observe(duration.Seconds())
	t.latency.Observe(latency.Seconds())
	t.folds.Set(float64(folds))
}
