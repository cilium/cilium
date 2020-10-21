// Copyright 2019-2020 Authors of Cilium
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

const ipamSubsystem = "ipam"

type prometheusMetrics struct {
	registry              *prometheus.Registry
	AllocateInterfaceOps  *prometheus.CounterVec
	AllocateIpOps         *prometheus.CounterVec
	ReleaseIpOps          *prometheus.CounterVec
	IPsAllocated          *prometheus.GaugeVec
	AvailableInterfaces   prometheus.Gauge
	AvailableIPsPerSubnet *prometheus.GaugeVec
	Nodes                 *prometheus.GaugeVec
	Resync                prometheus.Counter
	poolMaintainer        *triggerMetrics
	k8sSync               *triggerMetrics
	resync                *triggerMetrics
}

// NewPrometheusMetrics returns a new interface metrics implementation backed by
// Prometheus metrics.
func NewPrometheusMetrics(namespace string, registry *prometheus.Registry) *prometheusMetrics {
	m := &prometheusMetrics{
		registry: registry,
	}

	m.IPsAllocated = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "ips",
		Help:      "Number of IPs allocated",
	}, []string{"type"})

	m.AllocateIpOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "allocation_ops",
		Help:      "Number of IP allocation operations",
	}, []string{"subnet_id"})

	m.ReleaseIpOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "release_ops",
		Help:      "Number of IP release operations",
	}, []string{"subnet_id"})

	m.AllocateInterfaceOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "interface_creation_ops",
		Help:      "Number of interfaces allocated",
	}, []string{"subnet_id", "status"})

	m.AvailableInterfaces = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "available",
		Help:      "Number of interfaces with addresses available",
	})

	m.AvailableIPsPerSubnet = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "available_ips_per_subnet",
		Help:      "Number of available IPs per subnet ID",
	}, []string{"subnet_id", "availability_zone"})

	m.Nodes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "nodes",
		Help:      "Number of nodes by category { total | in-deficit | at-capacity }",
	}, []string{"category"})

	m.Resync = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "resync_total",
		Help:      "Number of resync operations to synchronize and resolve IP deficit of nodes",
	})

	// pool_maintainer is a more generic name, but for backward compatibility
	// of dashboard, keep the metric name deficit_resolver unchanged
	m.poolMaintainer = NewTriggerMetrics(namespace, "deficit_resolver")
	m.k8sSync = NewTriggerMetrics(namespace, "k8s_sync")
	m.resync = NewTriggerMetrics(namespace, "resync")

	registry.MustRegister(m.IPsAllocated)
	registry.MustRegister(m.AllocateIpOps)
	registry.MustRegister(m.ReleaseIpOps)
	registry.MustRegister(m.AllocateInterfaceOps)
	registry.MustRegister(m.AvailableInterfaces)
	registry.MustRegister(m.AvailableIPsPerSubnet)
	registry.MustRegister(m.Nodes)
	registry.MustRegister(m.Resync)
	m.poolMaintainer.Register(registry)
	m.k8sSync.Register(registry)
	m.resync.Register(registry)

	return m
}

func (p *prometheusMetrics) PoolMaintainerTrigger() trigger.MetricsObserver {
	return p.poolMaintainer
}

func (p *prometheusMetrics) K8sSyncTrigger() trigger.MetricsObserver {
	return p.k8sSync
}

func (p *prometheusMetrics) ResyncTrigger() trigger.MetricsObserver {
	return p.resync
}

func (p *prometheusMetrics) IncAllocationAttempt(status, subnetID string) {
	p.AllocateInterfaceOps.WithLabelValues(subnetID, status).Inc()
}

func (p *prometheusMetrics) AddIPAllocation(subnetID string, allocated int64) {
	p.AllocateIpOps.WithLabelValues(subnetID).Add(float64(allocated))
}

func (p *prometheusMetrics) AddIPRelease(subnetID string, released int64) {
	p.ReleaseIpOps.WithLabelValues(subnetID).Add(float64(released))
}

func (p *prometheusMetrics) SetAllocatedIPs(typ string, allocated int) {
	p.IPsAllocated.WithLabelValues(typ).Set(float64(allocated))
}

func (p *prometheusMetrics) SetAvailableInterfaces(available int) {
	p.AvailableInterfaces.Set(float64(available))
}

func (p *prometheusMetrics) SetAvailableIPsPerSubnet(subnetID string, availabilityZone string, available int) {
	p.AvailableIPsPerSubnet.WithLabelValues(subnetID, availabilityZone).Set(float64(available))
}

func (p *prometheusMetrics) SetNodes(label string, nodes int) {
	p.Nodes.WithLabelValues(label).Set(float64(nodes))
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

func NewTriggerMetrics(namespace, name string) *triggerMetrics {
	return &triggerMetrics{
		total: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: ipamSubsystem,
			Name:      name + "_queued_total",
			Help:      "Number of queued triggers",
		}),
		folds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: ipamSubsystem,
			Name:      name + "_folds",
			Help:      "Current level of folding",
		}),
		callDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: ipamSubsystem,
			Name:      name + "_duration_seconds",
			Help:      "Duration of trigger runs",
		}),
		latency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: ipamSubsystem,
			Name:      name + "_latency_seconds",
			Help:      "Latency between queue and trigger run",
		}),
	}
}

func (t *triggerMetrics) Register(registry *prometheus.Registry) {
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

// NoOpMetricsObserver is a no-operation implementation of the metrics observer
type NoOpMetricsObserver struct{}

// MetricsObserver implementation
func (m *NoOpMetricsObserver) PostRun(callDuration, latency time.Duration, folds int) {}
func (m *NoOpMetricsObserver) QueueEvent(reason string)                               {}

// NoOpMetrics is a no-operation implementation of the metrics
type NoOpMetrics struct{}

func (m *NoOpMetrics) IncAllocationAttempt(status, subnetID string)                              {}
func (m *NoOpMetrics) AddIPAllocation(subnetID string, allocated int64)                          {}
func (m *NoOpMetrics) AddIPRelease(subnetID string, released int64)                              {}
func (m *NoOpMetrics) SetAllocatedIPs(typ string, allocated int)                                 {}
func (m *NoOpMetrics) SetAvailableInterfaces(available int)                                      {}
func (m *NoOpMetrics) SetAvailableIPsPerSubnet(subnetID, availabilityZone string, available int) {}
func (m *NoOpMetrics) SetNodes(category string, nodes int)                                       {}
func (m *NoOpMetrics) IncResyncCount()                                                           {}
func (m *NoOpMetrics) PoolMaintainerTrigger() trigger.MetricsObserver                            { return &NoOpMetricsObserver{} }
func (m *NoOpMetrics) K8sSyncTrigger() trigger.MetricsObserver                                   { return &NoOpMetricsObserver{} }
func (m *NoOpMetrics) ResyncTrigger() trigger.MetricsObserver                                    { return &NoOpMetricsObserver{} }
