// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/trigger"
)

const ipamSubsystem = "ipam"

type prometheusMetrics struct {
	registry             metrics.RegisterGatherer
	Allocation           *prometheus.HistogramVec
	Release              *prometheus.HistogramVec
	AllocateInterfaceOps *prometheus.CounterVec
	AllocateIpOps        *prometheus.CounterVec
	ReleaseIpOps         *prometheus.CounterVec
	AvailableIPs         *prometheus.GaugeVec
	UsedIPs              *prometheus.GaugeVec
	NeededIPs            *prometheus.GaugeVec
	// Deprecated, will be removed in version 1.15.
	// Use AvailableIPs, UsedIPs and NeededIPs instead.
	IPsAllocated *prometheus.GaugeVec
	// Deprecated, will be removed in version 1.14:
	// Use InterfaceCandidates and EmptyInterfaceSlots instead
	AvailableInterfaces   prometheus.Gauge
	InterfaceCandidates   prometheus.Gauge
	EmptyInterfaceSlots   prometheus.Gauge
	AvailableIPsPerSubnet *prometheus.GaugeVec
	Nodes                 *prometheus.GaugeVec
	Resync                prometheus.Counter
	poolMaintainer        *triggerMetrics
	k8sSync               *triggerMetrics
	resync                *triggerMetrics
}

const LabelTargetNodeName = "target_node"

// NewPrometheusMetrics returns a new interface metrics implementation backed by
// Prometheus metrics.
func NewPrometheusMetrics(namespace string, registry metrics.RegisterGatherer) *prometheusMetrics {
	m := &prometheusMetrics{
		registry: registry,
	}

	m.AvailableIPs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "available_ips",
		Help:      "Total available IPs on Node for IPAM allocation",
	}, []string{LabelTargetNodeName})

	m.UsedIPs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "used_ips",
		Help:      "Total used IPs on Node for IPAM allocation",
	}, []string{LabelTargetNodeName})

	m.NeededIPs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "needed_ips",
		Help:      "Number of IPs that are needed on the Node to satisfy IPAM allocation requests",
	}, []string{LabelTargetNodeName})

	m.IPsAllocated = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "ips",
		Help:      "Number of IPs allocated",
	}, []string{"type"})

	m.AllocateIpOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "ip_allocation_ops",
		Help:      "Number of IP allocation operations",
	}, []string{"subnet_id"})

	m.ReleaseIpOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "ip_release_ops",
		Help:      "Number of IP release operations",
	}, []string{"subnet_id"})

	m.AllocateInterfaceOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "interface_creation_ops",
		Help:      "Number of interfaces allocated",
	}, []string{"subnet_id"})

	m.AvailableInterfaces = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "available_interfaces",
		Help:      "Number of interfaces with addresses available",
	})

	m.InterfaceCandidates = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "interface_candidates",
		Help:      "Number of attached interfaces with IPs available for allocation",
	})

	m.EmptyInterfaceSlots = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "empty_interface_slots",
		Help:      "Number of empty interface slots available for interfaces to be attached",
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

	m.Allocation = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "allocation_duration_seconds",
		Help:      "Allocation ip or interface latency in seconds",
		Buckets: merge(
			prometheus.LinearBuckets(0.25, 0.25, 2), // 0.25s, 0.50s
			prometheus.LinearBuckets(1, 1, 60),      // 1s, 2s, 3s, ... 60s,
		),
	}, []string{"type", "status", "subnet_id"})

	m.Release = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: ipamSubsystem,
		Name:      "release_duration_seconds",
		Help:      "Release ip or interface latency in seconds",
		Buckets: merge(
			prometheus.LinearBuckets(0.25, 0.25, 2), // 0.25s, 0.50s
			prometheus.LinearBuckets(1, 1, 60),      // 1s, 2s, 3s, ... 60s,
		),
	}, []string{"type", "status", "subnet_id"})

	// pool_maintainer is a more generic name, but for backward compatibility
	// of dashboard, keep the metric name deficit_resolver unchanged
	m.poolMaintainer = NewTriggerMetrics(namespace, "deficit_resolver")
	m.k8sSync = NewTriggerMetrics(namespace, "k8s_sync")
	m.resync = NewTriggerMetrics(namespace, "resync")

	registry.MustRegister(m.AvailableIPs)
	registry.MustRegister(m.UsedIPs)
	registry.MustRegister(m.NeededIPs)

	registry.MustRegister(m.IPsAllocated)
	registry.MustRegister(m.AllocateIpOps)
	registry.MustRegister(m.ReleaseIpOps)
	registry.MustRegister(m.AllocateInterfaceOps)
	registry.MustRegister(m.AvailableInterfaces)
	registry.MustRegister(m.InterfaceCandidates)
	registry.MustRegister(m.EmptyInterfaceSlots)
	registry.MustRegister(m.AvailableIPsPerSubnet)
	registry.MustRegister(m.Nodes)
	registry.MustRegister(m.Resync)
	registry.MustRegister(m.Allocation)
	registry.MustRegister(m.Release)
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

func (p *prometheusMetrics) IncInterfaceAllocation(subnetID string) {
	p.AllocateInterfaceOps.WithLabelValues(subnetID).Inc()
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

func (p *prometheusMetrics) SetInterfaceCandidates(interfaceCandidates int) {
	p.InterfaceCandidates.Set(float64(interfaceCandidates))
}

func (p *prometheusMetrics) SetEmptyInterfaceSlots(emptyInterfaceSlots int) {
	p.EmptyInterfaceSlots.Set(float64(emptyInterfaceSlots))
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

func (p *prometheusMetrics) AllocationAttempt(typ, status, subnetID string, observe float64) {
	p.Allocation.WithLabelValues(typ, status, subnetID).Observe(observe)
}

func (p *prometheusMetrics) ReleaseAttempt(typ, status, subnetID string, observe float64) {
	p.Release.WithLabelValues(typ, status, subnetID).Observe(observe)
}

// Per Node metrics.
func (p *prometheusMetrics) SetIPAvailable(node string, cap int) {
	p.AvailableIPs.WithLabelValues(node).Set(float64(cap))
}

func (p *prometheusMetrics) SetIPUsed(node string, usage int) {
	p.UsedIPs.WithLabelValues(node).Set(float64(usage))
}

func (p *prometheusMetrics) SetIPNeeded(node string, usage int) {
	p.NeededIPs.WithLabelValues(node).Set(float64(usage))
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

func (t *triggerMetrics) Register(registry metrics.RegisterGatherer) {
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

func (m *NoOpMetrics) AllocationAttempt(typ, status, subnetID string, observe float64)           {}
func (m *NoOpMetrics) ReleaseAttempt(typ, status, subnetID string, observe float64)              {}
func (m *NoOpMetrics) IncInterfaceAllocation(subnetID string)                                    {}
func (m *NoOpMetrics) AddIPAllocation(subnetID string, allocated int64)                          {}
func (m *NoOpMetrics) AddIPRelease(subnetID string, released int64)                              {}
func (m *NoOpMetrics) SetAllocatedIPs(typ string, allocated int)                                 {}
func (m *NoOpMetrics) SetAvailableInterfaces(available int)                                      {}
func (m *NoOpMetrics) SetInterfaceCandidates(interfaceCandidates int)                            {}
func (m *NoOpMetrics) SetEmptyInterfaceSlots(emptyInterfaceSlots int)                            {}
func (m *NoOpMetrics) SetAvailableIPsPerSubnet(subnetID, availabilityZone string, available int) {}
func (m *NoOpMetrics) SetNodes(category string, nodes int)                                       {}
func (m *NoOpMetrics) IncResyncCount()                                                           {}
func (m *NoOpMetrics) SetIPAvailable(node string, n int)                                         {}
func (m *NoOpMetrics) SetIPUsed(node string, n int)                                              {}
func (m *NoOpMetrics) SetIPNeeded(node string, n int)                                            {}
func (m *NoOpMetrics) PoolMaintainerTrigger() trigger.MetricsObserver                            { return &NoOpMetricsObserver{} }
func (m *NoOpMetrics) K8sSyncTrigger() trigger.MetricsObserver                                   { return &NoOpMetricsObserver{} }
func (m *NoOpMetrics) ResyncTrigger() trigger.MetricsObserver                                    { return &NoOpMetricsObserver{} }

func merge(slices ...[]float64) []float64 {
	result := make([]float64, 1)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}

// SinceInSeconds gets the time since the specified start in seconds.
func SinceInSeconds(start time.Time) float64 {
	return time.Since(start).Seconds()
}
