// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	ciliumMetrics "github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

const ipamSubsystem = "ipam"

const LabelTargetNodeName = "target_node"

// Metrics holds all Prometheus metrics for the IPAM node manager.
type Metrics struct {
	// Per-node IP metrics
	AvailableIPs metric.DeletableVec[metric.Gauge]
	UsedIPs      metric.DeletableVec[metric.Gauge]
	NeededIPs    metric.DeletableVec[metric.Gauge]

	// Deprecated, will be removed in version 1.15.
	// Use AvailableIPs, UsedIPs and NeededIPs instead.
	IPsAllocated metric.Vec[metric.Gauge]

	// IP and interface allocation counters
	AllocateIpOps        metric.Vec[metric.Counter]
	ReleaseIpOps         metric.Vec[metric.Counter]
	AllocateInterfaceOps metric.Vec[metric.Counter]

	// Interface availability
	InterfaceCandidates   metric.Gauge
	EmptyInterfaceSlots   metric.Gauge
	AvailableIPsPerSubnet metric.Vec[metric.Gauge]

	// Deprecated, will be removed in version 1.14:
	// Use InterfaceCandidates and EmptyInterfaceSlots instead
	AvailableInterfaces metric.Gauge

	// Node category counts
	Nodes metric.Vec[metric.Gauge]

	// Resync counter
	ResyncTotal metric.Counter

	// Allocation/release latency histograms
	Allocation             metric.Vec[metric.Observer]
	Release                metric.Vec[metric.Observer]
	BackgroundSyncDuration metric.Vec[metric.Observer]

	// Trigger metrics
	// pool_maintainer is a more generic name, but for backward compatibility
	// of dashboard, keep the metric name deficit_resolver unchanged
	PoolMaintainerQueued       metric.Counter
	PoolMaintainerFolds        metric.Gauge
	PoolMaintainerCallDuration metric.Histogram
	PoolMaintainerLatency      metric.Histogram

	// Trigger metrics – k8s sync
	K8sSyncQueued       metric.Counter
	K8sSyncFolds        metric.Gauge
	K8sSyncCallDuration metric.Histogram
	K8sSyncLatency      metric.Histogram

	// Trigger metrics – resync
	ResyncQueued       metric.Counter
	ResyncFolds        metric.Gauge
	ResyncCallDuration metric.Histogram
	ResyncLatency      metric.Histogram
}

// NewMetrics returns a new interface metrics implementation.
func NewMetrics() *Metrics {
	ns := ciliumMetrics.CiliumOperatorNamespace
	return &Metrics{
		AvailableIPs: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "available_ips",
			Help:      "Total available IPs on Node for IPAM allocation",
		}, []string{LabelTargetNodeName}),

		UsedIPs: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "used_ips",
			Help:      "Total used IPs on Node for IPAM allocation",
		}, []string{LabelTargetNodeName}),

		NeededIPs: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "needed_ips",
			Help:      "Number of IPs that are needed on the Node to satisfy IPAM allocation requests",
		}, []string{LabelTargetNodeName}),

		IPsAllocated: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "ips",
			Help:      "Number of IPs allocated",
		}, []string{"type"}),

		AllocateIpOps: metric.NewCounterVec(metric.CounterOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "ip_allocation_ops",
			Help:      "Number of IP allocation operations",
		}, []string{"subnet_id"}),

		ReleaseIpOps: metric.NewCounterVec(metric.CounterOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "ip_release_ops",
			Help:      "Number of IP release operations",
		}, []string{"subnet_id"}),

		AllocateInterfaceOps: metric.NewCounterVec(metric.CounterOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "interface_creation_ops",
			Help:      "Number of interfaces allocated",
		}, []string{"subnet_id"}),

		AvailableInterfaces: metric.NewGauge(metric.GaugeOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "available_interfaces",
			Help:      "Number of interfaces with addresses available",
		}),

		InterfaceCandidates: metric.NewGauge(metric.GaugeOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "interface_candidates",
			Help:      "Number of attached interfaces with IPs available for allocation",
		}),

		EmptyInterfaceSlots: metric.NewGauge(metric.GaugeOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "empty_interface_slots",
			Help:      "Number of empty interface slots available for interfaces to be attached",
		}),

		AvailableIPsPerSubnet: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "available_ips_per_subnet",
			Help:      "Number of available IPs per subnet ID",
		}, []string{"subnet_id", "availability_zone"}),

		Nodes: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "nodes",
			Help:      "Number of nodes by category { total | in-deficit | at-capacity }",
		}, []string{"category"}),

		ResyncTotal: metric.NewCounter(metric.CounterOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "resync_total",
			Help:      "Number of resync operations to synchronize and resolve IP deficit of nodes",
		}),

		Allocation: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "allocation_duration_seconds",
			Help:      "Allocation ip or interface latency in seconds",
			Buckets: merge(
				prometheus.LinearBuckets(0.25, 0.25, 2),
				prometheus.LinearBuckets(1, 1, 60),
			),
		}, []string{"type", "status", "subnet_id"}),

		Release: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "release_duration_seconds",
			Help:      "Release ip or interface latency in seconds",
			Buckets: merge(
				prometheus.LinearBuckets(0.25, 0.25, 2),
				prometheus.LinearBuckets(1, 1, 60),
			),
		}, []string{"type", "status", "subnet_id"}),

		BackgroundSyncDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: ns,
			Subsystem: ipamSubsystem,
			Name:      "background_sync_duration_seconds",
			Help:      "Duration in seconds of the background API resync",
			Buckets: merge(
				prometheus.LinearBuckets(0.25, 0.25, 2),
				prometheus.LinearBuckets(1, 1, 60),
			),
		}, []string{"status"}),

		PoolMaintainerQueued:       newTriggerCounter(ns, "deficit_resolver"),
		PoolMaintainerFolds:        newTriggerFolds(ns, "deficit_resolver"),
		PoolMaintainerCallDuration: newTriggerDuration(ns, "deficit_resolver"),
		PoolMaintainerLatency:      newTriggerLatency(ns, "deficit_resolver"),

		K8sSyncQueued:       newTriggerCounter(ns, "k8s_sync"),
		K8sSyncFolds:        newTriggerFolds(ns, "k8s_sync"),
		K8sSyncCallDuration: newTriggerDuration(ns, "k8s_sync"),
		K8sSyncLatency:      newTriggerLatency(ns, "k8s_sync"),

		ResyncQueued:       newTriggerCounter(ns, "resync"),
		ResyncFolds:        newTriggerFolds(ns, "resync"),
		ResyncCallDuration: newTriggerDuration(ns, "resync"),
		ResyncLatency:      newTriggerLatency(ns, "resync"),
	}
}

// ipam.MetricsAPI implementation

func (m *Metrics) SetIPAvailable(node string, cap int) {
	m.AvailableIPs.WithLabelValues(node).Set(float64(cap))
}

func (m *Metrics) SetIPUsed(node string, usage int) {
	m.UsedIPs.WithLabelValues(node).Set(float64(usage))
}

func (m *Metrics) SetIPNeeded(node string, usage int) {
	m.NeededIPs.WithLabelValues(node).Set(float64(usage))
}

// DeleteNode removes all per-node metrics for the given node.
func (m *Metrics) DeleteNode(node string) {
	m.AvailableIPs.DeleteLabelValues(node)
	m.UsedIPs.DeleteLabelValues(node)
	m.NeededIPs.DeleteLabelValues(node)
}

func (m *Metrics) AllocationAttempt(typ, status, subnetID string, observe float64) {
	m.Allocation.WithLabelValues(typ, status, subnetID).Observe(observe)
}

func (m *Metrics) ReleaseAttempt(typ, status, subnetID string, observe float64) {
	m.Release.WithLabelValues(typ, status, subnetID).Observe(observe)
}

func (m *Metrics) IncInterfaceAllocation(subnetID string) {
	m.AllocateInterfaceOps.WithLabelValues(subnetID).Inc()
}

func (m *Metrics) AddIPAllocation(subnetID string, allocated int64) {
	m.AllocateIpOps.WithLabelValues(subnetID).Add(float64(allocated))
}

func (m *Metrics) AddIPRelease(subnetID string, released int64) {
	m.ReleaseIpOps.WithLabelValues(subnetID).Add(float64(released))
}

func (m *Metrics) SetAllocatedIPs(typ string, allocated int) {
	m.IPsAllocated.WithLabelValues(typ).Set(float64(allocated))
}

func (m *Metrics) SetAvailableInterfaces(available int) {
	m.AvailableInterfaces.Set(float64(available))
}

func (m *Metrics) SetInterfaceCandidates(interfaceCandidates int) {
	m.InterfaceCandidates.Set(float64(interfaceCandidates))
}

func (m *Metrics) SetEmptyInterfaceSlots(emptyInterfaceSlots int) {
	m.EmptyInterfaceSlots.Set(float64(emptyInterfaceSlots))
}

func (m *Metrics) SetAvailableIPsPerSubnet(subnetID string, availabilityZone string, available int) {
	m.AvailableIPsPerSubnet.WithLabelValues(subnetID, availabilityZone).Set(float64(available))
}

func (m *Metrics) SetNodes(label string, nodes int) {
	m.Nodes.WithLabelValues(label).Set(float64(nodes))
}

func (m *Metrics) IncResyncCount() {
	m.ResyncTotal.Inc()
}

func (m *Metrics) ObserveBackgroundSync(status string, duration time.Duration) {
	m.BackgroundSyncDuration.WithLabelValues(status).Observe(duration.Seconds())
}

func (m *Metrics) PoolMaintainerTrigger() trigger.MetricsObserver {
	return &triggerObserver{
		queued:       m.PoolMaintainerQueued,
		folds:        m.PoolMaintainerFolds,
		callDuration: m.PoolMaintainerCallDuration,
		latency:      m.PoolMaintainerLatency,
	}
}

func (m *Metrics) K8sSyncTrigger() trigger.MetricsObserver {
	return &triggerObserver{
		queued:       m.K8sSyncQueued,
		folds:        m.K8sSyncFolds,
		callDuration: m.K8sSyncCallDuration,
		latency:      m.K8sSyncLatency,
	}
}

func (m *Metrics) ResyncTrigger() trigger.MetricsObserver {
	return &triggerObserver{
		queued:       m.ResyncQueued,
		folds:        m.ResyncFolds,
		callDuration: m.ResyncCallDuration,
		latency:      m.ResyncLatency,
	}
}

// triggerObserver implements trigger.MetricsObserver using metric.* types.
type triggerObserver struct {
	queued       metric.Counter
	folds        metric.Gauge
	callDuration metric.Histogram
	latency      metric.Histogram
}

func (t *triggerObserver) QueueEvent(reason string) {
	t.queued.Inc()
}

func (t *triggerObserver) PostRun(callDuration, latency time.Duration, folds int) {
	t.callDuration.Observe(callDuration.Seconds())
	t.latency.Observe(latency.Seconds())
	t.folds.Set(float64(folds))
}

// Helpers for creating trigger metric fields.

func newTriggerCounter(ns, name string) metric.Counter {
	return metric.NewCounter(metric.CounterOpts{
		Namespace: ns,
		Subsystem: ipamSubsystem,
		Name:      name + "_queued_total",
		Help:      "Number of queued triggers",
	})
}

func newTriggerFolds(ns, name string) metric.Gauge {
	return metric.NewGauge(metric.GaugeOpts{
		Namespace: ns,
		Subsystem: ipamSubsystem,
		Name:      name + "_folds",
		Help:      "Current level of folding",
	})
}

func newTriggerDuration(ns, name string) metric.Histogram {
	return metric.NewHistogram(metric.HistogramOpts{
		Namespace: ns,
		Subsystem: ipamSubsystem,
		Name:      name + "_duration_seconds",
		Help:      "Duration of trigger runs",
		Buckets: []float64{0.005, 0.025, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3,
			4, 5, 6, 8, 10, 15, 20, 30, 45, 60},
	})
}

func newTriggerLatency(ns, name string) metric.Histogram {
	return metric.NewHistogram(metric.HistogramOpts{
		Namespace: ns,
		Subsystem: ipamSubsystem,
		Name:      name + "_latency_seconds",
		Help:      "Latency between queue and trigger run",
		Buckets: []float64{0.005, 0.025, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3,
			4, 5, 6, 8, 10, 15, 20, 30, 45, 60},
	})
}

// SinceInSeconds returns the time elapsed since start in seconds.
func SinceInSeconds(start time.Time) float64 {
	return time.Since(start).Seconds()
}

func merge(slices ...[]float64) []float64 {
	result := make([]float64, 1)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}
