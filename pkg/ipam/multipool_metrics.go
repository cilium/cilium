// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	multiPoolSubsystem = "ipam_multipool"

	labelPoolName = "pool"
	labelIPFamily = "family"
)

type MultiPoolMetrics struct {
	// AvailableIPs tracks the number of available IPs in the multi-pool IPAM pool.
	AvailableIPs metric.DeletableVec[metric.Gauge]

	// UsedIPs tracks the number of IPs in use in the multi-pool IPAM pool.
	UsedIPs metric.DeletableVec[metric.Gauge]

	// NeededIPs tracks the number of IPs needed from the multi-pool IPAM pool to satisfy demand.
	NeededIPs metric.DeletableVec[metric.Gauge]

	// AllocatedBlocks tracks the number of CIDR blocks (pod CIDRs) allocated to this node from the pool.
	AllocatedBlocks metric.DeletableVec[metric.Gauge]
}

// NewMultiPoolMetrics returns a new MultiPoolMetrics instance.
func NewMultiPoolMetrics() MultiPoolMetrics {
	return MultiPoolMetrics{
		AvailableIPs: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: multiPoolSubsystem,
			Name:      "available_ips",
			Help:      "Total IPs available (in-use and free) in the multi-pool IPAM pool",
		}, []string{labelPoolName, labelIPFamily}),

		UsedIPs: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: multiPoolSubsystem,
			Name:      "used_ips",
			Help:      "IPs in use from the multi-pool IPAM pool",
		}, []string{labelPoolName, labelIPFamily}),

		NeededIPs: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: multiPoolSubsystem,
			Name:      "needed_ips",
			Help:      "IPs needed from the multi-pool IPAM pool to satisfy demand",
		}, []string{labelPoolName, labelIPFamily}),

		AllocatedBlocks: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: multiPoolSubsystem,
			Name:      "allocated_blocks",
			Help:      "CIDR blocks (pod CIDRs) allocated to this node from the multi-pool IPAM pool",
		}, []string{labelPoolName, labelIPFamily}),
	}
}

// enabled reports whether a MultiPoolMetrics was injected.
// When no MultiPoolMetrics is provided (e.g. the ENI allocator or tests) the vecs are nil and metric operations no-op.
func (m MultiPoolMetrics) enabled() bool {
	return m.AvailableIPs != nil && m.UsedIPs != nil && m.NeededIPs != nil && m.AllocatedBlocks != nil
}

// setPoolFamily sets the metrics for a given pool and family.
// No-op when no MultiPoolMetrics was injected (see enabled).
func (m MultiPoolMetrics) setPoolFamily(pool string, family Family, available, used, needed, allocatedBlocks int) {
	if !m.enabled() {
		return
	}
	fam := string(family)
	m.AvailableIPs.WithLabelValues(pool, fam).Set(float64(available))
	m.UsedIPs.WithLabelValues(pool, fam).Set(float64(used))
	m.NeededIPs.WithLabelValues(pool, fam).Set(float64(needed))
	m.AllocatedBlocks.WithLabelValues(pool, fam).Set(float64(allocatedBlocks))
}

// deletePool drops both families' series for a pool once it is no longer used.
// No-op when no MultiPoolMetrics was injected (see enabled).
func (m MultiPoolMetrics) deletePool(pool string) {
	if !m.enabled() {
		return
	}
	labels := prometheus.Labels{labelPoolName: pool}
	m.AvailableIPs.DeletePartialMatch(labels)
	m.UsedIPs.DeletePartialMatch(labels)
	m.NeededIPs.DeletePartialMatch(labels)
	m.AllocatedBlocks.DeletePartialMatch(labels)
}
