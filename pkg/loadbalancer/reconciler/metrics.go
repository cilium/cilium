// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	subsystemName = "loadbalancer"

	// idAllocator for unique loadbalancer.ServiceID
	idAllocTypeService = "service"

	// idAllocator for unique loadbalancer.BackendID
	idAllocTypeBackend = "backend"
)

type reconcilerMetrics struct {
	// IDAllocatorCapacity tracks the size of the numeric range of IDs available
	// from an idAllocator.
	IDAllocatorCapacity metric.Vec[metric.Gauge]

	// IDAllocatorUsed tracks the number of used IDs within the capacity of an
	// idAllocator.
	IDAllocatorUsed metric.Vec[metric.Gauge]

	// IDAllocatorAttempts tracks the number of attempts by an idAllocator to
	// provide a new ID.
	IDAllocatorAttempts metric.Vec[metric.Counter]

	// IDAllocatorFailures tracks the number of times an idAllocator failed to
	// provide an ID, e.g. if the allocator had consumed its entire range of IDs.
	IDAllocatorFailures metric.Vec[metric.Counter]

	// IDMappingsPendingRestore tracks address-to-ID mappings restored from BPF
	// that have not yet been adopted or pruned by the reconciler.
	IDMappingsPendingRestore metric.Vec[metric.Gauge]
}

// newReconcilerMetrics returns a pointer to reconcilerMetrics.
func newReconcilerMetrics() *reconcilerMetrics {
	idAllocTypeLabels := metric.Labels{
		{Name: metrics.LabelType, Values: metric.NewValues(
			idAllocTypeService,
			idAllocTypeBackend,
		)},
	}

	return &reconcilerMetrics{
		IDAllocatorCapacity: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemName,
			Name:      "id_capacity",
			Help:      "Number of loadbalancer IDs in the allocation range",
		}, idAllocTypeLabels),
		IDAllocatorUsed: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemName,
			Name:      "id_allocations",
			Help:      "Number of loadbalancer IDs currently allocated",
		}, idAllocTypeLabels),
		IDAllocatorAttempts: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemName,
			Name:      "id_allocation_attempts_total",
			Help:      "Total number of loadbalancer ID allocation attempts",
		}, idAllocTypeLabels),
		IDAllocatorFailures: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemName,
			Name:      "id_allocation_failures_total",
			Help:      "Total number of loadbalancer ID allocation failures",
		}, idAllocTypeLabels),
		IDMappingsPendingRestore: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemName,
			Name:      "id_mappings_pending_restore",
			Help:      "Number of loadbalancer address-to-ID mappings pending restoration",
		}, idAllocTypeLabels),
	}
}

func newIDAllocatorMetrics(m *reconcilerMetrics, idType string) idAllocatorMetrics {
	return idAllocatorMetrics{
		capacity:           m.IDAllocatorCapacity.WithLabelValues(idType),
		allocations:        m.IDAllocatorUsed.WithLabelValues(idType),
		allocationAttempts: m.IDAllocatorAttempts.WithLabelValues(idType),
		allocationFailures: m.IDAllocatorFailures.WithLabelValues(idType),
	}
}

func (m *reconcilerMetrics) setIDMappingsPendingRestore(idType string, count int) {
	m.IDMappingsPendingRestore.WithLabelValues(idType).Set(float64(count))
}
