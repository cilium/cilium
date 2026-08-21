// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	KVStoreSyncQueueSize        metric.DeletableVec[metric.Gauge]
	KVStoreSyncErrors           metric.DeletableVec[metric.Counter]
	KVStoreInitialSyncCompleted metric.DeletableVec[metric.Gauge]
}

func MetricsProvider() *Metrics {
	return &Metrics{
		KVStoreSyncQueueSize: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metrics.SubsystemKVStore,
			Name:      "sync_queue_size",
			Help:      "Number of elements queued for synchronization in the kvstore",
		}, []string{metrics.LabelScope, metrics.LabelSourceCluster}),
		KVStoreSyncErrors: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: metrics.SubsystemKVStore,
			Name:      "sync_errors_total",
			Help:      "Number of times synchronization to the kvstore failed",
		}, []string{metrics.LabelScope, metrics.LabelSourceCluster}),
		KVStoreInitialSyncCompleted: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metrics.SubsystemKVStore,
			Name:      "initial_sync_completed",
			Help:      "Whether the initial synchronization from/to the kvstore has completed",
		}, []string{metrics.LabelScope, metrics.LabelSourceCluster, metrics.LabelAction}),
	}
}

func (m *Metrics) DeRegister(sourceCluster string) {
	m.KVStoreSyncQueueSize.DeletePartialMatch(prometheus.Labels{metrics.LabelSourceCluster: sourceCluster})
	m.KVStoreSyncErrors.DeletePartialMatch(prometheus.Labels{metrics.LabelSourceCluster: sourceCluster})
	m.KVStoreInitialSyncCompleted.DeletePartialMatch(prometheus.Labels{metrics.LabelSourceCluster: sourceCluster})
}
