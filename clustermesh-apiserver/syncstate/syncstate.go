// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package syncstate

import (
	"context"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/spanstat"
)

var Cell = cell.Module(
	"sync",
	"ClusterMesh Sync",

	cell.Metric(MetricsProvider),
	cell.Provide(new),
)

func new(metrics Metrics, clusterInfo types.ClusterInfo) SyncState {
	ss := SyncState{StoppableWaitGroup: lock.NewStoppableWaitGroup()}

	go func() {
		syncTime := spanstat.Start()
		<-ss.WaitChannel()
		metrics.BootstrapDuration.WithLabelValues(clusterInfo.Name).Set(syncTime.Seconds())
	}()
	return ss
}

// SyncState is a wrapper around lock.StoppableWaitGroup used to keep track of the synchronization
// of various resources to the kvstore.
type SyncState struct {
	*lock.StoppableWaitGroup
}

// Complete returns true if all resources have been synchronized to the kvstore.
func (ss SyncState) Complete() bool {
	select {
	case <-ss.WaitChannel():
		return true
	default:
		return false
	}
}

// WaitForResource adds a resource to the SyncState and returns a callback function that should be
// called when the resource has been synchronized.
func (ss SyncState) WaitForResource() func(context.Context) {
	ss.Add()
	return func(_ context.Context) {
		ss.Done()
	}
}

// Metrics contains metrics that should only be exported by the
// clustermesh-apiserver or kvstoremesh.
type Metrics struct {
	// BootstrapDuration tracks the duration in seconds until ready to serve requests.
	BootstrapDuration metric.Vec[metric.Gauge]
}

func MetricsProvider() Metrics {
	return Metrics{
		BootstrapDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Name:      "bootstrap_seconds",
			Help:      "Duration in seconds to complete bootstrap",
		}, []string{metrics.LabelSourceCluster}),
	}
}
