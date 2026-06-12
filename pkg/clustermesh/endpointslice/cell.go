// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslice

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/observer"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const Name observer.Name = "endpoint slices"

type params struct {
	cell.In

	Logger       *slog.Logger
	StoreFactory store.Factory
	Metrics      Metrics
	types.ServiceModeV2Config
}

var Cell = cell.Module(
	"clustermesh-endpointslice",
	"ClusterMesh EndpointSlice observer",

	cell.Provide(func(params params) observer.FactoryOut {
		return observer.NewFactoryOut(newFactory(params))
	}),
)

type Metrics struct {
	TotalEndpointSlices metric.Vec[metric.Gauge]
}

func MetricsProvider(namespace string) func() Metrics {
	return func() Metrics {
		return Metrics{
			TotalEndpointSlices: metric.NewGaugeVec(metric.GaugeOpts{
				Namespace: namespace,
				Subsystem: metrics.SubsystemClusterMesh,
				Name:      "remote_cluster_endpoint_slices",
				Help:      "The total number of endpoint slices in the remote cluster",
			}, []string{metrics.LabelTargetCluster}),
		}
	}
}
