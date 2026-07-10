// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// TotalServices tracks the number of total global services per remote cluster.
	TotalServices metric.Vec[metric.Gauge]
	// TotalServiceExports tracks the number of total MCS-API service exports per remote cluster.
	TotalServiceExports metric.Vec[metric.Gauge]
}

func NewMetrics() Metrics {
	return Metrics{
		TotalServices: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: metrics.SubsystemClusterMesh,
			Name:      "remote_cluster_services",
			Help:      "The total number of services in the remote cluster",
		}, []string{metrics.LabelTargetCluster}),
		TotalServiceExports: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: metrics.SubsystemClusterMesh,
			Name:      "remote_cluster_service_exports",
			Help:      "The total number of MCS-API service exports in the remote cluster",
		}, []string{metrics.LabelTargetCluster}),
	}
}
