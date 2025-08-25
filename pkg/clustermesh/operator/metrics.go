// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// TotalGlobalServices tracks the number of total global services in a remote cluster.
	TotalGlobalServices metric.Vec[metric.Gauge]
	// TotalServiceExports tracks the number of total MCS-API service exports in a remote cluster.
	TotalServiceExports metric.Vec[metric.Gauge]
}

func NewMetrics() Metrics {
	return Metrics{
		TotalGlobalServices: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "remote_cluster_global_services",
			Help:      "The total number of global services in the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelTargetCluster}),
		TotalServiceExports: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "remote_cluster_service_exports",
			Help:      "The total number of MCS-API service exports in the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelTargetCluster}),
	}
}
