// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// TotalNodes tracks the number of total nodes per remote cluster.
	TotalNodes metric.Vec[metric.Gauge]

	// TotalGlobalServices tracks the number of total global services per remote cluster.
	TotalGlobalServices metric.Vec[metric.Gauge]

	// TotalIdentities tracks the number of total identities per remote cluster.
	TotalIdentities metric.Vec[metric.Gauge]
}

func NewMetrics() Metrics {
	return Metrics{
		TotalNodes: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_" + subsystem + "_remote_cluster_nodes",
			Namespace:  metrics.Namespace,
			Subsystem:  subsystem,
			Name:       "remote_cluster_nodes",
			Help:       "The total number of nodes in the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),

		TotalGlobalServices: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_" + subsystem + "_remote_cluster_global_services",
			Namespace:  metrics.Namespace,
			Subsystem:  subsystem,
			Name:       "remote_cluster_global_services",
			Help:       "The total number of global services in the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),

		TotalIdentities: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_" + subsystem + "_remote_cluster_global_identities",
			Namespace:  metrics.Namespace,
			Subsystem:  subsystem,
			Name:       "remote_cluster_identities",
			Help:       "The total number of identities in the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),
	}
}
