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

	// TotalServices tracks the number of total services per remote cluster.
	TotalServices metric.Vec[metric.Gauge]

	// TotalEndpoints tracks the number of total IPs per remote cluster.
	TotalEndpoints metric.Vec[metric.Gauge]
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

		TotalServices: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_" + subsystem + "_remote_cluster_services",
			Namespace:  metrics.Namespace,
			Subsystem:  subsystem,
			Name:       "remote_cluster_services",
			Help:       "The total number of services in the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),

		TotalEndpoints: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_" + subsystem + "_remote_cluster_endpoints",
			Namespace:  metrics.Namespace,
			Subsystem:  subsystem,
			Name:       "remote_cluster_endpoints",
			Help:       "The total number of endpoints in the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),
	}
}
