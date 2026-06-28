// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// TotalNodes tracks the number of total nodes per remote cluster.
	TotalNodes metric.DeletableVec[metric.Gauge]

	// TotalServices tracks the number of total services per remote cluster.
	TotalServices metric.DeletableVec[metric.Gauge]

	// TotalEndpoints tracks the number of total IPs per remote cluster.
	TotalEndpoints metric.DeletableVec[metric.Gauge]
}

func NewMetrics() Metrics {
	return Metrics{
		TotalNodes: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metrics.SubsystemClusterMesh,
			Name:      "remote_cluster_nodes",
			Help:      "The total number of nodes in the remote cluster",
		}, []string{metrics.LabelTargetCluster}),

		TotalServices: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metrics.SubsystemClusterMesh,
			Name:      "remote_cluster_services",
			Help:      "The total number of services in the remote cluster",
		}, []string{metrics.LabelTargetCluster}),

		TotalEndpoints: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metrics.SubsystemClusterMesh,
			Name:      "remote_cluster_endpoints",
			Help:      "The total number of endpoints in the remote cluster",
		}, []string{metrics.LabelTargetCluster}),
	}
}

func (m *Metrics) DeRegister(targetCluster string) {
	m.TotalNodes.DeletePartialMatch(prometheus.Labels{metrics.LabelTargetCluster: targetCluster})
	m.TotalServices.DeletePartialMatch(prometheus.Labels{metrics.LabelTargetCluster: targetCluster})
	m.TotalEndpoints.DeletePartialMatch(prometheus.Labels{metrics.LabelTargetCluster: targetCluster})
}
