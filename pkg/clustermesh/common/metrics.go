// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// TotalRemoteClusters tracks the total number of remote clusters.
	TotalRemoteClusters metric.Vec[metric.Gauge]
	// LastFailureTimestamp tracks the last failure timestamp.
	LastFailureTimestamp metric.Vec[metric.Gauge]
	// ReadinessStatus tracks the readiness status of remote clusters.
	ReadinessStatus metric.Vec[metric.Gauge]
	// TotalFailure tracks the number of failures when connecting to remote clusters.
	TotalFailures metric.Vec[metric.Gauge]
}

func MetricsProvider(subsystem string) func() Metrics {
	return func() Metrics {
		return Metrics{
			TotalRemoteClusters: metric.NewGaugeVec(metric.GaugeOpts{
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "remote_clusters",
				Help:      "The total number of remote clusters meshed with the local cluster",
			}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName}),

			LastFailureTimestamp: metric.NewGaugeVec(metric.GaugeOpts{
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "remote_cluster_last_failure_ts",
				Help:      "The timestamp of the last failure of the remote cluster",
			}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),

			ReadinessStatus: metric.NewGaugeVec(metric.GaugeOpts{
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "remote_cluster_readiness_status",
				Help:      "The readiness status of the remote cluster",
			}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),

			TotalFailures: metric.NewGaugeVec(metric.GaugeOpts{
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "remote_cluster_failures",
				Help:      "The total number of failures related to the remote cluster",
			}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),
		}
	}
}
