// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// LeaderElectionStatus indicates state of leader election
	LeaderElectionStatus metric.Vec[metric.Gauge]
}

func MetricsProvider() Metrics {
	return Metrics{
		LeaderElectionStatus: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "",
			Name:      "leader_election_master_status",
			Help:      "leader election status",
		}, []string{metrics.LabelLeaderElectionName}),
	}
}
