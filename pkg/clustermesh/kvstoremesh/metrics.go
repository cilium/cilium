// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// LeaderElectionStatus indicates state of leader election
	LeaderElectionStatus metric.Gauge
}

func MetricsProvider() Metrics {
	return Metrics{
		// LeaderElectionStatus mimic similar metric in controller-manager
		// by using the same metrics name and forcing a name label
		LeaderElectionStatus: metric.NewGauge(metric.GaugeOpts{
			Namespace:   metrics.Namespace,
			Subsystem:   "",
			Name:        "leader_election_master_status",
			Help:        "The leader election status",
			ConstLabels: map[string]string{"name": "kvstoremesh"},
		}),
	}
}
