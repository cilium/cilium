// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type nodeMetrics struct {
	EventsReceived metric.Vec[metric.Counter]
	NumNodes       metric.Gauge
}

func NewNodeMetrics() *nodeMetrics {
	return &nodeMetrics{
		EventsReceived: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_nodes_all_events_received_total",
			Namespace:  metrics.Namespace,
			Subsystem:  "nodes",
			Name:       "all_events_received_total",
			Help:       "Number of node events received",
		}, []string{"event_type", "source"}),
		NumNodes: metric.NewGauge(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_nodes_all_num",
			Namespace:  metrics.Namespace,
			Subsystem:  "nodes",
			Name:       "all_num",
			Help:       "Number of nodes managed",
		}),
	}
}
