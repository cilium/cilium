// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	nodeEventAdd    = "add"
	nodeEventUpdate = "update"
	nodeEventDelete = "delete"
)

type nodeMetrics struct {
	// EventsReceived tracks node events received by NodeWriter.
	EventsReceived metric.Vec[metric.Counter]

	// NumNodes tracks the number of objects in the node table.
	NumNodes metric.Gauge

	// DatapathValidations tracks node datapath validations.
	DatapathValidations metric.Counter
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

		DatapathValidations: metric.NewCounter(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_nodes_all_datapath_validations_total",
			Namespace:  metrics.Namespace,
			Subsystem:  "nodes",
			Name:       "all_datapath_validations_total",
			Help:       "Number of node datapath validations",
		}),
	}
}

func registerNodeMetrics(
	jobs job.Group,
	db *statedb.DB,
	nodes statedb.Table[*Node],
	metrics *nodeMetrics,
) {
	jobs.Add(job.OneShot("node-metrics", func(ctx context.Context, _ cell.Health) error {
		return trackNodeCount(ctx, db, nodes, metrics)
	}))
}

func trackNodeCount(
	ctx context.Context,
	db *statedb.DB,
	nodes statedb.Table[*Node],
	metrics *nodeMetrics,
) error {
	for {
		txn := db.ReadTxn()
		metrics.NumNodes.Set(float64(nodes.NumObjects(txn)))
		_, watch := nodes.AllWatch(txn)
		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}
