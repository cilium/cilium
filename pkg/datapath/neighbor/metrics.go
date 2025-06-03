// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type neighborMetrics struct {
	NeighborEntryRefreshCount metric.Counter
	NexthopLookupCount        metric.Counter
	NeighborEntryInsertCount  metric.Counter
	NeighborEntryDeleteCount  metric.Counter
}

func NewNeighborMetrics() *neighborMetrics {
	return &neighborMetrics{
		NeighborEntryRefreshCount: metric.NewCounter(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_neighbor_entry_refresh_count",
			Namespace:  metrics.Namespace,
			Subsystem:  "neighbor",
			Name:       "entry_refresh_count",
			Help:       "Number of times a neighbor entry was refreshed",
			Disabled:   true,
		}),
		NexthopLookupCount: metric.NewCounter(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_neighbor_nexthop_lookup_count",
			Namespace:  metrics.Namespace,
			Subsystem:  "neighbor",
			Name:       "nexthop_lookup_count",
			Help:       "Number of times a nexthop lookup was performed",
			Disabled:   true,
		}),
		NeighborEntryInsertCount: metric.NewCounter(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_neighbor_entry_insert_count",
			Namespace:  metrics.Namespace,
			Subsystem:  "neighbor",
			Name:       "entry_insert_count",
			Help:       "Number of times a neighbor entry was inserted",
			Disabled:   true,
		}),
		NeighborEntryDeleteCount: metric.NewCounter(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_neighbor_entry_delete_count",
			Namespace:  metrics.Namespace,
			Subsystem:  "neighbor",
			Name:       "entry_delete_count",
			Help:       "Number of times a neighbor entry was deleted",
			Disabled:   true,
		}),
	}
}
