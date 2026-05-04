// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/node"
)

// registerNodeZoneWatcher registers a background job that watches Table[LocalNode] and
// refreshes the frontends with a configured TrafficDistribution to re-select backends.
func registerNodeZoneWatcher(jg job.Group, p zoneWatcherParams) {
	if p.Config.EnableServiceTopology {
		jg.Add(job.OneShot("zone-watcher", zoneWatcher{p}.run))
	}
}

type zoneWatcherParams struct {
	cell.In

	Config loadbalancer.Config
	Writer *Writer
	Nodes  statedb.Table[*node.LocalNode]
}

type zoneWatcher struct {
	zoneWatcherParams
}

func (zw zoneWatcher) run(ctx context.Context, health cell.Health) error {
	health.OK("Watching local node zone topology changes")
	var oldZone string
	for {
		txn := zw.Writer.WriteTxn()
		node, _, watch, found := zw.Nodes.GetWatch(txn, node.LocalNodeQuery)
		updated := false
		if found {
			newZone := node.Labels[corev1.LabelTopologyZone]
			// The zone changed if the label value shifted, or if the node newly
			// acquired or completely lost its zone label (e.g., label deleted,
			// where newZone becomes ""). We must trigger a refresh in all these
			// cases to allow topology fallback safeguards to re-evaluate.
			if newZone != oldZone {
				// Refresh all frontends associated with topology-aware services
				// as the backend selection might change based on the new zone.
				for fe := range zw.Writer.fes.All(txn) {
					if fe.Service.TrafficDistribution.RequiresZoneUpdate() {
						fe = fe.Clone()
						zw.Writer.refreshFrontend(txn, fe)
						zw.Writer.fes.Insert(txn, fe)
						updated = true
					}
				}
				// Track the previous zone to avoid infinite refresh churn on unrelated
				// node updates (e.g., annotation changes, pod CIDR updates).
				oldZone = newZone
			}
		}
		if updated {
			txn.Commit()
		} else {
			txn.Abort()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}
