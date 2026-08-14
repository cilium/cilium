// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb/reconciler"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const baseBackgroundSyncInterval = time.Minute

func registerNodeBackgroundSync(
	jobs job.Group,
	writer *NodeWriter,
	clusterSizeInterval ClusterSizeDependantIntervalFunc,
) {
	jobs.Add(job.OneShot("backgroundSync", func(ctx context.Context, health cell.Health) error {
		return writer.backgroundSync(ctx, health, clusterSizeInterval)
	}))
}

// backgroundSync periodically refreshes the realized state for every node.
// Nodes are paced across a cluster-size-dependent interval to avoid refreshing
// the whole cluster at once.
func (w *NodeWriter) backgroundSync(
	ctx context.Context,
	health cell.Health,
	clusterSizeInterval ClusterSizeDependantIntervalFunc,
) error {
	for {
		syncInterval := clusterSizeInterval(baseBackgroundSyncInterval)
		w.log.Debug(
			"Starting new iteration of background sync",
			logfields.SyncInterval, syncInterval,
		)
		w.singleBackgroundLoop(ctx, syncInterval)
		w.log.Debug(
			"Finished iteration of background sync",
			logfields.SyncInterval, syncInterval,
		)

		health.OK(fmt.Sprintf("Next node refresh in %s", syncInterval))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(syncInterval):
		}
	}
}

func (w *NodeWriter) singleBackgroundLoop(
	ctx context.Context,
	expectedLoopTime time.Duration,
) {
	targets := []string{}
	for n := range w.nodes.All(w.db.ReadTxn()) {
		targets = append(targets, n.Fullname())
	}

	// Refresh the first node immediately, then spread the remaining nodes evenly
	// over the expected loop time.
	limiter := rate.NewLimiter(
		rate.Limit(float64(len(targets))/expectedLoopTime.Seconds()),
		1,
	)
	for _, fullname := range targets {
		if err := limiter.Wait(ctx); err != nil {
			return
		}
		w.refreshNode(fullname)
		if !w.waitForNodeRefresh(ctx, fullname) {
			return
		}
	}
}

func (w *NodeWriter) waitForNodeRefresh(ctx context.Context, fullname string) bool {
	txn := w.db.ReadTxn()
	for {
		n, _, watch, found := w.nodes.GetWatch(txn, NodeByName(fullname))
		if !found || reconciliationFinished(n) {
			return true
		}

		select {
		case <-ctx.Done():
			return false
		case <-watch:
			txn = w.db.ReadTxn()
		}
	}
}

func (w *NodeWriter) refreshNode(fullname string) {
	txn := w.db.WriteTxn(w.nodes)
	defer txn.Abort()

	n, _, found := w.nodes.Get(txn, NodeByName(fullname))
	if !found {
		return
	}
	w.metrics.DatapathValidations.Inc()

	updated := n.DeepCopy()
	changed := false
	for name, status := range updated.Statuses.All() {
		if status.Kind == reconciler.StatusKindDone {
			updated.Statuses = updated.Statuses.Set(name, reconciler.StatusRefreshing())
			changed = true
		}
	}
	if !changed {
		return
	}
	w.nodes.Insert(txn, updated)
	txn.Commit()
}
