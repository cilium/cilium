// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

func nodeManagerNotifier(
	jg job.Group,
	cm *ClusterMesh,
) {
	if cm == nil {
		return
	}

	txn := cm.conf.DB.WriteTxn(cm.nodeObserver.Table())
	initDone := cm.nodeObserver.RegisterInitializer(txn, "clustermesh")
	txn.Commit()

	jg.Add(job.OneShot("clustermesh-nodemanager-notifier", func(ctx context.Context, _ cell.Health) error {
		defer func() {
			txn := cm.conf.DB.WriteTxn(cm.nodeObserver.Table())
			initDone(txn)
			txn.Commit()
		}()

		// wait for initial nodes listing from all remote clusters
		// before allowing stale node deletion
		return cm.NodesSynced(ctx)
	}))
}
