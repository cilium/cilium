// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

const nodeTableInitializerName = "clustermesh"

func nodeTableInitializer(
	jg job.Group,
	cm *ClusterMesh,
) {
	if cm == nil {
		return
	}

	txn := cm.conf.DB.WriteTxn(cm.nodeWriter.Table())
	initDone := cm.nodeWriter.RegisterInitializer(txn, nodeTableInitializerName)
	txn.Commit()

	jg.Add(job.OneShot("node-table-initializer", func(ctx context.Context, _ cell.Health) error {
		defer func() {
			txn := cm.conf.DB.WriteTxn(cm.nodeWriter.Table())
			initDone(txn)
			txn.Commit()
		}()

		// wait for initial nodes listing from all remote clusters
		// before allowing stale node deletion
		return cm.NodesSynced(ctx)
	}))
}
