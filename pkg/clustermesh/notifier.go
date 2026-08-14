// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/node"
)

func nodeTableInitializer(
	jg job.Group,
	cm *ClusterMesh,
	nodeWriter *node.NodeWriter,
	db *statedb.DB,
	nodes statedb.Table[*node.Node],
) {
	txn := db.WriteTxn(nodes)
	initialized := nodeWriter.RegisterInitializer(txn, "clustermesh-nodes")
	txn.Commit()
	jg.Add(job.OneShot("clustermesh-node-table-initializer", func(ctx context.Context, _ cell.Health) error {
		if cm != nil {
			// wait for initial nodes listing from all remote clusters
			// before allowing stale node deletion
			if err := cm.NodesSynced(ctx); err != nil {
				return err
			}
		}

		// Always complete mesh initialization, regardless of whether ClusterMesh is
		// enabled, so stale remote node pruning can proceed after it is disabled.
		txn := db.WriteTxn(nodes)
		initialized(txn)
		txn.Commit()
		return nil
	}))
}
