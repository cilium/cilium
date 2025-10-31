// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
)

func ipsetNotifier(
	jg job.Group,
	cm *ClusterMesh,
	ipsetMgr ipset.Manager,
) {
	if cm == nil {
		return
	}

	initializer := ipsetMgr.NewInitializer()

	jg.Add(job.OneShot("clustermesh-ipset-notifier", func(ctx context.Context, _ cell.Health) error {
		// wait for initial nodes listing from all remote clusters
		// before allowing stale ipset entries deletion
		if err := cm.NodesSynced(ctx); err != nil {
			return err
		}
		initializer.InitDone()
		return nil
	}))
}

func nodeManagerNotifier(
	jg job.Group,
	cm *ClusterMesh,
	nodeMgr nodeManager.NodeManager,
) {
	jg.Add(job.OneShot("clustermesh-nodemanager-notifier", func(ctx context.Context, _ cell.Health) error {
		if cm != nil {
			// wait for initial nodes listing from all remote clusters
			// before allowing stale node deletion
			if err := cm.NodesSynced(ctx); err != nil {
				return err
			}
		}

		// Always call [MeshNodeSync], regardless of whether ClusterMesh is enabled,
		// to ensure uniformity of behavior, and trigger pruning of stale remote
		// nodes in case ClusterMesh was first enabled, and then disabled subsequently.
		nodeMgr.MeshNodeSync()
		return nil
	}))
}
