// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
)

func ipsetSyncer(
	logger logrus.FieldLogger,
	lc cell.Lifecycle,
	jg job.Group,
	health cell.Health,
	cm *ClusterMesh,
	ipsetMgr ipset.Manager,
) {
	if cm == nil {
		return
	}

	initializer := ipsetMgr.NewInitializer()

	jg.Add(job.OneShot("clustermesh-ipset-syncer", func(ctx context.Context, _ cell.Health) error {
		// wait for initial nodes listing from all remote clusters
		// before allowing stale ipset entries deletion
		if err := cm.NodesSynced(ctx); err != nil {
			return err
		}
		initializer.InitDone()
		return nil
	}))
}
