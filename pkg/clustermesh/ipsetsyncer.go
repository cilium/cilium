// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"runtime/pprof"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
)

func ipsetSyncer(
	logger logrus.FieldLogger,
	lc cell.Lifecycle,
	jobRegistry job.Registry,
	scope cell.Scope,
	cm *ClusterMesh,
	ipsetMgr ipset.Manager,
) {
	if cm == nil {
		return
	}

	initializer := ipsetMgr.NewInitializer()

	jg := jobRegistry.NewGroup(
		scope,
		job.WithLogger(logger),
		job.WithPprofLabels(pprof.Labels("cell", "clustermesh-ipset-syncer")),
	)
	jg.Add(job.OneShot("clustermesh-ipset-syncer", func(ctx context.Context, _ cell.HealthReporter) error {
		// wait for initial nodes listing from all remote clusters
		// before allowing stale ipset entries deletion
		if err := cm.NodesSynced(ctx); err != nil {
			return err
		}
		initializer.InitDone()
		return nil
	}))

	lc.Append(jg)
}
