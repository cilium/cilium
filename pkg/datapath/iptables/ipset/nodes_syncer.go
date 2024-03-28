// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"context"
	"runtime/pprof"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/promise"
)

type nodesSyncedFunc func() bool

func newNodeSyncer(
	logger logrus.FieldLogger,
	lc cell.Lifecycle,
	jobRegistry job.Registry,
	scope cell.Scope,
	nodes resource.Resource[*cilium_api_v2.CiliumNode],
	nodesSyncerPromise promise.Promise[nodediscovery.Syncer],
	cm *clustermesh.ClusterMesh,
) nodesSyncedFunc {
	var synced atomic.Bool

	nodesResourceSynced := make(chan struct{})
	kvstoreSynced := make(chan struct{})
	cmSynced := make(chan struct{})

	jobGroup := jobRegistry.NewGroup(
		scope,
		job.WithLogger(logger),
		job.WithPprofLabels(pprof.Labels("cell", "ipset")),
	)
	lc.Append(jobGroup)

	jobGroup.Add(job.OneShot(
		"cn-resource-sync",
		func(ctx context.Context, _ cell.HealthReporter) error {
			defer close(nodesResourceSynced)
			for ev := range nodes.Events(ctx) {
				ev.Done(nil)
				if ev.Kind == resource.Sync {
					break
				}
			}
			return nil
		},
	))
	jobGroup.Add(job.OneShot(
		"kvstore-nodes-sync",
		func(ctx context.Context, _ cell.HealthReporter) error {
			defer close(kvstoreSynced)
			syncer, err := nodesSyncerPromise.Await(ctx)
			if err != nil {
				logger.WithError(err).Warning("Error waiting for nodes from kvstore to be synced")
				return err
			}
			syncer.WaitForRemoteNodesSync(ctx)
			return nil
		},
	))
	jobGroup.Add(job.OneShot(
		"cm-nodes-sync",
		func(ctx context.Context, _ cell.HealthReporter) error {
			defer close(cmSynced)
			if cm == nil {
				return nil
			}
			if err := cm.NodesSynced(ctx); err != nil {
				logger.WithError(err).Warning("Error waiting for remote nodes to be synced")
				return err
			}
			return nil
		},
	))
	jobGroup.Add(job.OneShot(
		"ipset-initial-nodes-sync",
		func(ctx context.Context, _ cell.HealthReporter) error {
			<-nodesResourceSynced
			<-kvstoreSynced
			<-cmSynced
			synced.Store(true)
			return nil
		},
	))

	return nodesSyncedFunc(func() bool {
		return synced.Load()
	})
}
