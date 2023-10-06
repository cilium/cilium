// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"
	"path"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// remoteCluster implements the clustermesh business logic on top of
// common.RemoteCluster.
type remoteCluster struct {
	// name is the name of the cluster
	name string

	meshNodeInformer *meshNodeInformer
	globalServices   *common.GlobalServiceCache

	// remoteServices is the shared store representing services in remote clusters
	remoteServices store.WatchStore

	storeFactory store.Factory

	// synced tracks the initial synchronization with the remote cluster.
	synced synced
}

func (rc *remoteCluster) Run(ctx context.Context, backend kvstore.BackendOperations, config *types.CiliumClusterConfig, ready chan<- error) {
	var capabilities types.CiliumClusterConfigCapabilities
	if config != nil {
		capabilities = config.Capabilities
	}

	var mgr store.WatchStoreManager
	if capabilities.SyncedCanaries {
		mgr = rc.storeFactory.NewWatchStoreManager(backend, rc.name)
	} else {
		mgr = store.NewWatchStoreManagerImmediate(rc.name)
	}

	adapter := func(prefix string) string { return prefix }
	if capabilities.Cached {
		adapter = kvstore.StateToCachePrefix
	}

	mgr.Register(adapter(serviceStore.ServiceStorePrefix), func(ctx context.Context) {
		rc.remoteServices.Watch(ctx, backend, path.Join(adapter(serviceStore.ServiceStorePrefix), rc.name))
	})

	close(ready)
	rc.meshNodeInformer.onAddCluster(rc.name)
	mgr.Run(ctx)
}

func (rc *remoteCluster) Stop() {
	rc.synced.Stop()
}

func (rc *remoteCluster) Remove() {
	rc.meshNodeInformer.onDeleteCluster(rc.name)
	// Draining shall occur only when the configuration for the remote cluster
	// is removed, and not in case the operator is shutting down, otherwise we
	// would break existing connections on restart.
	rc.remoteServices.Drain()
	rc.globalServices.OnClusterDelete(rc.name)
}

func (rc *remoteCluster) ClusterConfigRequired() bool { return false }

type synced struct {
	wait.SyncedCommon
	services *lock.StoppableWaitGroup
}

func newSynced() synced {
	return synced{
		SyncedCommon: wait.NewSyncedCommon(),
		services:     lock.NewStoppableWaitGroup(),
	}
}

// Services returns after that the initial list of shared services has been
// received from the remote cluster, the remote cluster is disconnected,
// or the given context is canceled.
func (s *synced) Services(ctx context.Context) error {
	return s.Wait(ctx, s.services.WaitChannel())
}
