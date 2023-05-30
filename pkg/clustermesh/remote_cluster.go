// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"path"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/clustermesh/internal"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// remoteCluster implements the clustermesh business logic on top of
// internal.RemoteCluster.
type remoteCluster struct {
	// name is the name of the cluster
	name string

	// clusterConfig is a configuration of the remote cluster taken
	// from remote kvstore.
	config *cmtypes.CiliumClusterConfig

	// mesh is the cluster mesh this remote cluster belongs to
	mesh *ClusterMesh

	// mutex protects the following variables:
	// - config
	// - remoteIdentityCache
	mutex lock.RWMutex

	// store is the shared store representing all nodes in the remote cluster
	remoteNodes store.WatchStore

	// remoteServices is the shared store representing services in remote
	// clusters
	remoteServices store.WatchStore

	// ipCacheWatcher is the watcher that notifies about IP<->identity
	// changes in the remote cluster
	ipCacheWatcher *ipcache.IPIdentityWatcher

	// remoteIdentityCache is a locally cached copy of the identity
	// allocations in the remote cluster
	remoteIdentityCache *allocator.RemoteCache

	// status is the function which fills the internal part of the status.
	status internal.StatusFunc

	swg *lock.StoppableWaitGroup
}

func (rc *remoteCluster) Run(ctx context.Context, backend kvstore.BackendOperations, config *cmtypes.CiliumClusterConfig) error {
	if err := rc.mesh.canConnect(rc.name, config); err != nil {
		return err
	}

	var capabilities types.CiliumClusterConfigCapabilities
	if config != nil {
		capabilities = config.Capabilities
	}

	remoteIdentityCache, err := rc.mesh.conf.RemoteIdentityWatcher.WatchRemoteIdentities(rc.name, backend)
	if err != nil {
		return err
	}

	defer remoteIdentityCache.Close()

	rc.mutex.Lock()
	rc.config = config
	rc.remoteIdentityCache = remoteIdentityCache
	rc.mutex.Unlock()

	var mgr store.WatchStoreManager
	if capabilities.SyncedCanaries {
		mgr = store.NewWatchStoreManagerSync(backend, rc.name)
	} else {
		mgr = store.NewWatchStoreManagerImmediate(rc.name)
	}

	mgr.Register(nodeStore.NodeStorePrefix, func(ctx context.Context) {
		rc.remoteNodes.Watch(ctx, backend, path.Join(nodeStore.NodeStorePrefix, rc.name))
	})

	mgr.Register(serviceStore.ServiceStorePrefix, func(ctx context.Context) {
		rc.remoteServices.Watch(ctx, backend, path.Join(serviceStore.ServiceStorePrefix, rc.name))
	})

	mgr.Register(ipcache.IPIdentitiesPath, func(ctx context.Context) {
		rc.ipCacheWatcher.Watch(ctx, backend)
	})

	mgr.Run(ctx)
	return nil
}

func (rc *remoteCluster) Stop() {}

func (rc *remoteCluster) Remove() {
	// Draining shall occur only when the configuration for the remote cluster
	// is removed, and not in case the agent is shutting down, otherwise we
	// would break existing connections on restart.
	rc.remoteNodes.Drain()
	rc.remoteServices.Drain()
	rc.ipCacheWatcher.Drain()

	rc.mesh.conf.RemoteIdentityWatcher.RemoveRemoteIdentities(rc.name)
	rc.mesh.globalServices.onClusterDelete(rc.name)
}

func (rc *remoteCluster) Status() *models.RemoteCluster {
	status := rc.status()

	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	status.NumNodes = int64(rc.remoteNodes.NumEntries())
	status.NumSharedServices = int64(rc.remoteServices.NumEntries())
	status.NumIdentities = int64(rc.remoteIdentityCache.NumEntries())
	return status
}
