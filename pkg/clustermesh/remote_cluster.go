// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"path"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// remoteCluster implements the clustermesh business logic on top of
// common.RemoteCluster.
type remoteCluster struct {
	// name is the name of the cluster
	name string

	// clusterID is the clusterID advertized by the remote cluster
	clusterID uint32

	// clusterConfigValidator validates the cluster configuration advertised
	// by remote clusters.
	clusterConfigValidator func(cmtypes.CiliumClusterConfig) error

	usedIDs ClusterIDsManager

	// mutex protects the following variables:
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

	// ipCacheWatcherExtraOpts returns extra options for watching ipcache entries.
	ipCacheWatcherExtraOpts IPCacheWatcherOptsFn

	// remoteIdentityWatcher allows watching remote identities.
	remoteIdentityWatcher RemoteIdentityWatcher

	// remoteIdentityCache is a locally cached copy of the identity
	// allocations in the remote cluster
	remoteIdentityCache *allocator.RemoteCache

	// status is the function which fills the common part of the status.
	status common.StatusFunc

	storeFactory store.Factory

	// synced tracks the initial synchronization with the remote cluster.
	synced synced

	log logrus.FieldLogger
}

func (rc *remoteCluster) Run(ctx context.Context, backend kvstore.BackendOperations, config cmtypes.CiliumClusterConfig, ready chan<- error) {
	if err := rc.clusterConfigValidator(config); err != nil {
		ready <- err
		close(ready)
		return
	}

	if err := rc.onUpdateConfig(config); err != nil {
		ready <- err
		close(ready)
		return
	}

	remoteIdentityCache, err := rc.remoteIdentityWatcher.WatchRemoteIdentities(rc.name, rc.clusterID, backend, config.Capabilities.Cached)
	if err != nil {
		ready <- err
		close(ready)
		return
	}

	rc.mutex.Lock()
	rc.remoteIdentityCache = remoteIdentityCache
	rc.mutex.Unlock()

	var mgr store.WatchStoreManager
	if config.Capabilities.SyncedCanaries {
		mgr = rc.storeFactory.NewWatchStoreManager(backend, rc.name)
	} else {
		mgr = store.NewWatchStoreManagerImmediate(rc.name)
	}

	adapter := func(prefix string) string { return prefix }
	if config.Capabilities.Cached {
		adapter = kvstore.StateToCachePrefix
	}

	mgr.Register(adapter(nodeStore.NodeStorePrefix), func(ctx context.Context) {
		rc.remoteNodes.Watch(ctx, backend, path.Join(adapter(nodeStore.NodeStorePrefix), rc.name))
	})

	mgr.Register(adapter(serviceStore.ServiceStorePrefix), func(ctx context.Context) {
		rc.remoteServices.Watch(ctx, backend, path.Join(adapter(serviceStore.ServiceStorePrefix), rc.name))
	})

	mgr.Register(adapter(ipcache.IPIdentitiesPath), func(ctx context.Context) {
		rc.ipCacheWatcher.Watch(ctx, backend, rc.ipCacheWatcherOpts(&config)...)
	})

	mgr.Register(adapter(identityCache.IdentitiesPath), func(ctx context.Context) {
		rc.remoteIdentityCache.Watch(ctx, func(context.Context) { rc.synced.identities.Done() })
	})

	close(ready)
	mgr.Run(ctx)
}

func (rc *remoteCluster) Stop() {
	rc.synced.Stop()
}

func (rc *remoteCluster) Remove(context.Context) {
	// Draining shall occur only when the configuration for the remote cluster
	// is removed, and not in case the agent is shutting down, otherwise we
	// would break existing connections on restart.
	rc.remoteNodes.Drain()
	rc.remoteServices.Drain()
	rc.ipCacheWatcher.Drain()

	rc.remoteIdentityWatcher.RemoveRemoteIdentities(rc.name)

	rc.usedIDs.ReleaseClusterID(rc.clusterID)
}

func (rc *remoteCluster) Status() *models.RemoteCluster {
	status := rc.status()

	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	status.NumNodes = int64(rc.remoteNodes.NumEntries())
	status.NumSharedServices = int64(rc.remoteServices.NumEntries())
	status.NumIdentities = int64(rc.remoteIdentityCache.NumEntries())
	status.NumEndpoints = int64(rc.ipCacheWatcher.NumEntries())

	status.Synced = &models.RemoteClusterSynced{
		Nodes:      rc.remoteNodes.Synced(),
		Services:   rc.remoteServices.Synced(),
		Identities: rc.remoteIdentityCache.Synced(),
		Endpoints:  rc.ipCacheWatcher.Synced(),
	}

	status.Ready = status.Ready &&
		status.Synced.Nodes && status.Synced.Services &&
		status.Synced.Identities && status.Synced.Endpoints

	return status
}

func (rc *remoteCluster) onUpdateConfig(newConfig cmtypes.CiliumClusterConfig) error {
	if newConfig.ID == rc.clusterID {
		return nil
	}

	// Let's fully drain all previously known entries if the remote cluster changed
	// the cluster ID. Although synthetic deletion events would be generated in any
	// case upon initial listing (as the entries with the incorrect ID would not pass
	// validation), that would leave a window of time in which there would still be
	// stale entries for a Cluster ID that has already been released, potentially
	// leading to inconsistencies if the same ID is acquired again in the meanwhile.
	if rc.clusterID != cmtypes.ClusterIDUnset {
		rc.log.WithField(logfields.ClusterID, newConfig.ID).
			Info("Remote Cluster ID changed: draining all known entries before reconnecting. ",
				"Expect connectivity disruption towards this cluster")
		rc.remoteNodes.Drain()
		rc.remoteServices.Drain()
		rc.ipCacheWatcher.Drain()
		rc.remoteIdentityWatcher.RemoveRemoteIdentities(rc.name)
	}

	if err := rc.usedIDs.ReserveClusterID(newConfig.ID); err != nil {
		return err
	}

	rc.usedIDs.ReleaseClusterID(rc.clusterID)
	rc.clusterID = newConfig.ID

	return nil
}

func (rc *remoteCluster) ipCacheWatcherOpts(config *cmtypes.CiliumClusterConfig) []ipcache.IWOpt {
	var opts []ipcache.IWOpt

	if config != nil {
		opts = append(opts, ipcache.WithCachedPrefix(config.Capabilities.Cached))
		opts = append(opts, ipcache.WithIdentityValidator(config.ID))
	}

	if rc.ipCacheWatcherExtraOpts != nil {
		opts = append(opts, rc.ipCacheWatcherExtraOpts(config)...)
	}

	return opts
}

type synced struct {
	wait.SyncedCommon
	services   *lock.StoppableWaitGroup
	nodes      chan struct{}
	ipcache    chan struct{}
	identities *lock.StoppableWaitGroup
}

func newSynced() synced {
	// Use a StoppableWaitGroup for identities, instead of a plain channel to
	// avoid having to deal with the possibility of a closed channel if already
	// synced (as the callback is executed every time the etcd connection
	// is restarted, differently from the other resource types).
	idswg := lock.NewStoppableWaitGroup()
	idswg.Add()
	idswg.Stop()

	return synced{
		SyncedCommon: wait.NewSyncedCommon(),
		services:     lock.NewStoppableWaitGroup(),
		nodes:        make(chan struct{}),
		ipcache:      make(chan struct{}),
		identities:   idswg,
	}
}

// Nodes returns after that the initial list of nodes has been received
// from the remote cluster, and synchronized with the different subscribers,
// the remote cluster is disconnected, or the given context is canceled.
func (s *synced) Nodes(ctx context.Context) error {
	return s.Wait(ctx, s.nodes)
}

// Services returns after that the initial list of shared services has been
// received from the remote cluster, and synchronized with the BPF datapath,
// the remote cluster is disconnected, or the given context is canceled.
func (s *synced) Services(ctx context.Context) error {
	return s.Wait(ctx, s.services.WaitChannel())
}

// IPIdentities returns after that the initial list of ipcache entries and
// identities has been received from the remote cluster, and synchronized
// with the BPF datapath, the remote cluster is disconnected, or the given
// context is canceled. We additionally need to explicitly wait for nodes
// synchronization because they also trigger the insertion of ipcache entries
// (i.e., node addresses, health, ingress, ...).
func (s *synced) IPIdentities(ctx context.Context) error {
	return s.Wait(ctx, s.ipcache, s.identities.WaitChannel(), s.nodes)
}
