// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"errors"
	"path"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// remoteCluster implements the clustermesh business logic on top of
// common.RemoteCluster.
type remoteCluster struct {
	// name is the name of the cluster
	name string

	// clusterConfig is a configuration of the remote cluster taken
	// from remote kvstore.
	config *cmtypes.CiliumClusterConfig

	// mesh is the cluster mesh this remote cluster belongs to
	mesh *ClusterMesh

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

	// remoteIdentityCache is a locally cached copy of the identity
	// allocations in the remote cluster
	remoteIdentityCache *allocator.RemoteCache

	// status is the function which fills the common part of the status.
	status common.StatusFunc

	storeFactory store.Factory

	// synced tracks the initial synchronization with the remote cluster.
	synced synced
}

func (rc *remoteCluster) Run(ctx context.Context, backend kvstore.BackendOperations, config *cmtypes.CiliumClusterConfig, ready chan<- error) {
	if err := rc.mesh.conf.ClusterInfo.ValidateRemoteConfig(rc.ClusterConfigRequired(), config); err != nil {
		ready <- err
		close(ready)
		return
	}

	if err := rc.onUpdateConfig(config); err != nil {
		ready <- err
		close(ready)
		return
	}

	var capabilities types.CiliumClusterConfigCapabilities
	if config != nil {
		capabilities = config.Capabilities
	}

	remoteIdentityCache, err := rc.mesh.conf.RemoteIdentityWatcher.WatchRemoteIdentities(rc.name, backend, capabilities.Cached)
	if err != nil {
		ready <- err
		close(ready)
		return
	}

	rc.mutex.Lock()
	rc.remoteIdentityCache = remoteIdentityCache
	rc.mutex.Unlock()

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

	mgr.Register(adapter(nodeStore.NodeStorePrefix), func(ctx context.Context) {
		rc.remoteNodes.Watch(ctx, backend, path.Join(adapter(nodeStore.NodeStorePrefix), rc.name))
	})

	mgr.Register(adapter(serviceStore.ServiceStorePrefix), func(ctx context.Context) {
		rc.remoteServices.Watch(ctx, backend, path.Join(adapter(serviceStore.ServiceStorePrefix), rc.name))
	})

	mgr.Register(adapter(ipcache.IPIdentitiesPath), func(ctx context.Context) {
		rc.ipCacheWatcher.Watch(ctx, backend, rc.ipCacheWatcherOpts(config)...)
	})

	mgr.Register(adapter(identityCache.IdentitiesPath), func(ctx context.Context) {
		rc.remoteIdentityCache.Watch(ctx, func(context.Context) { rc.synced.identities.Done() })
	})

	close(ready)
	mgr.Run(ctx)
}

func (rc *remoteCluster) Stop() {
	rc.synced.stop()
}

func (rc *remoteCluster) Remove() {
	// Draining shall occur only when the configuration for the remote cluster
	// is removed, and not in case the agent is shutting down, otherwise we
	// would break existing connections on restart.
	rc.remoteNodes.Drain()
	rc.remoteServices.Drain()
	rc.ipCacheWatcher.Drain()

	rc.mesh.conf.RemoteIdentityWatcher.RemoveRemoteIdentities(rc.name)
	rc.mesh.globalServices.onClusterDelete(rc.name)

	if rc.config != nil {
		rc.usedIDs.ReleaseClusterID(rc.config.ID)
	}
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

func (rc *remoteCluster) ClusterConfigRequired() bool {
	return rc.mesh.conf.ConfigValidationMode == types.Strict
}

func (rc *remoteCluster) onUpdateConfig(newConfig *cmtypes.CiliumClusterConfig) error {
	oldConfig := rc.config

	if newConfig != nil && oldConfig != nil && newConfig.ID == oldConfig.ID {
		return nil
	}
	if newConfig != nil {
		if err := rc.usedIDs.ReserveClusterID(newConfig.ID); err != nil {
			return err
		}
	}
	if oldConfig != nil {
		rc.usedIDs.ReleaseClusterID(oldConfig.ID)
	}
	rc.config = newConfig

	return nil
}

func (rc *remoteCluster) ipCacheWatcherOpts(config *cmtypes.CiliumClusterConfig) []ipcache.IWOpt {
	var opts []ipcache.IWOpt

	if config != nil {
		opts = append(opts, ipcache.WithCachedPrefix(config.Capabilities.Cached))
	}

	if rc.ipCacheWatcherExtraOpts != nil {
		opts = append(opts, rc.ipCacheWatcherExtraOpts(config)...)
	}

	return opts
}

var (
	// ErrRemoteClusterDisconnected is the error returned by wait for sync
	// operations if the remote cluster is disconnected while still waiting.
	ErrRemoteClusterDisconnected = errors.New("remote cluster disconnected")
)

type synced struct {
	services   *lock.StoppableWaitGroup
	nodes      chan struct{}
	ipcache    chan struct{}
	identities *lock.StoppableWaitGroup
	stopped    chan struct{}
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
		services:   lock.NewStoppableWaitGroup(),
		nodes:      make(chan struct{}),
		ipcache:    make(chan struct{}),
		identities: idswg,
		stopped:    make(chan struct{}),
	}
}

// Nodes returns after that the initial list of nodes has been received
// from the remote cluster, and synchronized with the different subscribers,
// the remote cluster is disconnected, or the given context is canceled.
func (s *synced) Nodes(ctx context.Context) error {
	return s.wait(ctx, s.nodes)
}

// Services returns after that the initial list of shared services has been
// received from the remote cluster, and synchronized with the BPF datapath,
// the remote cluster is disconnected, or the given context is canceled.
func (s *synced) Services(ctx context.Context) error {
	return s.wait(ctx, s.services.WaitChannel())
}

// IPIdentities returns after that the initial list of ipcache entries and
// identities has been received from the remote cluster, and synchronized
// with the BPF datapath, the remote cluster is disconnected, or the given
// context is canceled. We additionally need to explicitly wait for nodes
// synchronization because they also trigger the insertion of ipcache entries
// (i.e., node addresses, health, ingress, ...).
func (s *synced) IPIdentities(ctx context.Context) error {
	return s.wait(ctx, s.ipcache, s.identities.WaitChannel(), s.nodes)
}

func (s *synced) wait(ctx context.Context, chs ...<-chan struct{}) error {
	for _, ch := range chs {
		select {
		case <-ch:
			continue
		case <-s.stopped:
			return ErrRemoteClusterDisconnected
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (s *synced) stop() {
	close(s.stopped)
}
