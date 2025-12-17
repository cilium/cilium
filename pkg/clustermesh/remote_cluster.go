// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"errors"
	"log/slog"
	"path"
	"sync/atomic"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/observer"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// ErrObserverNotRegistered is the error returned when referencing an observer
	// which has not been registered.
	ErrObserverNotRegistered = errors.New("observer not registered")
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
	remoteIdentityCache allocator.RemoteIDCache

	// observers are observers watching additional prefixes.
	observers map[observer.Name]observer.Observer

	// status is the function which fills the common part of the status.
	status common.StatusFunc

	storeFactory store.Factory

	// registered represents whether the observers have been registered.
	registered atomic.Bool

	// synced tracks the initial synchronization with the remote cluster.
	synced synced

	log *slog.Logger

	// featureMetrics will track which features are enabled with in clustermesh.
	featureMetrics ClusterMeshMetrics

	// featureMetricMaxClusters contains the max clusters defined for this
	// clustermesh config.
	featureMetricMaxClusters string
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

	rc.featureMetrics.AddClusterMeshConfig(ClusterMeshMode(config, option.Config.IdentityAllocationMode), rc.featureMetricMaxClusters)

	defer rc.featureMetrics.DelClusterMeshConfig(ClusterMeshMode(config, option.Config.IdentityAllocationMode), rc.featureMetricMaxClusters)

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
		mgr = store.NewWatchStoreManagerImmediate(rc.log)
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
		rc.remoteIdentityCache.Watch(ctx, func(context.Context) { rc.synced.identitiesDone() })
	})

	for _, obs := range rc.observers {
		obs.Register(mgr, backend, config)
	}

	rc.registered.Store(true)
	defer rc.registered.Store(false)

	close(ready)
	mgr.Run(ctx)
}

func (rc *remoteCluster) Stop() {
	rc.synced.Stop()
}

// RevokeCache performs a partial revocation of the remote cluster's cache, draining only remote
// services. This prevents the agent from load-balancing to potentially stale service backends.
// Other resources, besides extra observers that may also implement revocation, are left intact to
// reduce churn and avoid disrupting existing connections like active IPsec security associations.
func (rc *remoteCluster) RevokeCache(ctx context.Context) {
	rc.remoteServices.Drain()

	for _, obs := range rc.observers {
		obs.Revoke()
	}
}

func (rc *remoteCluster) Remove(context.Context) {
	// Draining shall occur only when the configuration for the remote cluster
	// is removed, and not in case the agent is shutting down, otherwise we
	// would break existing connections on restart.
	rc.remoteNodes.Drain()
	rc.remoteServices.Drain()
	rc.ipCacheWatcher.Drain()

	rc.remoteIdentityWatcher.RemoveRemoteIdentities(rc.name)

	for _, obs := range rc.observers {
		obs.Drain()
	}

	rc.usedIDs.ReleaseClusterID(rc.clusterID)
}

func (rc *remoteCluster) Status() *models.RemoteCluster {
	status := rc.status()

	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	status.NumNodes = int64(rc.remoteNodes.NumEntries())
	status.NumSharedServices = int64(rc.remoteServices.NumEntries())
	status.NumEndpoints = int64(rc.ipCacheWatcher.NumEntries())

	status.Synced = &models.RemoteClusterSynced{
		Nodes:     rc.remoteNodes.Synced(),
		Services:  rc.remoteServices.Synced(),
		Endpoints: rc.ipCacheWatcher.Synced(),
	}

	if rc.remoteIdentityCache != nil {
		status.NumIdentities = int64(rc.remoteIdentityCache.NumEntries())
		status.Synced.Identities = rc.remoteIdentityCache.Synced()
	}

	status.Ready = status.Ready &&
		status.Synced.Nodes && status.Synced.Services &&
		status.Synced.Identities && status.Synced.Endpoints

	// We mark the status as ready only after being sure that all observers
	// have been registered, as at that point we expect that [status.Enabled]
	// is set if the reflector is enabled for the current configuration.
	status.Ready = status.Ready && rc.registered.Load()
	for _, obs := range rc.observers {
		var st = obs.Status()
		status.Ready = status.Ready && (!st.Enabled || st.Synced)
	}

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
		rc.log.Info(
			"Remote Cluster ID changed: draining all known entries before reconnecting. "+
				"Expect connectivity disruption towards this cluster",
			logfields.ClusterID, newConfig.ID,
		)
		rc.remoteNodes.Drain()
		rc.remoteServices.Drain()
		rc.ipCacheWatcher.Drain()
		rc.remoteIdentityWatcher.RemoveRemoteIdentities(rc.name)

		for _, obs := range rc.observers {
			obs.Drain()
		}
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
	services       chan struct{}
	nodes          chan struct{}
	ipcache        chan struct{}
	identities     *lock.StoppableWaitGroup
	identitiesDone lock.DoneFunc

	observers map[observer.Name]chan struct{}
}

func newSynced() synced {
	// Use a StoppableWaitGroup for identities, instead of a plain channel to
	// avoid having to deal with the possibility of a closed channel if already
	// synced (as the callback is executed every time the etcd connection
	// is restarted, differently from the other resource types).
	idswg := lock.NewStoppableWaitGroup()
	done := idswg.Add()
	idswg.Stop()

	return synced{
		SyncedCommon:   wait.NewSyncedCommon(),
		services:       make(chan struct{}),
		nodes:          make(chan struct{}),
		ipcache:        make(chan struct{}),
		identities:     idswg,
		identitiesDone: done,
		observers:      make(map[observer.Name]chan struct{}),
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
	return s.Wait(ctx, s.services)
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

// ObserverSynced returns after that either the given named observer has
// received the initial list of entries from the remote clusters, the
// remote cluster is disconnected, or the given context is canceled.
// It returns an error if the target observer is not registered.
func (s *synced) Observer(ctx context.Context, name observer.Name) error {
	wait, ok := s.observers[name]
	if !ok {
		return ErrObserverNotRegistered
	}

	return s.Wait(ctx, wait)
}

type ClusterMeshMetrics interface {
	AddClusterMeshConfig(mode string, maxClusters string)
	DelClusterMeshConfig(mode string, maxClusters string)
}

const (
	ClusterMeshModeClusterMeshAPIServer       = "clustermesh-apiserver"
	ClusterMeshModeETCD                       = "etcd"
	ClusterMeshModeKVStoreMesh                = "kvstoremesh"
	ClusterMeshModeClusterMeshAPIServerOrETCD = ClusterMeshModeClusterMeshAPIServer + "_or_" + ClusterMeshModeETCD
)

// ClusterMeshMode returns the mode of the local cluster.
func ClusterMeshMode(rcc cmtypes.CiliumClusterConfig, identityMode string) string {
	switch {
	case rcc.Capabilities.Cached:
		return ClusterMeshModeKVStoreMesh
	case identityMode == option.IdentityAllocationModeCRD:
		return ClusterMeshModeClusterMeshAPIServer
	case identityMode == option.IdentityAllocationModeKVstore:
		return ClusterMeshModeETCD
	default:
		return ClusterMeshModeClusterMeshAPIServerOrETCD
	}
}
