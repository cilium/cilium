// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

const subsystem = "clustermesh"

// Configuration is the configuration that must be provided to
// NewClusterMesh()
type Configuration struct {
	cell.In

	common.Config
	wait.TimeoutConfig

	// ClusterInfo is the id/name of the local cluster. This is used for logging and metrics
	ClusterInfo cmtypes.ClusterInfo

	// ServiceMerger is the interface responsible to merge service and
	// endpoints into an existing cache
	ServiceMerger ServiceMerger

	// NodeObserver reacts to node events.
	NodeObserver nodeStore.NodeManager

	// RemoteIdentityWatcher provides identities that have been allocated on a
	// remote cluster.
	RemoteIdentityWatcher RemoteIdentityWatcher

	IPCache ipcache.IPCacher

	// ClusterSizeDependantInterval allows to calculate intervals based on cluster size.
	ClusterSizeDependantInterval kvstore.ClusterSizeDependantIntervalFunc

	// ServiceResolver, if not nil, is used to create a custom dialer for service resolution.
	ServiceResolver *dial.ServiceResolver

	// IPCacheWatcherExtraOpts returns extra options for watching ipcache entries.
	IPCacheWatcherExtraOpts IPCacheWatcherOptsFn `optional:"true"`

	// ClusterIDsManager handles the reservation of the ClusterIDs associated
	// with remote clusters, to ensure their uniqueness.
	ClusterIDsManager clusterIDsManager

	Metrics       Metrics
	CommonMetrics common.Metrics
	StoreFactory  store.Factory

	FeatureMetrics ClusterMeshMetrics

	Logger *slog.Logger
}

// RemoteIdentityWatcher is any type which provides identities that have been
// allocated on a remote cluster.
type RemoteIdentityWatcher interface {
	// WatchRemoteIdentities returns a RemoteCache instance which can be later
	// started to watch identities in another kvstore and sync them to the local
	// identity cache. remoteName should be unique unless replacing an existing
	// remote's backend. When cachedPrefix is set, identities are assumed to be
	// stored under the "cilium/cache" prefix, and the watcher is adapted accordingly.
	WatchRemoteIdentities(remoteName string, remoteID uint32, backend kvstore.BackendOperations, cachedPrefix bool) (allocator.RemoteIDCache, error)

	// RemoveRemoteIdentities removes any reference to a remote identity source,
	// emitting a deletion event for all previously known identities.
	RemoveRemoteIdentities(name string)
}

// IPCacheWatcherOptsFn is a function which returns extra options for watching
// ipcache entries.
type IPCacheWatcherOptsFn func(config *cmtypes.CiliumClusterConfig) []ipcache.IWOpt

// ClusterMesh is a cache of multiple remote clusters
type ClusterMesh struct {
	// conf is the configuration, it is immutable after NewClusterMesh()
	conf Configuration

	// common implements the common logic to connect to remote clusters.
	common common.ClusterMesh

	// globalServices is a list of all global services. The datastructure
	// is protected by its own mutex inside the structure.
	globalServices *common.GlobalServiceCache

	// nodeName is the name of the local node. This is used for logging and metrics
	nodeName string

	// syncTimeoutLogOnce ensures that the warning message triggered upon failure
	// waiting for remote clusters synchronization is output only once.
	syncTimeoutLogOnce sync.Once

	// FeatureMetrics will track which features are enabled with in clustermesh.
	FeatureMetrics ClusterMeshMetrics
}

// NewClusterMesh creates a new remote cluster cache based on the
// provided configuration
func NewClusterMesh(lifecycle cell.Lifecycle, c Configuration) *ClusterMesh {
	if c.ClusterInfo.ID == 0 || c.ClusterMeshConfig == "" {
		return nil
	}

	nodeName := nodeTypes.GetName()
	cm := &ClusterMesh{
		conf:     c,
		nodeName: nodeName,
		globalServices: common.NewGlobalServiceCache(
			c.Logger,
			c.Metrics.TotalGlobalServices.WithLabelValues(c.ClusterInfo.Name, nodeName),
		),
		FeatureMetrics: c.FeatureMetrics,
	}

	cm.common = common.NewClusterMesh(common.Configuration{
		Logger:                       c.Logger,
		Config:                       c.Config,
		ClusterInfo:                  c.ClusterInfo,
		ClusterSizeDependantInterval: c.ClusterSizeDependantInterval,
		ServiceResolver:              c.ServiceResolver,

		NewRemoteCluster: cm.NewRemoteCluster,

		NodeName: nodeName,
		Metrics:  c.CommonMetrics,
	})

	lifecycle.Append(cm.common)
	return cm
}

func (cm *ClusterMesh) NewRemoteCluster(name string, status common.StatusFunc) common.RemoteCluster {
	rc := &remoteCluster{
		name:                     name,
		clusterID:                cmtypes.ClusterIDUnset,
		clusterConfigValidator:   cm.conf.ClusterInfo.ValidateRemoteConfig,
		usedIDs:                  cm.conf.ClusterIDsManager,
		status:                   status,
		storeFactory:             cm.conf.StoreFactory,
		remoteIdentityWatcher:    cm.conf.RemoteIdentityWatcher,
		synced:                   newSynced(),
		log:                      cm.conf.Logger.With(logfields.ClusterName, name),
		featureMetrics:           cm.FeatureMetrics,
		featureMetricMaxClusters: fmt.Sprintf("%d", cm.conf.ClusterInfo.MaxConnectedClusters),
	}
	rc.remoteNodes = cm.conf.StoreFactory.NewWatchStore(
		name,
		nodeStore.ValidatingKeyCreator(
			nodeStore.ClusterNameValidator(name),
			nodeStore.NameValidator(),
			nodeStore.ClusterIDValidator(&rc.clusterID),
		),
		nodeStore.NewNodeObserver(cm.conf.NodeObserver, source.ClusterMesh),
		store.RWSWithOnSyncCallback(func(ctx context.Context) { close(rc.synced.nodes) }),
		store.RWSWithEntriesMetric(cm.conf.Metrics.TotalNodes.WithLabelValues(cm.conf.ClusterInfo.Name, cm.nodeName, rc.name)),
	)

	rc.remoteServices = cm.conf.StoreFactory.NewWatchStore(
		name,
		serviceStore.KeyCreator(
			serviceStore.ClusterNameValidator(name),
			serviceStore.NamespacedNameValidator(),
			serviceStore.ClusterIDValidator(&rc.clusterID),
		),
		common.NewSharedServicesObserver(
			rc.log,
			cm.globalServices,
			func(svc *serviceStore.ClusterService) {
				cm.conf.ServiceMerger.MergeExternalServiceUpdate(svc, rc.synced.services)
			},
			func(svc *serviceStore.ClusterService) {
				cm.conf.ServiceMerger.MergeExternalServiceDelete(svc, rc.synced.services)
			},
		),
		store.RWSWithOnSyncCallback(func(ctx context.Context) { rc.synced.services.Stop() }),
	)

	rc.ipCacheWatcher = ipcache.NewIPIdentityWatcher(
		cm.conf.Logger,
		name, cm.conf.IPCache, cm.conf.StoreFactory, source.ClusterMesh,
		store.RWSWithOnSyncCallback(func(ctx context.Context) { close(rc.synced.ipcache) }),
	)
	rc.ipCacheWatcherExtraOpts = cm.conf.IPCacheWatcherExtraOpts

	return rc
}

// NumReadyClusters returns the number of remote clusters to which a connection
// has been established
func (cm *ClusterMesh) NumReadyClusters() int {
	return cm.common.NumReadyClusters()
}

// NodesSynced returns after that either the initial list of nodes has been received
// from all remote clusters, and synchronized with the different subscribers, or the
// maximum wait period controlled by the clustermesh-sync-timeout flag elapsed. It
// returns an error if the given context expired.
func (cm *ClusterMesh) NodesSynced(ctx context.Context) error {
	return cm.synced(ctx, func(rc *remoteCluster) wait.Fn { return rc.synced.Nodes })
}

// ServicesSynced returns after that either the initial list of shared services has
// been received from all remote clusters, and synchronized with the BPF datapath, or
// the maximum wait period controlled by the clustermesh-sync-timeout flag elapsed.
// It returns an error if the given context expired.
func (cm *ClusterMesh) ServicesSynced(ctx context.Context) error {
	return cm.synced(ctx, func(rc *remoteCluster) wait.Fn { return rc.synced.Services })
}

// IPIdentitiesSynced returns after that either the initial list of ipcache entries
// and identities has been received from all remote clusters, and synchronized with
// the BPF datapath, or the maximum wait period controlled by the clustermesh-sync-timeout
// flag elapsed. It returns an error if the given context expired.
func (cm *ClusterMesh) IPIdentitiesSynced(ctx context.Context) error {
	return cm.synced(ctx, func(rc *remoteCluster) wait.Fn { return rc.synced.IPIdentities })
}

func (cm *ClusterMesh) synced(ctx context.Context, toWaitFn func(*remoteCluster) wait.Fn) error {
	wctx, cancel := context.WithTimeout(ctx, cm.conf.ClusterMeshSyncTimeout)
	defer cancel()

	waiters := make([]wait.Fn, 0)
	cm.common.ForEachRemoteCluster(func(rci common.RemoteCluster) error {
		rc := rci.(*remoteCluster)
		waiters = append(waiters, toWaitFn(rc))
		return nil
	})

	err := wait.ForAll(wctx, waiters)
	if ctx.Err() == nil && wctx.Err() != nil {
		// The sync timeout expired, but the parent context is still valid, which
		// means that the circuit breaker was triggered. Print a warning message
		// and continue normally, as if the synchronization completed successfully.
		// This ensures that we don't block forever in case of misconfigurations.
		cm.syncTimeoutLogOnce.Do(func() {
			cm.conf.Logger.Warn("Failed waiting for clustermesh synchronization, expect possible disruption of cross-cluster connections")
		})

		return nil
	}

	return err
}

// Status returns the status of the ClusterMesh subsystem
func (cm *ClusterMesh) Status() (status *models.ClusterMeshStatus) {
	status = &models.ClusterMeshStatus{
		NumGlobalServices: int64(cm.globalServices.Size()),
	}

	cm.common.ForEachRemoteCluster(func(rci common.RemoteCluster) error {
		rc := rci.(*remoteCluster)
		status.Clusters = append(status.Clusters, rc.Status())
		return nil
	})

	// Sort the remote clusters status to ensure consistent ordering.
	slices.SortFunc(status.Clusters,
		func(a, b *models.RemoteCluster) int { return cmp.Compare(a.Name, b.Name) })

	return
}
