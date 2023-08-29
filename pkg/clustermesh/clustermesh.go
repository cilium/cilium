// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"errors"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

const subsystem = "clustermesh"

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

// Configuration is the configuration that must be provided to
// NewClusterMesh()
type Configuration struct {
	cell.In

	common.Config

	// ClusterInfo is the id/name of the local cluster. This is used for logging and metrics
	ClusterInfo types.ClusterInfo

	// NodeKeyCreator is the function used to create node instances as
	// nodes are being discovered in remote clusters
	NodeKeyCreator store.KeyCreator

	// ServiceMerger is the interface responsible to merge service and
	// endpoints into an existing cache
	ServiceMerger ServiceMerger

	// NodeObserver reacts to node events.
	NodeObserver store.Observer

	// RemoteIdentityWatcher provides identities that have been allocated on a
	// remote cluster.
	RemoteIdentityWatcher RemoteIdentityWatcher

	IPCache ipcache.IPCacher

	// ClusterSizeDependantInterval allows to calculate intervals based on cluster size.
	ClusterSizeDependantInterval kvstore.ClusterSizeDependantIntervalFunc

	// ServiceIPGetter, if not nil, is used to create a custom dialer for service resolution.
	ServiceIPGetter k8s.ServiceIPGetter

	// ConfigValidationMode defines whether the CiliumClusterConfig is always
	// expected to be exposed by remote clusters.
	ConfigValidationMode types.ValidationMode `optional:"true"`

	// IPCacheWatcherExtraOpts returns extra options for watching ipcache entries.
	IPCacheWatcherExtraOpts IPCacheWatcherOptsFn `optional:"true"`

	// ClusterIDsManager handles the reservation of the ClusterIDs associated
	// with remote clusters, to ensure their uniqueness.
	ClusterIDsManager clusterIDsManager

	Metrics       Metrics
	CommonMetrics common.Metrics
	StoreFactory  store.Factory
}

// RemoteIdentityWatcher is any type which provides identities that have been
// allocated on a remote cluster.
type RemoteIdentityWatcher interface {
	// WatchRemoteIdentities returns a RemoteCache instance which can be later
	// started to watch identities in another kvstore and sync them to the local
	// identity cache. remoteName should be unique unless replacing an existing
	// remote's backend. When cachedPrefix is set, identities are assumed to be
	// stored under the "cilium/cache" prefix, and the watcher is adapted accordingly.
	WatchRemoteIdentities(remoteName string, backend kvstore.BackendOperations, cachedPrefix bool) (*allocator.RemoteCache, error)

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
	globalServices *globalServiceCache

	// nodeName is the name of the local node. This is used for logging and metrics
	nodeName string
}

// NewClusterMesh creates a new remote cluster cache based on the
// provided configuration
func NewClusterMesh(lifecycle hive.Lifecycle, c Configuration) *ClusterMesh {
	if c.ClusterInfo.ID == 0 || c.ClusterMeshConfig == "" {
		return nil
	}

	nodeName := nodeTypes.GetName()
	cm := &ClusterMesh{
		conf:     c,
		nodeName: nodeName,
		globalServices: newGlobalServiceCache(
			c.Metrics.TotalGlobalServices.WithLabelValues(c.ClusterInfo.Name, nodeName),
		),
	}

	cm.common = common.NewClusterMesh(common.Configuration{
		Config:                       c.Config,
		ClusterInfo:                  c.ClusterInfo,
		ClusterSizeDependantInterval: c.ClusterSizeDependantInterval,
		ServiceIPGetter:              c.ServiceIPGetter,

		NewRemoteCluster: cm.NewRemoteCluster,

		NodeName: nodeName,
		Metrics:  c.CommonMetrics,
	})

	lifecycle.Append(&cm.common)
	return cm
}

func (cm *ClusterMesh) NewRemoteCluster(name string, status common.StatusFunc) common.RemoteCluster {
	rc := &remoteCluster{
		name:         name,
		mesh:         cm,
		usedIDs:      cm.conf.ClusterIDsManager,
		status:       status,
		storeFactory: cm.conf.StoreFactory,
		synced:       newSynced(),
	}
	rc.remoteNodes = cm.conf.StoreFactory.NewWatchStore(
		name,
		cm.conf.NodeKeyCreator,
		cm.conf.NodeObserver,
		store.RWSWithOnSyncCallback(func(ctx context.Context) { close(rc.synced.nodes) }),
		store.RWSWithEntriesMetric(cm.conf.Metrics.TotalNodes.WithLabelValues(cm.conf.ClusterInfo.Name, cm.nodeName, rc.name)),
	)

	rc.remoteServices = cm.conf.StoreFactory.NewWatchStore(
		name,
		func() store.Key { return new(serviceStore.ClusterService) },
		&remoteServiceObserver{remoteCluster: rc, swg: rc.synced.services},
		store.RWSWithOnSyncCallback(func(ctx context.Context) { rc.synced.services.Stop() }),
	)

	rc.ipCacheWatcher = ipcache.NewIPIdentityWatcher(
		name, cm.conf.IPCache, cm.conf.StoreFactory,
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

// SyncedWaitFn is the type of a function to wait for the initial synchronization
// of a given resource type from all remote clusters.
type SyncedWaitFn func(ctx context.Context) error

// NodesSynced returns after that the initial list of nodes has been received
// from all remote clusters, and synchronized with the different subscribers.
func (cm *ClusterMesh) NodesSynced(ctx context.Context) error {
	return cm.synced(ctx, func(rc *remoteCluster) SyncedWaitFn { return rc.synced.Nodes })
}

// ServicesSynced returns after that the initial list of shared services has been
// received from all remote clusters, and synchronized with the BPF datapath.
func (cm *ClusterMesh) ServicesSynced(ctx context.Context) error {
	return cm.synced(ctx, func(rc *remoteCluster) SyncedWaitFn { return rc.synced.Services })
}

// IPIdentitiesSynced returns after that the initial list of ipcache entries and
// identities has been received from all remote clusters, and synchronized with
// the BPF datapath.
func (cm *ClusterMesh) IPIdentitiesSynced(ctx context.Context) error {
	return cm.synced(ctx, func(rc *remoteCluster) SyncedWaitFn { return rc.synced.IPIdentities })
}

func (cm *ClusterMesh) synced(ctx context.Context, toWaitFn func(*remoteCluster) SyncedWaitFn) error {
	waiters := make([]SyncedWaitFn, 0)
	cm.common.ForEachRemoteCluster(func(rci common.RemoteCluster) error {
		rc := rci.(*remoteCluster)
		waiters = append(waiters, toWaitFn(rc))
		return nil
	})

	for _, wait := range waiters {
		err := wait(ctx)

		// Ignore the error in case the given cluster was disconnected in
		// the meanwhile, as we do not longer care about it.
		if err != nil && !errors.Is(err, ErrRemoteClusterDisconnected) {
			return err
		}
	}
	return nil
}

// Status returns the status of the ClusterMesh subsystem
func (cm *ClusterMesh) Status() (status *models.ClusterMeshStatus) {
	status = &models.ClusterMeshStatus{
		NumGlobalServices: int64(cm.globalServices.size()),
	}

	cm.common.ForEachRemoteCluster(func(rci common.RemoteCluster) error {
		rc := rci.(*remoteCluster)
		status.Clusters = append(status.Clusters, rc.Status())
		return nil
	})

	return
}
