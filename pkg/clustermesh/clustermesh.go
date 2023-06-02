// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

const (
	// configNotificationsChannelSize is the size of the channel used to
	// notify a clustermesh of configuration changes
	configNotificationsChannelSize = 512

	subsystem = "clustermesh"
)

// Configuration is the configuration that must be provided to
// NewClusterMesh()
type Configuration struct {
	cell.In

	Config

	// ClusterIDName is the id/name of the local cluster. This is used for logging and metrics
	types.ClusterIDName

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
	ClusterSizeDependantInterval kvstore.ClusterSizeDependantIntervalFunc `optional:"true"`
}

func SetClusterConfig(ctx context.Context, clusterName string, config *cmtypes.CiliumClusterConfig, backend kvstore.BackendOperations) error {
	key := path.Join(kvstore.ClusterConfigPrefix, clusterName)

	val, err := json.Marshal(config)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	_, err = backend.UpdateIfDifferent(ctx, key, val, true)
	if err != nil {
		return err
	}

	return nil
}

func GetClusterConfig(ctx context.Context, clusterName string, backend kvstore.BackendOperations) (*cmtypes.CiliumClusterConfig, error) {
	var config cmtypes.CiliumClusterConfig

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	val, err := backend.Get(ctx, path.Join(kvstore.ClusterConfigPrefix, clusterName))
	if err != nil {
		return nil, err
	}

	// Cluster configuration missing, but it's not an error
	if val == nil {
		return nil, nil
	}

	if err := json.Unmarshal(val, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// IsClusterConfigRequired returns whether the remote kvstore guarantees that the
// cilium cluster config will be eventually created.
func IsClusterConfigRequired(ctx context.Context, backend kvstore.BackendOperations) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	val, err := backend.Get(ctx, kvstore.HasClusterConfigPath)
	return val != nil, err
}

// RemoteIdentityWatcher is any type which provides identities that have been
// allocated on a remote cluster.
type RemoteIdentityWatcher interface {
	// WatchRemoteIdentities starts watching for identities in another kvstore and
	// syncs all identities to the local identity cache. RemoteName should be unique
	// unless replacing an existing remote's backend.
	WatchRemoteIdentities(remoteName string, backend kvstore.BackendOperations) (*allocator.RemoteCache, error)

	// RemoveRemoteIdentities removes any reference to a remote identity source.
	RemoveRemoteIdentities(name string)

	// Close stops the watcher.
	Close()
}

// ClusterMesh is a cache of multiple remote clusters
type ClusterMesh struct {
	// conf is the configuration, it is immutable after NewClusterMesh()
	conf Configuration

	mutex         lock.RWMutex
	clusters      map[string]*remoteCluster
	configWatcher *configDirectoryWatcher

	// globalServices is a list of all global services. The datastructure
	// is protected by its own mutex inside the structure.
	globalServices *globalServiceCache

	// nodeName is the name of the local node. This is used for logging and metrics
	nodeName string

	// metricTotalRemoteClusters is gauge metric keeping track of total number
	// of remote clusters.
	metricTotalRemoteClusters *prometheus.GaugeVec

	// metricLastFailureTimestamp is a gauge metric tracking the last failure timestamp
	metricLastFailureTimestamp *prometheus.GaugeVec

	// metricReadinessStatus is a gauge metric tracking the readiness status of a remote cluster
	metricReadinessStatus *prometheus.GaugeVec

	// metricTotalFailure is a gauge metric tracking the number of failures when connecting to a remote cluster
	metricTotalFailures *prometheus.GaugeVec

	// metricTotalNodes is a gauge metric tracking the number of total nodes in a remote cluster
	metricTotalNodes *prometheus.GaugeVec
}

// NewClusterMesh creates a new remote cluster cache based on the
// provided configuration
func NewClusterMesh(lifecycle hive.Lifecycle, c Configuration) *ClusterMesh {
	if c.ClusterID == 0 {
		return nil
	}

	if c.ClusterMeshConfig == "" {
		return nil
	}

	nodeName := nodeTypes.GetName()
	cm := &ClusterMesh{
		conf:           c,
		clusters:       map[string]*remoteCluster{},
		globalServices: newGlobalServiceCache(c.ClusterName, nodeName),
		nodeName:       nodeName,

		metricTotalRemoteClusters: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "remote_clusters",
			Help:      "The total number of remote clusters meshed with the local cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName}),

		metricLastFailureTimestamp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "remote_cluster_last_failure_ts",
			Help:      "The timestamp of the last failure of the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),

		metricReadinessStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "remote_cluster_readiness_status",
			Help:      "The readiness status of the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),

		metricTotalFailures: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "remote_cluster_failures",
			Help:      "The total number of failures related to the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),

		metricTotalNodes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "remote_cluster_nodes",
			Help:      "The total number of nodes in the remote cluster",
		}, []string{metrics.LabelSourceCluster, metrics.LabelSourceNodeName, metrics.LabelTargetCluster}),
	}

	lifecycle.Append(cm)
	return cm
}

func (cm *ClusterMesh) Start(hive.HookContext) error {
	w, err := createConfigDirectoryWatcher(cm.conf.ClusterMeshConfig, cm)
	if err != nil {
		return fmt.Errorf("unable to create config directory watcher: %w", err)
	}

	cm.configWatcher = w

	if err := cm.configWatcher.watch(); err != nil {
		return fmt.Errorf("unable to start config directory watcher: %w", err)
	}

	_ = metrics.RegisterList([]prometheus.Collector{
		cm.metricTotalRemoteClusters,
		cm.metricLastFailureTimestamp,
		cm.metricReadinessStatus,
		cm.metricTotalFailures,
		cm.metricTotalNodes,
	})

	return nil
}

// Close stops watching for remote cluster configuration files to appear and
// will close all connections to remote clusters
func (cm *ClusterMesh) Stop(hive.HookContext) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.configWatcher != nil {
		cm.configWatcher.close()
	}

	for name, cluster := range cm.clusters {
		cluster.onStop()
		delete(cm.clusters, name)
	}

	metrics.Unregister(cm.metricTotalRemoteClusters)
	metrics.Unregister(cm.metricLastFailureTimestamp)
	metrics.Unregister(cm.metricReadinessStatus)
	metrics.Unregister(cm.metricTotalFailures)
	metrics.Unregister(cm.metricTotalNodes)

	return nil
}

func (cm *ClusterMesh) newRemoteCluster(name, path string) *remoteCluster {
	rc := &remoteCluster{
		name:        name,
		configPath:  path,
		mesh:        cm,
		changed:     make(chan bool, configNotificationsChannelSize),
		controllers: controller.NewManager(),
		swg:         lock.NewStoppableWaitGroup(),
	}

	rc.remoteNodes = store.NewRestartableWatchStore(
		name,
		cm.conf.NodeKeyCreator,
		cm.conf.NodeObserver,
		store.RWSWithEntriesMetric(rc.mesh.metricTotalNodes.WithLabelValues(rc.mesh.conf.ClusterName, rc.mesh.nodeName, rc.name)),
	)

	rc.remoteServices = store.NewRestartableWatchStore(
		name,
		func() store.Key { return new(serviceStore.ClusterService) },
		&remoteServiceObserver{remoteCluster: rc, swg: rc.swg},
		store.RWSWithOnSyncCallback(func(ctx context.Context) { rc.swg.Stop() }),
	)

	return rc
}

func (cm *ClusterMesh) add(name, path string) {
	if name == cm.conf.ClusterName {
		log.WithField(fieldClusterName, name).Debug("Ignoring configuration for own cluster")
		return
	}

	inserted := false
	cm.mutex.Lock()
	cluster, ok := cm.clusters[name]
	if !ok {
		cluster = cm.newRemoteCluster(name, path)
		cm.clusters[name] = cluster
		inserted = true
	}

	cm.metricTotalRemoteClusters.WithLabelValues(cm.conf.ClusterName, cm.nodeName).Set(float64(len(cm.clusters)))
	cm.mutex.Unlock()

	log.WithField(fieldClusterName, name).Debug("Remote cluster configuration added")

	if inserted {
		cluster.onInsert(cm.conf.RemoteIdentityWatcher)
	} else {
		// signal a change in configuration
		cluster.changed <- true
	}
}

func (cm *ClusterMesh) remove(name string) {
	cm.mutex.Lock()
	if cluster, ok := cm.clusters[name]; ok {
		cluster.onRemove()
		delete(cm.clusters, name)
		cm.metricTotalRemoteClusters.WithLabelValues(cm.conf.ClusterName, cm.nodeName).Set(float64(len(cm.clusters)))
		cm.globalServices.onClusterDelete(name)
	}
	cm.mutex.Unlock()

	log.WithField(fieldClusterName, name).Debug("Remote cluster configuration removed")
}

// NumReadyClusters returns the number of remote clusters to which a connection
// has been established
func (cm *ClusterMesh) NumReadyClusters() int {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	nready := 0
	for _, cm := range cm.clusters {
		if cm.isReady() {
			nready++
		}
	}

	return nready
}

func (cm *ClusterMesh) canConnect(name string, config *cmtypes.CiliumClusterConfig) error {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	for n, rc := range cm.clusters {
		if err := func() error {
			rc.mutex.RLock()
			defer rc.mutex.RUnlock()

			if rc.name == name || !rc.isReadyLocked() || rc.config == nil {
				return nil
			}

			if err := rc.config.IsCompatible(config); err != nil {
				return err
			}

			return nil
		}(); err != nil {
			return fmt.Errorf("configuration of %s is not compatible with %s: %w", name, n, err)
		}
	}

	return nil
}

// ClustersSynced returns after all clusters were synchronized with the bpf
// datapath.
func (cm *ClusterMesh) ClustersSynced(ctx context.Context) error {
	cm.mutex.RLock()
	swgs := make([]*lock.StoppableWaitGroup, 0, len(cm.clusters))
	for _, cluster := range cm.clusters {
		swgs = append(swgs, cluster.swg)
	}
	cm.mutex.RUnlock()

	for _, swg := range swgs {
		select {
		case <-swg.WaitChannel():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Status returns the status of the ClusterMesh subsystem
func (cm *ClusterMesh) Status() (status *models.ClusterMeshStatus) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	status = &models.ClusterMeshStatus{
		NumGlobalServices: int64(cm.globalServices.size()),
	}

	for _, cm := range cm.clusters {
		status.Clusters = append(status.Clusters, cm.status())
	}

	return
}
