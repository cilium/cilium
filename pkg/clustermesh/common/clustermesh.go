// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type StatusFunc func() *models.RemoteCluster
type RemoteClusterCreatorFunc func(name string, status StatusFunc) RemoteCluster

// Configuration is the configuration that must be provided to
// NewClusterMesh()
type Configuration struct {
	Logger *slog.Logger

	Config

	// ClusterInfo is the id/name of the local cluster. This is used for logging and metrics
	ClusterInfo types.ClusterInfo

	// NewRemoteCluster is a function returning a new implementation of the remote cluster business logic.
	NewRemoteCluster RemoteClusterCreatorFunc

	// nodeName is the name of the local node. This is used for logging and metrics
	NodeName string

	// ClusterSizeDependantInterval allows to calculate intervals based on cluster size.
	ClusterSizeDependantInterval kvstore.ClusterSizeDependantIntervalFunc

	// ServiceResolver, if not nil, is used to create a custom dialer for service resolution.
	ServiceResolver *dial.ServiceResolver

	// Metrics holds the different clustermesh metrics.
	Metrics Metrics
}

type ClusterMesh interface {
	cell.HookInterface

	// ForEachRemoteCluster calls the provided function for each remote cluster
	// in the ClusterMesh.
	ForEachRemoteCluster(fn func(RemoteCluster) error) error
	// NumReadyClusters returns the number of remote clusters to which a connection
	// has been established
	NumReadyClusters() int
}

// clusterMesh is a cache of multiple remote clusters
type clusterMesh struct {
	// conf is the configuration, it is immutable after NewClusterMesh()
	conf Configuration

	mutex lock.RWMutex
	wg    sync.WaitGroup

	clusters      map[string]*remoteCluster
	configWatcher *configDirectoryWatcher

	// tombstones tracks the remote cluster configurations that have been removed,
	// and whose cleanup process is being currently performed. This allows for
	// asynchronously performing the appropriate tasks, while preventing the
	// reconnection to the same cluster until the previously cleanup completed.
	tombstones map[string]string

	// rctx is a context that is used on cluster removal, to allow aborting
	// the associated process if still running during shutdown (via rcancel).
	rctx    context.Context
	rcancel context.CancelFunc
}

// NewClusterMesh creates a new remote cluster cache based on the
// provided configuration
func NewClusterMesh(c Configuration) ClusterMesh {
	rctx, rcancel := context.WithCancel(context.Background())
	return &clusterMesh{
		conf:       c,
		clusters:   map[string]*remoteCluster{},
		tombstones: map[string]string{},
		rctx:       rctx,
		rcancel:    rcancel,
	}
}

func (cm *clusterMesh) Start(cell.HookContext) error {
	w, err := createConfigDirectoryWatcher(cm.conf.Logger, cm.conf.ClusterMeshConfig, cm)
	if err != nil {
		return fmt.Errorf("unable to create config directory watcher: %w", err)
	}

	cm.configWatcher = w

	if err := cm.configWatcher.watch(); err != nil {
		return fmt.Errorf("unable to start config directory watcher: %w", err)
	}

	return nil
}

// Close stops watching for remote cluster configuration files to appear and
// will close all connections to remote clusters
func (cm *clusterMesh) Stop(cell.HookContext) error {
	if cm.configWatcher != nil {
		cm.configWatcher.close()
	}

	// Wait until all in-progress removal processes have completed, if any.
	// We must not hold the mutex at this point, as needed by the go routines.
	cm.rcancel()
	cm.wg.Wait()

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	for name, cluster := range cm.clusters {
		cluster.onStop()
		delete(cm.clusters, name)
	}

	return nil
}

func (cm *clusterMesh) newRemoteCluster(name, path string) *remoteCluster {
	rc := &remoteCluster{
		name:                         name,
		configPath:                   path,
		clusterSizeDependantInterval: cm.conf.ClusterSizeDependantInterval,

		resolvers: func() []dial.Resolver {
			if cm.conf.ServiceResolver != nil {
				return []dial.Resolver{cm.conf.ServiceResolver}
			}
			return nil
		}(),

		controllers:                    controller.NewManager(),
		remoteConnectionControllerName: fmt.Sprintf("remote-etcd-%s", name),

		logger: cm.conf.Logger.With(logfields.ClusterName, name),

		backendFactory:     kvstore.NewClient,
		clusterLockFactory: newClusterLock,

		metricLastFailureTimestamp: cm.conf.Metrics.LastFailureTimestamp.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName, name),
		metricReadinessStatus:      cm.conf.Metrics.ReadinessStatus.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName, name),
		metricTotalFailures:        cm.conf.Metrics.TotalFailures.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName, name),
	}

	rc.RemoteCluster = cm.conf.NewRemoteCluster(name, rc.status)
	return rc
}

func (cm *clusterMesh) add(name, path string) {
	if name == cm.conf.ClusterInfo.Name {
		cm.conf.Logger.Debug("Ignoring configuration for own cluster", fieldClusterName, name)
		return
	}

	if err := types.ValidateClusterName(name); err != nil {
		cm.conf.Logger.Error(
			"Cannot connect to remote cluster",
			logfields.Error, fmt.Errorf("invalid cluster name: %w", err),
			fieldClusterName, name,
		)
		return
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.addLocked(name, path)
}

func (cm *clusterMesh) addLocked(name, path string) {
	if _, ok := cm.tombstones[name]; ok {
		// The configuration for this cluster has been recreated before the cleanup
		// of the same cluster completed. Let's queue it for delayed processing.
		cm.tombstones[name] = path
		cm.conf.Logger.Info("Delaying configuration of remote cluster, which is still being removed", fieldClusterName, name)
		return
	}

	cluster, ok := cm.clusters[name]
	if !ok {
		cluster = cm.newRemoteCluster(name, path)
		cm.clusters[name] = cluster
	}

	cm.conf.Metrics.TotalRemoteClusters.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName).Set(float64(len(cm.clusters)))

	cluster.connect()
}

func (cm *clusterMesh) remove(name string) {
	const removed = ""

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cluster, ok := cm.clusters[name]
	if !ok {
		if _, alreadyRemoving := cm.tombstones[name]; alreadyRemoving {
			// Reset possibly queued add events
			cm.tombstones[name] = removed
		}

		return
	}

	cm.tombstones[name] = removed
	delete(cm.clusters, name)
	cm.conf.Metrics.TotalRemoteClusters.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName).Set(float64(len(cm.clusters)))

	cm.wg.Add(1)
	go func() {
		defer cm.wg.Done()

		// Run onRemove in a separate go routing as potentially slow, to avoid
		// blocking the processing of further events in the meanwhile.
		cluster.onRemove(cm.rctx)

		cm.mutex.Lock()
		path := cm.tombstones[name]
		delete(cm.tombstones, name)

		if path != removed {
			// Let's replay the queued add event.
			cm.conf.Logger.Info("Replaying delayed configuration of new remote cluster after removal", fieldClusterName, name)
			cm.addLocked(name, path)
		}
		cm.mutex.Unlock()
	}()

	cm.conf.Logger.Debug("Remote cluster configuration removed", fieldClusterName, name)
}

// NumReadyClusters returns the number of remote clusters to which a connection
// has been established
func (cm *clusterMesh) NumReadyClusters() int {
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

func (cm *clusterMesh) ForEachRemoteCluster(fn func(RemoteCluster) error) error {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	for _, cluster := range cm.clusters {
		if err := fn(cluster.RemoteCluster); err != nil {
			return err
		}
	}

	return nil
}
