// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// configNotificationsChannelSize is the size of the channel used to
	// notify a clustermesh of configuration changes
	configNotificationsChannelSize = 512
)

type Config struct {
	// ClusterMeshConfig is the path to the clustermesh configuration directory.
	ClusterMeshConfig string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String("clustermesh-config", def.ClusterMeshConfig, "Path to the ClusterMesh configuration directory")
}

type StatusFunc func() *models.RemoteCluster
type RemoteClusterCreatorFunc func(name string, status StatusFunc) RemoteCluster

// Configuration is the configuration that must be provided to
// NewClusterMesh()
type Configuration struct {
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

	mutex         lock.RWMutex
	clusters      map[string]*remoteCluster
	configWatcher *configDirectoryWatcher
}

// NewClusterMesh creates a new remote cluster cache based on the
// provided configuration
func NewClusterMesh(c Configuration) ClusterMesh {
	return &clusterMesh{
		conf:     c,
		clusters: map[string]*remoteCluster{},
	}
}

func (cm *clusterMesh) Start(cell.HookContext) error {
	w, err := createConfigDirectoryWatcher(cm.conf.ClusterMeshConfig, cm)
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
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.configWatcher != nil {
		cm.configWatcher.close()
	}

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

		changed:     make(chan bool, configNotificationsChannelSize),
		controllers: controller.NewManager(),

		logger: log.WithField(logfields.ClusterName, name),

		metricLastFailureTimestamp: cm.conf.Metrics.LastFailureTimestamp.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName, name),
		metricReadinessStatus:      cm.conf.Metrics.ReadinessStatus.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName, name),
		metricTotalFailures:        cm.conf.Metrics.TotalFailures.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName, name),
	}

	rc.RemoteCluster = cm.conf.NewRemoteCluster(name, rc.status)
	return rc
}

func (cm *clusterMesh) add(name, path string) {
	if name == cm.conf.ClusterInfo.Name {
		log.WithField(fieldClusterName, name).Debug("Ignoring configuration for own cluster")
		return
	}

	if err := types.ValidateClusterName(name); err != nil {
		log.WithField(fieldClusterName, name).WithError(err).
			Error("Remote cluster name is invalid. The connection will be forbidden starting from Cilium v1.17")
	}

	inserted := false
	cm.mutex.Lock()
	cluster, ok := cm.clusters[name]
	if !ok {
		cluster = cm.newRemoteCluster(name, path)
		cm.clusters[name] = cluster
		inserted = true
	}

	cm.conf.Metrics.TotalRemoteClusters.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName).Set(float64(len(cm.clusters)))
	cm.mutex.Unlock()

	if inserted {
		cluster.onInsert()
	} else {
		// signal a change in configuration
		cluster.changed <- true
	}
}

func (cm *clusterMesh) remove(name string) {
	cm.mutex.Lock()
	if cluster, ok := cm.clusters[name]; ok {
		cluster.onRemove()
		delete(cm.clusters, name)
		cm.conf.Metrics.TotalRemoteClusters.WithLabelValues(cm.conf.ClusterInfo.Name, cm.conf.NodeName).Set(float64(len(cm.clusters)))
	}
	cm.mutex.Unlock()

	log.WithField(fieldClusterName, name).Debug("Remote cluster configuration removed")
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
