// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clustermesh

import (
	"fmt"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// configNotificationsChannelSize is the size of the channel used to
	// notify a clustermesh of configuration changes
	configNotificationsChannelSize = 512
)

// Configuration is the configuration that must be provided to
// NewClusterMesh()
type Configuration struct {
	// Name is the name of the remote cluster cache. This is for logging
	// purposes only
	Name string

	// ConfigDirectory is the path to the directory that will be watched for etcd
	// configuration files to appear
	ConfigDirectory string

	// NodeKeyCreator is the function used to create node instances as
	// nodes are being discovered in remote clusters
	NodeKeyCreator store.KeyCreator

	// ServiceMerger is the interface responsible to merge service and
	// endpoints into an existing cache
	ServiceMerger ServiceMerger

	// NodeManager is the node manager to manage all discovered remote
	// nodes
	NodeManager *nodemanager.Manager

	nodeObserver store.Observer

	// RemoteIdentityWatcher provides identities that have been allocated on a
	// remote cluster.
	RemoteIdentityWatcher RemoteIdentityWatcher
}

// RemoteIdentityWatcher is any type which provides identities that have been
// allocated on a remote cluster.
type RemoteIdentityWatcher interface {
	// WatchRemoteIdentities starts watching for identities in another kvstore and
	// syncs all identities to the local identity cache.
	WatchRemoteIdentities(backend kvstore.BackendOperations) (*allocator.RemoteCache, error)

	// Close stops the watcher.
	Close()
}

// NodeObserver returns the node store observer of the configuration
func (c *Configuration) NodeObserver() store.Observer {
	if c.nodeObserver != nil {
		return c.nodeObserver
	}

	return nodeStore.NewNodeObserver(c.NodeManager)
}

// ClusterMesh is a cache of multiple remote clusters
type ClusterMesh struct {
	// conf is the configuration, it is immutable after NewClusterMesh()
	conf Configuration

	mutex         lock.RWMutex
	clusters      map[string]*remoteCluster
	controllers   *controller.Manager
	configWatcher *configDirectoryWatcher

	// globalServices is a list of all global services. The datastructure
	// is protected by its own mutex inside of the structure.
	globalServices *globalServiceCache
}

// NewClusterMesh creates a new remote cluster cache based on the
// provided configuration
func NewClusterMesh(c Configuration) (*ClusterMesh, error) {
	cm := &ClusterMesh{
		conf:           c,
		clusters:       map[string]*remoteCluster{},
		controllers:    controller.NewManager(),
		globalServices: newGlobalServiceCache(),
	}

	w, err := createConfigDirectoryWatcher(c.ConfigDirectory, cm)
	if err != nil {
		return nil, fmt.Errorf("unable to create config directory watcher: %s", err)
	}

	cm.configWatcher = w

	if err := cm.configWatcher.watch(); err != nil {
		return nil, err
	}

	return cm, nil
}

// Close stops watching for remote cluster configuration files to appear and
// will close all connections to remote clusters
func (cm *ClusterMesh) Close() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.configWatcher != nil {
		cm.configWatcher.close()
	}

	for name, cluster := range cm.clusters {
		cluster.onRemove()
		delete(cm.clusters, name)
	}

	cm.controllers.RemoveAllAndWait()
}

func (cm *ClusterMesh) newRemoteCluster(name, path string) *remoteCluster {
	return &remoteCluster{
		name:        name,
		configPath:  path,
		mesh:        cm,
		changed:     make(chan bool, configNotificationsChannelSize),
		controllers: controller.NewManager(),
	}
}

func (cm *ClusterMesh) add(name, path string) {
	if name == option.Config.ClusterName {
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
	cm.mutex.Unlock()

	log.WithField(fieldClusterName, name).Debug("Remote cluster configuration added")

	if inserted {
		cluster.onInsert()
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
