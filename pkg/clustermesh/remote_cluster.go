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
	"context"
	"fmt"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/service"

	"github.com/sirupsen/logrus"
)

// remoteCluster represents another cluster other than the cluster the agent is
// running in
type remoteCluster struct {
	// name is the name of the cluster
	name string

	// configPath is the path to the etcd configuration to be used to
	// connect to the etcd cluster of the remote cluster
	configPath string

	// changed receives an event when the remote cluster configuration has
	// changed and is closed when the configuration file was removed
	changed chan bool

	// mesh is the cluster mesh this remote cluster belongs to
	mesh *ClusterMesh

	controllers *controller.Manager

	// remoteConnectionControllerName is the name of the backing controller
	// that maintains the remote connection
	remoteConnectionControllerName string

	// mutex protects the following variables
	// - store
	// - remoteNodes
	// - ipCacheWatcher
	// - remoteIdentityCache
	mutex lock.RWMutex

	// store is the shared store representing all nodes in the remote cluster
	remoteNodes *store.SharedStore

	// remoteServices is the shared store representing services in remote
	// clusters
	remoteServices *store.SharedStore

	// ipCacheWatcher is the watcher that notifies about IP<->identity
	// changes in the remote cluster
	ipCacheWatcher *ipcache.IPIdentityWatcher

	// remoteIdentityCache is a locally cached copy of the identity
	// allocations in the remote cluster
	remoteIdentityCache *allocator.RemoteCache

	// backend is the kvstore backend being used
	backend kvstore.BackendOperations
}

var (
	// skipKvstoreConnection skips the etcd connection, used for testing
	skipKvstoreConnection bool
)

func (rc *remoteCluster) getLogger() *logrus.Entry {
	var (
		status string
		err    error
	)

	if rc.backend != nil {
		status, err = rc.backend.Status()
	}

	return log.WithFields(logrus.Fields{
		fieldClusterName:   rc.name,
		fieldConfig:        rc.configPath,
		fieldKVStoreStatus: status,
		fieldKVStoreErr:    err,
	})
}

func (rc *remoteCluster) releaseOldConnection() {
	if rc.ipCacheWatcher != nil {
		rc.ipCacheWatcher.Close()
		rc.ipCacheWatcher = nil
	}

	if rc.remoteNodes != nil {
		rc.remoteNodes.Close()
		rc.remoteNodes = nil
	}
	if rc.remoteIdentityCache != nil {
		rc.remoteIdentityCache.Close()
		rc.remoteIdentityCache = nil
	}
	if rc.remoteServices != nil {
		rc.remoteServices.Close()
		rc.remoteServices = nil
	}
	if rc.backend != nil {
		rc.backend.Close()
		rc.backend = nil
	}
}

func (rc *remoteCluster) restartRemoteConnection() {
	rc.controllers.UpdateController(rc.remoteConnectionControllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				rc.mutex.Lock()
				if rc.backend != nil {
					rc.releaseOldConnection()
				}
				rc.mutex.Unlock()

				backend, errChan := kvstore.NewClient(kvstore.EtcdBackendName,
					map[string]string{
						kvstore.EtcdOptionConfig: rc.configPath,
					},
					nil)

				// Block until either an error is returned or
				// the channel is closed due to success of the
				// connection
				rc.getLogger().Debugf("Waiting for connection to be established")
				err, isErr := <-errChan
				if isErr {
					if backend != nil {
						backend.Close()
					}
					rc.getLogger().WithError(err).Warning("Unable to establish etcd connection to remote cluser")
					return err
				}

				remoteNodes, err := store.JoinSharedStore(store.Configuration{
					Prefix:                  path.Join(nodeStore.NodeStorePrefix, rc.name),
					KeyCreator:              rc.mesh.conf.NodeKeyCreator,
					SynchronizationInterval: time.Minute,
					Backend:                 backend,
					Observer:                rc.mesh.conf.NodeObserver(),
				})
				if err != nil {
					backend.Close()
					return err
				}

				remoteServices, err := store.JoinSharedStore(store.Configuration{
					Prefix: path.Join(service.ServiceStorePrefix, rc.name),
					KeyCreator: func() store.Key {
						svc := service.ClusterService{}
						return &svc
					},
					SynchronizationInterval: time.Minute,
					Backend:                 backend,
					Observer: &remoteServiceObserver{
						remoteCluster: rc,
					},
				})
				if err != nil {
					remoteNodes.Close()
					backend.Close()
					return err
				}

				ipCacheWatcher := ipcache.NewIPIdentityWatcher(backend)
				go ipCacheWatcher.Watch()

				remoteIdentityCache := cache.WatchRemoteIdentities(backend)

				rc.mutex.Lock()
				rc.remoteNodes = remoteNodes
				rc.remoteServices = remoteServices
				rc.backend = backend
				rc.ipCacheWatcher = ipCacheWatcher
				rc.remoteIdentityCache = remoteIdentityCache
				rc.mutex.Unlock()

				rc.getLogger().Info("Established connection to remote etcd")

				return nil
			},
			StopFunc: func(ctx context.Context) error {
				rc.mutex.Lock()
				rc.releaseOldConnection()
				rc.mutex.Unlock()

				rc.getLogger().Info("All resources of remote cluster cleaned up")

				return nil
			},
		},
	)
}

func (rc *remoteCluster) onInsert() {
	rc.getLogger().Info("New remote cluster discovered")

	if skipKvstoreConnection {
		return
	}

	rc.remoteConnectionControllerName = fmt.Sprintf("remote-etcd-%s", rc.name)
	rc.restartRemoteConnection()

	go func() {
		for {
			val := <-rc.changed
			if val {
				rc.getLogger().Info("etcd configuration has changed, re-creating connection")
				rc.restartRemoteConnection()
			} else {
				rc.getLogger().Info("Closing connection to remote etcd")
				return
			}
		}
	}()
}

func (rc *remoteCluster) onRemove() {
	rc.controllers.RemoveAllAndWait()
	close(rc.changed)

	rc.getLogger().Info("Remote cluster disconnected")
}

func (rc *remoteCluster) isReady() bool {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	return rc.backend != nil && rc.remoteNodes != nil && rc.ipCacheWatcher != nil
}
