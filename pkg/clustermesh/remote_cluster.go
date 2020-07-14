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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	serviceStore "github.com/cilium/cilium/pkg/service/store"

	strfmt "github.com/go-openapi/strfmt"
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
	// - backend
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

	swg *lock.StoppableWaitGroup

	// failures is the number of observed failures
	failures int

	// lastFailure is the timestamp of the last failure
	lastFailure time.Time
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

// releaseOldConnection releases the etcd connection to a remote cluster
func (rc *remoteCluster) releaseOldConnection() {
	rc.mutex.Lock()
	ipCacheWatcher := rc.ipCacheWatcher
	rc.ipCacheWatcher = nil

	remoteNodes := rc.remoteNodes
	rc.remoteNodes = nil

	remoteIdentityCache := rc.remoteIdentityCache
	rc.remoteIdentityCache = nil

	remoteServices := rc.remoteServices
	rc.remoteServices = nil

	backend := rc.backend
	rc.backend = nil
	rc.mutex.Unlock()

	// Release resources asynchroneously in the background. Many of these
	// operations may time out if the connection was closed due to an error
	// condition.
	go func() {
		if ipCacheWatcher != nil {
			ipCacheWatcher.Close()
		}
		if remoteNodes != nil {
			remoteNodes.Close(context.TODO())
		}
		if remoteIdentityCache != nil {
			remoteIdentityCache.Close()
		}
		if remoteServices != nil {
			remoteServices.Close(context.TODO())
		}
		if backend != nil {
			backend.Close()
		}
	}()
}

func (rc *remoteCluster) restartRemoteConnection(allocator RemoteIdentityWatcher) {
	rc.controllers.UpdateController(rc.remoteConnectionControllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				rc.releaseOldConnection()

				backend, errChan := kvstore.NewClient(context.TODO(), kvstore.EtcdBackendName,
					map[string]string{
						kvstore.EtcdOptionConfig: rc.configPath,
					},
					&kvstore.ExtraOptions{NoLockQuorumCheck: true})

				// Block until either an error is returned or
				// the channel is closed due to success of the
				// connection
				rc.getLogger().Debugf("Waiting for connection to be established")
				err, isErr := <-errChan
				if isErr {
					if backend != nil {
						backend.Close()
					}
					rc.getLogger().WithError(err).Warning("Unable to establish etcd connection to remote cluster")
					return err
				}

				rc.getLogger().Info("Connection to remote cluster established")

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
					Prefix: path.Join(serviceStore.ServiceStorePrefix, rc.name),
					KeyCreator: func() store.Key {
						svc := serviceStore.ClusterService{}
						return &svc
					},
					SynchronizationInterval: time.Minute,
					Backend:                 backend,
					Observer: &remoteServiceObserver{
						remoteCluster: rc,
						swg:           rc.swg,
					},
				})
				if err != nil {
					remoteNodes.Close(context.TODO())
					backend.Close()
					return err
				}
				rc.swg.Stop()

				remoteIdentityCache, err := allocator.WatchRemoteIdentities(backend)
				if err != nil {
					remoteServices.Close(context.TODO())
					remoteNodes.Close(context.TODO())
					backend.Close()
					return err
				}

				ipCacheWatcher := ipcache.NewIPIdentityWatcher(backend)
				go ipCacheWatcher.Watch(ctx)

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
				rc.releaseOldConnection()
				rc.getLogger().Info("All resources of remote cluster cleaned up")
				return nil
			},
		},
	)
}

func (rc *remoteCluster) onInsert(allocator RemoteIdentityWatcher) {
	rc.getLogger().Info("New remote cluster configuration")

	if skipKvstoreConnection {
		return
	}

	rc.remoteConnectionControllerName = fmt.Sprintf("remote-etcd-%s", rc.name)
	rc.restartRemoteConnection(allocator)

	go func() {
		for {
			val := <-rc.changed
			if val {
				rc.getLogger().Info("etcd configuration has changed, re-creating connection")
				rc.restartRemoteConnection(allocator)
			} else {
				rc.getLogger().Info("Closing connection to remote etcd")
				return
			}
		}
	}()

	go func() {
		for {
			select {
			// terminate routine when remote cluster is removed
			case _, ok := <-rc.changed:
				if !ok {
					return
				}
			default:
			}

			// wait for backend to appear
			rc.mutex.RLock()
			if rc.backend == nil {
				rc.mutex.RUnlock()
				time.Sleep(10 * time.Millisecond)
				continue
			}
			statusCheckErrors := rc.backend.StatusCheckErrors()
			rc.mutex.RUnlock()

			err, ok := <-statusCheckErrors
			if ok && err != nil {
				rc.getLogger().WithError(err).Warning("Error observed on etcd connection, reconnecting etcd")
				rc.mutex.Lock()
				rc.failures++
				rc.lastFailure = time.Now()
				rc.mutex.Unlock()
				rc.restartRemoteConnection(allocator)
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

	return rc.isReadyLocked()
}

func (rc *remoteCluster) isReadyLocked() bool {
	return rc.backend != nil && rc.remoteNodes != nil && rc.ipCacheWatcher != nil
}

func (rc *remoteCluster) status() *models.RemoteCluster {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	// This can happen when the controller in restartRemoteConnection is waiting
	// for the first connection to succeed.
	var backendStatus = "Waiting for initial connection to be established"
	if rc.backend != nil {
		var backendError error
		backendStatus, backendError = rc.backend.Status()
		if backendError != nil {
			backendStatus = backendError.Error()
		}
	}

	return &models.RemoteCluster{
		Name:              rc.name,
		Ready:             rc.isReadyLocked(),
		NumNodes:          int64(rc.remoteNodes.NumEntries()),
		NumSharedServices: int64(rc.remoteServices.NumEntries()),
		NumIdentities:     int64(rc.remoteIdentityCache.NumEntries()),
		Status:            backendStatus,
		NumFailures:       int64(rc.failures),
		LastFailure:       strfmt.DateTime(rc.lastFailure),
	}
}
