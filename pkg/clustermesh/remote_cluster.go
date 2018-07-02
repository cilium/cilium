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
	"path"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"

	"github.com/sirupsen/logrus"
)

type remoteCluster struct {
	// name is the name of the remote cluster
	name string

	// configPath is the path to the etcd configuration
	configPath string

	// changed receives an event when the remote cluster configuration has
	// changed and is closed when the configuration file was removed
	changed chan bool

	controllers *controller.Manager

	// controllerName is the name of the backing controller that maintains
	// the remote connection
	controllerName string

	// nodesKeyCreator is the creator to be used for the remoteNodes store
	nodesKeyCreator store.KeyCreator

	// mutex protects the following variables
	// - store
	// - backend
	mutex lock.RWMutex

	// store is the shared store representing all nodes in the remote cluster
	remoteNodes *store.SharedStore

	// backend is the kvstor backend being used
	backend kvstore.BackendOperations
}

var (
	// skipKvstoreConnection skips the etcd connection, used for testing
	skipKvstoreConnection bool
)

func newRemoteCluster(name, path string, keyCreator store.KeyCreator) *remoteCluster {
	return &remoteCluster{
		name:            name,
		configPath:      path,
		nodesKeyCreator: keyCreator,
		changed:         make(chan bool, 512),
		controllers:     controller.NewManager(),
	}
}

func (rc *remoteCluster) getLogger() *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"name": rc.name,
	})
}

func (rc *remoteCluster) restartRemoteConnection() {
	rc.controllers.UpdateController(rc.controllerName,
		controller.ControllerParams{
			DoFunc: func() error {
				opts := map[string]string{
					"etcd.config": rc.configPath,
				}
				backend, err := kvstore.NewClient("etcd", opts)
				if err != nil {
					return err
				}

				remoteNodes, err := store.JoinSharedStore(store.Configuration{
					Prefix:                  path.Join(node.NodeStorePrefix, rc.name),
					KeyCreator:              rc.nodesKeyCreator,
					SynchronizationInterval: time.Minute,
					Backend:                 backend,
				})
				if err != nil {
					backend.Close()
					return err
				}

				rc.mutex.Lock()
				rc.remoteNodes = remoteNodes
				rc.backend = backend
				rc.mutex.Unlock()

				rc.getLogger().Info("Established connection to remote etcd")

				return nil
			},
			StopFunc: func() error {
				rc.mutex.Lock()
				if rc.remoteNodes != nil {
					rc.remoteNodes.Close()
				}
				if rc.backend != nil {
					rc.backend.Close()
				}
				rc.mutex.Unlock()

				return nil
			},
		},
	)
}

func (rc *remoteCluster) onInsert() {
	if skipKvstoreConnection {
		return
	}

	rc.controllerName = fmt.Sprintf("remote-etcd-%s", rc.name)
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
	rc.controllers.RemoveAll()
	close(rc.changed)
}

func (rc *remoteCluster) isReady() bool {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	return rc.backend != nil && rc.remoteNodes != nil
}
