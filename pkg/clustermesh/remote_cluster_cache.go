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

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
)

const (
	configDirectory = "/var/lib/cilium/multicluster/"
)

var (
	keyCreator = func() store.Key {
		n := node.Node{}
		return &n
	}
)

type RemoteClustersCache struct {
	mutex         lock.RWMutex
	clusters      map[string]*remoteCluster
	keyCreator    store.KeyCreator
	controllers   *controller.Manager
	configWatcher *configDirectoryWatcher
}

func NewRemoteClustersCache(name, configDirectory string, keyCreator store.KeyCreator) (*RemoteClustersCache, error) {
	rc := &RemoteClustersCache{
		clusters:    map[string]*remoteCluster{},
		keyCreator:  keyCreator,
		controllers: controller.NewManager(),
	}

	w, err := createConfigDirectoryWatcher(configDirectory, rc)
	if err != nil {
		return nil, fmt.Errorf("unable to create config directory watcher: %s", err)
	}

	rc.configWatcher = w

	rc.controllers.UpdateController("read-multicluster-config",
		controller.ControllerParams{
			DoFunc: func() error { return rc.configWatcher.watch() },
		},
	)

	return rc, nil
}

func (rc *RemoteClustersCache) Close() {
	if rc.configWatcher != nil {
		rc.configWatcher.close()
	}
	rc.controllers.RemoveAll()
}

func (rc *RemoteClustersCache) add(name, path string) {
	inserted := false
	log.WithField("name", name).Debug("Remote cluster configuration added")

	rc.mutex.Lock()
	cluster, ok := rc.clusters[name]
	if !ok {
		cluster = newRemoteCluster(name, path, rc.keyCreator)
		rc.clusters[name] = cluster
		inserted = true
	}
	rc.mutex.Unlock()

	if inserted {
		cluster.onInsert()
	} else {
		// signal a change in configuration
		log.Debug("signaling a change")
		cluster.changed <- true
	}
}

func (rc *RemoteClustersCache) remove(name string) {
	log.WithField("name", name).Debug("Remote cluster configuration removed")

	rc.mutex.Lock()
	if cluster, ok := rc.clusters[name]; ok {
		cluster.onRemove()
		delete(rc.clusters, name)
	}
	rc.mutex.Unlock()
}

func (rc *RemoteClustersCache) NumReadyClusters() int {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	nready := 0
	for _, rc := range rc.clusters {
		if rc.isReady() {
			nready++
		}
	}

	return nready
}
