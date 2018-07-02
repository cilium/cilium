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
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

var (
	nodes      = map[string]*testNode{}
	nodesMutex lock.RWMutex
)

type testNode struct {
	// Name is the name of the node. This is typically the hostname of the node.
	Name string

	// Cluster is the name of the cluster the node is associated with
	Cluster string
}

func (n *testNode) GetKeyName() string {
	return path.Join(n.Name, n.Cluster)
}

func (n *testNode) OnUpdate() {
	nodesMutex.Lock()
	nodes[n.GetKeyName()] = n
	nodesMutex.Unlock()
}

func (n *testNode) OnDelete() {
	nodesMutex.Lock()
	delete(nodes, n.GetKeyName())
	nodesMutex.Unlock()
}

func (n *testNode) Marshal() ([]byte, error) {
	return json.Marshal(n)
}

func (n *testNode) Unmarshal(data []byte) error {
	return json.Unmarshal(data, n)
}

var testNodeCreator = func() store.Key {
	n := testNode{}
	return &n
}

func (s *ClusterMeshTestSuite) TestRemoteConnection(c *C) {
	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	dir, err := ioutil.TempDir("", "multicluster")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	etcdConfig := []byte("endpoints:\n- http://127.0.0.1:4002\n")
	err = ioutil.WriteFile(path.Join(dir, "cluster1"), etcdConfig, 0644)
	c.Assert(err, IsNil)

	err = ioutil.WriteFile(path.Join(dir, "cluster2"), etcdConfig, 0644)
	c.Assert(err, IsNil)

	remote, err := NewRemoteClustersCache("test2", dir, testNodeCreator)
	c.Assert(err, IsNil)
	c.Assert(remote, Not(IsNil))

	nodeNames := []string{"foo", "bar", "baz"}
	numClusters := 2

	// wait for all clusters to appear
	c.Assert(testutils.WaitUntil(func() bool {
		remote.mutex.RLock()
		defer remote.mutex.RUnlock()
		for _, rc := range remote.clusters {
			rc.mutex.RLock()
			nodeStoreAvailable := rc.remoteNodes != nil
			rc.mutex.RUnlock()
			if !nodeStoreAvailable {
				return false
			}
		}
		return len(remote.clusters) == numClusters
	}, 5*time.Second), IsNil)

	remote.mutex.RLock()
	for _, rc := range remote.clusters {
		rc.mutex.RLock()
		for _, name := range nodeNames {
			err = rc.remoteNodes.UpdateLocalKeySync(&testNode{Name: name, Cluster: rc.name})
			c.Assert(err, IsNil)
		}
		rc.mutex.RUnlock()
	}
	remote.mutex.RUnlock()

	// wait for all clusters to announce all nodes
	c.Assert(testutils.WaitUntil(func() bool {
		nodesMutex.RLock()
		defer nodesMutex.RUnlock()
		return len(nodes) == numClusters*len(nodeNames)
	}, 10*time.Second), IsNil)
}
