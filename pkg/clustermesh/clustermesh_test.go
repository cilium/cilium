// Copyright 2018-2019 Authors of Cilium
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

// +build !privileged_tests

package clustermesh

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type ClusterMeshTestSuite struct{}

var _ = Suite(&ClusterMeshTestSuite{})

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

func (n *testNode) DeepKeyCopy() store.LocalKey {
	return &testNode{
		Name:    n.Name,
		Cluster: n.Cluster,
	}
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

type testObserver struct{}

func (o *testObserver) OnUpdate(k store.Key) {
	n := k.(*testNode)
	nodesMutex.Lock()
	nodes[n.GetKeyName()] = n
	nodesMutex.Unlock()
}

func (o *testObserver) OnDelete(k store.NamedKey) {
	n := k.(*testNode)
	nodesMutex.Lock()
	delete(nodes, n.GetKeyName())
	nodesMutex.Unlock()
}

type identityAllocatorOwnerMock struct{}

func (i *identityAllocatorOwnerMock) UpdateIdentities(added, deleted cache.IdentityCache) {}

func (i *identityAllocatorOwnerMock) GetNodeSuffix() string {
	return "foo"
}

func (s *ClusterMeshTestSuite) TestClusterMesh(c *C) {
	kvstore.SetupDummy("etcd")
	defer kvstore.Close()

	identity.InitWellKnownIdentities()
	cache.InitIdentityAllocator(&identityAllocatorOwnerMock{})
	defer cache.Close()

	dir, err := ioutil.TempDir("", "multicluster")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	etcdConfig := []byte(fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))

	config1 := path.Join(dir, "cluster1")
	err = ioutil.WriteFile(config1, etcdConfig, 0644)
	c.Assert(err, IsNil)

	config2 := path.Join(dir, "cluster2")
	err = ioutil.WriteFile(config2, etcdConfig, 0644)
	c.Assert(err, IsNil)

	cm, err := NewClusterMesh(Configuration{
		Name:            "test2",
		ConfigDirectory: dir,
		NodeKeyCreator:  testNodeCreator,
		nodeObserver:    &testObserver{},
	})
	c.Assert(err, IsNil)
	c.Assert(cm, Not(IsNil))

	nodeNames := []string{"foo", "bar", "baz"}

	// wait for both clusters to appear in the list of cm clusters
	c.Assert(testutils.WaitUntil(func() bool {
		return cm.NumReadyClusters() == 2
	}, 10*time.Second), IsNil)

	cm.mutex.RLock()
	for _, rc := range cm.clusters {
		rc.mutex.RLock()
		for _, name := range nodeNames {
			err = rc.remoteNodes.UpdateLocalKeySync(&testNode{Name: name, Cluster: rc.name})
			c.Assert(err, IsNil)
		}
		rc.mutex.RUnlock()
	}
	cm.mutex.RUnlock()

	// wait for all cm nodes in both clusters to appear in the node list
	c.Assert(testutils.WaitUntil(func() bool {
		nodesMutex.RLock()
		defer nodesMutex.RUnlock()
		return len(nodes) == 2*len(nodeNames)
	}, 10*time.Second), IsNil)

	os.RemoveAll(config2)

	// wait for the removed cluster to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		return cm.NumReadyClusters() == 1
	}, 5*time.Second), IsNil)

	// wait for the nodes of the removed cluster to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		nodesMutex.RLock()
		defer nodesMutex.RUnlock()
		return len(nodes) == len(nodeNames)
	}, 10*time.Second), IsNil)

	os.RemoveAll(config1)

	// wait for the removed cluster to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		return cm.NumReadyClusters() == 0
	}, 5*time.Second), IsNil)

	// wait for the nodes of the removed cluster to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		nodesMutex.RLock()
		defer nodesMutex.RUnlock()
		return len(nodes) == 0
	}, 10*time.Second), IsNil)

	cm.Close()
}
