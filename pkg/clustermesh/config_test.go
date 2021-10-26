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

// +build !privileged_tests

package clustermesh

import (
	"os"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/identity"

	. "gopkg.in/check.v1"
)

func createFile(c *C, name string) {
	err := os.WriteFile(name, []byte("endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2379\n"), 0644)
	c.Assert(err, IsNil)
}

func expectExists(c *C, cm *ClusterMesh, name string) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	c.Assert(cm.clusters[name], Not(IsNil))
}

func expectChange(c *C, cm *ClusterMesh, name string) {
	cm.mutex.RLock()
	cluster := cm.clusters[name]
	cm.mutex.RUnlock()
	c.Assert(cluster, Not(IsNil))

	select {
	case <-cluster.changed:
	case <-time.After(time.Second):
		c.Fatal("timeout while waiting for changed event")
	}
}

func expectNotExist(c *C, cm *ClusterMesh, name string) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	c.Assert(cm.clusters[name], IsNil)
}

func (s *ClusterMeshTestSuite) TestWatchConfigDirectory(c *C) {
	skipKvstoreConnection = true
	defer func() {
		skipKvstoreConnection = false
	}()

	dir, err := os.MkdirTemp("", "multicluster")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	file1 := path.Join(dir, "cluster1")
	file2 := path.Join(dir, "cluster2")
	file3 := path.Join(dir, "cluster3")

	createFile(c, file1)
	createFile(c, file2)

	mgr := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	<-mgr.InitIdentityAllocator(nil, nil)

	cm, err := NewClusterMesh(Configuration{
		Name:                  "test1",
		ConfigDirectory:       dir,
		NodeKeyCreator:        testNodeCreator,
		RemoteIdentityWatcher: mgr,
	})
	c.Assert(err, IsNil)
	c.Assert(cm, Not(IsNil))
	defer cm.Close()

	// wait for cluster1 and cluster2 to appear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return len(cm.clusters) == 2
	}, time.Second), IsNil)
	expectExists(c, cm, "cluster1")
	expectExists(c, cm, "cluster2")
	expectNotExist(c, cm, "cluster3")

	err = os.RemoveAll(file1)
	c.Assert(err, IsNil)

	// wait for cluster1 to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return len(cm.clusters) == 1
	}, time.Second), IsNil)

	createFile(c, file3)

	// wait for cluster3 to appear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return len(cm.clusters) == 2
	}, time.Second), IsNil)
	expectNotExist(c, cm, "cluster1")
	expectExists(c, cm, "cluster2")
	expectExists(c, cm, "cluster3")

	// Test renaming of file from cluster3 to cluster1
	err = os.Rename(file3, file1)
	c.Assert(err, IsNil)

	// wait for cluster1 to appear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return cm.clusters["cluster1"] != nil
	}, time.Second), IsNil)
	expectExists(c, cm, "cluster2")
	expectNotExist(c, cm, "cluster3")

	// touch file
	err = os.Chtimes(file1, time.Now(), time.Now())
	c.Assert(err, IsNil)

	// give time for events to be processed
	time.Sleep(100 * time.Millisecond)
	expectChange(c, cm, "cluster1")

	err = os.RemoveAll(file1)
	c.Assert(err, IsNil)
	err = os.RemoveAll(file2)
	c.Assert(err, IsNil)

	// wait for all clusters to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return len(cm.clusters) == 0
	}, time.Second), IsNil)
	expectNotExist(c, cm, "cluster1")
	expectNotExist(c, cm, "cluster2")
	expectNotExist(c, cm, "cluster3")

}

func (s *ClusterMeshTestSuite) TestIsEtcdConfigFile(c *C) {
	dir, err := os.MkdirTemp("", "etcdconfig")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	validPath := path.Join(dir, "valid")
	err = os.WriteFile(validPath, []byte("endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2379\n"), 0644)
	c.Assert(err, IsNil)
	c.Assert(isEtcdConfigFile(validPath), Equals, true)

	invalidPath := path.Join(dir, "valid")
	err = os.WriteFile(invalidPath, []byte("sf324kj234lkjsdvl\nwl34kj23l4k\nendpoints"), 0644)
	c.Assert(err, IsNil)
	c.Assert(isEtcdConfigFile(invalidPath), Equals, false)
}
