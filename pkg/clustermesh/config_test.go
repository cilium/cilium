// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"crypto/sha256"
	"os"
	"path"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	content1 = "endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2379\n"
	content2 = "endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2380\n"
)

func writeFile(c *C, name, content string) {
	err := os.WriteFile(name, []byte(content), 0644)
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

func expectNoChange(c *C, cm *ClusterMesh, name string) {
	cm.mutex.RLock()
	cluster := cm.clusters[name]
	cm.mutex.RUnlock()
	c.Assert(cluster, Not(IsNil))

	select {
	case <-cluster.changed:
		c.Fatal("unexpected changed event detected")
	case <-time.After(100 * time.Millisecond):
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

	baseDir, err := os.MkdirTemp("", "multicluster")
	c.Assert(err, IsNil)
	defer os.RemoveAll(baseDir)

	dataDir := path.Join(baseDir, "..data")
	dataDirTmp := path.Join(baseDir, "..data_tmp")
	dataDir1 := path.Join(baseDir, "..data-1")
	dataDir2 := path.Join(baseDir, "..data-2")
	dataDir3 := path.Join(baseDir, "..data-3")

	c.Assert(os.Symlink(dataDir1, dataDir), IsNil)
	c.Assert(os.Mkdir(dataDir1, 0755), IsNil)
	c.Assert(os.Mkdir(dataDir2, 0755), IsNil)
	c.Assert(os.Mkdir(dataDir3, 0755), IsNil)

	file1 := path.Join(baseDir, "cluster1")
	file2 := path.Join(baseDir, "cluster2")
	file3 := path.Join(baseDir, "cluster3")

	writeFile(c, file1, content1)
	writeFile(c, path.Join(dataDir1, "cluster2"), content1)
	writeFile(c, path.Join(dataDir2, "cluster2"), content2)
	writeFile(c, path.Join(dataDir3, "cluster2"), content1)

	// Create an indirect link, as in case of Kubernetes COnfigMaps/Secret mounted inside pods.
	c.Assert(os.Symlink(path.Join(dataDir, "cluster2"), file2), IsNil)

	cm := NewClusterMesh(hivetest.Lifecycle(c), Configuration{
		Config:        Config{ClusterMeshConfig: baseDir},
		ClusterIDName: types.ClusterIDName{ClusterID: 255, ClusterName: "test2"},
	})
	c.Assert(cm, Not(IsNil))

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

	writeFile(c, file3, content1)

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
	c.Assert(os.Chtimes(file1, time.Now(), time.Now()), IsNil)
	expectNoChange(c, cm, "cluster1")

	// update file content changing the symlink target, adopting
	// the same approach of the kubelet on ConfigMap/Secret update
	c.Assert(os.Symlink(dataDir2, dataDirTmp), IsNil)
	c.Assert(os.Rename(dataDirTmp, dataDir), IsNil)
	c.Assert(os.RemoveAll(dataDir1), IsNil)
	expectChange(c, cm, "cluster2")

	// update file content once more
	c.Assert(os.Symlink(dataDir3, dataDirTmp), IsNil)
	c.Assert(os.Rename(dataDirTmp, dataDir), IsNil)
	c.Assert(os.RemoveAll(dataDir2), IsNil)
	expectChange(c, cm, "cluster2")

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

	// Ensure that per-config watches are removed properly
	wl := cm.configWatcher.watcher.WatchList()
	c.Assert(wl, HasLen, 1)
	c.Assert(wl[0], Equals, baseDir)
}

func (s *ClusterMeshTestSuite) TestIsEtcdConfigFile(c *C) {
	dir, err := os.MkdirTemp("", "etcdconfig")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	validPath := path.Join(dir, "valid")
	content := []byte("endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2379\n")
	err = os.WriteFile(validPath, content, 0644)
	c.Assert(err, IsNil)

	isConfig, hash := isEtcdConfigFile(validPath)
	c.Assert(isConfig, Equals, true)
	c.Assert(hash, Equals, fhash(sha256.Sum256(content)))

	invalidPath := path.Join(dir, "valid")
	err = os.WriteFile(invalidPath, []byte("sf324kj234lkjsdvl\nwl34kj23l4k\nendpoints"), 0644)
	c.Assert(err, IsNil)

	isConfig, hash = isEtcdConfigFile(validPath)
	c.Assert(isConfig, Equals, false)
	c.Assert(hash, Equals, fhash{})

	isConfig, hash = isEtcdConfigFile(dir)
	c.Assert(isConfig, Equals, false)
	c.Assert(hash, Equals, fhash{})
}
