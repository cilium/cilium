// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"crypto/sha256"
	"os"
	"path"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
)

const (
	content1 = "endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2379\n"
	content2 = "endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2380\n"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

type fakeRemoteCluster struct{}

func (*fakeRemoteCluster) Run(_ context.Context, _ kvstore.BackendOperations, _ types.CiliumClusterConfig, ready chan<- error) {
	close(ready)
}
func (*fakeRemoteCluster) Stop()   {}
func (*fakeRemoteCluster) Remove() {}

func writeFile(t *testing.T, name, content string) {
	t.Helper()

	err := os.WriteFile(name, []byte(content), 0644)
	require.NoError(t, err)
}

func expectChange(t *testing.T, cm *clusterMesh, name string) {
	t.Helper()

	cm.mutex.RLock()
	require.Contains(t, cm.clusters, name)
	cluster := cm.clusters[name]
	cm.mutex.RUnlock()

	select {
	case <-cluster.changed:
	case <-time.After(time.Second):
		t.Fatal("timeout while waiting for changed event")
	}
}

func expectNoChange(t *testing.T, cm *clusterMesh, name string) {
	t.Helper()

	cm.mutex.RLock()
	cluster := cm.clusters[name]
	cm.mutex.RUnlock()
	require.NotNil(t, cluster)

	select {
	case <-cluster.changed:
		t.Fatal("unexpected changed event detected")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWatchConfigDirectory(t *testing.T) {
	skipKvstoreConnection = true
	defer func() {
		skipKvstoreConnection = false
	}()

	baseDir := t.TempDir()

	dataDir := path.Join(baseDir, "..data")
	dataDirTmp := path.Join(baseDir, "..data_tmp")
	dataDir1 := path.Join(baseDir, "..data-1")
	dataDir2 := path.Join(baseDir, "..data-2")
	dataDir3 := path.Join(baseDir, "..data-3")

	require.NoError(t, os.Symlink(dataDir1, dataDir))
	require.NoError(t, os.Mkdir(dataDir1, 0755))
	require.NoError(t, os.Mkdir(dataDir2, 0755))
	require.NoError(t, os.Mkdir(dataDir3, 0755))

	file1 := path.Join(baseDir, "cluster1")
	file2 := path.Join(baseDir, "cluster2")
	file3 := path.Join(baseDir, "cluster3")

	writeFile(t, file1, content1)
	writeFile(t, path.Join(dataDir1, "cluster2"), content1)
	writeFile(t, path.Join(dataDir2, "cluster2"), content2)
	writeFile(t, path.Join(dataDir3, "cluster2"), content1)

	// Create an indirect link, as in case of Kubernetes COnfigMaps/Secret mounted inside pods.
	require.NoError(t, os.Symlink(path.Join(dataDir, "cluster2"), file2))

	gcm := NewClusterMesh(Configuration{
		Config:           Config{ClusterMeshConfig: baseDir},
		ClusterInfo:      types.ClusterInfo{ID: 255, Name: "test2"},
		NewRemoteCluster: func(string, StatusFunc) RemoteCluster { return &fakeRemoteCluster{} },
		Metrics:          MetricsProvider("clustermesh")(),
	})
	cm := gcm.(*clusterMesh)
	hivetest.Lifecycle(t).Append(cm)

	// wait for cluster1 and cluster2 to appear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.ElementsMatch(c, maps.Keys(cm.clusters), []string{"cluster1", "cluster2"})
	}, timeout, tick)

	require.NoError(t, os.RemoveAll(file1))

	// wait for cluster1 to disappear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.ElementsMatch(c, maps.Keys(cm.clusters), []string{"cluster2"})
	}, timeout, tick)

	writeFile(t, file3, content1)

	// wait for cluster3 to appear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.ElementsMatch(c, maps.Keys(cm.clusters), []string{"cluster2", "cluster3"})
	}, timeout, tick)

	// Test renaming of file from cluster3 to cluster1
	require.NoError(t, os.Rename(file3, file1))

	// wait for cluster1 to appear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.ElementsMatch(c, maps.Keys(cm.clusters), []string{"cluster1", "cluster2"})
	}, timeout, tick)

	// touch file
	require.NoError(t, os.Chtimes(file1, time.Now(), time.Now()))
	expectNoChange(t, cm, "cluster1")

	// update file content changing the symlink target, adopting
	// the same approach of the kubelet on ConfigMap/Secret update
	require.NoError(t, os.Symlink(dataDir2, dataDirTmp))
	require.NoError(t, os.Rename(dataDirTmp, dataDir))
	require.NoError(t, os.RemoveAll(dataDir1))
	expectChange(t, cm, "cluster2")

	// update file content once more
	require.NoError(t, os.Symlink(dataDir3, dataDirTmp))
	require.NoError(t, os.Rename(dataDirTmp, dataDir))
	require.NoError(t, os.RemoveAll(dataDir2))
	expectChange(t, cm, "cluster2")

	require.NoError(t, os.RemoveAll(file1))
	require.NoError(t, os.RemoveAll(file2))

	// wait for all clusters to disappear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.Empty(c, cm.clusters)
	}, timeout, tick)

	// Ensure that per-config watches are removed properly
	wl := cm.configWatcher.watcher.WatchList()
	require.ElementsMatch(t, wl, []string{baseDir})
}

func TestIsEtcdConfigFile(t *testing.T) {
	dir := t.TempDir()

	validPath := path.Join(dir, "valid")
	content := []byte("endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2379\n")
	err := os.WriteFile(validPath, content, 0644)
	require.NoError(t, err)

	isConfig, hash := isEtcdConfigFile(validPath)
	require.True(t, isConfig)
	require.Equal(t, fhash(sha256.Sum256(content)), hash)

	invalidPath := path.Join(dir, "valid")
	err = os.WriteFile(invalidPath, []byte("sf324kj234lkjsdvl\nwl34kj23l4k\nendpoints"), 0644)
	require.NoError(t, err)

	isConfig, hash = isEtcdConfigFile(validPath)
	require.False(t, isConfig)
	require.Equal(t, fhash{}, hash)

	isConfig, hash = isEtcdConfigFile(dir)
	require.False(t, isConfig)
	require.Equal(t, fhash{}, hash)
}
