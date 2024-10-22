// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"crypto/sha256"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/renameio/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/lock"
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

func writeFile(t *testing.T, name, content string) {
	t.Helper()

	err := renameio.WriteFile(name, []byte(content), 0644, renameio.WithTempDir(os.TempDir()))
	require.NoError(t, err)
}

type fakeLifecycle struct {
	clusters map[string]chan struct{}
	mutex    lock.RWMutex
}

func newFakeLifecycle() *fakeLifecycle {
	return &fakeLifecycle{clusters: map[string]chan struct{}{}}
}

func (fl *fakeLifecycle) add(clusterName, _ string) {
	fl.mutex.Lock()
	defer fl.mutex.Unlock()

	ch, ok := fl.clusters[clusterName]
	if ok {
		ch <- struct{}{}
	} else {
		fl.clusters[clusterName] = make(chan struct{}, 1)
	}
}

func (fl *fakeLifecycle) remove(clusterName string) {
	fl.mutex.Lock()
	delete(fl.clusters, clusterName)
	fl.mutex.Unlock()
}

func (fl *fakeLifecycle) expectChange(t *testing.T, name string) {
	t.Helper()

	fl.mutex.RLock()
	changed := fl.clusters[name]
	fl.mutex.RUnlock()

	require.NotNil(t, changed, "Could not find cluster %s", name)

	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("timeout while waiting for changed event")
	}
}

func (fl *fakeLifecycle) expectNoChange(t *testing.T, name string) {
	t.Helper()

	fl.mutex.RLock()
	changed := fl.clusters[name]
	fl.mutex.RUnlock()

	require.NotNil(t, changed, "Could not find cluster %s", name)

	select {
	case <-changed:
		t.Fatal("unexpected changed event detected")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWatchConfigDirectory(t *testing.T) {
	baseDir := t.TempDir()

	dataDir := filepath.Join(baseDir, "..data")
	dataDirTmp := filepath.Join(baseDir, "..data_tmp")
	dataDir1 := filepath.Join(baseDir, "..data-1")
	dataDir2 := filepath.Join(baseDir, "..data-2")
	dataDir3 := filepath.Join(baseDir, "..data-3")

	require.NoError(t, os.Symlink(dataDir1, dataDir))
	require.NoError(t, os.Mkdir(dataDir1, 0755))
	require.NoError(t, os.Mkdir(dataDir2, 0755))
	require.NoError(t, os.Mkdir(dataDir3, 0755))

	file1 := filepath.Join(baseDir, "cluster1")
	file2 := filepath.Join(baseDir, "cluster2")
	file3 := filepath.Join(baseDir, "cluster3")

	writeFile(t, file1, content1)
	writeFile(t, filepath.Join(dataDir1, "cluster2"), content1)
	writeFile(t, filepath.Join(dataDir2, "cluster2"), content2)
	writeFile(t, filepath.Join(dataDir3, "cluster2"), content1)

	// Create an indirect link, as in case of Kubernetes COnfigMaps/Secret mounted inside pods.
	require.NoError(t, os.Symlink(filepath.Join(dataDir, "cluster2"), file2))

	cm := newFakeLifecycle()
	watcher, err := createConfigDirectoryWatcher(baseDir, cm)
	require.NoError(t, err, "Failed to create configuration watcher")
	t.Cleanup(watcher.close)

	require.NoError(t, watcher.watch(), "Failed to start the configuration watcher")

	// wait for cluster1 and cluster2 to appear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.ElementsMatch(c, slices.Collect(maps.Keys(cm.clusters)), []string{"cluster1", "cluster2"})
	}, timeout, tick)

	require.NoError(t, os.RemoveAll(file1))

	// wait for cluster1 to disappear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.ElementsMatch(c, slices.Collect(maps.Keys(cm.clusters)), []string{"cluster2"})
	}, timeout, tick)

	writeFile(t, file3, content1)

	// wait for cluster3 to appear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.ElementsMatch(c, slices.Collect(maps.Keys(cm.clusters)), []string{"cluster2", "cluster3"})
	}, timeout, tick)

	// Test renaming of file from cluster3 to cluster1
	require.NoError(t, os.Rename(file3, file1))

	// wait for cluster1 to appear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.ElementsMatch(c, slices.Collect(maps.Keys(cm.clusters)), []string{"cluster1", "cluster2"})
	}, timeout, tick)

	// touch file
	require.NoError(t, os.Chtimes(file1, time.Now(), time.Now()))
	cm.expectNoChange(t, "cluster1")

	// update file content changing the symlink target, adopting
	// the same approach of the kubelet on ConfigMap/Secret update
	require.NoError(t, os.Symlink(dataDir2, dataDirTmp))
	require.NoError(t, os.Rename(dataDirTmp, dataDir))
	require.NoError(t, os.RemoveAll(dataDir1))
	cm.expectChange(t, "cluster2")

	// update file content once more
	require.NoError(t, os.Symlink(dataDir3, dataDirTmp))
	require.NoError(t, os.Rename(dataDirTmp, dataDir))
	require.NoError(t, os.RemoveAll(dataDir2))
	cm.expectChange(t, "cluster2")

	require.NoError(t, os.RemoveAll(file1))
	require.NoError(t, os.RemoveAll(file2))

	// wait for all clusters to disappear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		assert.Empty(c, cm.clusters)
	}, timeout, tick)

	// Ensure that per-config watches are removed properly
	wl := watcher.watcher.WatchList()
	require.ElementsMatch(t, wl, []string{baseDir})

	// Attempting to watch a non existing directory should return an error
	_, err = createConfigDirectoryWatcher(filepath.Join(baseDir, "non-existing"), cm)
	require.Error(t, err, "Attempting to watch a non existing directory should return an error")
}

func TestIsEtcdConfigFile(t *testing.T) {
	dir := t.TempDir()

	validPath := filepath.Join(dir, "valid")
	content := []byte("endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2379\n")
	err := os.WriteFile(validPath, content, 0644)
	require.NoError(t, err)

	isConfig, hash := isEtcdConfigFile(validPath)
	require.True(t, isConfig)
	require.Equal(t, fhash(sha256.Sum256(content)), hash)

	invalidPath := filepath.Join(dir, "valid")
	err = os.WriteFile(invalidPath, []byte("sf324kj234lkjsdvl\nwl34kj23l4k\nendpoints"), 0644)
	require.NoError(t, err)

	isConfig, hash = isEtcdConfigFile(validPath)
	require.False(t, isConfig)
	require.Equal(t, fhash{}, hash)

	isConfig, hash = isEtcdConfigFile(dir)
	require.False(t, isConfig)
	require.Equal(t, fhash{}, hash)
}

func TestConfigFiles(t *testing.T) {
	var (
		baseDir  = t.TempDir()
		empty    = filepath.Join(baseDir, "empty")
		expected = make(map[string]string)
	)

	require.NoError(t, os.Mkdir(empty, 0755))
	writeFile(t, filepath.Join(baseDir, "other"), "something else")
	for _, name := range []string{"foo", "bar", "baz"} {
		path := filepath.Join(baseDir, name)
		expected[name] = path
		writeFile(t, path, content1)
	}

	configs, err := ConfigFiles(baseDir)
	require.NoError(t, err, "ConfigFiles should not have failed")
	require.Equal(t, expected, configs, "ConfigFiles returned incorrect configurations")

	configs, err = ConfigFiles(empty)
	require.NoError(t, err, "ConfigFiles should not have failed for an empty directory")
	require.Empty(t, configs, "ConfigFiles should not have returned any configuration for an empty directory")

	_, err = ConfigFiles(filepath.Join(baseDir, "non-existing"))
	require.Error(t, err, "ConfigFiles should have failed for a non-existing directory")
}
