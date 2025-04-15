// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
)

type fakeRemoteCluster struct{ onRun, onStop, onRemove func(ctx context.Context) }

func (f *fakeRemoteCluster) Run(ctx context.Context, _ kvstore.BackendOperations, _ types.CiliumClusterConfig, ready chan<- error) {
	if f.onRun != nil {
		f.onRun(ctx)
	}
	close(ready)
	<-ctx.Done()
}

func (f *fakeRemoteCluster) Stop() {
	if f.onStop != nil {
		f.onStop(context.Background())
	}
}

func (f *fakeRemoteCluster) Remove(ctx context.Context) {
	if f.onRemove != nil {
		f.onRemove(ctx)
	}
}

func TestClusterMesh(t *testing.T) {
	testutils.IntegrationTest(t)
	client := kvstore.SetupDummy(t, "etcd")

	baseDir := t.TempDir()
	path := func(name string) string { return filepath.Join(baseDir, name) }
	data := fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress())

	capabilities := types.CiliumClusterConfigCapabilities{Cached: true, MaxConnectedClusters: 511}
	for i, cluster := range []string{"cluster1", "cluster2", "cluster3"} {
		cfg := types.CiliumClusterConfig{ID: uint32(i + 1), Capabilities: capabilities}
		require.NoError(t, utils.SetClusterConfig(context.Background(), cluster, cfg, client))
	}

	var ready, stopped, removed lock.Map[string, bool]
	is := func(state *lock.Map[string, bool], name string) bool {
		st, _ := state.Load(name)
		return st
	}

	var statuses lock.Map[string, StatusFunc]
	assertStatus := func(t *testing.T, name string, id uint32) {
		t.Helper()

		sf, _ := statuses.Load(name)
		require.NotNil(t, sf, "The status function for %s should have been registered", name)
		status := sf()

		require.Equal(t, name, status.Name, "The status for %s should propagate the cluster name", name)
		require.True(t, status.Connected, "The status for %s should be reported as connected", name)
		require.True(t, status.Ready, "The status for %s should be reported as ready", name)
		require.Zero(t, status.NumFailures, "The status for %s should not report failures", name)
		require.Zero(t, status.LastFailure, "The status for %s should not report a last failure", name)

		cfg := models.RemoteClusterConfig{ClusterID: int64(id), Kvstoremesh: true, Required: true, Retrieved: true, SyncCanaries: false}
		require.Equal(t, &cfg, status.Config, "The status for %s should propagate the cluster configuration", name)
	}

	// clusters is not protected by a mutex, as always guaranteed to be accessed
	// by a thread at a time only.
	var clusters []*fakeRemoteCluster

	cm := NewClusterMesh(Configuration{
		Logger:      hivetest.Logger(t),
		Config:      Config{ClusterMeshConfig: baseDir},
		ClusterInfo: types.ClusterInfo{ID: 255, Name: "local"},
		NewRemoteCluster: func(name string, sf StatusFunc) RemoteCluster {
			statuses.Store(name, sf)
			rc := &fakeRemoteCluster{
				onRun:    func(context.Context) { ready.Store(name, true) },
				onStop:   func(context.Context) { stopped.Store(name, true) },
				onRemove: func(context.Context) { removed.Store(name, true) },
			}

			clusters = append(clusters, rc)
			return rc
		},
		Metrics: MetricsProvider("clustermesh")(),
	})

	assertForEachRemoteCluster := func(t *testing.T, expected uint) {
		t.Helper()
		var count uint
		require.NoError(t, cm.ForEachRemoteCluster(func(rc RemoteCluster) error {
			require.Contains(t, clusters, rc, "ForEachRemoteCluster triggered for unknown cluster")
			count++
			return nil
		}), "ForEachRemoteCluster should not have returned an error")
		require.Equal(t, expected, count, "ForEachRemoteCluster not triggered for all expected clusters")
	}

	// Verify that the onStop method of remote clusters is called upon clustermesh
	// stop, but not the onRemove one (which is triggered only when the configuration
	// is explicitly removed).
	t.Cleanup(func() {
		for _, cluster := range []string{"cluster1", "cluster3", "cluster4"} {
			require.True(t, is(&stopped, cluster), "Cluster %s should have been stopped", cluster)
			require.False(t, is(&removed, cluster), "Cluster %s should not have been removed", cluster)
		}
	})

	// The configuration matching the local cluster should be ignored
	writeFile(t, path("local"), data)

	writeFile(t, path("cluster1"), data)
	writeFile(t, path("cluster2"), data)

	hivetest.Lifecycle(t).Append(cm)

	// Clusters whose configuration is already present before starting clustermesh should eventually turn ready
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, is(&ready, "cluster1")) }, timeout, tick, "Cluster1 is not ready")
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, is(&ready, "cluster2")) }, timeout, tick, "Cluster2 is not ready")
	assertStatus(t, "cluster1", 1)
	assertStatus(t, "cluster2", 2)
	require.Equal(t, 2, cm.NumReadyClusters(), "Number of ready remote clusters reported incorrectly")
	assertForEachRemoteCluster(t, 2)

	// A cluster whose configuration is subsequently added should eventually turn ready
	writeFile(t, path("cluster3"), data)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, is(&ready, "cluster3")) }, timeout, tick, "Cluster3 is not ready")
	assertStatus(t, "cluster3", 3)
	require.Equal(t, 3, cm.NumReadyClusters(), "Number of ready remote clusters reported incorrectly")
	assertForEachRemoteCluster(t, 3)

	// A cluster whose configuration is changed should eventually turn ready again
	ready.Store("cluster3", false)
	writeFile(t, path("cluster3"), data+"\n")
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, is(&ready, "cluster3")) }, timeout, tick, "Cluster3 is not ready")
	assertStatus(t, "cluster3", 3)
	require.Equal(t, 3, cm.NumReadyClusters(), "Number of ready remote clusters reported incorrectly")
	assertForEachRemoteCluster(t, 3)

	// A cluster for which etcd does not contain the cluster configuration should not turn ready
	writeFile(t, path("cluster4"), data)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		sf, _ := statuses.Load("cluster4")
		if !assert.NotNil(c, sf, "The status function for cluster4 should have been registered") {
			return
		}

		status := sf()
		assert.Equal(c, "cluster4", status.Name, "The status for cluster4 should propagate the cluster name")
		assert.True(c, status.Connected, "The status for cluster4 should be reported as connected")
		assert.False(c, status.Ready, "The status for cluster4 should be reported as not ready")

		cfg := models.RemoteClusterConfig{Required: true, Retrieved: false}
		assert.Equal(c, &cfg, status.Config, "The status for cluster4 should report the cluster config as required but not found")
	}, timeout, tick, "Status incorrectly reported for cluster4")
	require.False(t, is(&ready, "cluster4"), "Cluster4 should not be ready")
	require.Equal(t, 3, cm.NumReadyClusters(), "Number of ready remote clusters reported incorrectly")
	assertForEachRemoteCluster(t, 4)

	// A cluster whose configuration is removed should be stopped and removed
	require.NoError(t, os.Remove(path("cluster2")))
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, is(&stopped, "cluster2")) }, timeout, tick, "Cluster2 has not been stopped")
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, is(&removed, "cluster2")) }, timeout, tick, "Cluster2 has not been removed")
	require.Equal(t, 2, cm.NumReadyClusters(), "Number of ready remote clusters reported incorrectly")
	assertForEachRemoteCluster(t, 3)

	// ForEachRemoteCluster should correctly propagate errors
	err := errors.New("error")
	require.ErrorIs(t, cm.ForEachRemoteCluster(func(rc RemoteCluster) error { return err }), err)
}

func TestClusterMeshMultipleAddRemove(t *testing.T) {
	testutils.IntegrationTest(t)
	client := kvstore.SetupDummy(t, "etcd")

	baseDir := t.TempDir()
	path := func(name string) string { return filepath.Join(baseDir, name) }

	for i, cluster := range []string{"cluster1", "cluster2", "cluster3", "cluster4"} {
		writeFile(t, path(cluster), fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))
		cfg := types.CiliumClusterConfig{ID: uint32(i + 1)}
		require.NoError(t, utils.SetClusterConfig(context.Background(), cluster, cfg, client))
	}

	var ready lock.Map[string, bool]
	isReady := func(name string) bool {
		rdy, _ := ready.Load(name)
		return rdy
	}

	var blockRemoval lock.Map[string, chan struct{}]
	blockRemoval.Store("cluster1", make(chan struct{}))
	blockRemoval.Store("cluster2", make(chan struct{}))
	blockRemoval.Store("cluster3", make(chan struct{}))
	blockRemoval.Store("cluster4", make(chan struct{}))

	gcm := NewClusterMesh(Configuration{
		Logger:      hivetest.Logger(t),
		Config:      Config{ClusterMeshConfig: baseDir},
		ClusterInfo: types.ClusterInfo{ID: 255, Name: "local"},
		NewRemoteCluster: func(name string, _ StatusFunc) RemoteCluster {
			return &fakeRemoteCluster{
				onRun: func(context.Context) { ready.Store(name, true) },
				onRemove: func(ctx context.Context) {
					wait, _ := blockRemoval.Load(name)
					select {
					case <-wait:
					case <-ctx.Done():
					}
				},
			}
		},
		Metrics: MetricsProvider("clustermesh")(),
	})
	hivetest.Lifecycle(t).Append(gcm)
	cm := gcm.(*clusterMesh)

	// Directly call the add/remove methods, rather than creating/removing the
	// files to prevent race conditions due to the interplay with the watcher.
	cm.add("cluster1", path("cluster1"))
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, isReady("cluster1")) }, timeout, tick, "Cluster1 is not ready")

	// A blocked cluster removal operation should not block parallel cluster additions
	cm.remove("cluster1")

	cm.add("cluster2", path("cluster2"))
	cm.add("cluster3", path("cluster3"))

	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, isReady("cluster2")) }, timeout, tick, "Cluster2 is not ready")
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, isReady("cluster3")) }, timeout, tick, "Cluster3 is not ready")

	// Unblock the cluster removal
	block, _ := blockRemoval.Load("cluster1")
	close(block)

	// Multiple removals and additions, ending with an addition should lead to a ready cluster
	ready.Store("cluster2", false)
	cm.remove("cluster2")
	cm.add("cluster2", path("cluster2"))
	cm.remove("cluster2")
	cm.add("cluster2", path("cluster2"))

	require.False(t, isReady("cluster2"), "Cluster2 is ready, although it shouldn't")

	// Unblock the cluster removal
	block, _ = blockRemoval.Load("cluster2")
	close(block)

	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, isReady("cluster2")) }, timeout, tick, "Cluster2 is not ready")

	// Multiple removals and additions, ending with a removal should lead to a non-ready cluster
	ready.Store("cluster3", false)
	cm.remove("cluster3")
	cm.add("cluster3", path("cluster3"))
	cm.remove("cluster3")
	cm.add("cluster3", path("cluster3"))
	cm.remove("cluster3")

	require.False(t, isReady("cluster3"), "Cluster3 is ready, although it shouldn't")

	// Unblock the cluster removal
	block, _ = blockRemoval.Load("cluster3")
	close(block)

	// Make sure that the deletion go routine terminated before checking
	cm.wg.Wait()
	require.False(t, isReady("cluster3"), "Cluster3 is ready, although it shouldn't")

	cm.add("cluster4", path("cluster4"))
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.True(c, isReady("cluster4")) }, timeout, tick, "Cluster4 is not ready")

	// Never unblock the cluster removal, and assert that the stop hook terminates
	// regardless due to the context being closed.
	cm.remove("cluster4")
}
