// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestClusterMeshMultipleAddRemove(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")

	baseDir := t.TempDir()
	path := func(name string) string { return filepath.Join(baseDir, name) }

	for i, cluster := range []string{"cluster1", "cluster2", "cluster3", "cluster4"} {
		writeFile(t, path(cluster), fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))
		cfg := types.CiliumClusterConfig{ID: uint32(i + 1)}
		require.NoError(t, utils.SetClusterConfig(context.Background(), cluster, cfg, kvstore.Client()))
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
