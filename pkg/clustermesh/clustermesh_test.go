// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

const (
	localClusterID   = 99
	localClusterName = "local"
)

type testObserver struct {
	nodes      map[string]*nodeTypes.Node
	nodesMutex lock.RWMutex
}

func newNodesObserver() *testObserver {
	return &testObserver{nodes: make(map[string]*nodeTypes.Node)}
}

func (o *testObserver) NodeUpdated(no nodeTypes.Node) {
	o.nodesMutex.Lock()
	o.nodes[no.Fullname()] = &no
	o.nodesMutex.Unlock()
}

func (o *testObserver) NodeDeleted(no nodeTypes.Node) {
	o.nodesMutex.Lock()
	delete(o.nodes, no.Fullname())
	o.nodesMutex.Unlock()
}

func TestClusterMesh(t *testing.T) {
	testutils.IntegrationTest(t)
	logger := hivetest.Logger(t)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		wg.Wait()
	}()

	client := kvstore.SetupDummy(t, "etcd")

	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := cache.NewCachingIdentityAllocator(logger, &testidentity.IdentityAllocatorOwnerMock{}, cache.AllocatorConfig{})
	<-mgr.InitIdentityAllocator(nil)
	t.Cleanup(mgr.Close)

	dir := t.TempDir()
	etcdConfig := fmt.Appendf(nil, "endpoints:\n- %s\n", kvstore.EtcdDummyAddress())

	// cluster3 doesn't have cluster configuration on kvstore.
	// We should not be able to establish a connection in this case.
	for i, name := range []string{"test2", "cluster1", "cluster2"} {
		config := types.CiliumClusterConfig{
			ID: uint32(i + 1),
			Capabilities: types.CiliumClusterConfigCapabilities{
				MaxConnectedClusters: 255,
			},
		}

		if name == "cluster2" {
			// Cluster2 supports synced canaries
			config.Capabilities.SyncedCanaries = true
		}

		err := cmutils.SetClusterConfig(ctx, name, config, client)
		require.NoErrorf(t, err, "Failed to set cluster config for %s", name)
	}

	config1 := path.Join(dir, "cluster1")
	require.NoError(t, os.WriteFile(config1, etcdConfig, 0644), "Failed to write config file for cluster1")

	config2 := path.Join(dir, "cluster2")
	require.NoError(t, os.WriteFile(config2, etcdConfig, 0644), "Failed to write config file for cluster2")

	config3 := path.Join(dir, "cluster3")
	require.NoError(t, os.WriteFile(config3, etcdConfig, 0644), "Failed to write config file for cluster3")

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: ctx,
		Logger:  logger,
	})
	t.Cleanup(func() { ipc.Shutdown() })

	usedIDs := NewClusterMeshUsedIDs(localClusterID)
	storeFactory := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())
	nodesObserver := newNodesObserver()
	cm := NewClusterMesh(hivetest.Lifecycle(t), Configuration{
		Config:                common.Config{ClusterMeshConfig: dir},
		ClusterInfo:           types.ClusterInfo{ID: localClusterID, Name: localClusterName, MaxConnectedClusters: 255},
		NodeObserver:          nodesObserver,
		RemoteIdentityWatcher: mgr,
		IPCache:               ipc,
		ClusterIDsManager:     usedIDs,
		Metrics:               NewMetrics(),
		CommonMetrics:         common.MetricsProvider(subsystem)(),
		StoreFactory:          storeFactory,
		FeatureMetrics:        NewClusterMeshMetricsNoop(),
		Logger:                slog.Default(),
	})
	require.NotNil(t, cm, "Failed to initialize clustermesh")
	// cluster2 is the cluster which is tested with sync canaries
	nodesWSS := storeFactory.NewSyncStore("cluster2", client, nodeStore.NodeStorePrefix)
	wg.Add(1)
	go func() {
		nodesWSS.Run(ctx)
		wg.Done()
	}()
	nodeNames := []string{"foo", "bar", "baz"}

	// wait for the two expected clusters to appear in the list of cm clusters
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 2, cm.NumReadyClusters())
	}, timeout, tick, "Clusters did not become ready in time")

	// Ensure that ClusterIDs are reserved correctly after connect
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		usedIDs.UsedClusterIDsMutex.Lock()
		defer usedIDs.UsedClusterIDsMutex.Unlock()

		assert.Contains(c, usedIDs.UsedClusterIDs, uint32(2))
		assert.Contains(c, usedIDs.UsedClusterIDs, uint32(3))
		assert.Len(c, usedIDs.UsedClusterIDs, 2)
	}, timeout, tick, "Cluster IDs were not reserved correctly")

	// Reconnect cluster with changed ClusterID
	config := types.CiliumClusterConfig{
		ID: 255,
		Capabilities: types.CiliumClusterConfigCapabilities{
			MaxConnectedClusters: 255,
		},
	}
	err := cmutils.SetClusterConfig(ctx, "cluster1", config, client)
	require.NoErrorf(t, err, "Failed to set cluster config for cluster1")
	// Ugly hack to trigger config update
	etcdConfigNew := append(etcdConfig, []byte("\n")...)
	require.NoError(t, os.WriteFile(config1, etcdConfigNew, 0644), "Failed to write config file for cluster1")

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		usedIDs.UsedClusterIDsMutex.Lock()
		defer usedIDs.UsedClusterIDsMutex.Unlock()

		// Ensure if old ClusterID for cluster1 is released
		// and new ClusterID is reserved.
		assert.NotContains(c, usedIDs.UsedClusterIDs, uint32(2))
		assert.Contains(c, usedIDs.UsedClusterIDs, uint32(255))
	}, timeout, tick, "Reserved cluster IDs not updated correctly")

	for cluster, id := range map[string]uint32{"cluster1": 255, "cluster2": 3, "cluster3": 4} {
		for _, name := range nodeNames {
			require.NoErrorf(t, nodesWSS.UpsertKey(ctx, &nodeTypes.Node{Name: name, Cluster: cluster, ClusterID: id}),
				"Failed upserting node %s/%s into kvstore", cluster, name)
		}
	}

	// Write the sync canary for cluster2
	require.NoError(t, nodesWSS.Synced(ctx), "Failed writing the synched key into kvstore")

	// wait for all cm nodes in both clusters to appear in the node list
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		nodesObserver.nodesMutex.RLock()
		defer nodesObserver.nodesMutex.RUnlock()
		assert.Len(c, nodesObserver.nodes, 2*len(nodeNames))
	}, timeout, tick, "Nodes not watched correctly")

	require.NoError(t, os.Remove(config2), "Failed to remove config file for cluster2")

	// wait for the removed cluster to disappear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 1, cm.NumReadyClusters())
	}, timeout, tick, "Cluster2 was not correctly removed")

	// Make sure that ID is freed
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		usedIDs.UsedClusterIDsMutex.Lock()
		defer usedIDs.UsedClusterIDsMutex.Unlock()
		assert.NotContains(c, usedIDs.UsedClusterIDs, uint32(2))
		assert.Len(c, usedIDs.UsedClusterIDs, 1)
	}, timeout, tick, "Cluster IDs were not freed correctly")

	// wait for the nodes of the removed cluster to disappear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		nodesObserver.nodesMutex.RLock()
		defer nodesObserver.nodesMutex.RUnlock()
		assert.Len(c, nodesObserver.nodes, 1*len(nodeNames))
	}, timeout, tick, "Nodes were not drained correctly")

	require.NoError(t, os.Remove(config1), "Failed to remove config file for cluster1")
	require.NoError(t, os.Remove(config3), "Failed to remove config file for cluster3")

	// wait for the removed cluster to disappear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 0, cm.NumReadyClusters())
	}, timeout, tick, "Clusters were not correctly removed")

	// wait for the nodes of the removed cluster to disappear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		nodesObserver.nodesMutex.RLock()
		defer nodesObserver.nodesMutex.RUnlock()
		assert.Empty(c, nodesObserver.nodes)
	}, timeout, tick, "Nodes were not drained correctly")

	// Make sure that IDs are freed
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		usedIDs.UsedClusterIDsMutex.Lock()
		defer usedIDs.UsedClusterIDsMutex.Unlock()
		assert.Empty(c, usedIDs.UsedClusterIDs)
	}, timeout, tick, "Cluster IDs were not freed correctly")
}
