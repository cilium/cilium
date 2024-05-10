// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

type testNode struct {
	// Name is the name of the node. This is typically the hostname of the node.
	Name string

	// Cluster is the name of the cluster the node is associated with
	Cluster string
}

func (n *testNode) GetKeyName() string {
	return path.Join(n.Cluster, n.Name)
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

func (n *testNode) Unmarshal(_ string, data []byte) error {
	return json.Unmarshal(data, n)
}

var testNodeCreator = func() store.Key {
	n := testNode{}
	return &n
}

type testObserver struct {
	nodes      map[string]*testNode
	nodesMutex lock.RWMutex
}

func newNodesObserver() *testObserver {
	return &testObserver{nodes: make(map[string]*testNode)}
}

func (o *testObserver) OnUpdate(k store.Key) {
	n := k.(*testNode)
	o.nodesMutex.Lock()
	o.nodes[n.GetKeyName()] = n
	o.nodesMutex.Unlock()
}

func (o *testObserver) OnDelete(k store.NamedKey) {
	n := k.(*testNode)
	o.nodesMutex.Lock()
	delete(o.nodes, n.GetKeyName())
	o.nodesMutex.Unlock()
}

func TestClusterMesh(t *testing.T) {
	testutils.IntegrationTest(t)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		wg.Wait()
	}()

	kvstore.SetupDummy(t, "etcd")

	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	<-mgr.InitIdentityAllocator(nil)
	t.Cleanup(mgr.Close)

	dir := t.TempDir()
	etcdConfig := []byte(fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))

	// cluster3 doesn't have cluster configuration on kvstore. This emulates
	// the old Cilium version which doesn't support cluster configuration
	// feature. We should be able to connect to such a cluster for
	// compatibility.
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

		err := cmutils.SetClusterConfig(ctx, name, &config, kvstore.Client())
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
	})
	t.Cleanup(func() { ipc.Shutdown() })

	usedIDs := NewClusterMeshUsedIDs()
	storeFactory := store.NewFactory(store.MetricsProvider())
	nodesObserver := newNodesObserver()
	cm := NewClusterMesh(hivetest.Lifecycle(t), Configuration{
		Config:                common.Config{ClusterMeshConfig: dir},
		ClusterInfo:           types.ClusterInfo{ID: 255, Name: "test2", MaxConnectedClusters: 255},
		NodeKeyCreator:        testNodeCreator,
		NodeObserver:          nodesObserver,
		RemoteIdentityWatcher: mgr,
		IPCache:               ipc,
		ClusterIDsManager:     usedIDs,
		Metrics:               NewMetrics(),
		CommonMetrics:         common.MetricsProvider(subsystem)(),
		StoreFactory:          storeFactory,
	})
	require.NotNil(t, cm, "Failed to initialize clustermesh")
	// cluster2 is the cluster which is tested with sync canaries
	nodesWSS := storeFactory.NewSyncStore("cluster2", kvstore.Client(), nodeStore.NodeStorePrefix)
	wg.Add(1)
	go func() {
		nodesWSS.Run(ctx)
		wg.Done()
	}()
	nodeNames := []string{"foo", "bar", "baz"}

	// wait for all clusters to appear in the list of cm clusters
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 3, cm.NumReadyClusters())
	}, timeout, tick, "Clusters did not become ready in time")

	// Ensure that ClusterIDs are reserved correctly after connect
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		usedIDs.UsedClusterIDsMutex.Lock()
		defer usedIDs.UsedClusterIDsMutex.Unlock()

		assert.Contains(c, usedIDs.UsedClusterIDs, uint32(2))
		assert.Contains(c, usedIDs.UsedClusterIDs, uint32(3))
		// cluster3 doesn't have config, so only 2 IDs should be reserved
		assert.Len(c, usedIDs.UsedClusterIDs, 2)
	}, timeout, tick, "Cluster IDs were not reserved correctly")

	// Reconnect cluster with changed ClusterID
	config := types.CiliumClusterConfig{
		ID: 255,
		Capabilities: types.CiliumClusterConfigCapabilities{
			MaxConnectedClusters: 255,
		},
	}
	err := cmutils.SetClusterConfig(ctx, "cluster1", &config, kvstore.Client())
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

	for _, cluster := range []string{"cluster1", "cluster2", "cluster3"} {
		for _, name := range nodeNames {
			require.NoErrorf(t, nodesWSS.UpsertKey(ctx, &testNode{Name: name, Cluster: cluster}),
				"Failed upserting node %s/%s into kvstore", cluster, name)
		}
	}

	// Write the sync canary for cluster2
	require.NoError(t, nodesWSS.Synced(ctx), "Failed writing the synched key into kvstore")

	// wait for all cm nodes in both clusters to appear in the node list
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		nodesObserver.nodesMutex.RLock()
		defer nodesObserver.nodesMutex.RUnlock()
		assert.Len(c, nodesObserver.nodes, 3*len(nodeNames))
	}, timeout, tick, "Nodes not watched correctly")

	require.NoError(t, os.Remove(config2), "Failed to remove config file for cluster2")

	// wait for the removed cluster to disappear
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 2, cm.NumReadyClusters())
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
		assert.Len(c, nodesObserver.nodes, 2*len(nodeNames))
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
		assert.Len(c, nodesObserver.nodes, 0)
	}, timeout, tick, "Nodes were not drained correctly")

	// Make sure that IDs are freed
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		usedIDs.UsedClusterIDsMutex.Lock()
		defer usedIDs.UsedClusterIDsMutex.Unlock()
		assert.Len(c, usedIDs.UsedClusterIDs, 0)
	}, timeout, tick, "Cluster IDs were not freed correctly")
}
