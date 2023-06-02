// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	fakeConfig "github.com/cilium/cilium/pkg/option/fake"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

func Test(t *testing.T) {
	TestingT(t)
}

type ClusterMeshTestSuite struct{}

var _ = Suite(&ClusterMeshTestSuite{})

func (s *ClusterMeshTestSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

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

func (s *ClusterMeshTestSuite) TestClusterMesh(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kvstore.SetupDummy("etcd")
	defer func() {
		kvstore.Client().DeletePrefix(context.TODO(), kvstore.ClusterConfigPrefix)
		kvstore.Client().DeletePrefix(context.TODO(), kvstore.SyncedPrefix)
		kvstore.Client().DeletePrefix(context.TODO(), nodeStore.NodeStorePrefix)
		kvstore.Client().Close(ctx)
	}()

	identity.InitWellKnownIdentities(&fakeConfig.Config{})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	mgr := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()

	dir, err := os.MkdirTemp("", "multicluster")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	etcdConfig := []byte(fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))

	// cluster3 doesn't have cluster configuration on kvstore. This emulates
	// the old Cilium version which doesn't support cluster configuration
	// feature. We should be able to connect to such a cluster for
	// compatibility.
	for i, name := range []string{"test2", "cluster1", "cluster2"} {
		config := cmtypes.CiliumClusterConfig{
			ID: uint32(i),
		}

		if name == "cluster2" {
			// Cluster2 supports synced canaries
			config.Capabilities.SyncedCanaries = true
		}

		err = SetClusterConfig(ctx, name, &config, kvstore.Client())
		c.Assert(err, IsNil)
	}

	config1 := path.Join(dir, "cluster1")
	err = os.WriteFile(config1, etcdConfig, 0644)
	c.Assert(err, IsNil)

	config2 := path.Join(dir, "cluster2")
	err = os.WriteFile(config2, etcdConfig, 0644)
	c.Assert(err, IsNil)

	config3 := path.Join(dir, "cluster3")
	err = os.WriteFile(config3, etcdConfig, 0644)
	c.Assert(err, IsNil)

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: ctx,
	})
	defer ipc.Shutdown()

	cm := NewClusterMesh(hivetest.Lifecycle(c), Configuration{
		Config: Config{ClusterMeshConfig: dir},

		ClusterIDName:         types.ClusterIDName{ClusterID: 255, ClusterName: "test2"},
		NodeKeyCreator:        testNodeCreator,
		NodeObserver:          &testObserver{},
		RemoteIdentityWatcher: mgr,
		IPCache:               ipc,
	})
	c.Assert(cm, Not(IsNil))

	nodesWSS := store.NewWorkqueueSyncStore(kvstore.Client(), nodeStore.NodeStorePrefix,
		store.WSSWithSourceClusterName("cluster2"), // The one which is tested with sync canaries
	)
	go nodesWSS.Run(ctx)
	nodeNames := []string{"foo", "bar", "baz"}

	// wait for all clusters to appear in the list of cm clusters
	c.Assert(testutils.WaitUntil(func() bool {
		return cm.NumReadyClusters() == 3
	}, 10*time.Second), IsNil)

	cm.mutex.RLock()
	for _, rc := range cm.clusters {
		rc.mutex.RLock()
		for _, name := range nodeNames {
			nodesWSS.UpsertKey(ctx, &testNode{Name: name, Cluster: rc.name})
			c.Assert(err, IsNil)
		}
		rc.mutex.RUnlock()
	}
	cm.mutex.RUnlock()

	// Write the sync canary for cluster2
	nodesWSS.Synced(ctx)

	// wait for all cm nodes in both clusters to appear in the node list
	c.Assert(testutils.WaitUntil(func() bool {
		nodesMutex.RLock()
		defer nodesMutex.RUnlock()
		return len(nodes) == 3*len(nodeNames)
	}, 10*time.Second), IsNil)

	os.RemoveAll(config2)

	// wait for the removed cluster to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		return cm.NumReadyClusters() == 2
	}, 5*time.Second), IsNil)

	// wait for the nodes of the removed cluster to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		nodesMutex.RLock()
		defer nodesMutex.RUnlock()
		return len(nodes) == 2*len(nodeNames)
	}, 10*time.Second), IsNil)

	os.RemoveAll(config1)
	os.RemoveAll(config3)

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
}
