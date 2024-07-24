// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

type remoteEtcdClientWrapper struct {
	kvstore.BackendOperations
	name                  string
	syncedCanariesWatched bool
}

// Override the ListAndWatch method so that we can track whether the synced canaries prefix has been watched.
func (w *remoteEtcdClientWrapper) ListAndWatch(ctx context.Context, prefix string, chanSize int) *kvstore.Watcher {
	if prefix == fmt.Sprintf("cilium/synced/%s/", w.name) {
		w.syncedCanariesWatched = true
	}

	return w.BackendOperations.ListAndWatch(ctx, prefix, chanSize)
}

type fakeIPCache struct{ updates atomic.Int32 }

func (f *fakeIPCache) Delete(string, source.Source) bool { return false }
func (f *fakeIPCache) Upsert(string, net.IP, uint8, *ipcache.K8sMetadata, ipcache.Identity) (bool, error) {
	f.updates.Add(1)
	return false, nil
}

func TestRemoteClusterRun(t *testing.T) {
	testutils.IntegrationTest(t)

	kvstore.SetupDummyWithConfigOpts(t, "etcd",
		// Explicitly set higher QPS than the default to speedup the test
		map[string]string{kvstore.EtcdRateLimitOption: "100"},
	)

	tests := []struct {
		name   string
		srccfg types.CiliumClusterConfig
		kvs    map[string]string
	}{
		{
			name:   "remote cluster has no capabilities",
			srccfg: types.CiliumClusterConfig{ID: 1},
			kvs: map[string]string{
				"cilium/state/nodes/v1/foo/bar":        `{"name": "bar", "cluster": "foo", "clusterID": 1}`,
				"cilium/state/services/v1/foo/baz/bar": `{"name": "bar", "namespace": "baz", "cluster": "foo", "clusterID": 1}`,
				"cilium/state/identities/v1/id/65538":  `key1=value1;key2=value2;k8s:io.cilium.k8s.policy.cluster=foo`,
				"cilium/state/ip/v1/default/1.1.1.1":   `{"IP": "1.1.1.1", "ID": 65538}`,
			},
		},
		{
			name: "remote cluster supports sync canaries",
			srccfg: types.CiliumClusterConfig{
				ID: 255,
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries:       true,
					MaxConnectedClusters: 255,
				},
			},
			kvs: map[string]string{
				"cilium/state/nodes/v1/foo/bar":          `{"name": "bar", "cluster": "foo", "clusterID": 255}`,
				"cilium/state/services/v1/foo/baz/bar":   `{"name": "bar", "namespace": "baz", "cluster": "foo", "clusterID": 255}`,
				"cilium/state/identities/v1/id/16711681": `key1=value1;key2=value2;k8s:io.cilium.k8s.policy.cluster=foo`,
				"cilium/state/ip/v1/default/1.1.1.1":     `{"IP": "1.1.1.1", "ID": 16711681}`,

				"cilium/synced/foo/cilium/state/nodes/v1":      "true",
				"cilium/synced/foo/cilium/state/services/v1":   "true",
				"cilium/synced/foo/cilium/state/identities/v1": "true",
				"cilium/synced/foo/cilium/state/ip/v1":         "true",
			},
		},
		{
			name: "remote cluster supports both sync canaries and cached prefixes",
			srccfg: types.CiliumClusterConfig{
				ID: 255,
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries:       true,
					Cached:               true,
					MaxConnectedClusters: 255,
				},
			},
			kvs: map[string]string{
				"cilium/cache/nodes/v1/foo/bar":              `{"name": "bar", "cluster": "foo", "clusterID": 255}`,
				"cilium/cache/services/v1/foo/baz/bar":       `{"name": "bar", "namespace": "baz", "cluster": "foo", "clusterID": 255}`,
				"cilium/cache/identities/v1/foo/id/16711681": `key1=value1;key2=value2;k8s:io.cilium.k8s.policy.cluster=foo`,
				"cilium/cache/ip/v1/foo/1.1.1.1":             `{"IP": "1.1.1.1", "ID": 16711681}`,

				"cilium/synced/foo/cilium/cache/nodes/v1":      "true",
				"cilium/synced/foo/cilium/cache/services/v1":   "true",
				"cilium/synced/foo/cilium/cache/identities/v1": "true",
				"cilium/synced/foo/cilium/cache/ip/v1":         "true",
			},
		},
	}

	store := store.NewFactory(store.MetricsProvider())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())

			// The nils are only used by k8s CRD identities. We default to kvstore.
			allocator := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
			<-allocator.InitIdentityAllocator(nil)

			t.Cleanup(func() {
				cancel()
				wg.Wait()

				allocator.Close()
				require.NoError(t, kvstore.Client().DeletePrefix(context.Background(), kvstore.BaseKeyPrefix))
			})

			// Populate the kvstore with the appropriate KV pairs
			for key, value := range tt.kvs {
				require.NoErrorf(t, kvstore.Client().Update(ctx, key, []byte(value), false), "Failed to set %s=%s", key, value)
			}

			var ipc fakeIPCache
			cm := ClusterMesh{
				conf: Configuration{
					NodeObserver:          newNodesObserver(),
					IPCache:               &ipc,
					RemoteIdentityWatcher: allocator,
					ClusterIDsManager:     NewClusterMeshUsedIDs(localClusterID),
					Metrics:               NewMetrics(),
					StoreFactory:          store,
					ClusterInfo:           types.ClusterInfo{ID: localClusterID, Name: localClusterName, MaxConnectedClusters: 255},
					Logger:                logrus.New(),
				},
				globalServices: common.NewGlobalServiceCache(metrics.NoOpGauge),
			}
			rc := cm.NewRemoteCluster("foo", nil).(*remoteCluster)
			ready := make(chan error)

			remoteClient := &remoteEtcdClientWrapper{
				BackendOperations: kvstore.Client(),
				name:              "foo",
			}

			wg.Add(1)
			go func() {
				rc.Run(ctx, remoteClient, tt.srccfg, ready)
				wg.Done()
			}()

			require.NoError(t, <-ready, "rc.Run() failed")

			// Assert that we correctly watch nodes
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.EqualValues(c, 1, rc.remoteNodes.NumEntries())
			}, timeout, tick, "Nodes are not watched correctly")

			// Assert that we correctly watch services
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.EqualValues(c, 1, rc.remoteServices.NumEntries())
			}, timeout, tick, "Services are not watched correctly")

			// Assert that we correctly watch ipcache entries
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.EqualValues(c, 1, ipc.updates.Load())
			}, timeout, tick, "IPCache entries are not watched correctly")

			// Assert that we correctly watch identities
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				rc.mutex.RLock()
				defer rc.mutex.RUnlock()
				assert.EqualValues(c, 1, rc.remoteIdentityCache.NumEntries())
			}, timeout, tick, "Identities are not watched correctly")

			// Assert that synced canaries have been watched if expected
			require.Equal(t, tt.srccfg.Capabilities.SyncedCanaries, remoteClient.syncedCanariesWatched)
		})
	}
}

type fakeObserver struct {
	updates atomic.Uint32
	deletes atomic.Uint32
}

func (o *fakeObserver) reset() {
	o.updates.Store(0)
	o.deletes.Store(0)
}

func (o *fakeObserver) NodeUpdated(_ nodeTypes.Node) { o.updates.Add(1) }
func (o *fakeObserver) NodeDeleted(_ nodeTypes.Node) { o.deletes.Add(1) }

func (o *fakeObserver) MergeExternalServiceUpdate(_ *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	o.updates.Add(1)
	swg.Done()
}

func (o *fakeObserver) MergeExternalServiceDelete(_ *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	o.deletes.Add(1)
	swg.Done()
}

func (o *fakeObserver) Upsert(string, net.IP, uint8, *ipcache.K8sMetadata, ipcache.Identity) (bool, error) {
	o.updates.Add(1)
	return false, nil
}

func (o *fakeObserver) Delete(string, source.Source) bool {
	o.deletes.Add(1)
	return false
}

func TestRemoteClusterClusterIDChange(t *testing.T) {
	const cid1, cid2, cid3 = 10, 20, 30
	testutils.IntegrationTest(t)

	kvstore.SetupDummyWithConfigOpts(t, "etcd",
		// Explicitly set higher QPS than the default to speedup the test
		map[string]string{kvstore.EtcdRateLimitOption: "100"},
	)

	id := func(clusterID uint32) identity.NumericIdentity { return identity.NumericIdentity(clusterID<<16 + 9999) }
	// Use the KVStoreMesh API to prevent the allocator from thinking that the
	// identity belongs to the local cluster.
	kvs := func(clusterID uint32) map[string]string {
		return map[string]string{
			"cilium/cache/nodes/v1/foo/bar":        fmt.Sprintf(`{"name": "bar", "cluster": "foo", "clusterID": %d}`, clusterID),
			"cilium/cache/nodes/v1/foo/baz":        fmt.Sprintf(`{"name": "baz", "cluster": "foo", "clusterID": %d}`, clusterID),
			"cilium/cache/nodes/v1/foo/qux":        fmt.Sprintf(`{"name": "qux", "cluster": "foo", "clusterID": %d}`, clusterID),
			"cilium/cache/services/v1/foo/baz/bar": fmt.Sprintf(`{"name": "bar", "namespace": "baz", "cluster": "foo", "clusterID": %d, "shared": true}`, clusterID),
			"cilium/cache/services/v1/foo/baz/qux": fmt.Sprintf(`{"name": "qux", "namespace": "baz", "cluster": "foo", "clusterID": %d, "shared": true}`, clusterID),
			"cilium/cache/ip/v1/foo/1.1.1.1":       fmt.Sprintf(`{"IP": "1.1.1.1", "ID": %d}`, id(clusterID)),
			"cilium/cache/ip/v1/foo/1.1.1.2":       fmt.Sprintf(`{"IP": "1.1.1.2", "ID": %d}`, id(clusterID)),
			"cilium/cache/ip/v1/foo/1.1.1.3":       fmt.Sprintf(`{"IP": "1.1.1.3", "ID": %d}`, id(clusterID)),

			fmt.Sprintf("cilium/cache/identities/v1/foo/id/%d", id(clusterID)): `key1=value1;key2=value2;k8s:io.cilium.k8s.policy.cluster=foo`,
		}
	}

	store := store.NewFactory(store.MetricsProvider())
	var wg sync.WaitGroup
	ctx := context.Background()

	// The nils are only used by k8s CRD identities. We default to kvstore.
	allocator := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	<-allocator.InitIdentityAllocator(nil)

	t.Cleanup(func() {
		allocator.Close()
		require.NoError(t, kvstore.Client().DeletePrefix(context.Background(), kvstore.BaseKeyPrefix))
	})

	var obs fakeObserver
	cm := ClusterMesh{
		conf: Configuration{
			NodeObserver:          &obs,
			ServiceMerger:         &obs,
			IPCache:               &obs,
			RemoteIdentityWatcher: allocator,
			ClusterIDsManager:     NewClusterMeshUsedIDs(localClusterID),
			Metrics:               NewMetrics(),
			StoreFactory:          store,
			ClusterInfo:           types.ClusterInfo{ID: localClusterID, Name: localClusterName, MaxConnectedClusters: 255},
			Logger:                logrus.New(),
		},
		globalServices: common.NewGlobalServiceCache(metrics.NoOpGauge),
	}
	rc := cm.NewRemoteCluster("foo", nil).(*remoteCluster)

	fixture := func(t *testing.T, id uint32, run func(t *testing.T, ready <-chan error)) {
		ctx, cancel := context.WithCancel(ctx)
		ready := make(chan error)

		defer func() {
			cancel()
			wg.Wait()
		}()

		wg.Add(1)
		go func() {
			cfg := types.CiliumClusterConfig{ID: id, Capabilities: types.CiliumClusterConfigCapabilities{Cached: true}}
			rc.Run(ctx, kvstore.Client(), cfg, ready)
			wg.Done()
		}()

		run(t, ready)
	}

	fixture(t, cid1, func(t *testing.T, ready <-chan error) {
		require.NoError(t, <-ready, "rc.Run() failed")

		// Populate the kvstore with the appropriate KV pairs
		for key, value := range kvs(cid1) {
			require.NoErrorf(t, kvstore.Client().Update(ctx, key, []byte(value), false), "Failed to set %s=%s", key, value)
		}

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.EqualValues(c, 8, obs.updates.Load(), "Upsertions not observed correctly")
			assert.EqualValues(c, 0, obs.deletes.Load(), "Deletions not observed correctly")
			assert.NotNil(c, allocator.LookupIdentityByID(ctx, id(cid1)), "Identity upsertion not observed correctly")
		}, timeout, tick)
	})

	// Reconnect the cluster with a different ID, and assert that a synthetic
	// deletion event has been generated for all known entries.
	obs.reset()
	fixture(t, cid2, func(t *testing.T, ready <-chan error) {
		require.NoError(t, <-ready, "rc.Run() failed")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.EqualValues(c, 0, obs.updates.Load(), "Upsertions not observed correctly")
			assert.EqualValues(c, 8, obs.deletes.Load(), "Deletions not observed correctly")
			assert.Nil(c, allocator.LookupIdentityByID(ctx, id(cid1)), "Identity deletion not observed correctly")
		}, timeout, tick)

		// Update the kvstore pairs with the new ClusterID
		obs.reset()
		for key, value := range kvs(cid2) {
			require.NoErrorf(t, kvstore.Client().Update(ctx, key, []byte(value), false), "Failed to set %s=%s", key, value)
		}

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.EqualValues(c, 8, obs.updates.Load(), "Upsertions not observed correctly")
			assert.EqualValues(c, 0, obs.deletes.Load(), "Deletions not observed correctly")
			assert.NotNil(c, allocator.LookupIdentityByID(ctx, id(cid2)), "Identity upsertion not observed correctly")
		}, timeout, tick)
	})

	// Reconnect the cluster with yet another different ID, that is already reserved.
	// Assert that a synthetic deletion event has been generated for all known entries
	// also in this case (i.e., before actually reserving the Cluster ID).
	obs.reset()
	cm.conf.ClusterIDsManager.ReserveClusterID(cid3)
	fixture(t, cid3, func(t *testing.T, ready <-chan error) {
		require.ErrorContains(t, <-ready, "clusterID 30 is already used", "rc.Run() should have failed")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.EqualValues(c, 0, obs.updates.Load(), "Upsertions not observed correctly")
			assert.EqualValues(c, 8, obs.deletes.Load(), "Deletions not observed correctly")
			assert.Nil(c, allocator.LookupIdentityByID(ctx, id(cid2)), "Identity deletion not observed correctly")
		}, timeout, tick)
	})
}

func TestIPCacheWatcherOpts(t *testing.T) {
	tests := []struct {
		name     string
		config   *types.CiliumClusterConfig
		extra    IPCacheWatcherOptsFn
		expected int
	}{
		{
			name:     "nil config",
			expected: 0,
		},
		{
			name:     "non-nil config",
			config:   &types.CiliumClusterConfig{},
			expected: 2,
		},
		{
			name: "with extra opts",
			extra: func(config *types.CiliumClusterConfig) []ipcache.IWOpt {
				return []ipcache.IWOpt{ipcache.WithClusterID(10), ipcache.WithSelfDeletionProtection()}
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := remoteCluster{ipCacheWatcherExtraOpts: tt.extra}
			// Asserting the number of returned options, because it is not
			// possible to compare them, being functions.
			assert.Len(t, rc.ipCacheWatcherOpts(tt.config), tt.expected)
		})
	}
}
