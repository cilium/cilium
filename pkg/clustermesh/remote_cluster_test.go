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
	"testing/synctest"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/observer"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
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
func (w *remoteEtcdClientWrapper) ListAndWatch(ctx context.Context, prefix string) kvstore.EventChan {
	if prefix == fmt.Sprintf("cilium/synced/%s/", w.name) {
		w.syncedCanariesWatched = true
	}

	return w.BackendOperations.ListAndWatch(ctx, prefix)
}

type fakeIPCache struct{ updates atomic.Int32 }

func (f *fakeIPCache) Delete(string, source.Source) bool { return false }
func (f *fakeIPCache) Upsert(string, net.IP, uint8, *ipcache.K8sMetadata, ipcache.Identity) (bool, error) {
	f.updates.Add(1)
	return false, nil
}

func TestRemoteClusterRun(t *testing.T) {
	var (
		db     = statedb.New()
		local  = kvstore.NewInMemoryClient(db, "__local__")
		remote = kvstore.NewInMemoryClient(db, "__remote__")
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

	store := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())

			// The nils are only used by k8s CRD identities. We default to kvstore.
			allocator := cache.NewCachingIdentityAllocator(logger, &testidentity.IdentityAllocatorOwnerMock{}, cache.NewTestAllocatorConfig())
			<-allocator.InitIdentityAllocator(nil, local)

			t.Cleanup(func() {
				cancel()
				wg.Wait()

				allocator.Close()
			})

			// Populate the kvstore with the appropriate KV pairs
			for key, value := range tt.kvs {
				require.NoErrorf(t, remote.Update(ctx, key, []byte(value), false), "Failed to set %s=%s", key, value)
			}

			var ipc fakeIPCache
			cm := ClusterMesh{
				conf: Configuration{
					NodeObserver:          newNodesObserver(),
					IPCache:               &ipc,
					RemoteIdentityWatcher: allocator,
					ClusterIDsManager:     NewClusterMeshUsedIDs(localClusterID),
					ServiceMerger:         &fakeObserver{},
					Metrics:               NewMetrics(),
					StoreFactory:          store,
					ClusterInfo:           types.ClusterInfo{ID: localClusterID, Name: localClusterName, MaxConnectedClusters: 255},
					FeatureMetrics:        NewClusterMeshMetricsNoop(),
					Logger:                logger,
				},
				FeatureMetrics: NewClusterMeshMetricsNoop(),
				globalServices: common.NewGlobalServiceCache(logger),
			}
			rc := cm.NewRemoteCluster("foo", nil).(*remoteCluster)
			ready := make(chan error)

			remoteClient := &remoteEtcdClientWrapper{
				BackendOperations: remote,
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
				assert.Equal(c, 1, rc.remoteIdentityCache.NumEntries())
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

func (o *fakeObserver) MergeExternalServiceUpdate(_ *serviceStore.ClusterService) {
	o.updates.Add(1)
}

func (o *fakeObserver) MergeExternalServiceDelete(_ *serviceStore.ClusterService) {
	o.deletes.Add(1)
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

	var (
		db     = statedb.New()
		local  = kvstore.NewInMemoryClient(db, "__local__")
		remote = kvstore.NewInMemoryClient(db, "__remote__")
		extra  = fakeCMObserver{name: "extra"}
	)

	id := func(clusterID uint32) identity.NumericIdentity { return identity.NumericIdentity(clusterID<<16 + 9999) }
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

	logger := hivetest.Logger(t)
	store := store.NewFactory(logger, store.MetricsProvider())
	var wg sync.WaitGroup
	ctx := context.Background()

	// The nils are only used by k8s CRD identities. We default to kvstore.
	allocator := cache.NewCachingIdentityAllocator(logger, &testidentity.IdentityAllocatorOwnerMock{}, cache.NewTestAllocatorConfig())
	<-allocator.InitIdentityAllocator(nil, local)

	t.Cleanup(allocator.Close)

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
			FeatureMetrics:        NewClusterMeshMetricsNoop(),
			Logger:                logger,

			ObserverFactories: []observer.Factory{
				func(string, func()) observer.Observer { return &extra },
			},
		},
		FeatureMetrics: NewClusterMeshMetricsNoop(),
		globalServices: common.NewGlobalServiceCache(logger),
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
			rc.Run(ctx, remote, cfg, ready)
			wg.Done()
		}()

		run(t, ready)
	}

	fixture(t, cid1, func(t *testing.T, ready <-chan error) {
		require.NoError(t, <-ready, "rc.Run() failed")

		// Populate the kvstore with the appropriate KV pairs
		for key, value := range kvs(cid1) {
			require.NoErrorf(t, remote.Update(ctx, key, []byte(value), false), "Failed to set %s=%s", key, value)
		}

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.EqualValues(c, 8, obs.updates.Load(), "Upsertions not observed correctly")
			assert.EqualValues(c, 0, obs.deletes.Load(), "Deletions not observed correctly")
			assert.NotNil(c, allocator.LookupIdentityByID(ctx, id(cid1)), "Identity upsertion not observed correctly")
		}, timeout, tick)

		require.False(t, extra.drained.Swap(false), "Extra observers should not have been drained")
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
			require.NoErrorf(t, remote.Update(ctx, key, []byte(value), false), "Failed to set %s=%s", key, value)
		}

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.EqualValues(c, 8, obs.updates.Load(), "Upsertions not observed correctly")
			assert.EqualValues(c, 0, obs.deletes.Load(), "Deletions not observed correctly")
			assert.NotNil(c, allocator.LookupIdentityByID(ctx, id(cid2)), "Identity upsertion not observed correctly")
		}, timeout, tick)

		require.True(t, extra.drained.Swap(false), "Extra observers should have been drained")
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

		require.True(t, extra.drained.Swap(false), "Extra observers should have been drained")
	})
}

type fakeCMObserver struct {
	name       observer.Name
	onRegister func(store.WatchStoreManager, kvstore.BackendOperations, types.CiliumClusterConfig)
	enabled    bool

	cluster string
	onSync  func()

	synced     atomic.Bool
	registered atomic.Bool
	revoked    atomic.Bool
	drained    atomic.Bool
}

func (f *fakeCMObserver) Name() observer.Name { return f.name }
func (f *fakeCMObserver) Revoke()             { f.revoked.Store(true) }
func (f *fakeCMObserver) Drain()              { f.drained.Store(true) }

func (f *fakeCMObserver) Register(mgr store.WatchStoreManager, backend kvstore.BackendOperations, cfg types.CiliumClusterConfig) {
	f.registered.Store(true)
	if f.onRegister != nil {
		f.onRegister(mgr, backend, cfg)
	}
}

func (f *fakeCMObserver) Status() observer.Status {
	return observer.Status{Enabled: f.enabled, Synced: f.synced.Load()}
}

func TestRemoteClusterExtraObservers(t *testing.T) {
	var (
		logger = hivetest.Logger(t)
		remote = kvstore.NewInMemoryClient(statedb.New(), "__remote__")

		cfg = types.CiliumClusterConfig{
			ID: 10, Capabilities: types.CiliumClusterConfigCapabilities{
				MaxConnectedClusters: 123, ServiceExportsEnabled: ptr.To(true),
			},
		}

		onRegister = func(mgr store.WatchStoreManager, backend kvstore.BackendOperations, got types.CiliumClusterConfig) {
			require.NotNil(t, mgr, "Received invalid [store.WatchStoreManager]")
			require.NotNil(t, backend, "Received invalid [kvstore.BackendOperations]")
			require.Equal(t, cfg, got, "Received mismatching [types.CiliumClusterConfig]")
		}

		fooobs = fakeCMObserver{name: "foo", onRegister: onRegister, enabled: true}
		barobs = fakeCMObserver{name: "bar", onRegister: onRegister, enabled: false}

		factory = func(obs *fakeCMObserver) observer.Factory {
			return func(cluster string, onSync func()) observer.Observer {
				obs.cluster = cluster
				obs.onSync = func() {
					onSync()
					obs.synced.Store(true)
				}
				return obs
			}
		}
	)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	cm := ClusterMesh{
		conf: Configuration{
			ClusterIDsManager:     NewClusterMeshUsedIDs(localClusterID),
			ServiceMerger:         &fakeObserver{},
			RemoteIdentityWatcher: cache.NewNoopIdentityAllocator(logger),
			ObserverFactories:     []observer.Factory{factory(&fooobs), factory(&barobs)},
			Metrics:               NewMetrics(),
			StoreFactory:          store.NewFactory(logger, store.MetricsProvider()),
			ClusterInfo:           types.ClusterInfo{ID: localClusterID, Name: localClusterName, MaxConnectedClusters: 255},
			FeatureMetrics:        NewClusterMeshMetricsNoop(),
			Logger:                logger,
		},
		FeatureMetrics: NewClusterMeshMetricsNoop(),
		globalServices: common.NewGlobalServiceCache(logger),
	}

	rc := cm.NewRemoteCluster("foo", func() *models.RemoteCluster {
		return &models.RemoteCluster{Ready: true}
	}).(*remoteCluster)

	require.False(t, rc.Status().Ready, "Status should not be ready before [Run] is invoked")

	ready := make(chan error)
	wg.Go(func() { rc.Run(ctx, remote, cfg, ready) })

	require.NoError(t, <-ready, "rc.Run() failed")

	// Wait for the main observers to synchronize.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, &models.RemoteClusterSynced{
			Endpoints:  true,
			Identities: true,
			Nodes:      true,
			Services:   true,
		}, rc.Status().Synced)
	}, timeout, tick)

	require.True(t, fooobs.registered.Swap(false), "[Register] should have been invoked")
	require.True(t, barobs.registered.Swap(false), "[Register] should have been invoked")
	require.False(t, fooobs.revoked.Load(), "[Revoke] should not have been invoked")
	require.False(t, fooobs.drained.Load(), "[Drain] should not have been invoked")

	require.False(t, rc.Status().Ready, "Status should not be ready before all enabled observers are synced")
	fooobs.onSync()
	require.True(t, rc.Status().Ready, "Status should be ready once all enabled observers are synced")

	cancel()
	wg.Wait()

	rc.RevokeCache(ctx)
	require.True(t, fooobs.revoked.Swap(false), "[Revoke] should have been invoked")
	require.True(t, barobs.revoked.Swap(false), "[Revoke] should have been invoked")
	require.False(t, fooobs.registered.Load(), "[Register] should not have been invoked")
	require.False(t, fooobs.drained.Load(), "[Drain] should not have been invoked")

	rc.Remove(ctx)
	require.True(t, fooobs.drained.Swap(false), "[Drain] should have been invoked")
	require.True(t, barobs.drained.Swap(false), "[Drain] should have been invoked")
	require.False(t, fooobs.registered.Load(), "[Register] should not have been invoked")
	require.False(t, fooobs.revoked.Load(), "[Revoke] should not have been invoked")
}

func TestRemoteClusterExtraObserversSynced(t *testing.T) {
	// Make use of synctest to leverage [synctest.Wait], which allows waiting
	// until all goroutines are durably blocked, which is not otherwise possible.
	synctest.Test(t, func(t *testing.T) {
		var (
			obs    = fakeCMObserver{name: "foo"}
			logger = hivetest.Logger(t)
		)

		cm := ClusterMesh{
			conf: Configuration{
				StoreFactory: store.NewFactory(logger, store.MetricsProvider()),
				ObserverFactories: []observer.Factory{
					func(cluster string, onSync func()) observer.Observer {
						obs.onSync = onSync
						return &obs
					},
				},
				ServiceMerger: &fakeObserver{},
				Logger:        logger,
				Metrics:       NewMetrics(),
			},
		}

		rc := cm.NewRemoteCluster("foo", nil).(*remoteCluster)

		var ch = make(chan error, 1)

		ctx, cancel := context.WithCancel(t.Context())
		go func() { ch <- rc.synced.Observer(ctx, obs.name) }()

		synctest.Wait()
		cancel()

		require.ErrorIs(t, <-ch, context.Canceled, "The observer should not be synced")

		obs.onSync()
		require.NoError(t, rc.synced.Observer(t.Context(), obs.name), "The observer should be now synced")

		require.ErrorIs(t, rc.synced.Observer(ctx, "non-existing"), ErrObserverNotRegistered)
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
				return []ipcache.IWOpt{ipcache.WithClusterID(10), ipcache.WithIdentityValidator(25)}
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

type clusterMeshMetricsNoop struct{}

func (m clusterMeshMetricsNoop) AddClusterMeshConfig(mode string, maxClusters string) {
}

func (m clusterMeshMetricsNoop) DelClusterMeshConfig(mode string, maxClusters string) {
}

func NewClusterMeshMetricsNoop() ClusterMeshMetrics {
	return &clusterMeshMetricsNoop{}
}
