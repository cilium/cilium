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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/metrics"
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
		srccfg *types.CiliumClusterConfig
		kvs    map[string]string
	}{
		{
			name:   "remote cluster has no cluster config",
			srccfg: nil,
			kvs: map[string]string{
				"cilium/state/nodes/v1/foo/bar":      `{"name": "bar"}`,
				"cilium/state/services/v1/foo/bar":   `{"name": "bar"}`,
				"cilium/state/identities/v1/id/9999": `key1=value1;key2=value2`,
				"cilium/state/ip/v1/default/1.1.1.1": `{"IP": "1.1.1.1"}`,
			},
		},
		{
			name: "remote cluster supports sync canaries",
			srccfg: &types.CiliumClusterConfig{
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries:       true,
					MaxConnectedClusters: 255,
				},
			},
			kvs: map[string]string{
				"cilium/state/nodes/v1/foo/bar":      `{"name": "bar"}`,
				"cilium/state/services/v1/foo/bar":   `{"name": "bar"}`,
				"cilium/state/identities/v1/id/9999": `key1=value1;key2=value2`,
				"cilium/state/ip/v1/default/1.1.1.1": `{"IP": "1.1.1.1"}`,

				"cilium/synced/foo/cilium/state/nodes/v1":      "true",
				"cilium/synced/foo/cilium/state/services/v1":   "true",
				"cilium/synced/foo/cilium/state/identities/v1": "true",
				"cilium/synced/foo/cilium/state/ip/v1":         "true",
			},
		},
		{
			name: "remote cluster supports both sync canaries and cached prefixes",
			srccfg: &types.CiliumClusterConfig{
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries:       true,
					Cached:               true,
					MaxConnectedClusters: 255,
				},
			},
			kvs: map[string]string{
				"cilium/cache/nodes/v1/foo/bar":          `{"name": "bar"}`,
				"cilium/cache/services/v1/foo/bar":       `{"name": "bar"}`,
				"cilium/cache/identities/v1/foo/id/9999": `key1=value1;key2=value2`,
				"cilium/cache/ip/v1/foo/1.1.1.1":         `{"IP": "1.1.1.1"}`,

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

			defer t.Cleanup(func() {
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
					NodeKeyCreator:        testNodeCreator,
					NodeObserver:          newNodesObserver(),
					IPCache:               &ipc,
					RemoteIdentityWatcher: allocator,
					ClusterIDsManager:     NewClusterMeshUsedIDs(),
					Metrics:               NewMetrics(),
					StoreFactory:          store,
					ClusterInfo:           types.ClusterInfo{MaxConnectedClusters: 255},
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
			require.Equal(t, tt.srccfg != nil && tt.srccfg.Capabilities.SyncedCanaries, remoteClient.syncedCanariesWatched)
		})
	}
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
			expected: 1,
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
