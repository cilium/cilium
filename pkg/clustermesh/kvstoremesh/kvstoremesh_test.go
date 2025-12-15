// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/clustermesh/clustercfg"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/testutils"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

type RemoteClient kvstore.Client

func fixture(extra ...cell.Cell) *hive.Hive {
	return hive.New(
		Cell,

		store.Cell,
		cell.Provide(
			func() types.ClusterInfo { return types.ClusterInfo{ID: 10, Name: "local"} },
			func() Config { return DefaultConfig },
			func(db *statedb.DB) (kvstore.Client, RemoteClient) {
				return kvstore.NewInMemoryClient(db, "__local__"), kvstore.NewInMemoryClient(db, "__remote__")
			},
		),

		cell.DecorateAll(func(client RemoteClient) common.RemoteClientFactoryFn {
			// All remote clusters share the same underlying client.
			return func(context.Context, *slog.Logger, string, kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
				errch := make(chan error)
				close(errch)
				return client, errch
			}
		}),

		cell.Group(extra...),
	)
}

type remoteClientWrapper struct {
	kvstore.Client
	syncedCanariesWatched atomic.Bool
}

// Override the ListAndWatch method to track whether synced canaries have been watched.
func (w *remoteClientWrapper) ListAndWatch(ctx context.Context, prefix string) kvstore.EventChan {
	if strings.HasPrefix(prefix, "cilium/synced/") {
		w.syncedCanariesWatched.Store(true)
	}

	return w.Client.ListAndWatch(ctx, prefix)
}

func TestMain(m *testing.M) {
	testutils.GoleakVerifyTestMain(m)
}

func TestRemoteClusterRun(t *testing.T) {
	tests := []struct {
		name   string
		srccfg types.CiliumClusterConfig
		dstcfg types.CiliumClusterConfig
		kvs    map[string]string
	}{
		{
			name:   "remote cluster has empty cluster config",
			srccfg: types.CiliumClusterConfig{},
			dstcfg: types.CiliumClusterConfig{
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries: true,
					Cached:         true,
				},
			},
			kvs: map[string]string{
				"cilium/state/nodes/v1/foo/bar":          "qux1",
				"cilium/state/services/v1/foo/bar":       "qux2",
				"cilium/state/serviceexports/v1/foo/bar": "qux3",
				"cilium/state/identities/v1/id/bar":      "qux4",
				"cilium/state/identities/v1/value/bar":   "qux5",
				"cilium/state/ip/v1/default/bar":         "qux6",
			},
		},
		{
			name: "remote cluster supports the synced canaries",
			srccfg: types.CiliumClusterConfig{
				Capabilities: types.CiliumClusterConfigCapabilities{
					ServiceExportsEnabled: ptr.To(true),
					SyncedCanaries:        true,
				},
			},
			dstcfg: types.CiliumClusterConfig{
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries:        true,
					Cached:                true,
					ServiceExportsEnabled: ptr.To(true),
				},
			},
			kvs: map[string]string{
				"cilium/state/nodes/v1/foo/bar":          "qux1",
				"cilium/state/services/v1/foo/bar":       "qux2",
				"cilium/state/serviceexports/v1/foo/bar": "qux3",
				"cilium/state/identities/v1/id/bar":      "qux4",
				"cilium/state/identities/v1/value/bar":   "qux5",
				"cilium/state/ip/v1/default/bar":         "qux6",
			},
		},
		{
			name: "remote cluster supports the cached prefixes",
			srccfg: types.CiliumClusterConfig{
				ID: 10,
				Capabilities: types.CiliumClusterConfigCapabilities{
					Cached:                true,
					ServiceExportsEnabled: ptr.To(false),
				},
			},
			dstcfg: types.CiliumClusterConfig{
				ID: 10,
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries:        true,
					Cached:                true,
					ServiceExportsEnabled: ptr.To(false),
				},
			},
			kvs: map[string]string{
				"cilium/cache/nodes/v1/foo/bar":            "qux1",
				"cilium/cache/services/v1/foo/bar":         "qux2",
				"cilium/cache/serviceexports/v1/foo/bar":   "qux3",
				"cilium/cache/identities/v1/foo/id/bar":    "qux4",
				"cilium/cache/identities/v1/foo/value/bar": "qux5",
				"cilium/cache/ip/v1/foo/bar":               "qux6",
			},
		},
		{
			name: "remote cluster supports both synced canaries and cached prefixes",
			srccfg: types.CiliumClusterConfig{
				ID: 10,
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries:        true,
					Cached:                true,
					ServiceExportsEnabled: ptr.To(true),
				},
			},
			dstcfg: types.CiliumClusterConfig{
				ID: 10,
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries:        true,
					Cached:                true,
					ServiceExportsEnabled: ptr.To(true),
				},
			},
			kvs: map[string]string{
				"cilium/cache/nodes/v1/foo/bar":            "qux1",
				"cilium/cache/services/v1/foo/bar":         "qux2",
				"cilium/cache/serviceexports/v1/foo/bar":   "qux3",
				"cilium/cache/identities/v1/foo/id/bar":    "qux4",
				"cilium/cache/identities/v1/foo/value/bar": "qux5",
				"cilium/cache/ip/v1/foo/bar":               "qux6",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				wg     sync.WaitGroup
				local  kvstore.Client
				remote *remoteClientWrapper
				km     *KVStoreMesh
			)

			h := fixture(
				cell.Invoke(func(local_ kvstore.Client, remote_ RemoteClient, km_ *KVStoreMesh) {
					local, remote, km = local_, &remoteClientWrapper{Client: remote_}, km_
				}),
			)
			require.NoError(t, h.Populate(hivetest.Logger(t)), "hive.Populate")

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(func() {
				cancel()
				wg.Wait()
			})

			// Populate the remote instance with the desired keys.
			for key, value := range tt.kvs {
				require.NoError(t, remote.Update(ctx, key, []byte(value), false))
			}

			// And additionally create the synced canaries.
			for _, key := range []string{"nodes", "services", "serviceexports", "identities", "ip"} {
				var state = "state"
				if tt.srccfg.Capabilities.Cached {
					state = "cache"
				}

				require.NoError(t, remote.Update(ctx,
					fmt.Sprintf("cilium/synced/foo/cilium/%s/%s/v1", state, key),
					[]byte("synced"), false))
			}

			rc := km.newRemoteCluster("foo", nil)
			ready := make(chan error)

			wg.Go(func() {
				rc.Run(ctx, remote, tt.srccfg, ready)
				rc.Stop()
			})

			require.NoError(t, <-ready, "rc.Run() failed")

			// Assert that the cluster config got properly propagated
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				cfg, err := clustercfg.Get(ctx, "foo", local)
				assert.NoError(c, err)
				assert.Equal(c, tt.dstcfg, cfg)
			}, timeout, tick, "Failed to retrieve the cluster config")

			expectedReflected := map[string]string{
				"cilium/cache/nodes/v1/foo/bar":         "qux1",
				"cilium/cache/services/v1/foo/bar":      "qux2",
				"cilium/cache/identities/v1/foo/id/bar": "qux4",
				"cilium/cache/ip/v1/foo/bar":            "qux6",
			}
			if tt.srccfg.Capabilities.ServiceExportsEnabled != nil {
				expectedReflected["cilium/cache/serviceexports/v1/foo/bar"] = "qux3"
			}
			// Assert that the keys have been properly reflected
			for key, value := range expectedReflected {
				require.EventuallyWithTf(t, func(c *assert.CollectT) {
					v, err := local.Get(ctx, key)
					assert.NoError(c, err)
					assert.Equal(c, value, string(v))
				}, timeout, tick, "Expected key %q does not seem to have the correct value %q", key, value)
			}

			// Assert that other keys have not been reflected
			values, err := local.ListPrefix(ctx, "cilium/cache/identities/v1/")
			require.NoError(t, err)
			require.Len(t, values, 1)

			expectedSyncedCanaries := []string{
				"cilium/synced/foo/cilium/cache/nodes/v1",
				"cilium/synced/foo/cilium/cache/services/v1",
				"cilium/synced/foo/cilium/cache/identities/v1",
				"cilium/synced/foo/cilium/cache/ip/v1",
			}
			if tt.srccfg.Capabilities.ServiceExportsEnabled != nil {
				expectedSyncedCanaries = append(expectedSyncedCanaries, "cilium/synced/foo/cilium/cache/serviceexports/v1")
			}
			// Assert that the sync canaries have been properly set
			for _, key := range expectedSyncedCanaries {
				require.EventuallyWithTf(t, func(c *assert.CollectT) {
					v, err := local.Get(ctx, key)
					assert.NoError(c, err)
					assert.NotEmpty(c, string(v))
				}, timeout, tick, "Expected sync canary %q is not correctly present", key)
			}

			// Assert that synced canaries have been watched if expected
			require.Equal(t, tt.srccfg.Capabilities.SyncedCanaries, remote.syncedCanariesWatched.Load())

			cancel()
			wg.Wait()

			// rc.Remove waits for a 3 minutes grace period before proceeding
			// with the deletion. Let's handle that in a synctest bubble.
			synctest.Test(t, func(t *testing.T) {
				go rc.Remove(t.Context())

				synctest.Wait()
				time.Sleep(3 * time.Minute)
				synctest.Wait()

				// Assert that Remove() removes all keys previously created
				pairs, err := local.ListPrefix(t.Context(), kvstore.BaseKeyPrefix)
				require.NoError(t, err, "Failed to retrieve kvstore keys")
				require.Empty(t, pairs, "Cached keys not correctly removed")
			})
		})
	}
}

type localClientWrapper struct {
	kvstore.Client
	errors map[string]uint
}

func (lcw *localClientWrapper) Delete(ctx context.Context, key string) error {
	if cnt := lcw.errors[key]; cnt > 0 {
		lcw.errors[key] = cnt - 1
		return errors.New("fake error")
	}

	return lcw.Client.Delete(ctx, key)
}

func (lcw *localClientWrapper) DeletePrefix(ctx context.Context, path string) error {
	if cnt := lcw.errors[path]; cnt > 0 {
		lcw.errors[path] = cnt - 1
		return errors.New("fake error")
	}

	return lcw.Client.DeletePrefix(ctx, path)
}

func TestRemoteClusterRemove(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var (
			ctx   = t.Context()
			local kvstore.Client
			km    *KVStoreMesh
		)

		h := fixture(
			cell.DecorateAll(func(local kvstore.Client) kvstore.Client {
				return &localClientWrapper{
					Client: local,
					errors: map[string]uint{
						"cilium/cache/nodes/v1/foobar/": 1,
						"cilium/cluster-config/baz":     10,
					},
				}
			}),

			cell.Invoke(func(local_ kvstore.Client, km_ *KVStoreMesh) {
				local, km = local_, km_
			}),
		)
		require.NoError(t, h.Populate(hivetest.Logger(t)), "hive.Populate")

		keys := func(name string) []string {
			return []string{
				fmt.Sprintf("cilium/cluster-config/%s", name),
				fmt.Sprintf("cilium/synced/%s/cilium/cache/nodes/v1", name),
				fmt.Sprintf("cilium/synced/%s/cilium/cache/services/v1", name),
				fmt.Sprintf("cilium/synced/%s/cilium/cache/identities/v1", name),
				fmt.Sprintf("cilium/synced/%s/cilium/cache/ip/v1", name),
				fmt.Sprintf("cilium/cache/identities/v1/%s/id/bar", name),
				fmt.Sprintf("cilium/cache/ip/v1/%s/bar", name),
				fmt.Sprintf("cilium/cache/nodes/v1/%s/bar", name),
				fmt.Sprintf("cilium/cache/services/v1/%s/bar", name),
			}
		}

		rcs := make(map[string]*remoteCluster)
		for _, cluster := range []string{"foo", "foobar", "baz"} {
			rcs[cluster] = km.newRemoteCluster(cluster, nil).(*remoteCluster)
			rcs[cluster].Stop()
		}

		for _, rc := range rcs {
			for _, key := range keys(rc.name) {
				require.NoError(t, local.Update(ctx, key, []byte("value"), false))
			}
		}

		var wg sync.WaitGroup

		assertDeleted := func(t *testing.T, ctx context.Context, key string) {
			synctest.Wait()
			value, err := local.Get(ctx, key)
			require.NoError(t, err, "Failed to retrieve kvstore key %s", key)
			require.Empty(t, string(value), "Key %s has not been deleted", key)
		}

		assertNotDeleted := func(t *testing.T, ctx context.Context, key string) {
			synctest.Wait()
			value, err := local.Get(ctx, key)
			require.NoError(t, err, "Failed to retrieve kvstore key %s", key)
			require.NotEmpty(t, string(value), "Key %s has been incorrectly deleted", key)
		}

		// Remove should only delete the cluster config key before grace period expiration
		wg.Go(func() { rcs["foo"].Remove(ctx) })

		assertDeleted(t, ctx, keys("foo")[0])
		for _, key := range keys("foo")[1:] {
			assertNotDeleted(t, ctx, key)
		}

		// Grace period should still not have expired
		time.Sleep(3*time.Minute - 1*time.Millisecond)
		for _, key := range keys("foo")[1:] {
			assertNotDeleted(t, ctx, key)
		}

		time.Sleep(1 * time.Millisecond)
		wg.Wait()

		// Grace period expired, all keys should now have been deleted
		for _, key := range keys("foo") {
			assertDeleted(t, ctx, key)
		}

		// Keys of other clusters should not have been touched
		for _, cluster := range []string{"foobar", "baz"} {
			for _, key := range keys(cluster) {
				assertNotDeleted(t, ctx, key)
			}
		}

		// Simulate the failure of one of the delete calls
		wg.Go(func() { rcs["foobar"].Remove(ctx) })

		time.Sleep(3 * time.Minute)
		// Only the keys up to the erroring one should have been deleted
		for _, key := range keys("foobar")[0:7] {
			assertDeleted(t, ctx, key)
		}
		for _, key := range keys("foobar")[7:] {
			assertNotDeleted(t, ctx, key)
		}

		time.Sleep(2*time.Second - 1*time.Millisecond)
		for _, key := range keys("foobar")[7:] {
			// Backoff should not have expired yet
			assertNotDeleted(t, ctx, key)
		}

		time.Sleep(1 * time.Millisecond)
		wg.Wait()

		for _, key := range keys("foobar") {
			// Backoff expired, all keys should have been deleted
			assertDeleted(t, ctx, key)
		}

		// Simulate the persistent failure of one of the delete calls
		var returned atomic.Bool
		wg.Go(func() { rcs["baz"].Remove(ctx); returned.Store(true) })

		time.Sleep(2 * time.Second)  // First retry
		time.Sleep(4 * time.Second)  // Second retry
		time.Sleep(8 * time.Second)  // Third retry
		time.Sleep(16 * time.Second) // Forth retry

		// Fifth and last retry
		time.Sleep(32*time.Second - 1*time.Millisecond)

		synctest.Wait()
		require.False(t, returned.Load(), "[Remove] should not have returned yet")

		time.Sleep(1 * time.Millisecond)
		wg.Wait()

		for _, key := range keys("baz") {
			// All keys should not have been deleted due to the persistent error
			assertNotDeleted(t, ctx, key)
		}

		// The context expired during grace period
		cctx, cancel := context.WithCancel(t.Context())
		wg.Go(func() { rcs["foo"].Remove(cctx) })
		time.Sleep(1 * time.Minute)
		cancel()
		wg.Wait()

		// The context expired during backoff
		cctx, cancel = context.WithCancel(t.Context())
		wg.Go(func() { rcs["baz"].Remove(cctx) })
		time.Sleep(1 * time.Minute)
		cancel()
		wg.Wait()
	})
}

func TestRemoteClusterRemoveShutdown(t *testing.T) {
	// Test that KVStoreMesh shutdown process is not blocked by possible
	// in-progress remote cluster removals.
	ctx := t.Context()

	dir := t.TempDir()
	cfg := fmt.Appendf(nil, "endpoints:\n- in-memory\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "remote"), cfg, 0644))

	var (
		km    *KVStoreMesh
		local kvstore.Client
	)

	h := fixture(
		cell.Invoke(func(local_ kvstore.Client, remote_ RemoteClient, km_ *KVStoreMesh) {
			local, km = local_, km_
			require.NoError(t, clustercfg.Set(ctx, "remote", types.CiliumClusterConfig{ID: 20}, remote_))
		}),
	)
	hive.AddConfigOverride(h, func(cfg *common.Config) { cfg.ClusterMeshConfig = dir })

	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, ctx), "Failed to start the hive")

	// Wait until the connection has been successfully established, before disconnecting.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		status := km.status()
		if assert.Len(c, status, 1) {
			assert.True(c, status[0].Ready)
		}
	}, timeout, tick, "Failed to connect to the remote cluster")

	require.NoError(t, os.Remove(filepath.Join(dir, "remote")))

	// Wait until the cluster config key has been removed, to ensure that we are
	// actually waiting for the grace period expiration.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		key := path.Join(kvstore.ClusterConfigPrefix, "remote")
		value, err := local.Get(ctx, key)
		assert.NoError(c, err, "Failed to retrieve kvstore key %s", key)
		assert.Empty(c, string(value), "Key %s has not been deleted", key)
	}, timeout, tick)

	sctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	require.NoError(t, h.Stop(tlog, sctx), "Failed to stop the hive")
}

func TestRemoteClusterStatus(t *testing.T) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(t.Context())

	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	var (
		remote kvstore.Client
		km     *KVStoreMesh
	)

	h := fixture(
		cell.Invoke(func(remote_ RemoteClient, km_ *KVStoreMesh) {
			remote, km = remote_, km_
		}),
	)
	require.NoError(t, h.Populate(hivetest.Logger(t)), "hive.Populate")

	for key, value := range map[string]string{
		"cilium/state/nodes/v1/foo/bar":          "qux0",
		"cilium/state/nodes/v1/foo/baz":          "qux1",
		"cilium/state/services/v1/foo/bar":       "qux2",
		"cilium/state/services/v1/foo/baz":       "qux3",
		"cilium/state/services/v1/foo/qux":       "qux4",
		"cilium/state/serviceexports/v1/foo/qux": "qux5",
		"cilium/state/identities/v1/id/bar":      "qux6",
		"cilium/state/ip/v1/default/fred":        "qux7",
		"cilium/state/ip/v1/default/bar":         "qux8",
		"cilium/state/ip/v1/default/baz":         "qux9",
		"cilium/state/ip/v1/default/qux":         "qux10",
	} {
		require.NoError(t, remote.Update(ctx, key, []byte(value), false))
	}

	rc := km.newRemoteCluster("foo", func() *models.RemoteCluster {
		return &models.RemoteCluster{
			Ready:  true,
			Config: &models.RemoteClusterConfig{ServiceExportsEnabled: ptr.To(true)},
		}
	})
	cfg := types.CiliumClusterConfig{
		ID: 10, Capabilities: types.CiliumClusterConfigCapabilities{
			SyncedCanaries: false, ServiceExportsEnabled: ptr.To(true),
		},
	}
	ready := make(chan error)

	// Validate the status before watching the remote cluster.
	status := rc.(*remoteCluster).Status()
	require.False(t, status.Ready, "Status should not be ready")

	require.False(t, status.Synced.Nodes, "Nodes should not be synced")
	require.False(t, status.Synced.Services, "Services should not be synced")
	require.False(t, status.Synced.ServiceExports != nil && *status.Synced.ServiceExports, "Service Exports should not be synced")
	require.False(t, status.Synced.Identities, "Identities should not be synced")
	require.False(t, status.Synced.Endpoints, "Endpoints should not be synced")

	require.EqualValues(t, 0, status.NumNodes, "Incorrect number of nodes")
	require.EqualValues(t, 0, status.NumSharedServices, "Incorrect number of services")
	require.EqualValues(t, 0, status.NumServiceExports, "Incorrect number of service exports")
	require.EqualValues(t, 0, status.NumIdentities, "Incorrect number of identities")
	require.EqualValues(t, 0, status.NumEndpoints, "Incorrect number of endpoints")

	wg.Go(func() {
		rc.Run(ctx, remote, cfg, ready)
		rc.Stop()
	})

	require.NoError(t, <-ready, "rc.Run() failed")

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		status := rc.(*remoteCluster).Status()
		assert.True(c, status.Ready, "Status should be ready")

		assert.True(c, status.Synced.Nodes, "Nodes should be synced")
		assert.True(c, status.Synced.Services, "Services should be synced")
		assert.True(c, status.Synced.ServiceExports != nil && *status.Synced.ServiceExports, "Service exports should be synced")
		assert.True(c, status.Synced.Identities, "Identities should be synced")
		assert.True(c, status.Synced.Endpoints, "Endpoints should be synced")

		assert.EqualValues(c, 2, status.NumNodes, "Incorrect number of nodes")
		assert.EqualValues(c, 3, status.NumSharedServices, "Incorrect number of services")
		assert.EqualValues(c, 1, status.NumServiceExports, "Incorrect number of service exports")
		assert.EqualValues(c, 1, status.NumIdentities, "Incorrect number of identities")
		assert.EqualValues(c, 4, status.NumEndpoints, "Incorrect number of endpoints")
	}, timeout, tick, "Reported status is not correct")
}

// mockClusterMesh is a mock implementation of the common.ClusterMesh interface
// allowing for direct manipulation of the clusters
type mockClusterMesh struct {
	clusters map[string]*remoteCluster
}

// ForEachRemoteCluster is a mirrored implementation of ClusterMesh.ForEachRemoteCluster that operates on the mocked clusters.
func (m *mockClusterMesh) ForEachRemoteCluster(fn func(common.RemoteCluster) error) error {
	for _, cluster := range m.clusters {
		if err := fn(cluster); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockClusterMesh) NumReadyClusters() int {
	return len(m.clusters)
}

func (m *mockClusterMesh) Start(cell.HookContext) error {
	return nil
}

func (m *mockClusterMesh) Stop(cell.HookContext) error {
	return nil
}

func TestRemoteClusterSync(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		connect bool
		sync    bool
	}{
		{
			name:    "remote cluster successfully syncs",
			config:  DefaultConfig,
			connect: true,
			sync:    true,
		},
		{
			name: "remote cluster fails to connect",
			// use very low timeouts to speed up the test since we expect failures
			config: Config{
				PerClusterReadyTimeout:      1 * time.Millisecond,
				GlobalReadyTimeout:          1 * time.Millisecond,
				DisableDrainOnDisconnection: false,
				EnableHeartBeat:             false,
			},
			connect: false,
			sync:    false,
		},
		{
			name: "remote cluster connects but fails to sync",
			// use a low timeout only for global sync to avoid racing the connected signal
			config: Config{
				PerClusterReadyTimeout:      5 * time.Second,
				GlobalReadyTimeout:          1 * time.Millisecond,
				DisableDrainOnDisconnection: false,
				EnableHeartBeat:             false,
			},
			connect: true,
			sync:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()

			mockClusterMesh := &mockClusterMesh{
				clusters: make(map[string]*remoteCluster),
			}
			km := KVStoreMesh{
				config:  tt.config,
				common:  mockClusterMesh,
				logger:  hivetest.Logger(t),
				started: make(chan struct{}),
			}
			close(km.started)

			rc := &remoteCluster{
				name:         "foo",
				synced:       newSynced(),
				readyTimeout: tt.config.PerClusterReadyTimeout,
				logger:       km.logger.With(logfields.ClusterName, "foo"),
			}
			swgDone := rc.synced.resources.Add()
			rc.synced.resources.Stop()

			mockClusterMesh.clusters[rc.name] = rc

			if tt.connect {
				close(rc.synced.connected)
			}

			// trigger the readiness timeout
			rc.waitForConnection(ctx)

			clusterSyncComplete := func() bool {
				select {
				case <-rc.synced.resources.WaitChannel():
					return true
				default:
					return false
				}
			}

			if tt.connect {
				require.False(t, clusterSyncComplete(), "Cluster sync should not be complete until all resources are done")
				swgDone()
			}

			require.NoError(t, rc.synced.Resources(ctx), "Still waiting for remote cluster resources")

			ss := syncstate.SyncState{StoppableWaitGroup: lock.NewStoppableWaitGroup()}
			require.False(t, ss.Complete())

			markCompleted := ss.WaitForResource()
			syncedCallback := func(ctx context.Context) {
				markCompleted(ctx)
				ss.Stop()
			}

			if !tt.sync {
				// reset the cluster's synced object so we can simulate a resource never syncing
				rc.synced = newSynced()
				rc.synced.resources.Add()
				rc.synced.resources.Stop()
				require.ErrorIs(t, km.synced(ctx, syncedCallback), context.DeadlineExceeded, "Expected timeout waiting for sync")
			} else {
				require.NoError(t, km.synced(ctx, syncedCallback), "Sync should have completed")
			}

			require.True(t, ss.Complete(), "Global sync not completed")
		})
	}
}
