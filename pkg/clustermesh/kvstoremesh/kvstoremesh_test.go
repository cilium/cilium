// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	baseclocktest "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

type remoteEtcdClientWrapper struct {
	kvstore.BackendOperations
	name   string
	cached bool

	kvs map[string]string
	mu  lock.Mutex

	syncedCanariesWatched bool
}

// Override the ListAndWatch method so that we can propagate whatever event we want without key conflicts with
// those eventually created by kvstoremesh. Additionally, this also allows to track which prefixes have been watched.
func (w *remoteEtcdClientWrapper) ListAndWatch(ctx context.Context, prefix string, chanSize int) *kvstore.Watcher {
	events := make(kvstore.EventChan, 10)

	w.mu.Lock()
	defer w.mu.Unlock()

	if prefix == fmt.Sprintf("cilium/synced/%s/", w.name) {
		state := "state"
		if w.cached {
			state = "cache"
		}

		w.syncedCanariesWatched = true
		events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: fmt.Sprintf("cilium/synced/%s/cilium/%s/nodes/v1", w.name, state)}
		events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: fmt.Sprintf("cilium/synced/%s/cilium/%s/services/v1", w.name, state)}
		events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: fmt.Sprintf("cilium/synced/%s/cilium/%s/serviceexports/v1", w.name, state)}
		events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: fmt.Sprintf("cilium/synced/%s/cilium/%s/identities/v1", w.name, state)}
		events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: fmt.Sprintf("cilium/synced/%s/cilium/%s/ip/v1", w.name, state)}
	} else {
		for key, value := range w.kvs {
			var found bool
			if strings.HasPrefix(key, prefix) {
				events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: key, Value: []byte(value)}
				found = true
				delete(w.kvs, key)
			}

			if found {
				events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeListDone}
			}
		}
	}

	go func() {
		<-ctx.Done()
		close(events)
	}()

	return &kvstore.Watcher{Events: events}
}

func clockAdvance(t assert.TestingT, fc *baseclocktest.FakeClock, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	timer, stop := inctimer.New()
	defer stop()

	for !fc.HasWaiters() {
		select {
		case <-ctx.Done():
			assert.FailNow(t, "Could not advance clock within expected timeout")
		case <-timer.After(1 * time.Millisecond):
		}
	}

	fc.Step(d)
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
				"cilium/state/identities/v1/bar":         "qux4",
				"cilium/state/ip/v1/default/bar":         "qux5",
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
				"cilium/state/identities/v1/bar":         "qux4",
				"cilium/state/ip/v1/default/bar":         "qux5",
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
				"cilium/cache/nodes/v1/foo/bar":          "qux1",
				"cilium/cache/services/v1/foo/bar":       "qux2",
				"cilium/cache/serviceexports/v1/foo/bar": "qux3",
				"cilium/cache/identities/v1/foo/bar":     "qux4",
				"cilium/cache/ip/v1/foo/bar":             "qux5",
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
				"cilium/cache/nodes/v1/foo/bar":          "qux1",
				"cilium/cache/services/v1/foo/bar":       "qux2",
				"cilium/cache/serviceexports/v1/foo/bar": "qux3",
				"cilium/cache/identities/v1/foo/bar":     "qux4",
				"cilium/cache/ip/v1/foo/bar":             "qux5",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())

			t.Cleanup(func() {
				cancel()
				wg.Wait()

				require.NoError(t, kvstore.Client().DeletePrefix(context.Background(), kvstore.BaseKeyPrefix))
			})

			remoteClient := &remoteEtcdClientWrapper{
				BackendOperations: kvstore.Client(),
				name:              "foo",
				cached:            tt.srccfg.Capabilities.Cached,
				kvs:               tt.kvs,
			}

			st := store.NewFactory(store.MetricsProvider())
			fakeclock := baseclocktest.NewFakeClock(time.Now())
			km := KVStoreMesh{backend: kvstore.Client(), storeFactory: st, logger: logrus.New(), clock: fakeclock}

			rc := km.newRemoteCluster("foo", nil)
			ready := make(chan error)

			wg.Add(1)
			go func() {
				rc.Run(ctx, remoteClient, tt.srccfg, ready)
				rc.Stop()
				wg.Done()
			}()

			require.NoError(t, <-ready, "rc.Run() failed")

			// Assert that the cluster config got properly propagated
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				cfg, err := utils.GetClusterConfig(ctx, "foo", kvstore.Client())
				assert.NoError(c, err)
				assert.Equal(c, tt.dstcfg, cfg)
			}, timeout, tick, "Failed to retrieve the cluster config")

			expectedReflected := map[string]string{
				"cilium/cache/nodes/v1/foo/bar":      "qux1",
				"cilium/cache/services/v1/foo/bar":   "qux2",
				"cilium/cache/identities/v1/foo/bar": "qux4",
				"cilium/cache/ip/v1/foo/bar":         "qux5",
			}
			if tt.srccfg.Capabilities.ServiceExportsEnabled != nil {
				expectedReflected["cilium/cache/serviceexports/v1/foo/bar"] = "qux3"
			}
			// Assert that the keys have been properly reflected
			for key, value := range expectedReflected {
				require.EventuallyWithTf(t, func(c *assert.CollectT) {
					v, err := kvstore.Client().Get(ctx, key)
					assert.NoError(c, err)
					assert.Equal(c, value, string(v))
				}, timeout, tick, "Expected key %q does not seem to have the correct value %q", key, value)
			}

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
					v, err := kvstore.Client().Get(ctx, key)
					assert.NoError(c, err)
					assert.NotEmpty(c, string(v))
				}, timeout, tick, "Expected sync canary %q is not correctly present", key)
			}

			// Assert that synced canaries have been watched if expected
			require.Equal(t, tt.srccfg.Capabilities.SyncedCanaries, remoteClient.syncedCanariesWatched)

			cancel()
			wg.Wait()

			// rc.Remove waits for a 3 minutes grace period before proceeding
			// with the deletion. Let's handle that by advancing the fake time.
			go clockAdvance(t, fakeclock, 3*time.Minute)

			// Assert that Remove() removes all keys previously created
			rc.Remove(context.Background())

			pairs, err := kvstore.Client().ListPrefix(context.Background(), kvstore.BaseKeyPrefix)
			require.NoError(t, err, "Failed to retrieve kvstore keys")
			require.Empty(t, pairs, "Cached keys not correctly removed")
		})
	}
}

type localClientWrapper struct {
	kvstore.BackendOperations
	errors map[string]uint
}

func (lcw *localClientWrapper) Delete(ctx context.Context, key string) error {
	if cnt := lcw.errors[key]; cnt > 0 {
		lcw.errors[key] = cnt - 1
		return errors.New("fake error")
	}

	return lcw.BackendOperations.Delete(ctx, key)
}

func (lcw *localClientWrapper) DeletePrefix(ctx context.Context, path string) error {
	if cnt := lcw.errors[path]; cnt > 0 {
		lcw.errors[path] = cnt - 1
		return errors.New("fake error")
	}

	return lcw.BackendOperations.DeletePrefix(ctx, path)
}

func TestRemoteClusterRemove(t *testing.T) {
	testutils.IntegrationTest(t)

	ctx := context.Background()
	kvstore.SetupDummyWithConfigOpts(t, "etcd",
		// Explicitly set higher QPS than the default to speedup the test
		map[string]string{kvstore.EtcdRateLimitOption: "100"},
	)

	keys := func(name string) []string {
		return []string{
			fmt.Sprintf("cilium/cluster-config/%s", name),
			fmt.Sprintf("cilium/synced/%s/cilium/cache/nodes/v1", name),
			fmt.Sprintf("cilium/synced/%s/cilium/cache/services/v1", name),
			fmt.Sprintf("cilium/synced/%s/cilium/cache/identities/v1", name),
			fmt.Sprintf("cilium/synced/%s/cilium/cache/ip/v1", name),
			fmt.Sprintf("cilium/cache/nodes/v1/%s/bar", name),
			fmt.Sprintf("cilium/cache/services/v1/%s/bar", name),
			fmt.Sprintf("cilium/cache/identities/v1/%s/bar", name),
			fmt.Sprintf("cilium/cache/ip/v1/%s/bar", name),
		}
	}

	wrapper := &localClientWrapper{
		BackendOperations: kvstore.Client(),
		errors: map[string]uint{
			"cilium/cache/identities/v1/foobar/": 1,
			"cilium/cluster-config/baz":          10,
		},
	}

	st := store.NewFactory(store.MetricsProvider())
	fakeclock := baseclocktest.NewFakeClock(time.Now())
	km := KVStoreMesh{backend: wrapper, storeFactory: st, logger: logrus.New(), clock: fakeclock}
	rcs := make(map[string]*remoteCluster)
	for _, cluster := range []string{"foo", "foobar", "baz"} {
		rcs[cluster] = km.newRemoteCluster(cluster, nil).(*remoteCluster)
		rcs[cluster].Stop()
	}

	for _, rc := range rcs {
		for _, key := range keys(rc.name) {
			require.NoError(t, kvstore.Client().Update(ctx, key, []byte("value"), false))
		}
	}

	var wg sync.WaitGroup
	bgrun := func(ctx context.Context, fn func(context.Context)) {
		wg.Add(1)
		go func() {
			fn(ctx)
			wg.Done()
		}()
	}

	assertDeleted := func(t assert.TestingT, ctx context.Context, key string) {
		value, err := kvstore.Client().Get(ctx, key)
		assert.NoError(t, err, "Failed to retrieve kvstore key %s", key)
		assert.Empty(t, string(value), "Key %s has not been deleted", key)
	}

	assertNotDeleted := func(t assert.TestingT, ctx context.Context, key string) {
		value, err := kvstore.Client().Get(ctx, key)
		assert.NoError(t, err, "Failed to retrieve kvstore key %s", key)
		assert.NotEmpty(t, string(value), "Key %s has been incorrectly deleted", key)
	}

	// Remove should only delete the cluster config key before grace period expiration
	bgrun(ctx, rcs["foo"].Remove)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assertDeleted(c, ctx, keys("foo")[0])
		for _, key := range keys("foo")[1:] {
			assertNotDeleted(c, ctx, key)
		}
	}, timeout, tick)

	clockAdvance(t, fakeclock, 3*time.Minute-1*time.Millisecond)

	// Grace period should still not have expired
	time.Sleep(tick)
	for _, key := range keys("foo")[1:] {
		assertNotDeleted(t, ctx, key)
	}

	clockAdvance(t, fakeclock, 1*time.Millisecond)
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
	bgrun(ctx, rcs["foobar"].Remove)

	clockAdvance(t, fakeclock, 3*time.Minute)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// Only the keys up to the erroring one should have been deleted
		for _, key := range keys("foobar")[0:7] {
			assertDeleted(c, ctx, key)
		}
		for _, key := range keys("foobar")[7:] {
			assertNotDeleted(c, ctx, key)
		}
	}, timeout, tick)

	clockAdvance(t, fakeclock, 2*time.Second-1*time.Millisecond)
	time.Sleep(tick)
	for _, key := range keys("foobar")[7:] {
		// Backoff should not have expired yet
		assertNotDeleted(t, ctx, key)
	}

	clockAdvance(t, fakeclock, 1*time.Millisecond)
	wg.Wait()

	for _, key := range keys("foobar") {
		// Backoff expired, all keys should have been deleted
		assertDeleted(t, ctx, key)
	}

	// Simulate the persistent failure of one of the delete calls
	bgrun(ctx, rcs["baz"].Remove)

	clockAdvance(t, fakeclock, 2*time.Second)  // First retry
	clockAdvance(t, fakeclock, 4*time.Second)  // Second retry
	clockAdvance(t, fakeclock, 8*time.Second)  // Third retry
	clockAdvance(t, fakeclock, 16*time.Second) // Forth retry

	// Fifth and last retry
	clockAdvance(t, fakeclock, 32*time.Second-1*time.Millisecond)

	// Make sure that Remove() is still actually waiting. If it weren't,
	// clockAdvance couldn't complete successfully.
	clockAdvance(t, fakeclock, 1*time.Millisecond)
	wg.Wait()

	for _, key := range keys("baz") {
		// All keys should not have been deleted due to the persistent error
		assertNotDeleted(t, ctx, key)
	}

	// The context expired during grace period
	cctx, cancel := context.WithCancel(context.Background())
	bgrun(cctx, rcs["foo"].Remove)
	clockAdvance(t, fakeclock, 1*time.Minute)
	cancel()
	wg.Wait()

	// Remove the existing waiter that we didn't clean-up due to context termination.
	if fakeclock.HasWaiters() {
		fakeclock.Step(5 * time.Minute)
	}

	// The context expired during backoff
	cctx, cancel = context.WithCancel(context.Background())
	bgrun(cctx, rcs["baz"].Remove)
	clockAdvance(t, fakeclock, 1*time.Minute)
	cancel()
	wg.Wait()

	// Remove the existing waiter that we didn't clean-up due to context termination.
	if fakeclock.HasWaiters() {
		fakeclock.Step(5 * time.Minute)
	}
}

func TestRemoteClusterRemoveShutdown(t *testing.T) {
	// Test that KVStoreMesh shutdown process is not blocked by possible
	// in-progress remote cluster removals.
	testutils.IntegrationTest(t)

	ctx := context.Background()
	kvstore.SetupDummyWithConfigOpts(t, "etcd",
		// Explicitly set higher QPS than the default to speedup the test
		map[string]string{kvstore.EtcdRateLimitOption: "100"},
	)

	dir := t.TempDir()
	cfg := []byte(fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "remote"), cfg, 0644))

	// Let's manually create a fake cluster configuration for the remote cluster,
	// because we are using the same kvstore. This will be used as a synchronization
	// point to stop the hive while blocked waiting for the grace period.
	require.NoError(t, utils.SetClusterConfig(ctx, "remote", types.CiliumClusterConfig{ID: 20}, kvstore.Client()))

	var km *KVStoreMesh
	h := hive.New(
		Cell,

		cell.Provide(
			func() types.ClusterInfo { return types.ClusterInfo{ID: 10, Name: "local"} },
			func() Config { return Config{} },
			func() promise.Promise[kvstore.BackendOperations] {
				clr, clp := promise.New[kvstore.BackendOperations]()
				clr.Resolve(kvstore.Client())
				return clp
			},
		),

		cell.Invoke(func(km_ *KVStoreMesh) { km = km_ }),
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
		value, err := kvstore.Client().Get(ctx, key)
		assert.NoError(c, err, "Failed to retrieve kvstore key %s", key)
		assert.Empty(c, string(value), "Key %s has not been deleted", key)
	}, timeout, tick)

	sctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	require.NoError(t, h.Stop(tlog, sctx), "Failed to stop the hive")
}

func TestRemoteClusterStatus(t *testing.T) {
	testutils.IntegrationTest(t)

	kvstore.SetupDummy(t, "etcd")

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	t.Cleanup(func() {
		cancel()
		wg.Wait()

		require.NoError(t, kvstore.Client().DeletePrefix(context.Background(), kvstore.BaseKeyPrefix))
	})

	remoteClient := &remoteEtcdClientWrapper{
		BackendOperations: kvstore.Client(),
		name:              "foo",
		kvs: map[string]string{
			"cilium/state/nodes/v1/foo/bar":          "qux0",
			"cilium/state/nodes/v1/foo/baz":          "qux1",
			"cilium/state/services/v1/foo/bar":       "qux2",
			"cilium/state/services/v1/foo/baz":       "qux3",
			"cilium/state/services/v1/foo/qux":       "qux4",
			"cilium/state/serviceexports/v1/foo/qux": "qux5",
			"cilium/state/identities/v1/bar":         "qux6",
			"cilium/state/ip/v1/default/fred":        "qux7",
			"cilium/state/ip/v1/default/bar":         "qux8",
			"cilium/state/ip/v1/default/baz":         "qux9",
			"cilium/state/ip/v1/default/qux":         "qux10",
		},
	}
	st := store.NewFactory(store.MetricsProvider())
	km := KVStoreMesh{backend: kvstore.Client(), storeFactory: st, logger: logrus.New()}

	rc := km.newRemoteCluster("foo", func() *models.RemoteCluster {
		return &models.RemoteCluster{
			Ready:  true,
			Config: &models.RemoteClusterConfig{ServiceExportsEnabled: ptr.To(true)},
		}
	})
	cfg := types.CiliumClusterConfig{
		ID: 10, Capabilities: types.CiliumClusterConfigCapabilities{
			SyncedCanaries: true, ServiceExportsEnabled: ptr.To(true),
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

	wg.Add(1)
	go func() {
		rc.Run(ctx, remoteClient, cfg, ready)
		rc.Stop()
		wg.Done()
	}()

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
			config:  Config{PerClusterReadyTimeout: 1 * time.Millisecond, GlobalReadyTimeout: 1 * time.Millisecond},
			connect: false,
			sync:    false,
		},
		{
			name: "remote cluster connects but fails to sync",
			// use a low timeout only for global sync to avoid racing the connected signal
			config:  Config{PerClusterReadyTimeout: 5 * time.Second, GlobalReadyTimeout: 1 * time.Millisecond},
			connect: true,
			sync:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			mockClusterMesh := &mockClusterMesh{
				clusters: make(map[string]*remoteCluster),
			}
			km := KVStoreMesh{
				config: tt.config,
				common: mockClusterMesh,
				logger: logrus.New(),
			}

			rc := &remoteCluster{
				name:         "foo",
				synced:       newSynced(),
				readyTimeout: tt.config.PerClusterReadyTimeout,
				logger:       km.logger.WithField(logfields.ClusterName, "foo"),
			}
			rc.synced.resources.Add()
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
				rc.synced.resources.Done()
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
