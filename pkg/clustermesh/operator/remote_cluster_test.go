// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"context"
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
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/clustermesh/observer"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/testutils"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

func TestMain(m *testing.M) {
	testutils.GoleakVerifyTestMain(m)
}

func TestRemoteClusterStatus(t *testing.T) {
	client := kvstore.NewInMemoryClient(statedb.New(), "__remote__")
	kvsService := map[string]string{
		"cilium/state/services/v1/foo/baz/bar": `{"name": "bar", "namespace": "baz", "cluster": "foo", "clusterID": 1}`,
	}
	kvsServiceExport := map[string]string{
		"cilium/state/serviceexports/v1/foo/baz/bar": `{"name": "bar", "namespace": "baz", "cluster": "foo", "exportCreationTimestamp": "2024-07-07T15:55:07.627472784+02:00", "type": "ClusterSetIP", "sessionAffinity": "None"}`,
	}

	tests := []struct {
		name                            string
		clusterMeshEnableEndpointSync   bool
		clusterMeshEnableMCSAPI         bool
		capabilityServiceExportsEnabled *bool
		expectedServiceSync             bool
		expectedMCSAPISync              bool
	}{
		{
			name:                            "Everything disabled",
			clusterMeshEnableEndpointSync:   false,
			clusterMeshEnableMCSAPI:         false,
			capabilityServiceExportsEnabled: nil,
			expectedServiceSync:             false,
			expectedMCSAPISync:              false,
		},
		{
			name:                            "Both config enabled but remote doesn't support service exports",
			clusterMeshEnableEndpointSync:   true,
			clusterMeshEnableMCSAPI:         true,
			capabilityServiceExportsEnabled: nil,
			expectedServiceSync:             true,
			expectedMCSAPISync:              false,
		},
		{
			name:                            "Both config enabled and remote supports service exports",
			clusterMeshEnableEndpointSync:   true,
			clusterMeshEnableMCSAPI:         true,
			capabilityServiceExportsEnabled: ptr.To(false),
			expectedServiceSync:             true,
			expectedMCSAPISync:              true,
		},
	}

	st := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())

			t.Cleanup(func() {
				cancel()
				wg.Wait()
			})

			logger := hivetest.Logger(t)
			metrics := NewMetrics()
			cm := clusterMesh{
				logger:               logger,
				metrics:              metrics,
				storeFactory:         st,
				globalServices:       common.NewGlobalServiceCache(logger),
				globalServiceExports: NewGlobalServiceExportCache(),
				cfg:                  ClusterMeshConfig{ClusterMeshEnableEndpointSync: tt.clusterMeshEnableEndpointSync},
				cfgMCSAPI:            mcsapitypes.MCSAPIConfig{EnableMCSAPI: tt.clusterMeshEnableMCSAPI},
			}

			// Populate the kvstore with the appropriate KV pairs
			for key, value := range kvsService {
				require.NoErrorf(t, client.Update(ctx, key, []byte(value), false), "Failed to set %s=%s", key, value)
			}
			if tt.capabilityServiceExportsEnabled != nil {
				for key, value := range kvsServiceExport {
					require.NoErrorf(t, client.Update(ctx, key, []byte(value), false), "Failed to set %s=%s", key, value)
				}
			}

			rc := cm.newRemoteCluster("foo", func() *models.RemoteCluster {
				return &models.RemoteCluster{Ready: true, Config: &models.RemoteClusterConfig{
					ServiceExportsEnabled: tt.capabilityServiceExportsEnabled,
				}}
			})

			// Validate the status before watching the remote cluster.
			status := rc.(*remoteCluster).Status()
			if tt.expectedServiceSync || tt.expectedMCSAPISync {
				require.False(t, status.Ready, "Status should not be ready")
			}

			if tt.expectedServiceSync {
				require.False(t, status.Synced.Services, "Services should not be synced")
			}
			if tt.expectedMCSAPISync {
				require.False(t, status.Synced.ServiceExports != nil && *status.Synced.ServiceExports, "Service Exports should not be synced")
			} else {
				require.Nil(t, status.Synced.ServiceExports, "Service Exports should not be considered for syncing")
			}

			require.EqualValues(t, 0, status.NumSharedServices, "Incorrect number of services")
			require.EqualValues(t, 0, status.NumServiceExports, "Incorrect number of service exports")

			cfg := types.CiliumClusterConfig{
				ID: 10, Capabilities: types.CiliumClusterConfigCapabilities{
					ServiceExportsEnabled: tt.capabilityServiceExportsEnabled,
				},
			}
			ready := make(chan error)
			wg.Add(1)
			go func() {
				rc.Run(ctx, client, cfg, ready)
				wg.Done()
			}()

			require.NoError(t, <-ready, "rc.Run() failed")

			require.EventuallyWithT(t, func(c *assert.CollectT) {
				status := rc.(*remoteCluster).Status()
				assert.True(c, status.Ready, "Status should be ready")

				assert.True(c, status.Synced.Services, "Services should be synced")
				if tt.expectedMCSAPISync {
					assert.True(c, status.Synced.ServiceExports != nil && *status.Synced.ServiceExports, "Service Exports should be synced")
				} else {
					assert.Nil(c, status.Synced.ServiceExports, "Service Exports should not be considered for syncing")
				}

				if tt.expectedServiceSync {
					assert.EqualValues(c, 1, status.NumSharedServices, "Incorrect number of services")
				} else {
					assert.EqualValues(c, 0, status.NumSharedServices, "Incorrect number of services")
				}
				if tt.expectedMCSAPISync {
					assert.EqualValues(c, 1, status.NumServiceExports, "Incorrect number of service exports")
				} else {
					assert.EqualValues(c, 0, status.NumServiceExports, "Incorrect number of service exports")
				}
			}, timeout, tick, "Reported status is not correct")
		})
	}
}

func TestRemoteClusterHooks(t *testing.T) {
	client := kvstore.NewInMemoryClient(statedb.New(), "__remote__")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	logger := hivetest.Logger(t)
	metrics := NewMetrics()
	st := store.NewFactory(logger, store.MetricsProvider())
	cm := clusterMesh{
		logger:               logger,
		metrics:              metrics,
		storeFactory:         st,
		globalServices:       common.NewGlobalServiceCache(logger),
		globalServiceExports: NewGlobalServiceExportCache(),
	}

	clusterAddCalledCount := atomic.Uint32{}
	clusterRemoveCalledCount := atomic.Uint32{}

	cm.RegisterClusterAddHook(func(s string) {
		clusterAddCalledCount.Add(1)
	})
	cm.RegisterClusterDeleteHook(func(s string) {
		clusterRemoveCalledCount.Add(1)
	})

	cfg := types.CiliumClusterConfig{
		ID: 10, Capabilities: types.CiliumClusterConfigCapabilities{},
	}
	ready := make(chan error)
	rc := cm.newRemoteCluster("foo", func() *models.RemoteCluster {
		return &models.RemoteCluster{Ready: true, Config: &models.RemoteClusterConfig{}}
	})

	wg.Add(1)
	go func() {
		rc.Run(ctx, client, cfg, ready)
		wg.Done()
	}()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.EqualValues(c, 1, clusterAddCalledCount.Load(), "cluster add called once")
	}, timeout, tick, "Reported status is not correct")

	rc.Remove(ctx)
	require.EqualValues(t, 1, clusterRemoveCalledCount.Load(), "cluster remove called once")
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

	cm := clusterMesh{
		logger:            logger,
		metrics:           NewMetrics(),
		observerFactories: []observer.Factory{factory(&fooobs), factory(&barobs)},
		storeFactory:      store.NewFactory(logger, store.MetricsProvider()),
	}

	rc := cm.newRemoteCluster("foo", func() *models.RemoteCluster {
		return &models.RemoteCluster{Ready: true}
	}).(*remoteCluster)

	require.False(t, rc.Status().Ready, "Status should not be ready before [Run] is invoked")

	ready := make(chan error)
	wg.Go(func() { rc.Run(ctx, remote, cfg, ready) })

	require.NoError(t, <-ready, "rc.Run() failed")

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

		cm := clusterMesh{
			logger:  logger,
			metrics: NewMetrics(),
			observerFactories: []observer.Factory{
				func(cluster string, onSync func()) observer.Observer {
					obs.onSync = onSync
					return &obs
				},
			},
			storeFactory: store.NewFactory(logger, store.MetricsProvider()),
		}

		rc := cm.newRemoteCluster("foo", nil).(*remoteCluster)

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
