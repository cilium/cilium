// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/common"
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

func TestRemoteClusterStatus(t *testing.T) {
	testutils.IntegrationTest(t)

	client := kvstore.SetupDummy(t, "etcd")
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

				require.NoError(t, client.DeletePrefix(context.Background(), kvstore.BaseKeyPrefix))
			})

			metrics := NewMetrics()
			logger := hivetest.Logger(t)
			cm := clusterMesh{
				logger:         logger,
				storeFactory:   st,
				globalServices: common.NewGlobalServiceCache(logger, metrics.TotalGlobalServices.WithLabelValues("foo")),
				globalServiceExports: NewGlobalServiceExportCache(
					metrics.TotalGlobalServiceExports.WithLabelValues("foo"),
				),
				cfg:       ClusterMeshConfig{ClusterMeshEnableEndpointSync: tt.clusterMeshEnableEndpointSync},
				cfgMCSAPI: MCSAPIConfig{ClusterMeshEnableMCSAPI: tt.clusterMeshEnableMCSAPI},
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
	testutils.IntegrationTest(t)

	client := kvstore.SetupDummy(t, "etcd")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	logger := hivetest.Logger(t)
	st := store.NewFactory(logger, store.MetricsProvider())
	metrics := NewMetrics()
	cm := clusterMesh{
		logger:         logger,
		storeFactory:   st,
		globalServices: common.NewGlobalServiceCache(logger, metrics.TotalGlobalServices.WithLabelValues("foo")),
		globalServiceExports: NewGlobalServiceExportCache(
			metrics.TotalGlobalServiceExports.WithLabelValues("foo"),
		),
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
