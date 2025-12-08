// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	ciliumk8s "github.com/cilium/cilium/pkg/k8s"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/testutils"
)

// mockNamespaceManager is a mock implementation of cmnamespace.Manager for testing
type mockNamespaceManager struct {
	mu               sync.RWMutex
	globalNamespaces map[string]bool
	defaultGlobal    bool
}

func newMockNamespaceManager(defaultGlobal bool) *mockNamespaceManager {
	return &mockNamespaceManager{
		globalNamespaces: make(map[string]bool),
		defaultGlobal:    defaultGlobal,
	}
}

func (m *mockNamespaceManager) IsGlobalNamespaceEnabledByDefault() bool {
	return m.defaultGlobal
}

func (m *mockNamespaceManager) IsGlobalNamespaceByName(ns string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if isGlobal, exists := m.globalNamespaces[ns]; exists {
		return isGlobal, nil
	}
	return m.defaultGlobal, nil
}

func (m *mockNamespaceManager) IsGlobalNamespaceByObject(ns *slim_corev1.Namespace) bool {
	if ns == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if isGlobal, exists := m.globalNamespaces[ns.Name]; exists {
		return isGlobal
	}
	return m.defaultGlobal
}

func (m *mockNamespaceManager) setNamespaceGlobal(ns string, isGlobal bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalNamespaces[ns] = isGlobal
}

var (
	exportTime            = metav1.Now().Rfc3339Copy()
	serviceExportFixtures = []*mcsapiv1alpha1.ServiceExport{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "basic",
				Namespace:         "default",
				CreationTimestamp: exportTime,
			},
			Spec: mcsapiv1alpha1.ServiceExportSpec{
				ExportedAnnotations: map[string]string{
					"my-annotation": "test",
				},
				ExportedLabels: map[string]string{
					"my-label": "test",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "headless",
				Namespace:         "default",
				CreationTimestamp: exportTime,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "remove-service",
				Namespace:         "default",
				CreationTimestamp: exportTime,
			},
		},
	}

	serviceFixtures = []*slim_corev1.Service{
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "basic",
				Namespace: "default",
			},
			Spec: slim_corev1.ServiceSpec{
				Ports: []slim_corev1.ServicePort{{
					Name: "my-port-1",
				}},
				SessionAffinity: slim_corev1.ServiceAffinityNone,
			},
		},
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "headless",
				Namespace: "default",
			},
			Spec: slim_corev1.ServiceSpec{
				ClusterIP:       corev1.ClusterIPNone,
				SessionAffinity: slim_corev1.ServiceAffinityNone,
			},
		},
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "remove-service-export",
				Namespace: "default",
			},
		},
	}
)

func Test_mcsServiceExportSync_Reconcile(t *testing.T) {
	testutils.IntegrationTest(t)

	// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
	tick := 10 * time.Millisecond
	timeout := 5 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()

	var services resource.Resource[*slim_corev1.Service]
	var serviceExports resource.Resource[*mcsapiv1alpha1.ServiceExport]
	hive := hive.New(
		k8sFakeClient.FakeClientCell(),
		cell.Group( // k8s resources (importing 'operator/k8s' would cause a cycle)
			cell.Config(ciliumk8s.DefaultConfig),
			cell.Provide(ciliumk8s.DefaultServiceWatchConfig),
			cell.Provide(
				ciliumk8s.ServiceResource,
			),
		),
		cell.Config(envoyCfg.SecretSyncConfig{}),
		cell.Provide(ServiceExportResource),
		cell.Provide(func() mcsapitypes.MCSAPIConfig {
			return mcsapitypes.MCSAPIConfig{EnableMCSAPI: true}
		}),
		cell.Invoke(func(
			svc resource.Resource[*slim_corev1.Service],
			svcExport resource.Resource[*mcsapiv1alpha1.ServiceExport],
		) {
			services = svc
			serviceExports = svcExport
		}),
	)
	tlog := hivetest.Logger(t)
	err := hive.Start(tlog, ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer hive.Stop(tlog, context.Background())
	serviceStore, err := services.Store(ctx)
	require.NoError(t, err)
	serviceExportStore, err := serviceExports.Store(ctx)
	require.NoError(t, err)

	// Create initial state
	for _, svc := range serviceFixtures {
		require.NoError(t, serviceStore.CacheStore().Add(svc))
	}
	for _, svcExport := range serviceExportFixtures {
		require.NoError(t, serviceExportStore.CacheStore().Add(svcExport))
	}

	client := kvstore.SetupDummy(t, "etcd")

	clusterName := "cluster1"
	storeFactory := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())
	kvs := storeFactory.NewSyncStore(clusterName, client, types.ServiceExportStorePrefix)
	go kvs.Run(ctx)

	require.NoError(t, kvs.UpsertKey(ctx, &types.MCSAPIServiceSpec{
		Cluster:                 clusterName,
		Name:                    "remove-service",
		Namespace:               "default",
		ExportCreationTimestamp: exportTime,
	}))
	require.NoError(t, kvs.UpsertKey(ctx, &types.MCSAPIServiceSpec{
		Cluster:                 clusterName,
		Name:                    "remove-service-export",
		Namespace:               "default",
		ExportCreationTimestamp: exportTime,
	}))
	go (&serviceExportSync{
		logger:         hivetest.Logger(t),
		clusterName:    clusterName,
		enabled:        true,
		store:          kvs,
		serviceExports: serviceExports,
		services:       services,
	}).loop(ctx)

	t.Run("Test basic case", func(t *testing.T) {
		name := "basic"
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			storeKey := "cilium/state/serviceexports/v1/cluster1/default/" + name
			v, err := client.Get(ctx, storeKey)
			assert.NoError(c, err)
			mcsAPISvcSpec := types.MCSAPIServiceSpec{}
			assert.NoError(c, mcsAPISvcSpec.Unmarshal("", v))
			assert.Equal(c, name, mcsAPISvcSpec.Name)
			assert.Equal(c, "default", mcsAPISvcSpec.Namespace)
			assert.Equal(c, "cluster1", mcsAPISvcSpec.Cluster)
			assert.Len(c, mcsAPISvcSpec.Ports, 1)
			if len(mcsAPISvcSpec.Ports) == 1 {
				assert.Equal(c, "my-port-1", mcsAPISvcSpec.Ports[0].Name)
			}
			assert.Equal(c, map[string]string{"my-annotation": "test"}, mcsAPISvcSpec.Annotations)
			assert.Equal(c, map[string]string{"my-label": "test"}, mcsAPISvcSpec.Labels)
			assert.True(c, exportTime.Equal(&mcsAPISvcSpec.ExportCreationTimestamp), "Export time should be equal")
			assert.Equal(c, mcsapiv1alpha1.ClusterSetIP, mcsAPISvcSpec.Type)
		}, timeout, tick, "MCSAPIServiceSpec is not correctly synced")
	})

	t.Run("Test headless case", func(t *testing.T) {
		name := "headless"
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			storeKey := "cilium/state/serviceexports/v1/cluster1/default/" + name
			v, err := client.Get(ctx, storeKey)
			assert.NoError(c, err)
			mcsAPISvcSpec := types.MCSAPIServiceSpec{}
			assert.NoError(c, mcsAPISvcSpec.Unmarshal("", v))
			assert.True(c, exportTime.Equal(&mcsAPISvcSpec.ExportCreationTimestamp), "Export time should be equal")
			assert.Equal(c, mcsapiv1alpha1.Headless, mcsAPISvcSpec.Type)
		}, timeout, tick, "MCSAPIServiceSpec is not correctly synced")
	})

	t.Run("Test remove service", func(t *testing.T) {
		name := "remove-service"
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			storeKey := "cilium/state/serviceexports/v1/cluster1/default/" + name
			v, err := client.Get(ctx, storeKey)
			assert.NoError(c, err)
			assert.Empty(c, string(v))
		}, timeout, tick, "MCSAPIServiceSpec is not correctly synced")
	})

	t.Run("Test remove service export", func(t *testing.T) {
		name := "remove-service-export"
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			storeKey := "cilium/state/serviceexports/v1/cluster1/default/" + name
			v, err := client.Get(ctx, storeKey)
			assert.NoError(c, err)
			assert.Empty(c, string(v))
		}, timeout, tick, "MCSAPIServiceSpec is not correctly synced")
	})
}

func Test_mcsServiceExportSync_NamespaceFiltering(t *testing.T) {
	testutils.IntegrationTest(t)

	tick := 10 * time.Millisecond
	timeout := 5 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var services resource.Resource[*slim_corev1.Service]
	var serviceExports resource.Resource[*mcsapiv1alpha1.ServiceExport]
	var namespaces resource.Resource[*slim_corev1.Namespace]
	hive := hive.New(
		k8sFakeClient.FakeClientCell(),
		cell.Group( // k8s resources (importing 'operator/k8s' would cause a cycle)
			cell.Config(ciliumk8s.DefaultConfig),
			cell.Provide(ciliumk8s.DefaultServiceWatchConfig),
			cell.Provide(ciliumk8s.ServiceResource),
			cell.Provide(ciliumk8s.NamespaceResource),
		),
		cell.Config(envoyCfg.SecretSyncConfig{}),
		cell.Provide(ServiceExportResource),
		cell.Provide(func() mcsapitypes.MCSAPIConfig {
			return mcsapitypes.MCSAPIConfig{EnableMCSAPI: true}
		}),
		cell.Invoke(func(
			svc resource.Resource[*slim_corev1.Service],
			svcExport resource.Resource[*mcsapiv1alpha1.ServiceExport],
			ns resource.Resource[*slim_corev1.Namespace],
		) {
			services = svc
			serviceExports = svcExport
			namespaces = ns
		}),
	)
	tlog := hivetest.Logger(t)
	require.NoError(t, hive.Start(tlog, ctx))
	defer hive.Stop(tlog, context.Background())

	serviceStore, err := services.Store(ctx)
	require.NoError(t, err)
	serviceExportStore, err := serviceExports.Store(ctx)
	require.NoError(t, err)

	client := kvstore.SetupDummy(t, "etcd")
	clusterName := "cluster1"
	storeFactory := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())
	kvs := storeFactory.NewSyncStore(clusterName, client, types.ServiceExportStorePrefix)
	go kvs.Run(ctx)

	// Mock namespace manager with default global = false
	nsMgr := newMockNamespaceManager(false)
	nsMgr.setNamespaceGlobal("global-ns", true)
	nsMgr.setNamespaceGlobal("non-global-ns", false)

	// Create test services and exports
	for _, tc := range []struct {
		name, namespace string
	}{
		{"global-svc", "global-ns"},
		{"non-global-svc", "non-global-ns"},
		{"no-filter-svc", "any-ns"},
	} {
		require.NoError(t, serviceStore.CacheStore().Add(&slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{Name: tc.name, Namespace: tc.namespace},
			Spec:       slim_corev1.ServiceSpec{Ports: []slim_corev1.ServicePort{{Name: "http"}}, SessionAffinity: slim_corev1.ServiceAffinityNone},
		}))
		require.NoError(t, serviceExportStore.CacheStore().Add(&mcsapiv1alpha1.ServiceExport{
			ObjectMeta: metav1.ObjectMeta{Name: tc.name, Namespace: tc.namespace, CreationTimestamp: exportTime},
		}))
	}

	t.Run("with namespace filtering enabled", func(t *testing.T) {
		syncCtx, syncCancel := context.WithCancel(ctx)
		defer syncCancel()

		go (&serviceExportSync{
			logger: hivetest.Logger(t), clusterName: clusterName, enabled: true,
			store: kvs, serviceExports: serviceExports, services: services,
			namespaceManager: nsMgr, namespaces: namespaces,
		}).loop(syncCtx)

		// Global namespace should be synced
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			v, err := client.Get(ctx, "cilium/state/serviceexports/v1/cluster1/global-ns/global-svc")
			assert.NoError(c, err)
			assert.NotEmpty(c, string(v))
		}, timeout, tick)

		// Non-global namespace should NOT be synced
		time.Sleep(100 * time.Millisecond)
		v, err := client.Get(ctx, "cilium/state/serviceexports/v1/cluster1/non-global-ns/non-global-svc")
		require.NoError(t, err)
		assert.Empty(t, string(v), "non-global namespace should not be synced")
	})

	t.Run("without namespace manager (backward compatibility)", func(t *testing.T) {
		syncCtx, syncCancel := context.WithCancel(ctx)
		defer syncCancel()

		go (&serviceExportSync{
			logger: hivetest.Logger(t), clusterName: clusterName, enabled: true,
			store: kvs, serviceExports: serviceExports, services: services,
			namespaceManager: nil, // No filtering - all namespaces synced
		}).loop(syncCtx)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			v, err := client.Get(ctx, "cilium/state/serviceexports/v1/cluster1/any-ns/no-filter-svc")
			assert.NoError(c, err)
			assert.NotEmpty(c, string(v))
		}, timeout, tick)
	})
}
