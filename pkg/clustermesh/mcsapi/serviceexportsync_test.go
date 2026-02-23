// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
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
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/testutils"
)

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
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "non-global-svc",
				Namespace:         "non-global-ns",
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
		{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "non-global-svc",
				Namespace: "non-global-ns",
			},
			Spec: slim_corev1.ServiceSpec{
				Ports:           []slim_corev1.ServicePort{{Name: "http", Port: 80}},
				SessionAffinity: slim_corev1.ServiceAffinityNone,
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
	var namespaces resource.Resource[*slim_corev1.Namespace]
	var namespaceManager cmnamespace.Manager
	hive := hive.New(
		k8sFakeClient.FakeClientCell(),
		cell.Group( // k8s resources (importing 'operator/k8s' would cause a cycle)
			cell.Config(k8s.DefaultConfig),
			cell.Provide(k8s.DefaultServiceWatchConfig),
			cell.Provide(
				k8s.ServiceResource,
				k8s.NamespaceResource,
			),
		),
		cell.Config(envoyCfg.SecretSyncConfig{}),
		cell.Provide(ServiceExportResource),
		cell.Provide(func() mcsapitypes.MCSAPIConfig {
			return mcsapitypes.MCSAPIConfig{EnableMCSAPI: true}
		}),
		cmnamespace.Cell,
		cell.Invoke(func(
			svc resource.Resource[*slim_corev1.Service],
			svcExport resource.Resource[*mcsapiv1alpha1.ServiceExport],
			ns resource.Resource[*slim_corev1.Namespace],
			nsMgr cmnamespace.Manager,
		) {
			services = svc
			serviceExports = svcExport
			namespaces = ns
			namespaceManager = nsMgr
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
	namespaceStore, err := namespaces.Store(ctx)
	require.NoError(t, err)

	// Create the default namespace (global by default)
	defaultNs := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "default",
		},
	}
	require.NoError(t, namespaceStore.CacheStore().Add(defaultNs))

	// Create a non-global namespace (with explicit global=false annotation)
	nonGlobalNs := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: "non-global-ns",
			Annotations: map[string]string{
				"clustermesh.cilium.io/global": "false",
			},
		},
	}
	require.NoError(t, namespaceStore.CacheStore().Add(nonGlobalNs))

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
	require.NoError(t, kvs.UpsertKey(ctx, &types.MCSAPIServiceSpec{
		Cluster:                 clusterName,
		Name:                    "non-global-svc",
		Namespace:               "non-global-ns",
		ExportCreationTimestamp: exportTime,
	}))

	var synced = make(chan struct{})
	kvs.Synced(ctx, func(ctx context.Context) { close(synced) })

	// Wait for the entries to appear in etcd.
	select {
	case <-synced:
	case <-ctx.Done():
		require.FailNow(t, "Expected entries did not appear in etcd")
	}

	go (&serviceExportSync{
		logger:           hivetest.Logger(t),
		clusterName:      clusterName,
		enabled:          true,
		store:            kvs,
		serviceExports:   serviceExports,
		services:         services,
		namespaceManager: namespaceManager,
		namespaces:       namespaces,
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

	t.Run("Test remove service export in non-global namespace", func(t *testing.T) {
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			storeKey := "cilium/state/serviceexports/v1/cluster1/non-global-ns/non-global-svc"
			v, err := client.Get(ctx, storeKey)
			assert.NoError(c, err)
			assert.Empty(c, string(v), "ServiceExport in non-global namespace should be removed")
		}, timeout, tick, "MCSAPIServiceSpec in non-global namespace is not correctly removed")
	})
}
