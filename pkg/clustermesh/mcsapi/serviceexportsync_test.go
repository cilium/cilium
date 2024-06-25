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

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
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

	var clientset k8sClient.Clientset
	var services resource.Resource[*slim_corev1.Service]
	var serviceExports resource.Resource[*mcsapiv1alpha1.ServiceExport]
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Provide(ServiceExportResource),
		cell.Invoke(func(
			cs k8sClient.Clientset,
			svc resource.Resource[*slim_corev1.Service],
			svcExport resource.Resource[*mcsapiv1alpha1.ServiceExport],
		) {
			clientset = cs
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

	kvstore.SetupDummy(t, "etcd")

	clusterName := "cluster1"
	storeFactory := store.NewFactory(store.MetricsProvider())
	kvs := storeFactory.NewSyncStore(
		clusterName, kvstore.Client(), types.ServiceExportStorePrefix)
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
	go StartSynchronizingServiceExports(ctx, ServiceExportSyncParameters{
		ClusterName:             "cluster1",
		ClusterMeshEnableMCSAPI: true,
		Clientset:               clientset,
		ServiceExports:          serviceExports,
		Services:                services,
		store:                   kvs,
		skipCrdCheck:            true,
		SyncCallback:            func(_ context.Context) {},
	})

	t.Run("Test basic case", func(t *testing.T) {
		name := "basic"
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			storeKey := "cilium/state/serviceexports/v1/cluster1/default/" + name
			v, err := kvstore.Client().Get(ctx, storeKey)
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
			assert.True(c, exportTime.Equal(&mcsAPISvcSpec.ExportCreationTimestamp), "Export time should be equal")
			assert.Equal(c, mcsapiv1alpha1.ClusterSetIP, mcsAPISvcSpec.Type)
		}, timeout, tick, "MCSAPIServiceSpec is not correctly synced")
	})

	t.Run("Test headless case", func(t *testing.T) {
		name := "headless"
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			storeKey := "cilium/state/serviceexports/v1/cluster1/default/" + name
			v, err := kvstore.Client().Get(ctx, storeKey)
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
			v, err := kvstore.Client().Get(ctx, storeKey)
			assert.NoError(c, err)
			assert.Empty(c, string(v))
		}, timeout, tick, "MCSAPIServiceSpec is not correctly synced")
	})

	t.Run("Test remove service export", func(t *testing.T) {
		name := "remove-service-export"
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			storeKey := "cilium/state/serviceexports/v1/cluster1/default/" + name
			v, err := kvstore.Client().Get(ctx, storeKey)
			assert.NoError(c, err)
			assert.Empty(c, string(v))
		}, timeout, tick, "MCSAPIServiceSpec is not correctly synced")
	})
}
