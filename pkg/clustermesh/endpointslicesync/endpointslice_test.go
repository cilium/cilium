// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/endpointslice-controller/endpointslice"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/service/store"
)

const (
	remoteClusterName string = "cluster-1"
)

func getControllerQueue(controller *endpointslice.Controller) workqueue.RateLimitingInterface {
	return *(*workqueue.RateLimitingInterface)(unsafe.Pointer(
		reflect.ValueOf(controller).Elem().FieldByName("queue").UnsafeAddr(),
	))
}

func waitEmptyQueue(queue workqueue.RateLimitingInterface) error {
	for i := 0; i < 20; i++ {
		time.Sleep(time.Millisecond * 10)
		if queue.Len() == 0 {
			return nil
		}
	}

	return fmt.Errorf("endpointSlice controller queue has not been emptied after 200ms")
}

func createService(name string) *slim_corev1.Service {
	return &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: name,
			Annotations: map[string]string{
				annotation.GlobalService:                   "true",
				annotation.GlobalServiceSyncEndpointSlices: "true",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Selector:   map[string]string{"test": "test"},
			IPFamilies: []slim_corev1.IPFamily{slim_corev1.IPv4Protocol},
		},
	}
}

func createGlobalService(globalService *common.GlobalServiceCache, podInformer *meshPodInformer, svcName string) {
	clusterSvc := &store.ClusterService{
		Cluster:   remoteClusterName,
		Namespace: svcName,
		Name:      svcName,
		Backends: map[string]store.PortConfiguration{
			"42.42.42.42": {"port-name": &loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 42}},
		},
		Shared:    true,
		ClusterID: 1,
	}
	globalService.OnUpdate(clusterSvc)
	// We manually call the rest of the informer for convenience
	podInformer.onClusterServiceUpdate(clusterSvc)

}

func getEndpointSlice(clientset k8sClient.Clientset, svcName string) (*discovery.EndpointSliceList, error) {
	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{
		discovery.LabelServiceName: svcName,
		discovery.LabelManagedBy:   utils.EndpointSliceMeshControllerName,
	}}
	return clientset.DiscoveryV1().EndpointSlices(svcName).
		List(context.Background(), metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&labelSelector)})
}

func Test_meshEndpointSlice_Reconcile(t *testing.T) {
	var fakeClient k8sClient.FakeClientset
	var services resource.Resource[*slim_corev1.Service]
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			svc resource.Resource[*slim_corev1.Service],
		) error {
			fakeClient = *c
			services = svc
			return nil
		}),
	)
	hive.Start(context.Background())

	globalService := common.NewGlobalServiceCache(metric.NewGauge(metric.GaugeOpts{}))
	podInformer := newMeshPodInformer(globalService)
	nodeInformer := newMeshNodeInformer()
	controller, serviceInformer, endpointsliceInformer := newEndpointSliceMeshController(
		context.Background(), ClusterMeshConfig{ClusterMeshMaxEndpointsPerSlice: 100},
		podInformer, nodeInformer, &fakeClient, services, globalService,
	)
	endpointsliceInformer.Start(context.Background().Done())
	go serviceInformer.Start(context.Background())
	cache.WaitForCacheSync(context.Background().Done(), serviceInformer.HasSynced)

	go controller.Run(context.Background(), 1)
	nodeInformer.onAddCluster(remoteClusterName)

	svcStore, _ := services.Store(context.Background())

	t.Run("Create service then global service", func(t *testing.T) {
		svcName := "local-svc-global-svc"
		svc1 := createService(svcName)
		svcStore.CacheStore().Add(svc1)
		serviceInformer.refreshAllCluster(svc1)
		createGlobalService(globalService, podInformer, svcName)

		queue := getControllerQueue(controller)
		require.NoError(t, waitEmptyQueue(queue))

		epList, err := getEndpointSlice(&fakeClient, svcName)
		require.NoError(t, err)
		require.Equal(t, 1, len(epList.Items))
		require.Equal(t, map[string]string{
			discovery.LabelServiceName:        svcName,
			discovery.LabelManagedBy:          utils.EndpointSliceMeshControllerName,
			mcsapiv1alpha1.LabelSourceCluster: remoteClusterName,
			corev1.IsHeadlessService:          "",
		}, epList.Items[0].Labels)
	})

	t.Run("Create global service then service", func(t *testing.T) {
		svcName := "global-svc-local-svc"
		createGlobalService(globalService, podInformer, svcName)
		svc1 := createService(svcName)
		svcStore.CacheStore().Add(svc1)
		serviceInformer.refreshAllCluster(svc1)

		queue := getControllerQueue(controller)
		require.NoError(t, waitEmptyQueue(queue))

		epList, err := getEndpointSlice(&fakeClient, svcName)
		require.NoError(t, err)
		require.Equal(t, 1, len(epList.Items))
		require.Equal(t, map[string]string{
			discovery.LabelServiceName:        svcName,
			discovery.LabelManagedBy:          utils.EndpointSliceMeshControllerName,
			mcsapiv1alpha1.LabelSourceCluster: remoteClusterName,
			corev1.IsHeadlessService:          "",
		}, epList.Items[0].Labels)
	})

	t.Run("Create service without global service", func(t *testing.T) {
		svcName := "local-svc-no-global-svc"
		svc1 := createService(svcName)
		svcStore.CacheStore().Add(svc1)
		serviceInformer.refreshAllCluster(svc1)

		queue := getControllerQueue(controller)
		require.NoError(t, waitEmptyQueue(queue))

		epList, err := getEndpointSlice(&fakeClient, svcName)
		require.NoError(t, err)
		require.Zero(t, len(epList.Items))
	})

	t.Run("Create global service without service", func(t *testing.T) {
		svcName := "global-svc-no-local-svc"
		createGlobalService(globalService, podInformer, svcName)

		queue := getControllerQueue(controller)
		require.NoError(t, waitEmptyQueue(queue))

		epList, err := getEndpointSlice(&fakeClient, svcName)
		require.NoError(t, err)
		require.Zero(t, len(epList.Items))
	})

	t.Run("Create service with global annotation and remove it", func(t *testing.T) {
		svcName := "svc-remove-annotation"
		createGlobalService(globalService, podInformer, svcName)
		svc1 := createService(svcName)
		svcStore.CacheStore().Add(svc1)
		serviceInformer.refreshAllCluster(svc1)

		queue := getControllerQueue(controller)
		require.NoError(t, waitEmptyQueue(queue))

		// Make sure that we have 1 endpointslice
		epList, err := getEndpointSlice(&fakeClient, svcName)
		require.NoError(t, err)
		require.Equal(t, 1, len(epList.Items))

		svc1.Annotations[annotation.GlobalServiceSyncEndpointSlices] = "false"
		svcStore.CacheStore().Update(svc1)
		serviceInformer.refreshAllCluster(svc1)

		require.NoError(t, waitEmptyQueue(queue))

		epList, err = getEndpointSlice(&fakeClient, svcName)
		require.NoError(t, err)
		require.Zero(t, len(epList.Items))
	})
}
