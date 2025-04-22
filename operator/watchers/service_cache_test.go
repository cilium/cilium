// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestServiceCacheEndpoints(t *testing.T) {
	endpoints := k8s.ParseEndpoints(&slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "2.2.2.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: slim_corev1.ProtocolTCP,
					},
				},
			},
		},
	})

	updateEndpoints := func(svcCache *serviceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.UpdateEndpoints(endpoints, swgEps)
	}
	deleteEndpoints := func(svcCache *serviceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.DeleteEndpoints(endpoints.EndpointSliceID, swgEps)
	}

	testServiceCache(t, updateEndpoints, deleteEndpoints)
}

func TestServiceCacheEndpointSlice(t *testing.T) {
	endpoints := k8s.ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-afbh9",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.2",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	})

	updateEndpoints := func(svcCache *serviceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.UpdateEndpoints(endpoints, swgEps)
	}
	deleteEndpoints := func(svcCache *serviceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.DeleteEndpoints(endpoints.EndpointSliceID, swgEps)
	}

	testServiceCache(t, updateEndpoints, deleteEndpoints)
}

func testServiceCache(t *testing.T,
	updateEndpointsCB, deleteEndpointsCB func(svcCache *serviceCache, swgEps *lock.StoppableWaitGroup)) {

	svcCache := newServiceCache(hivetest.Logger(t), nil)

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: slim_corev1.ServiceTypeClusterIP,
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcID := svcCache.UpdateService(k8sSvc, swgSvcs)

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received before endpoints have been imported")
	default:
	}

	swgEps := lock.NewStoppableWaitGroup()
	updateEndpointsCB(svcCache, swgEps)

	// The service should be ready as both service and endpoints have been
	// imported
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	endpoints, ready := svcCache.correlateEndpoints(svcID)
	require.True(t, ready)
	require.Equal(t, "2.2.2.2:8080/TCP", endpoints.String())

	// Updating the service without chaning it should not result in an event
	svcCache.UpdateService(k8sSvc, swgSvcs)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received for unchanged service object")
	default:
	}

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, svcID, event.ID)

		return true
	}, 2*time.Second))

	// Reinserting the service should re-match with the still existing endpoints
	svcCache.UpdateService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)

		return true
	}, 2*time.Second))

	// Deleting the endpoints will result in a service update event
	deleteEndpointsCB(svcCache, swgEps)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)

		return true
	}, 2*time.Second))

	endpoints, serviceReady := svcCache.correlateEndpoints(svcID)
	require.False(t, serviceReady)
	require.Empty(t, endpoints.String())

	// Reinserting the endpoints should re-match with the still existing service
	updateEndpointsCB(svcCache, swgEps)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	endpoints, serviceReady = svcCache.correlateEndpoints(svcID)
	require.True(t, serviceReady)
	require.Equal(t, "2.2.2.2:8080/TCP", endpoints.String())

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// Deleting the endpoints will not emit an event as the notification
	// was sent out when the service was deleted.
	deleteEndpointsCB(svcCache, swgEps)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.events:
		t.Error("Unexpected service delete event received")
	default:
	}

	swgSvcs.Stop()
	require.NoError(t, testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second))

	swgEps.Stop()
	require.NoError(t, testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second))
}

func TestCacheActionString(t *testing.T) {
	require.Equal(t, "service-updated", UpdateService.String())
	require.Equal(t, "service-deleted", DeleteService.String())
}

func TestServiceMutators(t *testing.T) {
	var m1, m2 int

	svcCache := newServiceCache(hivetest.Logger(t), nil)

	svcCache.serviceMutators = append(svcCache.serviceMutators,
		func(svc *slim_corev1.Service, svcInfo *k8s.Service) { m1++ },
		func(svc *slim_corev1.Service, svcInfo *k8s.Service) { m2++ },
	)
	swg := lock.NewStoppableWaitGroup()
	svcCache.UpdateService(&slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector:  map[string]string{"foo": "bar"},
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}, swg)

	// Assert that the service mutators configured have been executed.
	require.Equal(t, 1, m1)
	require.Equal(t, 1, m2)
}

func TestServiceCacheWith2EndpointSlice(t *testing.T) {
	k8sEndpointSlice1 := k8s.ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-yyyyy",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.2",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	})

	k8sEndpointSlice2 := k8s.ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-xxxxx",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.3",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	})

	k8sEndpointSlice3 := k8s.ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-xxxxx",
			Namespace: "baz",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.4",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	})

	svcCache := newServiceCache(hivetest.Logger(t), nil)

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: slim_corev1.ServiceTypeClusterIP,
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcID := svcCache.UpdateService(k8sSvc, swgSvcs)

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received before endpoints have been imported")
	default:
	}

	swgEps := lock.NewStoppableWaitGroup()
	svcCache.UpdateEndpoints(k8sEndpointSlice1, swgEps)
	svcCache.UpdateEndpoints(k8sEndpointSlice2, swgEps)
	svcCache.UpdateEndpoints(k8sEndpointSlice3, swgEps)

	// The service should be ready as both service and endpoints have been
	// imported for k8sEndpointSlice1
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// The service should be ready as both service and endpoints have been
	// imported for k8sEndpointSlice2
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received when endpoints not selected by a service have been imported")
	default:
	}
	endpoints, ready := svcCache.correlateEndpoints(svcID)
	require.True(t, ready)
	require.Equal(t, "2.2.2.2:8080/TCP,2.2.2.3:8080/TCP", endpoints.String())

	// Updating the service without changing it should not result in an event
	svcCache.UpdateService(k8sSvc, swgSvcs)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received for unchanged service object")
	default:
	}

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// Reinserting the service should re-match with the still existing endpoints
	svcCache.UpdateService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// Deleting the k8sEndpointSlice2 will result in a service update event
	svcCache.DeleteEndpoints(k8sEndpointSlice2.EndpointSliceID, swgEps)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	endpoints, ready = svcCache.correlateEndpoints(svcID)
	require.True(t, ready)
	require.Equal(t, "2.2.2.2:8080/TCP", endpoints.String())

	svcCache.DeleteEndpoints(k8sEndpointSlice1.EndpointSliceID, swgEps)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	endpoints, serviceReady := svcCache.correlateEndpoints(svcID)
	require.False(t, serviceReady)
	require.Empty(t, endpoints.String())

	// Reinserting the endpoints should re-match with the still existing service
	svcCache.UpdateEndpoints(k8sEndpointSlice1, swgEps)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	endpoints, serviceReady = svcCache.correlateEndpoints(svcID)
	require.True(t, serviceReady)
	require.Equal(t, "2.2.2.2:8080/TCP", endpoints.String())

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// Deleting the endpoints will not emit an event as the notification
	// was sent out when the service was deleted.
	svcCache.DeleteEndpoints(k8sEndpointSlice1.EndpointSliceID, swgEps)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.events:
		t.Error("Unexpected service delete event received")
	default:
	}

	swgSvcs.Stop()
	require.NoError(t, testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second))

	swgEps.Stop()
	require.NoError(t, testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second))
}

func TestServiceCacheWith2EndpointSliceSameAddress(t *testing.T) {
	k8sEndpointSlice1 := k8s.ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-yyyyy",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.2",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	})

	k8sEndpointSlice2 := k8s.ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-xxxxx",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.2",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc2"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8081); return &a }(),
			},
		},
	})

	svcCache := newServiceCache(hivetest.Logger(t), nil)

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: slim_corev1.ServiceTypeClusterIP,
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcID := svcCache.UpdateService(k8sSvc, swgSvcs)

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received before endpoints have been imported")
	default:
	}

	swgEps := lock.NewStoppableWaitGroup()
	svcCache.UpdateEndpoints(k8sEndpointSlice1, swgEps)
	svcCache.UpdateEndpoints(k8sEndpointSlice2, swgEps)

	// The service should be ready as both service and endpoints have been
	// imported for k8sEndpointSlice1
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// The service should be ready as both service and endpoints have been
	// imported for k8sEndpointSlice2
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received when endpoints not selected by a service have been imported")
	default:
	}
	endpoints, ready := svcCache.correlateEndpoints(svcID)
	require.True(t, ready)
	require.Equal(t, "2.2.2.2:8080/TCP,2.2.2.2:8081/TCP", endpoints.String())

	// Updating the service without changing it should not result in an event
	svcCache.UpdateService(k8sSvc, swgSvcs)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received for unchanged service object")
	default:
	}

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// Reinserting the service should re-match with the still existing endpoints
	svcCache.UpdateService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// Deleting the k8sEndpointSlice2 will result in a service update event
	svcCache.DeleteEndpoints(k8sEndpointSlice2.EndpointSliceID, swgEps)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	endpoints, ready = svcCache.correlateEndpoints(svcID)
	require.True(t, ready)
	require.Equal(t, "2.2.2.2:8080/TCP", endpoints.String())

	svcCache.DeleteEndpoints(k8sEndpointSlice1.EndpointSliceID, swgEps)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	endpoints, serviceReady := svcCache.correlateEndpoints(svcID)
	require.False(t, serviceReady)
	require.Empty(t, endpoints.String())

	// Reinserting the endpoints should re-match with the still existing service
	svcCache.UpdateEndpoints(k8sEndpointSlice1, swgEps)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	endpoints, serviceReady = svcCache.correlateEndpoints(svcID)
	require.True(t, serviceReady)
	require.Equal(t, "2.2.2.2:8080/TCP", endpoints.String())

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// Deleting the endpoints will not emit an event as the notification
	// was sent out when the service was deleted.
	svcCache.DeleteEndpoints(k8sEndpointSlice1.EndpointSliceID, swgEps)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.events:
		t.Error("Unexpected service delete event received")
	default:
	}

	swgSvcs.Stop()
	require.NoError(t, testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second))

	swgEps.Stop()
	require.NoError(t, testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second))
}

func BenchmarkCorrelateEndpoints(b *testing.B) {
	const epslices = 10
	const epsPerSlice = 100

	cache := newServiceCache(hivetest.Logger(b), nil)

	var swg lock.StoppableWaitGroup
	id := k8s.ServiceID{Name: "foo", Namespace: "bar"}
	cache.UpdateService(&slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "10.0.0.1",
			Selector:  map[string]string{"foo": "bar"},
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}, &swg)

	ip := netip.MustParseAddr("192.168.0.0")
	for i := range epslices {
		cache.UpdateEndpoints(func(i int) *k8s.Endpoints {
			return &k8s.Endpoints{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      fmt.Sprintf("foo-%04d", i),
					Namespace: "bar",
				},
				EndpointSliceID: k8s.EndpointSliceID{
					ServiceID:         id,
					EndpointSliceName: fmt.Sprintf("foo-%05d", i),
				},
				Backends: func() map[cmtypes.AddrCluster]*k8s.Backend {
					be := make(map[cmtypes.AddrCluster]*k8s.Backend)
					for range epsPerSlice {
						ip = ip.Next()
						be[cmtypes.AddrClusterFrom(ip, 0)] = &k8s.Backend{
							Ports: serviceStore.PortConfiguration{
								"http":     &loadbalancer.L4Addr{Port: 80, Protocol: "TCP"},
								"http-alt": &loadbalancer.L4Addr{Port: 8080, Protocol: "TCP"},
							},
						}
					}
					return be
				}(),
			}
		}(i), &swg)
	}

	for b.Loop() {
		eps, ready := cache.correlateEndpoints(id)
		assert.True(b, ready)
		assert.Len(b, eps.Backends, epslices*epsPerSlice)
	}
}
