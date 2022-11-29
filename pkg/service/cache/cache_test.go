package cache_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	. "github.com/cilium/cilium/pkg/service/cache"
)

var (
	gopherAddr = loadbalancer.NewL4Addr(loadbalancer.L4Type("TCP"), uint16(70))
)

type cacheResources struct {
	cell.Out
	Nodes     resource.Resource[*corev1.Node]
	Services  resource.Resource[*slim_corev1.Service]
	Endpoints resource.Resource[*k8s.Endpoints]
}

func TestServiceCache(t *testing.T) {
	var cache ServiceCache

	mockNodes := resource.NewMockResource[*corev1.Node]()
	mockServices := resource.NewMockResource[*slim_corev1.Service]()
	mockEndpoints := resource.NewMockResource[*k8s.Endpoints]()
	mocks := cacheResources{
		Nodes:     mockNodes,
		Services:  mockServices,
		Endpoints: mockEndpoints,
	}

	testHive := hive.New(
		// Dependencies:
		cell.Provide(func() cacheResources { return mocks }),
		cell.Provide(fakeDatapath.NewNodeAddressing),
		// ServiceCache itself:
		Cell,
		// Pull out the constructed ServiceCache so we can test
		// against it.
		cell.Invoke(func(s ServiceCache) {
			cache = s
		}),
	)

	err := testHive.Start(context.TODO())
	assert.NoError(t, err, "expected hive.Start to succeed")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	events := cache.Events(ctx)

	// FIXME test node labels
	// mockNodes.EmitUpdate(...)
	mockNodes.EmitSync()

	serviceID := k8s.ServiceID{Name: "svc1", Namespace: "default"}
	serviceClusterIP := "1.2.3.4"

	// Emit the service and mark services synced.
	mockServices.EmitUpsert(&slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{Namespace: serviceID.Namespace, Name: serviceID.Name, ResourceVersion: "1"},
		Spec: slim_corev1.ServiceSpec{
			Type:      slim_corev1.ServiceTypeClusterIP,
			ClusterIP: serviceClusterIP,
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "gopher",
					Protocol: "TCP",
					Port:     70,
				},
			},
		},
		Status: slim_corev1.ServiceStatus{},
	})

	epSliceID := k8s.EndpointSliceID{
		ServiceID:         serviceID,
		EndpointSliceName: serviceID.Name,
	}

	nodeName := "test-node"
	backendClusterIP := cmtypes.MustParseAddrCluster("2.3.4.5")

	// Emit the an endpoint for the service and mark endpoints synced.
	mockEndpoints.EmitUpsert(&k8s.Endpoints{
		EndpointSliceID: epSliceID,
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			backendClusterIP: {
				NodeName: nodeName,
				Ports:    map[string]*loadbalancer.L4Addr{"gopher": gopherAddr},
			},
		},
	})

	// Pull the first ServiceEvent and validate.
	ev := <-events
	assert.Equal(t, UpdateService, ev.Action)
	assert.Equal(t, serviceID, ev.ID)
	assert.Nil(t, ev.OldService)
	// Test that the service is set correctly. We assume parsing of services is tested separately.
	assert.Equal(t, []net.IP{net.ParseIP(serviceClusterIP)}, ev.Service.FrontendIPs)

	// Mark both resources as synced. This should emit the Synchronized event.
	mockServices.EmitSync()
	mockEndpoints.EmitSync()
	ev = <-events
	assert.Equal(t, Synchronized, ev.Action)

	// Check that current state is replayed when subscribing late.
	events2 := cache.Events(ctx)
	ev = <-events2
	assert.Equal(t, UpdateService, ev.Action)
	ev = <-events2
	assert.Equal(t, Synchronized, ev.Action)

	// ServiceCache should now be ready and lookups should work.
	ready := cache.WaitForSync(ctx)
	assert.True(t, ready)

	// GetEndpointsOfService
	eps := cache.GetEndpointsOfService(serviceID)
	assert.Equal(t, serviceID, eps.EndpointSliceID.ServiceID)
	assert.Len(t, eps.Backends, 1)
	assert.Equal(t, nodeName, eps.Backends[backendClusterIP].NodeName)

	// GetServiceFrontendIP
	ip := cache.GetServiceFrontendIP(serviceID, loadbalancer.SVCTypeClusterIP)
	assert.Equal(t, net.ParseIP(serviceClusterIP), ip)

	// GetServiceIP
	l3n4 := cache.GetServiceIP(serviceID)
	assert.Equal(t, serviceClusterIP+":70", l3n4.String())

	// EnsureService
	// TODO: Uh this is gnarly due to unbuffered channels. EnsureService
	// should not exist.
	ensured := make(chan *ServiceEvent, 2)
	go func() {
		for i := 0; i < 2; i++ {
			select {
			case ev := <-events:
				ensured <- ev
			case ev := <-events2:
				ensured <- ev
			}
		}
		close(ensured)
	}()
	exists := cache.EnsureService(serviceID)
	assert.True(t, exists)
	for ev := range ensured {
		assert.Equal(t, UpdateService, ev.Action)
	}

	// Unsubscribe and verify completion.
	cancel()

	// No further events are expected.
	ev, ok := <-events
	assert.Nil(t, ev)
	assert.False(t, ok)
	ev, ok = <-events2
	assert.Nil(t, ev)
	assert.False(t, ok)

	err = testHive.Stop(context.TODO())
	assert.NoError(t, err, "expected hive.Stop to succeed")

}
