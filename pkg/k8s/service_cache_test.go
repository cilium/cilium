// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"

	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/ip"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// looseMatch returns true if the provided frontend is found in the
// FrontendList. If the frontend has a protocol value set, it only matches a
// k8s service with a matching protocol. If no protocol is set, any k8s service
// matching frontend IP and port is considered a match, regardless of protocol.
func (l FrontendList) looseMatch(frontend loadbalancer.L3n4Addr) (exists bool) {
	switch frontend.Protocol {
	case loadbalancer.NONE:
		for _, protocol := range loadbalancer.AllProtocols {
			frontend.Protocol = protocol
			_, exists = l[frontend.StringWithProtocol()]
			if exists {
				return
			}
		}

	// If the protocol is set, perform an exact match
	default:
		_, exists = l[frontend.StringWithProtocol()]
	}
	return
}

// uniqueServiceFrontends returns all externally scoped services known to
// the service cache as a map, indexed by the string representation of a
// loadbalancer.L3n4Addr. This helper is only used in unit tests.
func (s *ServiceCacheImpl) uniqueServiceFrontends() FrontendList {
	uniqueFrontends := FrontendList{}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, svc := range s.services {
		for _, feIP := range svc.FrontendIPs {
			for _, p := range svc.Ports {
				address := loadbalancer.L3n4Addr{
					AddrCluster: cmtypes.MustAddrClusterFromIP(feIP),
					L4Addr:      *p,
					Scope:       loadbalancer.ScopeExternal,
				}
				uniqueFrontends[address.StringWithProtocol()] = struct{}{}
			}
		}

		for _, nodePortFEs := range svc.NodePorts {
			for _, fe := range nodePortFEs {
				if fe.Scope == loadbalancer.ScopeExternal {
					uniqueFrontends[fe.StringWithProtocol()] = struct{}{}
				}
			}
		}
	}

	return uniqueFrontends
}

// getServiceIP returns a random L3n4Addr that is backing the given Service ID.
// The returned IP is with external scope since its string representation might
// be used for net Dialer.
// Used in tests.
func (s *ServiceCacheImpl) getServiceIP(svcID ServiceID) *loadbalancer.L3n4Addr {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	svc := s.services[svcID]
	if svc == nil || len(svc.FrontendIPs) == 0 || len(svc.Ports) == 0 {
		return nil
	}

	feIP := ip.GetIPFromListByFamily(svc.FrontendIPs, option.Config.EnableIPv4)
	if feIP == nil {
		return nil
	}

	for _, port := range svc.Ports {
		return loadbalancer.NewL3n4Addr(port.Protocol, cmtypes.MustAddrClusterFromIP(feIP), port.Port,
			loadbalancer.ScopeExternal)
	}
	return nil
}

func newDB(t testing.TB) (*statedb.DB, statedb.RWTable[datapathTables.NodeAddress]) {
	db := statedb.New()
	nodeAddrs, err := datapathTables.NewNodeAddressTable()
	require.NoError(t, err)

	err = db.RegisterTable(nodeAddrs)
	require.NoError(t, err)

	txn := db.WriteTxn(nodeAddrs)
	for _, addr := range datapathTables.TestAddresses {
		nodeAddrs.Insert(txn, addr)
	}
	txn.Commit()

	return db, nodeAddrs
}

func TestGetUniqueServiceFrontends(t *testing.T) {
	svcID1 := ServiceID{Name: "svc1", Namespace: "default"}
	svcID2 := ServiceID{Name: "svc2", Namespace: "default"}

	endpoints := Endpoints{
		Backends: map[cmtypes.AddrCluster]*Backend{
			cmtypes.MustParseAddrCluster("3.3.3.3"): {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
				},
			},
		},
	}

	db, nodeAddrs := newDB(t)
	cache := NewServiceCache(hivetest.Logger(t), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

	cache.services = map[ServiceID]*Service{
		svcID1: {
			FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
			Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
				loadbalancer.FEPortName("foo"): {
					Protocol: loadbalancer.TCP,
					Port:     10,
				},
				loadbalancer.FEPortName("bar"): {
					Protocol: loadbalancer.TCP,
					Port:     20,
				},
			},
		},
		svcID2: {
			FrontendIPs: []net.IP{net.ParseIP("2.2.2.2")},
			Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
				loadbalancer.FEPortName("bar"): {
					Protocol: loadbalancer.UDP,
					Port:     20,
				},
			},
		},
	}
	cache.endpoints = map[ServiceID]*EndpointSlices{
		svcID1: {
			epSlices: map[string]*Endpoints{
				"": &endpoints,
			},
		},
		svcID2: {
			epSlices: map[string]*Endpoints{
				"": &endpoints,
			},
		},
	}

	frontends := cache.uniqueServiceFrontends()
	require.Equal(t, FrontendList{
		"1.1.1.1:10/TCP": {},
		"1.1.1.1:20/TCP": {},
		"2.2.2.2:20/UDP": {},
	}, frontends)

	scopes := []uint8{loadbalancer.ScopeExternal, loadbalancer.ScopeInternal}
	for _, scope := range scopes {
		// Validate all frontends as exact matches
		// These should match only for external scope
		exact_match_ok := scope == loadbalancer.ScopeExternal
		addrCluster1 := cmtypes.MustParseAddrCluster("1.1.1.1")
		addrCluster2 := cmtypes.MustParseAddrCluster("2.2.2.2")
		frontend := loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 10, scope)
		require.Equal(t, exact_match_ok, frontends.looseMatch(*frontend))
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 20, scope)
		require.Equal(t, exact_match_ok, frontends.looseMatch(*frontend))
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.UDP, addrCluster2, 20, scope)
		require.Equal(t, exact_match_ok, frontends.looseMatch(*frontend))

		// Validate protocol mismatch on exact match
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 20, scope)
		require.False(t, frontends.looseMatch(*frontend))

		// Validate protocol wildcard matching
		// These should match only for external scope
		wild_match_ok := scope == loadbalancer.ScopeExternal
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.NONE, addrCluster2, 20, scope)
		require.Equal(t, wild_match_ok, frontends.looseMatch(*frontend))
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.NONE, addrCluster1, 10, scope)
		require.Equal(t, wild_match_ok, frontends.looseMatch(*frontend))
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.NONE, addrCluster1, 20, scope)
		require.Equal(t, wild_match_ok, frontends.looseMatch(*frontend))
	}
}
func TestServiceCacheEndpoints(t *testing.T) {
	endpoints := ParseEndpoints(&slim_corev1.Endpoints{
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

	updateEndpoints := func(svcCache *ServiceCacheImpl, swgEps *lock.StoppableWaitGroup) {
		svcCache.UpdateEndpoints(endpoints, swgEps)
	}
	deleteEndpoints := func(svcCache *ServiceCacheImpl, swgEps *lock.StoppableWaitGroup) {
		svcCache.DeleteEndpoints(endpoints.EndpointSliceID, swgEps)
	}

	testServiceCache(t, updateEndpoints, deleteEndpoints)
}

func TestServiceCacheEndpointSlice(t *testing.T) {
	endpoints := ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
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

	updateEndpoints := func(svcCache *ServiceCacheImpl, swgEps *lock.StoppableWaitGroup) {
		svcCache.UpdateEndpoints(endpoints, swgEps)
	}
	deleteEndpoints := func(svcCache *ServiceCacheImpl, swgEps *lock.StoppableWaitGroup) {
		svcCache.DeleteEndpoints(endpoints.EndpointSliceID, swgEps)
	}

	testServiceCache(t, updateEndpoints, deleteEndpoints)
}

func testServiceCache(t *testing.T,
	updateEndpointsCB, deleteEndpointsCB func(svcCache *ServiceCacheImpl, swgEps *lock.StoppableWaitGroup)) {

	db, nodeAddrs := newDB(t)
	svcCache := NewServiceCache(hivetest.Logger(t), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

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

	// Add late subscriber, it should receive all events until it unsubscribes
	subCtx, subCancel := context.WithCancel(context.Background())
	svcNotifications := stream.ToChannel(subCtx, svcCache.Notifications(), stream.WithBufferSize(1))

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, svcID, event.ID)

		n := <-svcNotifications
		require.Equal(t, DeleteService, n.Action)
		require.Equal(t, svcID, n.ID)

		return true
	}, 2*time.Second))

	// Reinserting the service should re-match with the still existing endpoints
	svcCache.UpdateService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)

		n := <-svcNotifications
		require.Equal(t, UpdateService, n.Action)
		require.Equal(t, svcID, n.ID)

		return true
	}, 2*time.Second))

	// Deleting the endpoints will result in a service update event
	deleteEndpointsCB(svcCache, swgEps)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)

		n := <-svcNotifications
		require.Equal(t, UpdateService, n.Action)
		require.Equal(t, svcID, n.ID)

		return true
	}, 2*time.Second))

	// Stop subscription and wait for it to expire
	subCancel()
	require.NoError(t, testutils.WaitUntil(func() bool {
		_, stillSubscribed := <-svcNotifications
		return !stillSubscribed
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

func TestForEachService(t *testing.T) {
	db, nodeAddrs := newDB(t)
	svcCache := NewServiceCache(hivetest.Logger(t), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

	k8sSvc1 := &slim_corev1.Service{
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
	k8sEndpoints1 := ParseEndpoints(&slim_corev1.Endpoints{
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

	k8sSvc2 := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "baz",
			Namespace: "qux",
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "192.168.1.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}
	k8sEndpoints2 := ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "baz-xxxxx",
			Namespace: "qux",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "baz",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"1.1.1.1",
					"1.0.0.1",
				},
			},
		},
	})

	swg := lock.NewStoppableWaitGroup()
	svcCache.UpdateService(k8sSvc1, swg)
	svcCache.UpdateService(k8sSvc2, swg)

	svcID1, eps1 := svcCache.UpdateEndpoints(k8sEndpoints1, swg)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID1, event.ID)
		require.Equal(t, eps1, event.Endpoints)
		return true
	}, 2*time.Second))

	svcID2, eps2 := svcCache.UpdateEndpoints(k8sEndpoints2, swg)
	require.NoError(t, testutils.WaitUntil(func() bool {
		println("waiting for events2")
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID2, event.ID)
		require.Equal(t, eps2, event.Endpoints)
		return true
	}, 2*time.Second))

	services := map[ServiceID]*MinimalEndpoints{}
	svcCache.ForEachService(func(svcID ServiceID, svc *MinimalService, eps *MinimalEndpoints) bool {
		services[svcID] = eps
		return true
	})
	require.Equal(t, map[ServiceID]*MinimalEndpoints{
		svcID1: newMinimalEndpoints(eps1),
		svcID2: newMinimalEndpoints(eps2),
	}, services)
}

func TestCacheActionString(t *testing.T) {
	require.Equal(t, "service-updated", UpdateService.String())
	require.Equal(t, "service-deleted", DeleteService.String())
}

func TestServiceMutators(t *testing.T) {
	var m1, m2 int

	db, nodeAddrs := newDB(t)
	svcCache := NewServiceCache(hivetest.Logger(t), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

	svcCache.ServiceMutators = append(svcCache.ServiceMutators,
		func(svc *slim_corev1.Service, svcInfo *Service) { m1++ },
		func(svc *slim_corev1.Service, svcInfo *Service) { m2++ },
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

func TestExternalServiceMerging(t *testing.T) {
	db, nodeAddrs := newDB(t)
	svcCache := NewServiceCache(hivetest.Logger(t), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				"service.cilium.io/global": "true",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "foo",
					Protocol: slim_corev1.ProtocolTCP,
					Port:     80,
				},
			},
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcID := svcCache.UpdateService(k8sSvc, swgSvcs)

	endpoints := ParseEndpoints(&slim_corev1.Endpoints{
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

	swgEps := lock.NewStoppableWaitGroup()
	svcCache.UpdateEndpoints(endpoints, swgEps)

	// The service should be ready as both service and endpoints have been
	// imported
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// Merging a service update with own cluster name must not result in update
	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   option.Config.ClusterName,
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	},
		swgSvcs,
	)

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received")
	default:
	}

	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: false,
		Shared:          false,
	},
		swgSvcs,
	)

	// Adding non-shared remote endpoints will not trigger a service update, regardless of whether
	// IncludeExternal is set (i.e., the service is marked as a global one in the remote cluster).
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)

		require.Len(t, event.Endpoints.Backends, 1)
		require.Equal(t, &Backend{
			Ports: serviceStore.PortConfiguration{
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		}, event.Endpoints.Backends[cmtypes.MustParseAddrCluster("2.2.2.2")])

		return true
	}, 2*time.Second))

	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: true,
		Shared:          false,
	},
		swgSvcs,
	)

	// Adding non-shared remote endpoints will not trigger a service update, regardless of whether
	// IncludeExternal is set (i.e., the service is marked as a global one in the remote cluster).
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)

		require.Len(t, event.Endpoints.Backends, 1)
		require.Equal(t, &Backend{
			Ports: serviceStore.PortConfiguration{
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		}, event.Endpoints.Backends[cmtypes.MustParseAddrCluster("2.2.2.2")])

		return true
	}, 2*time.Second))

	// We do not test the case with shared remote endpoints and IncludeExternal not set
	// (i.e., the service is not marked as a global one in the remote cluster).
	// Indeed, this condition shall never happen, since a shared service shall always be global.

	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: true,
		Shared:          true,
	},
		swgSvcs,
	)

	// Adding shared remote endpoints will trigger a service update, in case IncludeExternal
	// is set (i.e., the service is marked as a global one in the remote cluster).
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		require.Equal(t, &Backend{
			Ports: serviceStore.PortConfiguration{
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		}, event.Endpoints.Backends[cmtypes.MustParseAddrCluster("2.2.2.2")])

		require.Equal(t, &Backend{
			Ports: serviceStore.PortConfiguration{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		}, event.Endpoints.Backends[cmtypes.MustParseAddrCluster("3.3.3.3")])

		return true
	}, 2*time.Second))

	// Merging a service for another name should not trigger any updates
	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster",
		Namespace: "bar",
		Name:      "foo2",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: true,
		Shared:          true,
	},
		swgSvcs,
	)

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received")
	default:
	}

	// Adding the service later must trigger an update
	svcID2 := svcCache.UpdateService(
		&slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "foo2",
				Namespace: "bar",
				Labels: map[string]string{
					"foo": "bar",
				},
				Annotations: map[string]string{
					"service.cilium.io/global": "true",
				},
			},
			Spec: slim_corev1.ServiceSpec{
				ClusterIP: "127.0.0.2",
				Selector: map[string]string{
					"foo": "bar",
				},
				Type: slim_corev1.ServiceTypeClusterIP,
			},
		},
		swgSvcs,
	)

	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID2, event.ID)
		return true
	}, 2*time.Second))

	cluster2svc := &serviceStore.ClusterService{
		Cluster:   "cluster2",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"4.4.4.4": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: true,
		Shared:          true,
	}

	// Adding another cluster to the first service will trigger an event
	svcCache.MergeExternalServiceUpdate(cluster2svc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, &Backend{
			Ports: serviceStore.PortConfiguration{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		}, event.Endpoints.Backends[cmtypes.MustParseAddrCluster("4.4.4.4")])

		return true
	}, 2*time.Second))

	svcCache.MergeExternalServiceDelete(cluster2svc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Nil(t, event.Endpoints.Backends[cmtypes.MustParseAddrCluster("4.4.4.4")])
		return true
	}, 2*time.Second))

	// Deletion of the service frontend will trigger the delete notification
	svcCache.DeleteService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, svcID, event.ID)
		return true
	}, 2*time.Second))

	// When re-adding the service, the remote endpoints of cluster1 must still be present
	svcCache.UpdateService(k8sSvc, swgSvcs)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID, event.ID)
		require.Equal(t, &Backend{
			Ports: serviceStore.PortConfiguration{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		}, event.Endpoints.Backends[cmtypes.MustParseAddrCluster("3.3.3.3")])
		return true
	}, 2*time.Second))

	k8sSvcID, _ := ParseService(hivetest.Logger(t), loadbalancer.DefaultConfig, k8sSvc, nil)
	addresses := svcCache.getServiceIP(k8sSvcID)
	require.Equal(t, loadbalancer.NewL3n4Addr(loadbalancer.TCP, cmtypes.MustParseAddrCluster("127.0.0.1"), 80, loadbalancer.ScopeExternal), addresses)

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

func TestExternalServiceDeletion(t *testing.T) {
	const cluster = "cluster"

	createEndpoints := func(clusters ...string) externalEndpoints {
		eeps := newExternalEndpoints()
		for i, cluster := range clusters {
			eps := newEndpoints()
			eps.Backends[cmtypes.MustParseAddrCluster(fmt.Sprintf("1.1.1.%d", i))] = &Backend{}
			eeps.endpoints[cluster] = eps
		}

		return eeps
	}

	svc := Service{IncludeExternal: true, Shared: true}
	clsvc := serviceStore.ClusterService{Cluster: cluster, Namespace: "bar", Name: "foo"}
	id1 := ServiceID{Namespace: "bar", Name: "foo"}
	id2 := ServiceID{Cluster: cluster, Namespace: "bar", Name: "foo"}

	swg := lock.NewStoppableWaitGroup()
	db, nodeAddrs := newDB(t)
	svcCache := NewServiceCache(hivetest.Logger(t), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

	// Store the service with the non-cluster-aware ID
	svcCache.services[id1] = &svc
	svcCache.externalEndpoints[id1] = createEndpoints(cluster)

	svcCache.MergeExternalServiceDelete(&clsvc, swg)
	_, ok := svcCache.services[id1]
	require.False(t, ok)
	_, ok = svcCache.externalEndpoints[id1]
	require.False(t, ok)

	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, id1, event.ID)
		return true
	}, 2*time.Second))

	// Store the service with the non-cluster-aware ID and multiple endpoints
	svcCache.services[id1] = &svc
	svcCache.externalEndpoints[id1] = createEndpoints(cluster, "other")

	svcCache.MergeExternalServiceDelete(&clsvc, swg)
	_, ok = svcCache.services[id1]
	require.True(t, ok)
	_, ok = svcCache.externalEndpoints[id1]
	require.True(t, ok)
	_, ok = svcCache.externalEndpoints[id1].endpoints[cluster]
	require.False(t, ok)

	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, id1, event.ID)
		return true
	}, 2*time.Second))

	// Store the service with the cluster-aware ID
	svcCache.services[id2] = &svc
	svcCache.externalEndpoints[id2] = createEndpoints(cluster)

	svcCache.MergeExternalServiceDelete(&clsvc, swg)
	_, ok = svcCache.services[id2]
	require.False(t, ok)
	_, ok = svcCache.externalEndpoints[id2]
	require.False(t, ok)

	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.events
		defer event.SWGDone()
		require.Equal(t, DeleteService, event.Action)
		require.Equal(t, id2, event.ID)
		return true
	}, 2*time.Second))
}

func TestNonSharedService(t *testing.T) {
	db, nodeAddrs := newDB(t)
	svcCache := NewServiceCache(hivetest.Logger(t), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				"service.cilium.io/global": "false",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcCache.UpdateService(k8sSvc, swgSvcs)

	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	},
		swgSvcs,
	)

	// The service is unshared, it should not trigger an update
	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.events:
		t.Error("Unexpected service event received")
	default:
	}

	swgSvcs.Stop()
	require.NoError(t, testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second))
}

func TestServiceCacheWith2EndpointSlice(t *testing.T) {
	k8sEndpointSlice1 := ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
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

	k8sEndpointSlice2 := ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
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

	k8sEndpointSlice3 := ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
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

	db, nodeAddrs := newDB(t)
	svcCache := NewServiceCache(hivetest.Logger(t), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

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
	k8sEndpointSlice1 := ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
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

	k8sEndpointSlice2 := ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
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

	db, nodeAddrs := newDB(t)
	svcCache := NewServiceCache(hivetest.Logger(t), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

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

func TestServiceEndpointFiltering(t *testing.T) {
	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels:    map[string]string{"foo": "bar"},
			Annotations: map[string]string{
				v1.DeprecatedAnnotationTopologyAwareHints: "auto",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector:  map[string]string{"foo": "bar"},
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}
	veryTrue := true
	k8sEndpointSlice := ParseEndpointSliceV1(hivetest.Logger(t), &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-ep-filtering",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{"10.0.0.1"},
				Hints: &slim_discovery_v1.EndpointHints{
					ForZones: []slim_discovery_v1.ForZone{{Name: "test-zone-1"}},
				},
				Conditions: slim_discovery_v1.EndpointConditions{Ready: &veryTrue},
			},
			{
				Addresses: []string{"10.0.0.2"},
				Hints: &slim_discovery_v1.EndpointHints{
					ForZones: []slim_discovery_v1.ForZone{{Name: "test-zone-2"}},
				},
				Conditions: slim_discovery_v1.EndpointConditions{Ready: &veryTrue},
			},
		},
	})

	store := node.NewTestLocalNodeStore(node.LocalNode{Node: types.Node{
		Labels: map[string]string{v1.LabelTopologyZone: "test-zone-2"},
	}})
	db, nodeAddrs := newDB(t)
	svcCache := newServiceCache(hivetest.Logger(t), hivetest.Lifecycle(t),
		loadbalancer.DefaultConfig,
		ServiceCacheConfig{EnableServiceTopology: true}, store,
		db, nodeAddrs, NewSVCMetricsNoop())

	swg := lock.NewStoppableWaitGroup()

	// Now update service and endpointslice. This should result in the service
	// update with 2.2.2.2 endpoint due to the zone filtering.
	svcID0 := svcCache.UpdateService(k8sSvc, swg)
	svcID1, eps := svcCache.UpdateEndpoints(k8sEndpointSlice, swg)
	require.Equal(t, svcID1, svcID0)
	require.Len(t, eps.Backends, 1)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.Events()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID0, event.ID)
		require.Len(t, event.Endpoints.Backends, 1)
		_, found := event.Endpoints.Backends[cmtypes.MustParseAddrCluster("10.0.0.2")]
		require.True(t, found)
		return true
	}, 2*time.Second))

	// Send self node update to remove the node's zone label. This should
	// generate the service update with both endpoints selected
	store.Update(func(ln *node.LocalNode) { ln.Labels = nil })
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.Events()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID0, event.ID)
		require.Len(t, event.Endpoints.Backends, 2)
		return true
	}, 2*time.Second))

	// Set the node's zone to test-zone-1 to select the first endpoint
	store.Update(func(ln *node.LocalNode) { ln.Labels = map[string]string{v1.LabelTopologyZone: "test-zone-1"} })
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.Events()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID0, event.ID)
		require.Len(t, event.Endpoints.Backends, 1)
		_, found := event.Endpoints.Backends[cmtypes.MustParseAddrCluster("10.0.0.1")]
		require.True(t, found)
		return true
	}, 2*time.Second))

	// Removing the service annotation should have no effect as long as EndpointSlice hints are set
	k8sSvc.ObjectMeta.Annotations = nil
	svcID0 = svcCache.UpdateService(k8sSvc, swg)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.Events()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID0, event.ID)
		require.Len(t, event.Endpoints.Backends, 1)
		return true
	}, 2*time.Second))

	// Remove the zone hints. This should select all endpoints
	k8sEndpointSlice = k8sEndpointSlice.DeepCopy()
	for _, be := range k8sEndpointSlice.Backends {
		be.HintsForZones = nil
	}
	svcID1, _ = svcCache.UpdateEndpoints(k8sEndpointSlice, swg)
	require.NoError(t, testutils.WaitUntil(func() bool {
		event := <-svcCache.Events()
		require.Equal(t, UpdateService, event.Action)
		require.Equal(t, svcID1, event.ID)
		require.Len(t, event.Endpoints.Backends, 2)
		return true
	}, 2*time.Second))
}

func BenchmarkCorrelateEndpoints(b *testing.B) {
	const epslices = 10
	const epsPerSlice = 100

	db, nodeAddrs := newDB(b)
	cache := NewServiceCache(hivetest.Logger(b), loadbalancer.DefaultConfig, db, nodeAddrs, NewSVCMetricsNoop())

	var swg lock.StoppableWaitGroup
	id := ServiceID{Name: "foo", Namespace: "bar"}
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
		cache.UpdateEndpoints(func(i int) *Endpoints {
			return &Endpoints{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:      fmt.Sprintf("foo-%04d", i),
					Namespace: "bar",
				},
				EndpointSliceID: EndpointSliceID{
					ServiceID:         id,
					EndpointSliceName: fmt.Sprintf("foo-%05d", i),
				},
				Backends: func() map[cmtypes.AddrCluster]*Backend {
					be := make(map[cmtypes.AddrCluster]*Backend)
					for range epsPerSlice {
						ip = ip.Next()
						be[cmtypes.AddrClusterFrom(ip, 0)] = &Backend{
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
